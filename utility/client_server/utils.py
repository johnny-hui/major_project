"""
Description:
This python file contains utility functions used by the larger
functions in client_server.py

"""
import multiprocessing
import pickle
import socket
import threading
import time
from tqdm import tqdm
from app.api.utility import EVENT_NODE_ADD_APPROVED_PEER, EVENT_NODE_REMOVE_PENDING_PEER, EVENT_NODE_ADD_BLOCK
from exceptions.exceptions import (RequestExpiredError, RequestAlreadyExistsError, InvalidSignatureError,
                                   TransactionNotFoundError, ConsensusInitError, InvalidTokenError,
                                   InvalidBlockchainError, InvalidBlockError, PeerInvalidBlockchainError,
                                   PeerInvalidBlockHashError)
from models.Block import Block
from models.Peer import Peer
from models.Token import Token
from models.Transaction import Transaction
from utility.blockchain.utils import save_blockchain_to_file
from utility.client_server.blockchain import receive_block
from utility.crypto.aes_utils import AES_decrypt, AES_encrypt
from utility.crypto.ec_keys_utils import serialize_private_key, serialize_public_key, deserialize_private_key, \
    deserialize_public_key
from utility.general.constants import (APPLICATION_PORT, FIND_HOST_TIMEOUT,
                                       CONNECTION_TIMEOUT_ERROR, CONNECTION_ERROR, ACK, STATUS_NOT_CONNECTED,
                                       STATUS_CONNECTED,
                                       BLOCK_SIZE, RESPONSE_EXPIRED, RECEIVED_TRANSACTION_SUCCESS, RESPONSE_EXISTS,
                                       RESPONSE_INVALID_SIG, TARGET_TRANSACTION_WAIT_TIME, TIMER_INTERVAL,
                                       TARGET_WAIT_REQUEST_MSG, VOTE_YES, VOTE_NO, MODE_VOTER,
                                       APPROVED_TO_NETWORK_MSG_INITIAL, ZERO_TRUST_POLICY_MSG, STATUS_APPROVED,
                                       TARGET_PEER_APPROVED_MSG, MODE_RECEIVER, JOIN_NETWORK_SUCCESS_MSG,
                                       ROLE_PEER, ROLE_DELEGATE, TARGET_NOT_CONNECTED_MSG,
                                       CONNECT_PEERS_AFTER_APPROVAL_MSG, MODE_INITIATOR, APPROVED_SIGNAL,
                                       CONN_REJECTED_INVALID_TOKEN_MSG, CONNECTION_SUCCESSFUL_MSG, RESPONSE_REJECTED,
                                       ROLE_ADMIN, STATUS_PENDING)
from utility.general.utils import timer, determine_delegate_status, start_parallel_operation
from utility.node.node_api import send_event_to_websocket
from utility.node.node_utils import (peer_exists, add_new_transaction, save_transaction_to_file,
                                     save_pending_peer_info, remove_pending_peer, delete_transaction,
                                     change_peer_status, change_peer_role, receive_approval_token,
                                     receive_peer_dictionary, update_peer_dict, get_peer, send_approval_token,
                                     remove_all_approved_peers, synchronize_blockchain)


def _connect_to_target_peer(ip: str,
                            port: int = APPLICATION_PORT,
                            timeout: int = FIND_HOST_TIMEOUT,
                            stop_event: multiprocessing.Event = None,
                            verbose: bool = True):
    """
    Connects to a target peer using socket connection.

    @attention stop_event (Use Case):
        Exclusively used for parallel host search

    @param ip:
        The IP address of the target peer

    @param port:
        The port number of the target peer (default = 323)

    @param timeout:
        An integer (in seconds) before a connection
        timeout is thrown

    @param stop_event:
        A multiprocessing event signal used to signal other processes
        executing function to stop if target host found
        (Optional; default = None)

    @param verbose:
        A boolean to switch on verbose mode (default=True)

    @return: target_sock or None
        A target socket object if successful; otherwise None
    """
    try:
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.settimeout(timeout)

        if stop_event is not None and stop_event.is_set():
            return None

        print(f"[+] Now attempting to connect to IP: {ip}...")
        target_sock.connect((ip, port))  # a hanging function

        if stop_event is not None:
            stop_event.set()

        print(f"[+] CONNECTION EVENT: An available peer has been found ({ip}, {port})!")
        target_sock.setblocking(True)
        return target_sock
    except socket.timeout:
        print(CONNECTION_TIMEOUT_ERROR.format(ip)) if verbose else None
        return None
    except (socket.error, OSError):
        print(CONNECTION_ERROR.format(ip, port)) if verbose else None
        return None


def _generate_new_ip_from_octet(host_ip: str, new_octet: int):
    """
    Generates a new IP address from the host machine's
    IP address by replacing the last octet.
    (Ex: 10.0.0.123 -> 10.0.0.321)

    @param host_ip:
        A string for the host machine's IP address (and subnet mask)

    @param new_octet:
        An integer representing the octet to be added

    @return: new_ip
        A string for the new IP address
    """
    octets = host_ip.split('.')
    octets[-1] = str(new_octet)
    new_ip = '.'.join(octets)
    return new_ip


def _perform_iterative_host_search(peer_dict: dict, host_ip: str,
                                   event: multiprocessing.Event,
                                   start: int, end: int):
    """
    A utility function that iteratively attempts to find an
    available host (based on a given start & end octet range).

    @param peer_dict:
        A dictionary containing peer information

    @param host_ip:
        A string for the host machine's IP address (and subnet mask)

    @param event:
        A process-shared flag that is used to signal to other
        processes to stop if a target host is found

    @param start:
        An integer for the IP octet to start from

    @param end:
        An integer for the IP octet to end at

    @return: peer_sock or None
        The target peer socket object (if connected); otherwise None
    """
    for octet in range(start, end + 1):
        target_ip = _generate_new_ip_from_octet(host_ip, octet)

        if target_ip != host_ip and not peer_exists(peer_dict, target_ip):
            peer_sock = _connect_to_target_peer(ip=target_ip, port=APPLICATION_PORT,
                                                stop_event=event, verbose=False)
            if peer_sock is not None:
                return peer_sock


def receive_request_handler(self: object, peer_socket: socket.socket, peer_ip: str,
                            shared_secret: bytes, mode: str, peer_iv: bytes = None,
                            save_info: bool = True, save_file: bool = True, set_stamp: bool = True):
    """
    A helper function that handles the receiving, decrypting, and
    validation of a requesting peer's Transaction (connection request).

    Additionally, takes the information from the request and saves information
    into a Peer object.

    @attention Use Case 1:
        Invoked when requesting peer wants to connect
        to the target Node and sends an encrypted Transaction
        object over the network

    @attention Use Case 2:
        Invoked when an admin or delegate receives a signal
        from a regular peer requesting approval for a connection
        request they've received by a peer wanting to join the
        network

    @param self:
        A reference to the calling class object (Node)

    @param peer_socket:
        The requesting peer's socket

    @param peer_ip:
        The requesting peer's IP address (String)

    @param shared_secret:
        Bytes of the shared secret

    @param mode:
        A string containing the cipher mode (CBC or ECB)

    @param peer_iv:
        Bytes of the initialization vector (IV) - Optional (default = None)

    @param save_info:
        A boolean flag to determine whether to save pending peer information (default = True)

    @param save_file:
        A boolean flag to determine whether to save the request to file (system storage)

    @param set_stamp:
        A boolean flag to set the 'received_by' attribute of the received request to the receiving
        host's IP (default = True)

    @return: request
        A Transaction object
    """
    def receive_request():
        """
        Receives data for Transaction (connection request)
        from the requesting peer.

        @return: buffer
            A bytearray containing encrypted data
        """
        buffer = bytearray()
        peer_socket.send(AES_encrypt(data=ACK.encode(), key=shared_secret, mode=mode, iv=peer_iv))  # Send ACK

        # Receive the size of transaction
        data = AES_decrypt(data=peer_socket.recv(BLOCK_SIZE), key=shared_secret, mode=mode, iv=peer_iv)
        transaction_size = int.from_bytes(data, byteorder='big')

        # Initialize the progress bar
        progress_bar = tqdm(total=transaction_size, unit='B', unit_scale=True,
                            desc='[+] Receiving Connection Request (Transaction)')

        while len(buffer) < transaction_size:
            chunk = peer_socket.recv(min(transaction_size - len(buffer), 4096))
            if not chunk:
                break
            buffer += chunk
            progress_bar.update(len(chunk))

        progress_bar.close()
        return buffer

    def process_request(data: bytearray):
        """
        Decrypts, verifies and processes the requesting peer's
        connection request and if valid, saves peer's request,
        information (in file and memory) and the socket.

        @param data:
            Encrypted data in a bytearray

        @return: request & file_path
            A decrypted, verified Transaction object and the
            file path where it is saved
        """
        buf_copy = data.copy()
        decrypted_data = AES_decrypt(data=buf_copy, key=shared_secret, mode=mode, iv=peer_iv)
        request = pickle.loads(decrypted_data)

        if request.is_expired():
            peer_socket.send(AES_encrypt(data=RESPONSE_EXPIRED.encode(), key=shared_secret, mode=mode, iv=peer_iv))
            peer_socket.close()
            raise RequestExpiredError(ip=peer_ip)
        elif request.is_verified():
            try:
                add_new_transaction(self, request, set_stamp)
                transaction_path = save_transaction_to_file(data=data,
                                                            shared_secret=shared_secret,
                                                            iv=peer_iv,
                                                            mode=mode) if save_file else None
                print(RECEIVED_TRANSACTION_SUCCESS.format(peer_ip))
                return request, transaction_path
            except RequestAlreadyExistsError:
                peer_socket.send(AES_encrypt(data=RESPONSE_EXISTS.encode(), key=shared_secret, mode=mode, iv=peer_iv))
                peer_socket.close()
                raise RequestAlreadyExistsError(ip=peer_ip)
        else:
            peer_socket.send(AES_encrypt(data=RESPONSE_INVALID_SIG.encode(), key=shared_secret, mode=mode, iv=peer_iv))
            peer_socket.close()
            raise InvalidSignatureError(ip=peer_ip)
    # ================================================================================
    try:
        encrypted_data = receive_request()
        request, file_path = process_request(data=encrypted_data)

        if save_info:
            save_pending_peer_info(self, peer_socket, peer_ip, request.first_name, request.last_name,
                                   shared_secret, mode, file_path, request.role, peer_iv)

        print(f"[+] A connection request (issued by peer (IP: {request.ip_addr})) has been successfully been received!")
        peer_socket.send(AES_encrypt(data=ACK.encode(), key=shared_secret, mode=self.mode, iv=peer_iv))
        peer_socket.settimeout(None)
        return request, file_path
    except InvalidSignatureError:
        raise InvalidSignatureError(ip=peer_ip)
    except RequestAlreadyExistsError:
        raise RequestAlreadyExistsError(ip=peer_ip)
    except RequestExpiredError:
        raise RequestExpiredError(ip=peer_ip)
    except socket.timeout as e:
        raise socket.timeout(e)


def approved_handler(self: object, target_sock: socket.socket, secret: bytes,
                     iv: bytes = None, own_request: Transaction = None):
    """
    A handler for the peer connecting to the P2P network directly after
    being approved by their target.

    @param self:
        A reference to the calling class object (Node)

    @param target_sock:
        The socket object of the target peer

    @param secret:
        Bytes of the shared secret

    @param iv:
        Bytes of the initialization vector (IV) - Optional

    @param own_request:
        A Transaction object

    @return: None
    """
    def start_timer_thread(event: threading.Event):
        """
        A function that prints the time remaining while waiting for
        target peer to send their request (only when not connected).

        @param event:
            An Event object

        @return: None
        """
        thread = threading.Thread(target=timer, args=(TARGET_TRANSACTION_WAIT_TIME,
                                                      TIMER_INTERVAL,
                                                      TARGET_WAIT_REQUEST_MSG,
                                                      event))
        thread.start()

    def connected_handler():
        """
        Handles the request to join a P2P network if the target peer
        is connected to a P2P network.
        @return: None
        """
        def process_results(results_list: list):
            """
            Processes the results returned from _connect_to_peer_after
            _approved() function.

            @attention Type String:
                If a type string is found within the results list,
                then an invalid Token was detected by one or more peers;
                hence - the host is removed from the network, as per
                'zero-trust policy'

            @param results_list:
                A list of values returned from each process executing
                the _connect_to_peer_after_approved() function

            @return: None
            """
            try:
                # Check if any invalid token errors occurred in any process (String occurrence)
                for item in results_list:
                    if isinstance(item, str):
                        print(f"[+] ERROR: Your approval token is invalid as determined by one or more peers! (IP: {item})")
                        raise InvalidTokenError(ip="host")

                # If no InvalidTokenErrors found, update peer information (Peer object occurrence)
                for item in results_list:
                    if isinstance(item, Peer):
                        self.peer_dict[item.ip] = item
                        self.peer_dict[item.ip].socket.setblocking(True)
                        self.fd_list.append(self.peer_dict[item.ip].socket)

            except InvalidTokenError:  # => remove all established connections and reset state
                remove_all_approved_peers(self.peer_dict)
                self.is_connected = False
                for item in results_list:
                    if isinstance(item, Peer):
                        item.socket.close()
                target_sock.close()
                print(CONN_REJECTED_INVALID_TOKEN_MSG)
        # ====================================================================================

        try:
            print("[+] Target peer is connected to a P2P network; now initializing into the network...")
            target_sock.settimeout(TARGET_TRANSACTION_WAIT_TIME)

            # Send ACK
            target_sock.send(AES_encrypt(data=ACK.encode(), key=secret, iv=iv, mode=self.mode))

            # Sync blockchain with target peer
            synchronize_blockchain(self, target_sock, secret, self.mode, MODE_RECEIVER,
                                   iv, do_init=False, is_target_approved=True)

            # Receive approval token, block, and peer dictionary from target peer
            token = receive_approval_token(target_sock, secret, self.mode, iv)
            block = receive_block(self, target_sock, 0, secret, self.mode, iv, do_add=False)
            new_peer_dict = receive_peer_dictionary(target_sock, secret, iv, self.mode)

            # Update info from new_peer_dict into own peer dictionary
            update_peer_dict(self.peer_dict, new_peer_dict)

            # Update target peer's information to own dictionary
            target_peer = get_peer(self.peer_dict, ip=target_sock.getpeername()[0])
            target_peer.socket, target_peer.secret, target_peer.iv, target_peer.mode = (target_sock, secret, iv, self.mode)

            # Generate an argument list for parallel connecting to peers (ignore target peer)
            peer_info = _process_peer_info_into_list(self, token, block, exclude=[target_peer.ip])

            # Use multiprocessing to connect to new peers and get security parameters + socket
            results = start_parallel_operation(task=_connect_to_peer_after_approved,
                                               task_args=peer_info,
                                               num_processes=len(peer_info),
                                               prompt=CONNECT_PEERS_AFTER_APPROVAL_MSG)

            # Process the results
            process_results(results)

            # Send final ACK to notify responsible peer initialization successful
            target_sock.send(AES_encrypt(data=ACK.encode(), key=secret, mode=self.mode, iv=iv))

            # Perform finishing touches
            self.blockchain.add_block(new_block=block)
            if self.blockchain.is_valid():
                send_event_to_websocket(queue=self.back_queue,
                                        event=EVENT_NODE_ADD_BLOCK,
                                        data=pickle.dumps(block)) if self.app_flag else None
                save_blockchain_to_file(self.blockchain, self.pvt_key, self.pub_key)
            self.fd_list.append(target_sock)
            self.is_connected = True
            del new_peer_dict
            print(CONNECTION_SUCCESSFUL_MSG)

        except (socket.error, ConnectionResetError, BrokenPipeError, socket.timeout,
                InvalidTokenError, InvalidBlockError, InvalidBlockchainError) as e:
            print(f"[+] ERROR: An error has occurred while initializing into the network! [REASON: {e}]")
            target_sock.close()
            self.peer_dict.clear()
            self.is_connected = False

    def not_connected_handler():
        """
        Handles the request to join a P2P network if the target peer
        is not connected to a P2P network.
        @return: None
        """
        def perform_finishing_steps():
            self.fd_list.append(target_sock)  # fd_list == approved list
            change_peer_status(self.peer_dict, ip=request.ip_addr, status=STATUS_APPROVED)
            delete_transaction(self.pending_transactions, request.ip_addr, file_path)
            self.is_connected = True
            if self.app_flag:
                approved_peer = get_peer(self.peer_dict, request.ip_addr).to_dict()
                send_event_to_websocket(queue=self.back_queue,
                                        event=EVENT_NODE_ADD_APPROVED_PEER,
                                        data=pickle.dumps(approved_peer))
            print(JOIN_NETWORK_SUCCESS_MSG.format(target_sock.getpeername()[0]))
        # =========================================================================================
        try:
            # Set a 5-minute timeout while waiting for target peer's Transaction object
            print(TARGET_NOT_CONNECTED_MSG)
            target_sock.settimeout(TARGET_TRANSACTION_WAIT_TIME)

            # Start a live timer (countdown 5 minutes)
            stop_event = threading.Event()
            start_timer_thread(event=stop_event)

            # Wait for REQUEST signal (here, the target must choose a photo to include with their Transaction object)
            target_sock.recv(1024)

            # Receive target request
            request, file_path = receive_request_handler(self, target_sock, target_sock.getpeername()[0],
                                                         secret, self.mode, iv, save_info=False,
                                                         save_file=False, set_stamp=False)
            stop_event.set()

            # Add target to peer dict
            self.peer_dict[request.ip_addr] = Peer(ip=request.ip_addr, first_name=request.first_name,
                                                   last_name=request.last_name, role=request.role,
                                                   secret=secret, iv=iv, status=STATUS_PENDING,
                                                   mode=self.mode, transaction_path=file_path,
                                                   socket=target_sock)

            # Start Consensus (a trust vote on verifying target peer)
            from models.Consensus import Consensus
            consensus = Consensus(request=request, mode=MODE_VOTER,
                                  peer_socket=target_sock, peer_dict=self.peer_dict,
                                  is_connected=False, event=self.consensus_event,
                                  blockchain=self.blockchain)
            vote = consensus.start()

            # Based on vote result, perform follow-up or remove pending peer
            if vote == VOTE_YES:
                print(TARGET_PEER_APPROVED_MSG.format(request.ip_addr))

                # Compare application timestamp and determine who gets delegate (if not admin)
                if request.role == ROLE_PEER and self.role == ROLE_PEER:
                    is_delegate = determine_delegate_status(target_sock, self.app_timestamp,
                                                            mode=MODE_RECEIVER, enc_mode=self.mode,
                                                            secret=secret, iv=iv)
                    if is_delegate:
                        print("[+] PROMOTION: You have been selected to be a 'Delegate' node!")
                        self.role = ROLE_DELEGATE
                        time.sleep(1)
                        synchronize_blockchain(self, target_sock, secret, initiators_request=own_request,
                                               peer_request=request, enc_mode=self.mode, mode=MODE_INITIATOR,
                                               iv=iv, do_init=True, is_target_approved=False)
                        save_blockchain_to_file(self.blockchain, self.pvt_key, self.pub_key)
                        perform_finishing_steps()
                        self.is_promoted = True
                        return None
                    else:
                        change_peer_role(self.peer_dict, ip=request.ip_addr, role=ROLE_DELEGATE)
                        synchronize_blockchain(self, target_sock, secret, initiators_request=own_request,
                                               peer_request=request, enc_mode=self.mode, mode=MODE_RECEIVER,
                                               iv=iv, do_init=True, is_target_approved=False)

                elif request.role == ROLE_ADMIN and self.role == ROLE_PEER:  # if admin
                    synchronize_blockchain(self, target_sock, secret, initiators_request=own_request,
                                           peer_request=request,enc_mode=self.mode, mode=MODE_RECEIVER,
                                           iv=iv, do_init=True, is_target_approved=False)

                elif request.role == ROLE_PEER and self.role == ROLE_ADMIN:
                    time.sleep(1)
                    synchronize_blockchain(self, target_sock, secret, initiators_request=own_request,
                                           peer_request=request, enc_mode=self.mode, mode=MODE_INITIATOR,
                                           iv=iv, do_init=True,is_target_approved=False)

                elif request.role == ROLE_ADMIN and self.role == ROLE_ADMIN:
                    synchronize_blockchain(self, target_sock, secret, initiators_request=own_request,
                                           peer_request=request,enc_mode=self.mode, mode=MODE_RECEIVER,
                                           iv=iv, do_init=True, is_target_approved=False)

                elif request.role == ROLE_DELEGATE and self.role == ROLE_PEER:
                    synchronize_blockchain(self, target_sock, secret, initiators_request=own_request,
                                           peer_request=request,enc_mode=self.mode, mode=MODE_RECEIVER,
                                           iv=iv, do_init=True, is_target_approved=False)

                elif request.role == ROLE_PEER and self.role == ROLE_DELEGATE:
                    time.sleep(1)
                    synchronize_blockchain(self, target_sock, secret, initiators_request=own_request,
                                           peer_request=request, enc_mode=self.mode, mode=MODE_INITIATOR,
                                           iv=iv, do_init=True,is_target_approved=False)

                elif request.role == ROLE_DELEGATE and self.role == ROLE_ADMIN:
                    time.sleep(1)
                    synchronize_blockchain(self, target_sock, secret, initiators_request=own_request,
                                           peer_request=request, enc_mode=self.mode, mode=MODE_INITIATOR,
                                           iv=iv, do_init=True,is_target_approved=False)

                elif request.role == ROLE_ADMIN and self.role == ROLE_DELEGATE:
                    synchronize_blockchain(self, target_sock, secret, initiators_request=own_request,
                                           peer_request=request,enc_mode=self.mode, mode=MODE_RECEIVER,
                                           iv=iv, do_init=True, is_target_approved=False)

                # Synchronize blockchain with target peer
                save_blockchain_to_file(self.blockchain, self.pvt_key, self.pub_key)

                # Perform finishing steps
                perform_finishing_steps()

            if vote == VOTE_NO:
                print("[+] You have declined the target peer's identity (in their request); returning to main menu...")
                remove_pending_peer(self, target_sock, ip=target_sock.getpeername()[0])

        except exceptions as msg:
            print(f"[+] ERROR: An error has occurred while performing approved_handler()! [REASON: {msg}]")
            remove_pending_peer(self, target_sock, ip=target_sock.getpeername()[0])
    # ================================================================================
    print(APPROVED_TO_NETWORK_MSG_INITIAL)
    print(ZERO_TRUST_POLICY_MSG)

    # Define exceptions
    exceptions = (ConsensusInitError, InvalidSignatureError, TransactionNotFoundError,
                  RequestAlreadyExistsError, RequestExpiredError, socket.timeout, InvalidBlockError,
                  InvalidBlockchainError, PeerInvalidBlockchainError)

    # Send ACK for synchronization
    target_sock.send(AES_encrypt(data=ACK.encode(), key=secret, mode=self.mode, iv=iv))

    # Receive status from target (connected or not connected to a P2P network)
    status = AES_decrypt(data=target_sock.recv(1024), key=secret, mode=self.mode, iv=iv).decode()

    # Handle status
    if status == STATUS_CONNECTED:
        connected_handler()

    if status == STATUS_NOT_CONNECTED:
        not_connected_handler()


def _connect_to_peer_after_approved(pvt_key: bytes, pub_key: bytes, target_peer: Peer,
                                    token: Token, mode: str, block_idx: int, block_hash: str):
    """
    Connects to and returns a target peer after being approved into the P2P network.

    @attention Use Case:
        Used by a newly approved peer when connecting to
        other peers within the P2P network

    @param pvt_key:
        The host's private key

    @param pub_key:
        The host's public key

    @param target_peer:
        A target Peer object

    @param token:
        An approval Token object

    @param mode:
        A string for the mode of encryption (ECB or CBC)

    @param block_idx:
        An integer for the issued block's index

    @param block_hash:
        A string for the issued block's hash

    @return: target_peer or target_ip
        Return an updated target peer object if success; otherwise, target_ip (if any errors)
    """
    def present_issued_block_hash(input_hash: str, idx: int):
        print(f"[+] Presenting your issued block's hash to {target_peer.ip}...")

        # Send hash and await for response
        target_sock.send(AES_encrypt(data=input_hash.encode(), key=secret, iv=iv, mode=mode))
        response = AES_decrypt(data=target_sock.recv(1024), key=secret, iv=iv, mode=mode).decode()

        if response == ACK:
            print("[+] Your issued block hash is correct and has been validated!")
            return None
        else:
            raise InvalidBlockError(index=idx)
    # ==============================================================================================
    try:
        print(f"[+] Now connecting to peer (IP: {target_peer.ip})...")

        # Deserialize private/public key pairs
        deserialized_pvt_key = deserialize_private_key(pvt_key_bytes=pvt_key)
        deserialized_pub_key = deserialize_public_key(pub_key_bytes=pub_key)

        # ConnectToNetwork to peer
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.settimeout(FIND_HOST_TIMEOUT)         # => 3-second timeout
        target_sock.connect((target_peer.ip, APPLICATION_PORT))

        # Establish security parameters (secret, iv, etc.)
        from utility.client_server.client_server import establish_secure_parameters
        secret, iv = establish_secure_parameters(deserialized_pvt_key, deserialized_pub_key,
                                                 target_sock, mode=MODE_INITIATOR, encryption=mode)

        # Send approval signal to target peer
        target_sock.send(AES_encrypt(data=APPROVED_SIGNAL.encode(), key=secret, iv=iv, mode=mode))

        # Wait for ACK
        target_sock.recv(1024)

        # Verify with target peer by presenting your approval token
        send_approval_token(target_sock, token, secret, mode, iv)

        # Verify with target peer by presenting the hash for your issued block
        present_issued_block_hash(input_hash=block_hash, idx=block_idx)

        # Update target_peer with information
        target_peer.socket = target_sock
        target_peer.secret = secret
        target_peer.iv = iv
        target_peer.mode = mode
        return target_peer

    except (socket.error, socket.timeout, BrokenPipeError, ConnectionResetError, InvalidTokenError, InvalidBlockError) as e:
        print(f"[+] ERROR: An error has occurred while connecting to peer (IP: {target_peer.ip})! [REASON: {e}]")
        return target_peer.ip


def approved_signal_handler(self: object, peer_socket: socket.socket, secret: bytes, mode: str, iv: bytes = None):
    """
    Handles a newly approved peer's 'APPROVED' peer signal, which
    includes the verification of an issued approval token and block
    hash (presented upon connection).

    @attention Use of Approval Tokens:
        This function validates the newly approved peer
        by verifying the signature of the token.

    @param self:
        A reference to the calling class object (Node)

    @param peer_socket:
        A socket object of the initiating peer

    @param secret:
        Bytes of the shared secret

    @param mode:
        A string for the encryption mode (ECB or CBC)

    @param iv:
        Bytes of the initialization vector (IV) - Optional

    @return: None
    """
    def update_peer_info(peer: Peer):
        """
        Updates peer information after validation and connection.

        @param peer:
            The connecting peer

        @return: None
        """
        peer.status = STATUS_APPROVED
        peer.socket = peer_socket
        peer.secret, peer.iv = secret, iv
        peer.mode = mode
        peer.token = None
        peer.block = None
        send_event_to_websocket(self.back_queue, event=EVENT_NODE_REMOVE_PENDING_PEER, data=ip) if self.app_flag else None
        print(f"[+] Information for peer (IP: {peer.ip}) has been updated!")

    def validate_issued_block_hash(peer_ip: str):
        """
        Gets the issued block hash from connecting peer
        and validates it.

        @param peer_ip:
            The connecting peer's IP address (String)

        @raise InvalidBlockError:
            Raised if the connecting peer presents an invalid hash
            for the block, they were issued upon being approved

        @return: None
        """
        print(f"[+] Now receiving issued block hash from requesting peer (IP: {peer_ip})...")
        received_block_hash = AES_decrypt(data=peer_socket.recv(1024), key=secret, iv=iv, mode=mode).decode()
        issued_block = get_peer(self.peer_dict, ip=peer_ip).block
        if issued_block.hash != received_block_hash:
            peer_socket.send(AES_encrypt(data=RESPONSE_REJECTED.encode(), key=secret, iv=iv, mode=mode))
            raise PeerInvalidBlockHashError(ip=peer_ip)
        else:
            print(f"[+] VERIFICATION SUCCESSFUL: The block issued for {issued_block.ip_addr} has the correct hash!")
            peer_socket.send(AES_encrypt(data=ACK.encode(), key=secret, iv=iv, mode=mode))
            return None
    # ==============================================================================================

    try:
        ip = peer_socket.getpeername()[0]

        # Validate connecting peer's approval token and issued block's hash
        receive_approval_token(peer_socket, secret=secret, mode=mode, iv=iv)
        validate_issued_block_hash(peer_ip=ip)

        # Add block to blockchain and validate the entirety of the blockchain
        new_block = get_peer(self.peer_dict, ip).block
        self.blockchain.add_block(new_block=new_block)
        if self.blockchain.is_valid():
            send_event_to_websocket(queue=self.back_queue,
                                    event=EVENT_NODE_ADD_BLOCK,
                                    data=pickle.dumps(new_block)) if self.app_flag else None
            save_blockchain_to_file(self.blockchain, self.pvt_key, self.pub_key)

        # Update peer info
        update_peer_info(get_peer(self.peer_dict, ip))
        self.fd_list.append(peer_socket)

        # Notify front-end application
        if self.app_flag:
            approved_peer = get_peer(self.peer_dict, ip).to_dict()
            send_event_to_websocket(queue=self.back_queue,
                                    event=EVENT_NODE_ADD_APPROVED_PEER,
                                    data=pickle.dumps(approved_peer))
        print(f"[+] NEW PEER CONNECTION: A new peer has been successfully verified and approved (IP: {ip}))!")
    except (InvalidTokenError, PeerInvalidBlockHashError) as msg:
        print(msg)
        del self.peer_dict[peer_socket.getpeername()[0]]
        peer_socket.close()


def _process_peer_info_into_list(self: object, token: Token, block: Block, exclude: list):
    """
    Processes information from peer dictionary into an argument list
    suitable for _connect_to_peer_after_approved() function.

    @param self:
        A reference to the calling class object (Node)

    @param token:
        An approval Token object

    @param exclude:
        A list of IP addresses to exclude from the list

    @return: peer_info
        A list of tuples containing parameters for _connect_to_peer_after_approved()
    """
    peer_info = []
    for peer in self.peer_dict.values():
        if peer.ip not in exclude:
            serialized_pvt_key = serialize_private_key(self.pvt_key)
            serialized_pub_key = serialize_public_key(self.pub_key)
            peer_info.append((serialized_pvt_key, serialized_pub_key, peer, token, self.mode, block.index, block.hash))
    return peer_info
