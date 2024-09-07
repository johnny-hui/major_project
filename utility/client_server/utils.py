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
from exceptions.exceptions import (RequestExpiredError, RequestAlreadyExistsError,
                                   InvalidSignatureError, TransactionNotFoundError,
                                   ConsensusInitError)
from utility.crypto.aes_utils import AES_decrypt, AES_encrypt
from utility.general.constants import (APPLICATION_PORT, FIND_HOST_TIMEOUT,
                                       CONNECTION_TIMEOUT_ERROR, CONNECTION_ERROR, ACK, STATUS_NOT_CONNECTED,
                                       STATUS_CONNECTED,
                                       BLOCK_SIZE, RESPONSE_EXPIRED, RECEIVED_TRANSACTION_SUCCESS, RESPONSE_EXISTS,
                                       RESPONSE_INVALID_SIG, TARGET_TRANSACTION_WAIT_TIME, TIMER_INTERVAL,
                                       TARGET_WAIT_REQUEST_MSG, VOTE_YES, VOTE_NO, MODE_VOTER,
                                       APPROVED_TO_NETWORK_MSG_INITIAL, ZERO_TRUST_POLICY_MSG, STATUS_APPROVED,
                                       TARGET_PEER_APPROVED_MSG, MODE_RECEIVER, JOIN_NETWORK_SUCCESS_MSG,
                                       ROLE_PEER, ROLE_DELEGATE, TARGET_NOT_CONNECTED_MSG)
from utility.general.utils import timer, determine_delegate_status
from utility.node.node_utils import (peer_exists, add_new_transaction, save_transaction_to_file,
                                     save_pending_peer_info, remove_pending_peer, delete_transaction,
                                     change_peer_status, change_peer_role)


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
                            save_info: bool = True, set_stamp: bool = True):
    """
    A helper function that handles the receiving, decrypting, and
    validation of a requesting peer's Transaction (connection request).

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

        # Get the size of transaction
        data = AES_decrypt(data=peer_socket.recv(BLOCK_SIZE), key=shared_secret, mode=mode, iv=peer_iv)
        size = int.from_bytes(data, byteorder='big')

        while len(buffer) < size:
            chunk = peer_socket.recv(min(size - len(buffer), 4096))
            if not chunk:
                break
            buffer += chunk

        return buffer

    def process_request(data: bytearray):
        """
        Decrypts, verifies and processes the requesting peer's
        connection request and if valid, saves peer's request,
        information and socket.

        @param data:
            Encrypted data in bytearray

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
                transaction_path = save_transaction_to_file(data=data, shared_secret=shared_secret, iv=peer_iv, mode=mode)
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


def approved_handler(self: object, target_sock: socket.socket, secret: bytes, iv: bytes):
    """
    A handler for the peer connecting to the P2P network
    after being approved.

    @param self:
        A reference to the calling class object (Node)

    @param target_sock:
        The socket object of the target peer

    @param secret:
        Bytes of the shared secret

    @param iv:
        Bytes of the initialization vector (IV)

    @return: None
    """
    def start_timer_thread(event: threading.Event):
        thread = threading.Thread(target=timer, args=(TARGET_TRANSACTION_WAIT_TIME,
                                                      TIMER_INTERVAL,
                                                      TARGET_WAIT_REQUEST_MSG,
                                                      event))
        thread.start()

    def connected_handler():
        print("[+] Implement!")

    def not_connected_handler():
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
            request, file_path = receive_request_handler(self, target_sock,
                                                         target_sock.getpeername()[0],
                                                         secret, self.mode, iv)
            stop_event.set()

            # Remove target socket from pending list (prevent select-related errors)
            if target_sock in self.fd_pending:
                self.fd_pending.remove(target_sock)
                time.sleep(1)

            # Start Consensus (a trust vote on verifying target peer)
            from models.Consensus import Consensus
            consensus = Consensus(request=request,
                                  mode=MODE_VOTER,
                                  peer_socket=target_sock,
                                  peer_dict=self.peer_dict,
                                  is_connected=False)
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
                        self.is_promoted = True
                    else:
                        change_peer_role(self.peer_dict, ip=request.ip_addr, role=ROLE_DELEGATE)

                # Perform finishing steps
                self.fd_list.append(target_sock)  # fd_list == approved list
                change_peer_status(self.peer_dict, ip=request.ip_addr, status=STATUS_APPROVED)
                delete_transaction(self.pending_transactions, request.ip_addr, file_path)
                self.is_connected = True
                print(JOIN_NETWORK_SUCCESS_MSG.format(target_sock.getpeername()[0]))

            if vote == VOTE_NO:
                print("[+] You have declined the target peer's identity (in their request); returning to main menu...")
                remove_pending_peer(self, target_sock, ip=target_sock.getpeername()[0])

        except exceptions as msg:
            print(f"[+] ERROR: An error has occurred while performing approved_handler() [REASON: {msg}]")
            remove_pending_peer(self, target_sock, ip=target_sock.getpeername()[0])
    # ================================================================================
    print(APPROVED_TO_NETWORK_MSG_INITIAL)
    print(ZERO_TRUST_POLICY_MSG)

    # Define exceptions
    exceptions = (ConsensusInitError, InvalidSignatureError, TransactionNotFoundError,
                  RequestAlreadyExistsError, RequestExpiredError, socket.timeout)

    # Send ACK for synchronization
    target_sock.send(AES_encrypt(data=ACK.encode(), key=secret, mode=self.mode, iv=iv))

    # Receive status from target (connected or not connected to a P2P network)
    status = AES_decrypt(data=target_sock.recv(1024), key=secret, mode=self.mode, iv=iv).decode()

    if status == STATUS_NOT_CONNECTED:
        not_connected_handler()

    if status == STATUS_CONNECTED:
        connected_handler()
