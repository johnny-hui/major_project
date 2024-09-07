"""
Description:
This python file is responsible for providing client/server
functionalities and defining protocols to the Node class.

"""
import multiprocessing
import pickle
import secrets
import socket
import time

from tinyec.ec import Point

from exceptions.exceptions import (RequestAlreadyExistsError, RequestExpiredError,
                                   InvalidSignatureError, InvalidProtocolError)
from models.Transaction import Transaction
from utility.client_server.utils import (_perform_iterative_host_search, _connect_to_target_peer,
                                         receive_request_handler, approved_handler)
from utility.crypto.aes_utils import AES_decrypt, AES_encrypt
from utility.crypto.ec_keys_utils import compress_pub_key, derive_shared_secret, compress_shared_secret
from utility.general.constants import CBC, MODE_RECEIVER, MODE_INITIATOR, PHOTO_SIGNAL, REQUEST_SIGNAL, \
    SHARED_SECRET_SUCCESS_MSG, APPROVED_SIGNAL, CONNECT_METHOD_PROMPT, BLOCK_SIZE, ACCEPT_NEW_PEER_TIMEOUT, \
    CONNECTION_AWAIT_TIMEOUT_MSG, CONNECTION_AWAIT_RESPONSE_MSG, RESPONSE_EXPIRED, RESPONSE_EXISTS, \
    RESPONSE_INVALID_SIG, SEND_REQUEST_MSG, SEND_REQUEST_SUCCESS, TARGET_RECONNECT_MSG, REQUEST_APPROVED_MSG, \
    RESPONSE_APPROVED, RESPONSE_REJECTED, REQUEST_REFUSED_MSG, REQUEST_ALREADY_EXISTS_MSG, REQUEST_INVALID_SIG_MSG, \
    REQUEST_EXPIRED_MSG, TARGET_RECONNECT_SUCCESS, TARGET_UNSUCCESSFUL_RECONNECT, TARGET_RECONNECT_TIMEOUT, \
    TARGET_DISCONNECT_MSG, CONNECT_PEER_EXISTS_ERROR, PURPOSE_REQUEST, PURPOSE_CONSENSUS, CONSENSUS_SIGNAL, ROLE_ADMIN, \
    ROLE_DELEGATE, PURPOSE_REQUEST_APPROVAL, REQUEST_APPROVAL_SIGNAL, REMOVE_SIGNAL, PROMOTION_SIGNAL
from utility.general.utils import get_user_command_option, get_target_ip, divide_subnet_search
from utility.node.node_utils import create_transaction, sign_transaction, peer_exists, get_peer, \
    launch_consensus

# CONSTANTS
ERROR_RESPONSE_MAP = {
    RESPONSE_EXPIRED: REQUEST_EXPIRED_MSG,
    RESPONSE_EXISTS: REQUEST_ALREADY_EXISTS_MSG,
    RESPONSE_INVALID_SIG: REQUEST_INVALID_SIG_MSG,
    RESPONSE_REJECTED: REQUEST_REFUSED_MSG,
}


def exchange_public_keys(pub_key: Point, sock: socket.socket, mode: str):
    """
    Performs the ECDH public key exchange process.

    @param pub_key:
        The public key to send over

    @param sock:
        A socket object

    @param mode:
        A string to denote whether calling class should
        receive or initiate the key exchange process

    @return: Public Key
        The other end's public key
    """
    if mode == MODE_RECEIVER:
        print("[+] PUBLIC KEY EXCHANGE: Now exchanging public keys with the requesting peer...")

        # Receive public key from requesting peer
        serialized_peer_pub_key = sock.recv(4096)
        peer_pub_key = pickle.loads(serialized_peer_pub_key)

        # Send over the public key to requesting peer
        serialized_key = pickle.dumps(pub_key)
        sock.sendall(serialized_key)
        return peer_pub_key

    if mode == MODE_INITIATOR:
        print("[+] PUBLIC KEY EXCHANGE: Now exchanging public keys with the target peer...")

        # Send Public Key to Target
        serialized_key = pickle.dumps(pub_key)
        sock.sendall(serialized_key)

        # Receive Public Key from Target
        serialized_target_pub_key = sock.recv(4096)
        peer_pub_key = pickle.loads(serialized_target_pub_key)
        return peer_pub_key


def establish_secure_parameters(self: object, peer_socket: socket.socket, mode: str):
    """
    Establishes a secure connection by exchanging & deriving
    protocol parameters (cipher mode, ECDH public key exchange,
    shared secret).

    @param self:
        A reference to the calling class object (Node)

    @param peer_socket:
        A peer's socket object

    @param mode:
        A string to determine if calling class is the
        'RECEIVER' or 'INITIATOR'

    @return: shared_secret, session_iv, mode
    """
    if mode == MODE_RECEIVER:  # => Receiver
        session_iv = None
        encrypt_mode = peer_socket.recv(1024).decode()
        print(f"[+] MODE RECEIVED: The encryption mode selected by the client for this session "
              f"is {encrypt_mode.upper()}")

        if encrypt_mode == CBC:
            session_iv = peer_socket.recv(1024)
            print(f"[+] IV RECEIVED: The initialization vector (IV) has been received "
                  f"from the peer ({session_iv.hex()})")

        peer_pub_key = exchange_public_keys(self.pub_key, peer_socket, mode=MODE_RECEIVER)
        print(f"[+] PUBLIC KEY RECEIVED: Successfully received the peer's public key "
              f"({compress_pub_key(peer_pub_key)})")

        shared_secret = derive_shared_secret(self.pvt_key, peer_pub_key)
        print(SHARED_SECRET_SUCCESS_MSG.format(compress_shared_secret(shared_secret), len(shared_secret)))
        return shared_secret, session_iv, encrypt_mode

    if mode == MODE_INITIATOR:  # => Sender
        session_iv = None
        time.sleep(0.5)
        peer_socket.send(self.mode.encode())
        print(f"[+] MODE SELECTED: The encryption mode chosen for this session is {self.mode.upper()}")

        # Generate new session IV and send to server (if CBC)
        if self.mode == CBC:
            session_iv = secrets.token_bytes(BLOCK_SIZE)
            time.sleep(0.5)
            peer_socket.send(session_iv)
            print(f"[+] IV GENERATED: An initialization vector (IV) has been generated for "
                  f"this session ({session_iv.hex()})")

        # Exchange Public Keys with Server
        server_pub_key = exchange_public_keys(self.pub_key, peer_socket, mode=MODE_INITIATOR)
        print(f"[+] PUBLIC KEY RECEIVED: Successfully received the server's public key "
              f"({compress_pub_key(server_pub_key)})")

        # Derive the shared secret
        shared_secret = derive_shared_secret(self.pvt_key, server_pub_key)  # In bytes
        self.shared_secret = shared_secret.hex()
        print(SHARED_SECRET_SUCCESS_MSG.format(compress_shared_secret(shared_secret), len(shared_secret)))
        return shared_secret, session_iv


def accept_new_peer_handler(self: object, own_sock: socket.socket):
    """
    A handler to accept a new peer connection request, which
    involves the ECDH public key exchange process and the
    generation of shared secret with the client to establish
    a secure connection.

    @param self:
        A reference to the calling class object (Node)

    @param own_sock:
        The socket object of the calling class

    @return: None
    """
    def signal_handler(signal: str):
        """
        Interprets the signal and invokes the appropriate
        handler to perform the next set of client/server
        operations.

        @param signal:
            A string representing a specific signal

        @return: None
        """
        try:
            if signal == PHOTO_SIGNAL:
                print("[+] Receive photo from app")  # TODO: Implement this part using AES instead
            elif signal == REQUEST_SIGNAL:
                receive_request_handler(self, peer_socket, peer_address[0], shared_secret, mode, session_iv)
            elif signal == APPROVED_SIGNAL:
                print("[+] Accept peer; peer is given a unique token upon approval, as they must present this upon "
                      "joining network!")
            else:
                peer_socket.close()
                raise InvalidProtocolError(ip=peer_socket.getpeername()[0])
        except (InvalidSignatureError, InvalidProtocolError, RequestAlreadyExistsError, RequestExpiredError) as msg:
            peer_socket.close()
            print(msg)
    # ===============================================================================================================
    peer_socket, peer_address = own_sock.accept()
    print(f"[+] NEW CONNECTION REQUEST: Accepted a peer connection from ({peer_address[0]}, {peer_address[1]})!")

    shared_secret, session_iv, mode = establish_secure_parameters(self, peer_socket, mode=MODE_RECEIVER)
    peer_socket.settimeout(ACCEPT_NEW_PEER_TIMEOUT)  # 10-second Timeout

    # Await, Receive and Decrypt Peer Signal
    try:
        decrypted_signal = AES_decrypt(data=peer_socket.recv(1024),
                                       key=shared_secret,
                                       mode=mode,
                                       iv=session_iv).decode()
        signal_handler(signal=decrypted_signal)
    except socket.timeout:
        print("[+] NEW PEER TIMEOUT: A new peer connection has timed out; connection has been terminated!")
        peer_socket.close()
    finally:
        print(f"[+] THREAD TERMINATED: A thread handling new peer ({peer_address}) has been successfully terminated!")


def send_request(peer_socket: socket.socket, ip: str,
                 shared_secret: bytes, mode: str, purpose: str,
                 transaction: Transaction, peer_iv: bytes = None):
    """
    Securely sends the Transaction (connection request) to a target peer.

    @attention Consensus (Use Case):
        The Consensus class uses this to send requests in parallel
        using multiprocessing module and in the event of peer socket
        disconnection, their IP is returned to handle cleanup
        (such as socket closure, removal of peer info, etc.)

    @raise (BrokenPipeError, ConnectionResetError, OSError, socket.timeout):
        This exception is primarily used to prevent multiple processes
        from stalling while executing this function during Consensus

    @param peer_socket:
        The target peer's socket object

    @param ip:
        The IP address of the target peer (String)

    @param shared_secret:
        Bytes of the shared secret

    @param mode:
        A string containing the cipher mode (CBC or ECB)

    @param purpose:
        A string containing the purpose of the sending (Consensus, Request)

    @param transaction:
        A Transaction object

    @param peer_iv:
        Bytes of the initialization vector (IV)

    @return: None, ip
        None if successful; otherwise, the IP of the disconnected peer
    """
    print(SEND_REQUEST_MSG.format(ip))
    try:
        # Set blocking (in case multiprocessing module sets to False)
        peer_socket.setblocking(True)

        # Send a signal (according to the purpose)
        if purpose == PURPOSE_REQUEST:
            peer_socket.send(AES_encrypt(data=REQUEST_SIGNAL.encode(), key=shared_secret, mode=mode, iv=peer_iv))
        if purpose == PURPOSE_CONSENSUS:
            peer_socket.send(AES_encrypt(data=CONSENSUS_SIGNAL.encode(), key=shared_secret, mode=mode, iv=peer_iv))
        if purpose == PURPOSE_REQUEST_APPROVAL:
            peer_socket.send(AES_encrypt(data=REQUEST_APPROVAL_SIGNAL.encode(), key=shared_secret, mode=mode, iv=peer_iv))

        # Wait for ACK
        peer_socket.recv(1024)

        # Serialize and AES encrypt the object
        serialized_request = pickle.dumps(transaction)
        encrypted_request = AES_encrypt(data=serialized_request, key=shared_secret, mode=mode, iv=peer_iv)

        # Send the size of the serialized object
        size = len(encrypted_request).to_bytes(4, byteorder='big')
        peer_socket.sendall(AES_encrypt(data=size, key=shared_secret, mode=mode, iv=peer_iv))

        # Send the encrypted request
        peer_socket.sendall(encrypted_request)

        # Wait for ACK
        peer_socket.recv(1024)
        print(SEND_REQUEST_SUCCESS.format(peer_socket.getpeername()[0]))
        return None
    except (BrokenPipeError, ConnectionResetError, OSError) as e:  # Used for consensus (parallel)
        print(f"[+] ERROR: An error has occurred while sending a request to peer ({ip})! [REASON: {e}]")
        return ip


def approved_peer_activity_handler(self: object, peer_sock: socket.socket):
    """
    Handles incoming data from approved peers and their
    associated activity (based on a specific signal protool).

    @param self:
        A reference to the calling class object (Node)

    @param peer_sock:
        The peer socket object

    @return: None
    """

    def default_action():
        """
        Prints out the signal or message sent by a peer.

        @attention Use Case:
            Used as a default if signal is undefined

        @return: None
        """
        print(f"[+] You have received a message from peer ({peer_ip}): {decrypted_signal}")

    def disconnect_handler(sock: socket.socket, peer_dict: dict):
        sock.close()
        del peer_dict[peer_ip]
        if len(peer_dict) == 0:
            self.is_connected = False
        print(f"[+] Connection closed by peer (IP: {peer_ip})!")

    def signal_handler(signal: str):
        """
        Handles approved peer activity signals.

        @param signal:
            A string representing the signal

        @return: None
        """
        # Define signals for all roles
        signals_if_admin_delegate = {
            REQUEST_APPROVAL_SIGNAL: lambda: receive_request_handler(self, peer_sock, peer_ip, peer.secret, peer.mode,
                                                                     peer.iv, save_info=False, set_stamp=False)
        }
        signals_if_regular_peer = {
            CONSENSUS_SIGNAL: lambda: launch_consensus(self, peer_sock, peer_ip, peer),
            REMOVE_SIGNAL: lambda: print("[+] Check if signal is coming from admin or delegate -> admin/delegate"
                                         "kicks a peer and informs regular peer to remove them locally"),
            PROMOTION_SIGNAL: lambda: print("[+] Check if signal is coming from admin or delegate; promote to"
                                            "delegate")
        }

        # Grab the signal
        if self.role in (ROLE_ADMIN, ROLE_DELEGATE):
            signal = signals_if_admin_delegate.get(signal, default_action)
        else:
            signal = signals_if_regular_peer.get(signal, default_action)

        # Handle the signal
        if signal:
            signal()
    # ===============================================================================================
    # Remove socket (to prevent select interference)
    self.fd_list.remove(peer_sock)

    # Get IP and notify host of incoming data
    peer_ip = peer_sock.getpeername()[0]

    # Get incoming data
    data = peer_sock.recv(1024)

    # Get security parameters and decrypt signal from incoming peer
    if data:
        peer = get_peer(self.peer_dict, ip=peer_sock.getpeername()[0])
        decrypted_signal = AES_decrypt(data=data, key=peer.secret, mode=peer.mode, iv=peer.iv).decode()

        # Handle the signal
        signal_handler(signal=decrypted_signal)
        self.fd_list.append(peer_sock)
    else:
        disconnect_handler(peer_sock, self.peer_dict)


def connect_to_P2P_network(self: object):
    """
    Finds, connects, and sends the connection request to a
    target peer using sockets.

    @param self:
        A reference to the calling class object (Node)

    @return: None
    """
    def process_transaction_with_peer(target_sock: socket.socket):
        """
        A utility function that involves securely sending a
        connection request (Transaction) to a target peer for
        approval into their P2P network.

        @param target_sock:
            The target peer's socket object

        @return: None
        """
        if target_sock is not None:
            shared_secret, session_iv = establish_secure_parameters(self, target_sock, mode=MODE_INITIATOR)
            sign_transaction(self, transaction)
            send_request(target_sock, target_ip, shared_secret, self.mode, PURPOSE_REQUEST, transaction, session_iv)
            response, target_sock = _await_response(self, target_sock, shared_secret,
                                                    self.mode, transaction, session_iv)

            if response:  # => if approved
                approved_handler(self, target_sock, shared_secret, session_iv)
    # ===============================================================================================================
    transaction = create_transaction(self)

    if transaction is not None:
        option = get_user_command_option(opt_range=tuple(range(3)), prompt=CONNECT_METHOD_PROMPT)

        if option == 0:
            return None

        if option == 1:
            target_ip = get_target_ip(self)
            if not peer_exists(self.peer_dict, target_ip, msg=CONNECT_PEER_EXISTS_ERROR):
                target_socket = _connect_to_target_peer(ip=target_ip)
                process_transaction_with_peer(target_socket)

        if option == 2:
            target_socket, target_ip = _perform_parallel_host_search(self.ip, self.peer_dict)
            process_transaction_with_peer(target_socket)


def _await_response(self: object, peer_socket: socket.socket, shared_secret: bytes,
                    mode: str, transaction: Transaction, peer_iv: bytes = None):
    """
    Awaits a response from the target peer.

    @attention Reconnect Handler:
        This function has the ability to reconnect
        to the target peer in the event they disconnect,
        which returns a reference to the new socket object.

    @param self:
        A reference to the calling class object (Node)

    @param peer_socket:
        The target peer's socket object

    @param shared_secret:
        Bytes of the shared secret

    @param mode:
        A string containing the cipher mode (CBC or ECB)

    @param transaction:
        A Transaction object

    @param peer_iv:
        Bytes of the initialization vector (IV)

    @return: Boolean (T/F), socket
        True if request accepted/approved; False otherwise and
        a reference to the peer socket object
    """
    def _response_handler(res: str, target_sock: socket.socket) -> bool:
        if res in ERROR_RESPONSE_MAP:
            print(ERROR_RESPONSE_MAP[res])
            target_sock.close()
            return False
        if res == RESPONSE_APPROVED:
            print(REQUEST_APPROVED_MSG)
            return True

    def _reconnect_to_target(target_ip: str):
        print(TARGET_RECONNECT_MSG)
        peer_socket.close()  # => Close disconnected (old) socket object
        self.fd_list.remove(self.own_socket)  # => temporarily remove to prevent select() conflict
        try:
            while True:
                self.own_socket.settimeout(transaction.get_time_remaining())
                new_sock, target_info = self.own_socket.accept()  # => a new reference to socket object
                if new_sock.getpeername()[0] == target_ip:  # => Re-established connection
                    print(TARGET_RECONNECT_SUCCESS)
                    return new_sock
                else:
                    new_sock.close()
        except socket.timeout:
            print(TARGET_UNSUCCESSFUL_RECONNECT)
            return None
        finally:
            self.own_socket.settimeout(None)
            self.fd_list.append(self.own_socket)

    def _reconnect_response_handler(new_sock: socket.socket):
        if new_sock is not None:
            try:
                new_sock.settimeout(transaction.get_time_remaining())
                data = new_sock.recv(1024)
                if not data:  # => If disconnects once again, close connection
                    print(TARGET_DISCONNECT_MSG)
                    new_sock.close()
                    return False
                response = AES_decrypt(data=data, key=shared_secret, mode=mode, iv=peer_iv).decode()
                return _response_handler(res=response, target_sock=new_sock)
            except socket.timeout:
                print(TARGET_RECONNECT_TIMEOUT)
                new_sock.close()
                return False
        return False
    # ===============================================================================
    try:
        print(CONNECTION_AWAIT_RESPONSE_MSG.format(transaction.get_time_remaining()))
        peer_socket.settimeout(transaction.get_time_remaining())
        data = peer_socket.recv(1024)

        if not data:  # attempt reconnection (if peer disconnects)
            new_socket = _reconnect_to_target(target_ip=peer_socket.getpeername()[0])
            return _reconnect_response_handler(new_socket), new_socket
        else:
            response = AES_decrypt(data=data, key=shared_secret, mode=mode, iv=peer_iv).decode()
            return _response_handler(res=response, target_sock=peer_socket), peer_socket
    except socket.timeout:
        print(CONNECTION_AWAIT_TIMEOUT_MSG)
        peer_socket.close()
        return False, None


def _perform_parallel_host_search(host_ip: str, peer_dict: dict):
    """
    Performs socket host search in parallel using the
    multiprocessing module.

    @param host_ip:
        A string representing the host machine's IP address
        (NOTE: This is used to get the subnet mask)

    @return: (peer_sock & peer_ip) or None
        The connected peer socket and their IP if found; otherwise None
    """
    def get_peer_socket_from_results(result: list):
        for item in result:
            if isinstance(item, socket.socket):
                return item, item.getpeername()[0]
        print("[+] CONNECTION FAILED: There are currently no available hosts within your local network...")
        return None
    # =================================================================
    # a) Get thread count and divide subnet into chunks
    thread_count = multiprocessing.cpu_count()
    search_chunks = divide_subnet_search(num_threads=thread_count)

    # b) Define global stop signal (shared between processes)
    with multiprocessing.Manager() as manager:
        stop_signal = manager.Event()

        # c) Call multiprocessing pool to spawn different processes for parallel search
        with multiprocessing.Pool(processes=thread_count) as pool:
            print(f"[+] Now finding an available host... [{thread_count} threads being used]")
            args = [(peer_dict, host_ip, stop_signal, start, end) for (start, end) in search_chunks]
            results = pool.starmap(func=_perform_iterative_host_search, iterable=args)
            pool.close()
            pool.join()

    # d) Gather results and get socket
    return get_peer_socket_from_results(results)
