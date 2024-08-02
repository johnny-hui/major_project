"""
Description:
This python file is responsible for providing client/server
functionalities and defining protocols to the Node class.

"""
import pickle
import secrets
import socket
import time
from tinyec.ec import Point
from exceptions.exceptions import RequestAlreadyExistsError, RequestExpiredError, InvalidSignatureError, \
    InvalidProtocolError
from models.Node import Node
from models.Transaction import Transaction
from utility.constants import CBC, MODE_RECEIVE, MODE_INITIATE, PHOTO_SIGNAL, REQUEST_SIGNAL, ACK, \
    RECEIVED_TRANSACTION_SUCCESS, SHARED_SECRET_SUCCESS_MSG, APPROVED_SIGNAL, CONNECTION_TIMEOUT_ERROR, \
    FIND_HOST_TIMEOUT, APPLICATION_PORT, CONNECTION_ERROR, CONNECT_METHOD_PROMPT, BLOCK_SIZE, ACCEPT_NEW_PEER_TIMEOUT, \
    CONNECTION_AWAIT_TIMEOUT_MSG, CONNECTION_AWAIT_RESPONSE_MSG, RESPONSE_EXPIRED, RESPONSE_EXISTS, \
    RESPONSE_INVALID_SIG, SEND_REQUEST_MSG, SEND_REQUEST_SUCCESS, TARGET_DISCONNECT_MSG, REQUEST_APPROVED_MSG, \
    RESPONSE_APPROVED, RESPONSE_REJECTED, REQUEST_REFUSED_MSG, REQUEST_ALREADY_EXISTS_MSG, REQUEST_INVALID_SIG_MSG, \
    REQUEST_EXPIRED_MSG, TARGET_RECONNECT_MSG
from utility.crypto.aes_utils import AES_decrypt, AES_encrypt
from utility.crypto.ec_keys_utils import compress_pub_key, derive_shared_secret, compress_shared_secret
from utility.node.node_utils import save_transaction_to_file, add_new_transaction, save_pending_peer_info, \
    create_transaction, sign_transaction
from utility.utils import get_user_command_option, get_target_ip


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
    if mode == MODE_RECEIVE:
        print("[+] PUBLIC KEY EXCHANGE: Now exchanging public keys with the requesting peer...")

        # Receive public key from requesting peer
        serialized_peer_pub_key = sock.recv(4096)
        peer_pub_key = pickle.loads(serialized_peer_pub_key)

        # Send over the public key to requesting peer
        serialized_key = pickle.dumps(pub_key)
        sock.sendall(serialized_key)
        return peer_pub_key

    if mode == MODE_INITIATE:
        print("[+] PUBLIC KEY EXCHANGE: Now exchanging public keys with the target peer...")

        # Send Public Key to Target
        serialized_key = pickle.dumps(pub_key)
        sock.sendall(serialized_key)

        # Receive Public Key from Target
        serialized_target_pub_key = sock.recv(4096)
        peer_pub_key = pickle.loads(serialized_target_pub_key)
        return peer_pub_key


def establish_secure_connection(self: Node, peer_socket: socket.socket, mode: str):
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
    if mode == MODE_RECEIVE:
        session_iv = None
        mode = peer_socket.recv(1024).decode()
        print(f"[+] MODE RECEIVED: The encryption mode selected by the client for this session is {mode.upper()}")

        if mode == CBC:
            session_iv = peer_socket.recv(1024)
            print(
                f"[+] IV RECEIVED: The initialization vector (IV) has been received from the peer ({session_iv.hex()})")

        peer_pub_key = exchange_public_keys(self.pub_key, peer_socket, mode=MODE_RECEIVE)
        print(f"[+] PUBLIC KEY RECEIVED: Successfully received the peer's public key "
              f"({compress_pub_key(peer_pub_key)})")

        shared_secret = derive_shared_secret(self.pvt_key, peer_pub_key)
        print(SHARED_SECRET_SUCCESS_MSG.format(compress_shared_secret(shared_secret), len(shared_secret)))
        return shared_secret, session_iv, mode

    if mode == MODE_INITIATE:
        session_iv = None
        time.sleep(0.5)
        peer_socket.send(self.mode.encode())
        print(f"[+] MODE SELECTED: The encryption mode chosen for this session is {self.mode.upper()}")

        # Generate new session IV and send to server (if CBC)
        if self.mode == CBC:
            iv = secrets.token_bytes(BLOCK_SIZE)
            time.sleep(0.5)
            peer_socket.send(iv)
            print(f"[+] IV GENERATED: An initialization vector (IV) has been generated for this session ({iv.hex()})")

        # Exchange Public Keys with Server
        server_pub_key = exchange_public_keys(self.pub_key, peer_socket, mode=MODE_INITIATE)
        print(f"[+] PUBLIC KEY RECEIVED: Successfully received the server's public key "
              f"({compress_pub_key(server_pub_key)})")

        # Derive the shared secret
        shared_secret = derive_shared_secret(self.pvt_key, server_pub_key)  # In bytes
        self.shared_secret = shared_secret.hex()
        print(SHARED_SECRET_SUCCESS_MSG.format(compress_shared_secret(shared_secret), len(shared_secret)))
        return shared_secret, session_iv


def _receive_request_handler(self: Node, peer_socket: socket.socket, peer_ip: str,
                             shared_secret: bytes, mode: str, peer_iv: bytes = None):
    """
    A helper function that handles the receiving, decrypting, and
    validation of a requesting peer's Transaction (connection request).

    @attention Use Case:
        Invoked when requesting peer wants to connect
        to the target Node and sends an encrypted Transaction
        object over the network

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
        Bytes of the initialization vector (IV)

    @return: None
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
        size = int.from_bytes(peer_socket.recv(4), byteorder='big')  # Get the size of transaction

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

        @return: request
            A decrypted and verified Transaction object
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
                add_new_transaction(self, request)
                save_transaction_to_file(data=data, shared_secret=shared_secret, iv=peer_iv, mode=mode)
                print(RECEIVED_TRANSACTION_SUCCESS.format(peer_ip))
                return request
            except RequestAlreadyExistsError:
                peer_socket.send(AES_encrypt(data=RESPONSE_EXISTS.encode(), key=shared_secret, mode=mode, iv=peer_iv))
                peer_socket.close()
                raise RequestAlreadyExistsError(ip=peer_ip)
        else:
            peer_socket.send(AES_encrypt(data=RESPONSE_INVALID_SIG.encode(), key=shared_secret, mode=mode, iv=peer_iv))
            peer_socket.close()
            raise InvalidSignatureError(ip=peer_ip)
    # ===============================================================================
    try:
        encrypted_data = receive_request()
        request = process_request(data=encrypted_data)
        save_pending_peer_info(self, peer_socket, peer_ip, request.first_name,
                               request.last_name, shared_secret, mode, peer_iv)
        peer_socket.settimeout(None)
    except InvalidSignatureError:
        raise InvalidSignatureError(ip=peer_ip)
    except RequestAlreadyExistsError:
        raise RequestAlreadyExistsError(ip=peer_ip)
    except RequestExpiredError:
        raise RequestExpiredError(ip=peer_ip)


def send_request(self: Node, peer_socket: socket.socket,
                 shared_secret: bytes, mode: str,
                 transaction: Transaction, peer_iv: bytes = None):
    """
    Sends the Transaction (connection request) to a target peer.

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

    @return: None
    """
    # Send REQUEST signal
    print(SEND_REQUEST_MSG.format(peer_socket.getpeername()[0]))
    peer_socket.send(AES_encrypt(data=REQUEST_SIGNAL.encode(), key=shared_secret, mode=mode, iv=peer_iv))

    # Wait for ACK
    peer_socket.recv(1024)

    # Sign the Transaction (connection request)
    sign_transaction(self, transaction)

    # Serialize and AES encrypt the object
    serialized_request = pickle.dumps(transaction)
    encrypted_request = AES_encrypt(data=serialized_request, key=shared_secret, mode=mode, iv=peer_iv)

    # Send the size of the serialized object
    peer_socket.sendall(len(encrypted_request).to_bytes(4, byteorder='big'))

    # Send the encrypted request
    peer_socket.sendall(serialized_request)
    print(SEND_REQUEST_SUCCESS)


def await_response(self: Node, peer_socket: socket.socket, shared_secret: bytes,
                   mode: str, transaction: Transaction, peer_iv: bytes = None):
    """
    Awaits a response from the target peer.

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

    @return: Boolean (T/F)
        True if request accepted; False otherwise
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
        print(TARGET_DISCONNECT_MSG)
        self.fd_list.remove(self.own_socket)  # => temporarily remove to prevent select() conflict
        self.own_socket.settimeout(transaction.get_time_remaining())
        try:
            while True:
                target_sock, target_info = self.own_socket.accept()
                if target_sock.getpeername()[0] == target_ip:  # => Re-established connection
                    print(TARGET_RECONNECT_MSG)
                    return target_sock
                else:
                    target_sock.close()
                    return None
        except socket.timeout():
            self.own_socket.settimeout(None)
            self.fd_list.append(self.own_socket)
            return None
    # ===============================================================================
    try:
        print(CONNECTION_AWAIT_RESPONSE_MSG.format(transaction.get_time_remaining()))
        peer_socket.settimeout(transaction.get_time_remaining())
        data = peer_socket.recv(1024)

        if not data:  # TODO: If disconnect, attempt reconnection
            sock = _reconnect_to_target(target_ip=peer_socket.getpeername()[0])
        else:
            response = AES_decrypt(data=data, key=shared_secret, mode=mode, iv=peer_iv).decode()
            return _response_handler(res=response, target_sock=peer_socket)
    except socket.timeout:
        print(CONNECTION_AWAIT_TIMEOUT_MSG)
        peer_socket.close()
        return False


def accept_new_peer_handler(self: Node, own_sock: socket.socket):
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
                _receive_request_handler(self, peer_socket, peer_address[0], shared_secret, mode, session_iv)
            elif signal == APPROVED_SIGNAL:
                print("[+] Accept peer")
            else:
                peer_socket.close()
                raise InvalidProtocolError(ip=peer_socket.getpeername()[0])
        except (InvalidSignatureError, InvalidProtocolError, RequestAlreadyExistsError, RequestExpiredError) as msg:
            print(msg)
    # ===============================================================================
    peer_socket, peer_address = own_sock.accept()
    print(f"[+] NEW CONNECTION REQUEST: Accepted a peer connection from ({peer_address[0]}, {peer_address[1]})!")

    shared_secret, session_iv, mode = establish_secure_connection(self, peer_socket, mode=MODE_RECEIVE)
    peer_socket.settimeout(ACCEPT_NEW_PEER_TIMEOUT)

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


def connect_to_target_peer(ip: str,
                           port: int = APPLICATION_PORT,
                           timeout: int = FIND_HOST_TIMEOUT):
    """
    Connects to a target peer using socket connection.

    @param ip:
        The IP address of the target peer

    @param port:
        The port number of the target peer (default = 323)

    @param timeout:
        An integer (in seconds) before a connection
        timeout is thrown

    @return: target_sock or None
        A target socket object if successful; otherwise None
    """
    try:
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.settimeout(timeout)
        target_sock.connect((ip, port))
        print(f"[+] CONNECTION EVENT: An available peer has been found ({ip}, {port})!")
        return target_sock
    except socket.timeout:
        print(CONNECTION_TIMEOUT_ERROR.format(ip))
        return None
    except socket.error:
        print(CONNECTION_ERROR.format(ip, port))
        return None


def connect_to_P2P_network(self: Node):
    """
    Finds, connects, and sends the connection request to a
    target peer using sockets.

    @param self:
        A reference to the calling class object (Node)

    @return: None
    """
    transaction = create_transaction(self)

    if transaction is not None:
        option = get_user_command_option(opt_range=tuple(range(3)), prompt=CONNECT_METHOD_PROMPT)
        if option == 0:
            return None
        if option == 1:
            target_ip = get_target_ip(self)
            target_sock = connect_to_target_peer(ip=target_ip)
            if target_sock is not None:
                shared_secret, session_iv = establish_secure_connection(self, target_sock, mode=MODE_INITIATE)
                send_request(self, target_sock, shared_secret, self.mode, transaction, session_iv)
                response = await_response(self, target_sock, shared_secret,
                                          self.mode, transaction, session_iv)
                if response:
                    print("[+] PLACEHOLDER - Follow up")
        if option == 2:
            print("[+] Multi-threaded iterative chunk search using timeouts")
            print("[+] Determine how many CPU cores for current machine, and spawn X threads to start search")
