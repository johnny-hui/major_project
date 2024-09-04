"""
Description:
This Python file contains utility functions for the Node class.

"""
import os
import pickle
import select
import socket
import time
from typing import TextIO
from prettytable import PrettyTable
from exceptions.exceptions import RequestAlreadyExistsError, TransactionNotFoundError
from models.Transaction import Transaction
from utility.crypto.aes_utils import AES_decrypt, AES_encrypt
from utility.crypto.ec_keys_utils import hash_data
from utility.general.constants import (MENU_TITLE, MENU_FIELD_OPTION, MENU_FIELD_DESC, MENU_OPTIONS_CONNECTED,
                                       MENU_OPTIONS,
                                       PEER_TABLE_TITLE, PEER_TABLE_FIELD_PERSON,
                                       PEER_TABLE_FIELD_IP, PEER_TABLE_FIELD_CIPHER_MODE,
                                       PEER_TABLE_FIELD_SECRET, PEER_TABLE_FIELD_IV,
                                       ROLE_DELEGATE, DELEGATE_MENU_OPTIONS, ROLE_ADMIN, ADMIN_MENU_OPTIONS, ROLE_PEER,
                                       CBC,
                                       INIT_FACTOR_BYTE_MAPPING,
                                       MODE_CBC_BYTE_MAPPING, MODE_ECB_BYTE_MAPPING, SHARED_KEY_BYTE_MAPPING,
                                       TRANSACTIONS_DIR,
                                       SAVE_TRANSACTION_SUCCESS, CBC_FLAG, ECB_FLAG, ECB,
                                       INVALID_MENU_SELECTION, MENU_ACTION_START_MSG, INVALID_INPUT_MENU_ERROR,
                                       TRANSACTION_INVALID_SIG_MSG, STATUS_PENDING, PEER_TABLE_FIELD_STATUS,
                                       VIEW_REQUEST_FURTHER_ACTION_PROMPT, VIEW_PHOTO_PROMPT, REVOKE_REQUEST_PROMPT,
                                       REVOKE_REQUEST_INITIAL_PROMPT, RESPONSE_REJECTED, APPLICATION_PORT,
                                       TAMPER_DETECTED_MSG, APPROVE_REQUEST_INITIAL_PROMPT, APPROVE_REQUEST_PROMPT,
                                       RESPONSE_APPROVED, STATUS_NOT_CONNECTED, MODE_INITIATOR,
                                       CONSENSUS_SUCCESS, CONSENSUS_FAILURE, REQUEST_REFUSED_MSG, APPROVED_PEER_MSG,
                                       STATUS_APPROVED, PEER_TABLE_FIELD_ROLE, ESTABLISHED_NETWORK_SUCCESS_MSG,
                                       APPROVE_NOT_CONNECTED_MSG)
from utility.general.utils import create_directory, is_directory_empty, write_to_file, get_img_path, load_image, \
    get_user_command_option, delete_file, create_transaction_table, determine_delegate_status
from utility.node.node_init import get_current_timestamp


def monitor_pending_peers(self: object):
    """
    Uses select() to monitor pending peer sockets
    that are awaiting consensus.

    @return: None
    """
    while not self.is_promoted:
        if self.terminate is True:
            break

        readable, _, _ = select.select(self.fd_pending, [], [], 1)

        for fd in readable:
            try:
                data = fd.recv(1024)
                if not data:
                    print(f"[+] A pending connection request has been closed by ({fd.getpeername()[0]}) due to "
                          f"a request timeout or manual disconnection!")
                    remove_pending_peer(self, peer_sock=fd, ip=fd.getpeername()[0])
            except (socket.error, socket.timeout, OSError) as e:
                print(f"[+] An error has occurred with socket ({fd.getpeername()}); connection closed! (REASON: {e})")
                remove_pending_peer(self, peer_sock=fd, ip=fd.getpeername()[0])


def remove_pending_peer(self: object, peer_sock: socket.socket, ip: str):
    """
    Removes a saved peer information and closes the
    socket connection with the pending peer.

    @param self:
        A reference to the calling class object (Node)

    @param peer_sock:
        The socket object of the pending peer to be removed

    @param ip:
        The IP address of the pending peer to be removed (String)

    @return: None
    """
    file_path = None
    try:
        file_path = self.peer_dict[ip][6]  # get the file path to remove from 'data/transactions/'
        del self.peer_dict[ip]
        self.fd_pending.remove(peer_sock)
    except (KeyError, ValueError):
        pass
    finally:
        delete_transaction(self.pending_transactions, ip=ip, request_path=file_path)
        peer_sock.close()
        print(f"[+] REMOVE PENDING PEER: Pending peer (IP: {ip}) has been successfully removed!")


def get_specific_peer_info(self: object, prompt: str):
    """
    Prompts user to select a specific peer to
    send a message to and returns saved peer
    information.

    @param self:
        A reference to the calling class object

    @param prompt:
        A string containing the prompt

    @return: tuple(socket, ip, shared_secret, iv, mode)
        A tuple containing the client socket, ip, shared secret,
        mode and the initialization vector (IV)
    """
    if len(self.fd_list) > 1:
        view_current_peers(self)

        while True:
            try:
                # Prompt user selection for a specific client
                client_index = int(input(prompt.format(1, len(self.peer_dict))))

                while client_index not in range(1, (len(self.peer_dict) + 1)):
                    print("[+] ERROR: Invalid selection range; please enter again.")
                    client_index = int(input(prompt.format(1, len(self.peer_dict))))

                # Get information of the client (from dictionary)
                ip, info = list(self.peer_dict.items())[client_index - 1]  # info = list
                secret, iv, mode = info[2], info[3], info[4]

                # Iterate over the list of sockets and find the corresponding one
                for sock in self.fd_list[1:]:
                    if sock.getpeername()[0] == ip:
                        return sock, ip, secret, iv, mode

            except (ValueError, TypeError) as e:
                print(f"[+] ERROR: An invalid selection provided ({e}); please enter again.")
    else:
        print("[+] ERROR: There are currently no connected peers to perform the selected option!")
        return None, None, None, None, None


def peer_exists(peer_dict: dict, ip: str, prompt: str = None):
    """
    Determines if a peer already exists in a peer dictionary
    (based on an input IP address).

    @param peer_dict:
        A dictionary containing peer information

    @param ip:
        The IP address used to search for an existing peer

    @param prompt:
        A string for the message to be printed if peer exists

    @return: Boolean (T/F)
        True if peer exists; False otherwise
    """
    if ip in peer_dict:
        print(prompt) if prompt else None
        return True
    else:
        return False


def get_pending_peer_info(peer_dict: dict, ip: str):
    """
    Returns information regarding a pending peer based on input IP.

    @param peer_dict:
        A dictionary containing peer information

    @param ip:
        A string for the target IP

    @return: f_name, l_name, shared_secret, iv, mode, status, file_path, role
    """
    f_name, l_name, shared_secret, iv, mode, status, file_path, role = peer_dict[ip]
    return f_name, l_name, shared_secret, iv, mode, status, file_path, role


def save_pending_peer_info(self: object, peer_socket: socket.socket, peer_ip: str,
                           first_name: str, last_name: str, shared_secret: bytes,
                           mode: str, file_path: str, role: str, peer_iv: bytes = None):
    """
    Saves information for a pending peer.

    @param self:
        A reference to the calling class object (Node)
    @param peer_socket:
        The socket object of the pending peer
    @param peer_ip:
        The IP address of the pending peer
    @param first_name:
        The first name of the pending peer
    @param last_name:
        The last name of the pending peer
    @param shared_secret:
        The shared secret of the pending peer
    @param mode:
        The selected cipher mode by the pending peer
    @param file_path:
        The file path of the saved connection request
    @param role:
        The role of the pending peer (PEER/DELEGATE/ADMIN)
    @param peer_iv:
        The pending peer's IV (if CBC)

    @return: None
    """
    self.fd_pending.append(peer_socket)
    self.peer_dict[peer_ip] = [first_name, last_name, shared_secret,
                               peer_iv, mode, STATUS_PENDING, file_path, role]


def change_peer_role(peer_dict: dict, ip: str, role: str):
    """
    Changes a role for a specific peer.

    @param peer_dict:
        A dictionary containing peer information

    @param ip:
        A string for the target IP (dictionary key)

    @param role:
        A string for the role (PEER, DELEGATE, ADMIN)

    @return: None
    """
    if role in (ROLE_PEER, ROLE_DELEGATE, ROLE_ADMIN):
        peer_dict[ip][7] = role
    else:
        print("[+] CHANGE PEER ROLE ERROR: Invalid role provided!")


def change_peer_status(peer_dict: dict, ip: str, status: str):
    """
    Changes the status for a specific peer.

    @param peer_dict:
        A dictionary containing peer information

    @param ip:
        A string for the target IP (dictionary key)

    @param status:
        A string for the status (PENDING, APPROVED)

    @return: None
    """
    if status in (STATUS_PENDING, STATUS_APPROVED):
        peer_dict[ip][5] = status
    else:
        print("[+] CHANGE PEER STATUS ERROR: Invalid status provided!")


def delete_transaction(pending_transactions: list[Transaction],
                       ip: str, request_path: str):
    """
    Removes a Transaction (connection request) object
    from the list (and in file) based on an input IP address.

    @param pending_transactions:
        A list of Transaction objects

    @param ip:
        The IP address of the request object
        to be removed (String)

    @param request_path:
        The file path of the saved connection request belonging
        to the pending peer to be removed (String)

    @return: None
    """
    if len(pending_transactions) == 0 or request_path is None:
        return None

    # Iterate and delete transaction from memory
    i = 0
    while i < len(pending_transactions):
        if pending_transactions[i].ip_addr == ip:
            del pending_transactions[i]
            break
        else:
            i += 1

    # Delete transaction file from system storage ('data/transactions/')
    delete_file(file_path=request_path)


def add_new_transaction(self: object, peer_request: Transaction):
    """
    Adds a new Transaction (connection request) object
    to the Node's pending_transaction list by ensuring
    no duplicates.

    @param self:
        A reference to the calling class object (Node)

    @param peer_request:
        A Transaction object

    @return: None
    """
    for request in self.pending_transactions:
        if peer_request.ip_addr == request.ip_addr:
            raise RequestAlreadyExistsError(ip=peer_request.ip_addr)
    peer_request.set_received_by(ip=self.ip)
    self.pending_transactions.append(peer_request)


def create_transaction(self: object):
    """
    Creates a new Transaction (connection request) object
    when attempting to connect to the P2P network.

    @param self:
        A reference to the calling class object (Node)

    @return: transaction or None
        A Transaction object if no errors; otherwise None
    """
    try:
        img_path = get_img_path()
        img_bytes = load_image(img_path)
        transaction = Transaction(ip=self.ip, port=self.port, first_name=self.first_name,
                                  last_name=self.last_name, public_key=self.pub_key)
        transaction.set_image(img_bytes)
        transaction.set_role(self.role)
        return transaction
    except (ValueError, FileNotFoundError, IOError) as e:
        print(f"[+] ERROR: An error has occurred while creating Transaction object; please try again... [REASON: {e}]")
        return None


def sign_transaction(self: object, transaction: Transaction):
    """
    Gets & sets an updated timestamp and signs
    the Transaction object.

    @param self:
        A reference to the calling class object (Node)

    @param transaction:
        A Transaction object

    @return: transaction
        A Transaction object
    """
    transaction.set_timestamp(timestamp=get_current_timestamp())
    transaction.sign_transaction(self.pvt_key)
    return transaction


def display_menu(role: str, is_connected: bool = False):
    """
    Displays the menu for user commands.

    @param role:
        A string representing the role of the Node
        (PEER, DELEGATE, ADMIN)

    @param is_connected:
        A boolean determining whether the Node is connected

    @return: None
    """
    menu = PrettyTable()
    menu.title = MENU_TITLE
    menu.field_names = [MENU_FIELD_OPTION, MENU_FIELD_DESC]

    if is_connected:
        if role == ROLE_DELEGATE:
            for item in DELEGATE_MENU_OPTIONS:
                menu.add_row(item)
        if role == ROLE_ADMIN:
            for item in ADMIN_MENU_OPTIONS:
                menu.add_row(item)
        if role == ROLE_PEER:
            for item in MENU_OPTIONS_CONNECTED:
                menu.add_row(item)
    else:
        for item in MENU_OPTIONS:
            menu.add_row(item)
    print(menu)


def get_user_menu_option(fd: TextIO, min_num_options: int, max_num_options: int):
    """
    Gets the user selection for the menu.

    @param fd:
        The file descriptor for stdin

    @param min_num_options:
        The minimum number of options possible

    @param max_num_options:
        The maximum number of options possible

    @return: command
        An integer representing the selection
    """
    while True:
        try:
            command = int(fd.readline().strip())
            while not (min_num_options <= command <= max_num_options):
                print(INVALID_MENU_SELECTION.format(min_num_options, max_num_options))
                command = int(fd.readline().strip())
            print(MENU_ACTION_START_MSG.format(command))
            return command
        except (ValueError, TypeError) as e:
            print(INVALID_INPUT_MENU_ERROR.format(e))
            print(INVALID_MENU_SELECTION.format(min_num_options, max_num_options))


def view_current_peers(self: object):
    """
    Displays information of all connected peers.

    @param self:
        A reference to the calling class object

    @return: None
    """
    def process_name(peer_info: list) -> str:
        return peer_info[0] + " " + peer_info[1]
    # ===============================================================================

    # Instantiate table and define title & columns
    table = PrettyTable()
    table.title = PEER_TABLE_TITLE
    table.field_names = [PEER_TABLE_FIELD_PERSON, PEER_TABLE_FIELD_IP,
                         PEER_TABLE_FIELD_CIPHER_MODE, PEER_TABLE_FIELD_SECRET,
                         PEER_TABLE_FIELD_IV, PEER_TABLE_FIELD_STATUS, PEER_TABLE_FIELD_ROLE]

    # Fill table with data
    if len(self.fd_list) > 1 or len(self.fd_pending) > 0:
        for ip, information in self.peer_dict.items():
            table.add_row(
                [
                    process_name(information),
                    ip,
                    information[4].upper(),     # encryption mode
                    hash_data(information[2]),  # secret
                    hash_data(information[3]),  # IV
                    information[5],             # status
                    information[7]              # role (PEER/DELEGATE/ADMIN)
                 ]
            )
        print(table)
    else:
        print("[+] VIEW CURRENT PEERS: You are not connected to any peers!")


def perform_transaction_expiry_check(transaction_list: list[Transaction]):
    """
    A utility function to remove any expired Transaction
    (connection request) objects from the list.

    @param transaction_list:
        A list of Transaction objects

    @return: None
    """
    i = 0
    while i < len(transaction_list):
        if transaction_list[i].is_expired():
            del transaction_list[i]
        i += 1


def view_pending_connection_requests(self: object, do_prompt: bool = True):
    """
    Prints the information of all received pending
    connection requests.

    @param self:
        A reference to the calling class object (Node)

    @param do_prompt:
        A boolean determining whether to prompt the user for
        further actions

    @return: None
    """
    def view_photo_prompt(req_list: list[Transaction]):
        command = get_user_command_option(opt_range=tuple(range(2)),
                                          prompt=VIEW_REQUEST_FURTHER_ACTION_PROMPT)
        if command == 0:
            return None
        if command == 1:
            request = get_transaction(req_list, prompt=VIEW_PHOTO_PROMPT.format(len(req_list)))
            if request is not None:
                request.show_image()
    # ===============================================================================
    # Expiry check for each Transaction
    perform_transaction_expiry_check(transaction_list=self.pending_transactions)

    if len(self.pending_transactions) == 0:
        print("[+] VIEW PENDING CONNECTION REQUESTS: There are currently no pending connection requests!")
        return None

    print(create_transaction_table(req_list=self.pending_transactions))

    # Prompt user the option to view the photo of a specific request (or quit)
    if do_prompt:
        view_photo_prompt(self.pending_transactions)


def get_transaction(req_list: list[Transaction],
                    prompt: str = None,
                    ip: str = None):
    """
    Prompts the user to select a specific Transaction
    (connection request) from the pending connections
    list.

    @attention Alternative Use Case:
        Can be used to get a Transaction object without prompt
        based on IP

    @param req_list:
        A list of Transaction (requests) objects

    @param prompt:
        A string for the printed prompt

    @param ip:
        An optional parameter to get a Transaction from the
        list (based on an IP address)

    @raise TransactionNotFoundError:
        If an IP is provided and a corresponding Transaction
        object is not found within the list.

    @return: req_list[index] or None
        The Transaction object if not expired; otherwise, None
    """
    if ip is not None:
        for transaction in req_list:
            if transaction.ip_addr == ip:
                return transaction
        raise TransactionNotFoundError(ip)

    while True:
        try:
            index = int(input(prompt)) - 1  # => adjust for zero-based indexing
            if index in tuple(range(len(req_list))):
                return req_list[index] if not req_list[index].is_expired() else None
            else:
                print("[+] ERROR: Invalid option provided; please try again.")
        except (ValueError, TypeError) as e:
            print(f"[+] ERROR: Invalid option selected; please try again! ({e})")


def close_application(self: object):
    """
    Terminates the application by setting a termination flag to
    end all current threads.

    @param self:
        A reference to the calling class object

    @return: None
    """
    self.terminate = True
    print("[+] CLOSE APPLICATION: Now closing the application...")
    print("[+] Application has been successfully terminated!")


def send_message(sock: socket.socket, mode: str,
                 secret: bytes, iv: bytes | None):
    """
    Prompts user for a plaintext message, encrypts it
    and sends it to a target socket.

    @param sock:
        The target socket

    @param mode:
        A string for the encryption mode

    @param iv:
        Bytes of the initialization factor (IV) or None (if mode=ECB)

    @param secret:
        Bytes of the shared secret

    @return: None
    """
    if sock is not None:
        ip = sock.getpeername()[0]
        message = input(f"[+] Enter a message to send to ({ip}): ")
        cipher_text = AES_encrypt(data=message.encode(), mode=mode, key=secret, iv=iv)
        sock.send(cipher_text)
        print("[+] Your message has been successfully sent!")


def save_transaction_to_file(data: bytes, shared_secret: bytes, mode: str, iv: bytes = None):
    """
    Saves an encrypted Transaction object (pending connection request)
    to a file within the 'data/transactions/' directory.

    @param data:
        Bytes containing the Transaction object (encrypted)

    @param shared_secret:
        Bytes containing the shared secret between two peers

    @param mode:
        A string representing the cipher mode used for secure
        communication

    @param iv:
        Bytes containing the IV between peers (default=None)

    @return: file_path
        The file path of the saved Transaction (string)
    """
    def find_latest_transaction_number(path: str = TRANSACTIONS_DIR):
        """
        Finds the latest transaction (connection request) number
        from the 'data/transactions/' directory.

        @param path:
            A string defining the directory path to 'data/transactions/'

        @return: max(file_numbers)
            An integer containing the latest transaction number
        """
        file_numbers = []
        for filename in os.listdir(path):
            if filename.startswith('request_') and filename.endswith('.json'):
                try:
                    file_number = int(filename.split('_')[1].split('.')[0])
                    file_numbers.append(file_number)
                except ValueError:
                    continue
        return max(file_numbers)
    # ===============================================================================

    create_directory(path=TRANSACTIONS_DIR)
    new_data = _obfuscate(data, shared_secret, mode, iv)

    if is_directory_empty(path=TRANSACTIONS_DIR):
        file_path = os.path.join(TRANSACTIONS_DIR, "request_1.json")
        write_to_file(file_path, new_data)
    else:
        latest_transaction_number = find_latest_transaction_number() + 1
        new_file_name = "request_" + str(latest_transaction_number) + ".json"
        file_path = os.path.join(TRANSACTIONS_DIR, new_file_name)
        write_to_file(file_path, new_data)

    print(SAVE_TRANSACTION_SUCCESS.format(file_path))
    return file_path


def load_transactions(self: object):
    """
    Loads and decrypts Transactions (pending connection requests)
    from files within the 'data/transactions/' directory and
    stores them into a list.

    @param self:
        Reference to the calling class object (Node)

    @return: None
    """
    def _extract_bytes_from_data(data: bytearray, byte_map: dict):
        item = bytearray()
        for (position, _) in byte_map.items():
            item.append(data[position])
        return bytes(item)

    def extract_mode_secret_iv(data: bytearray):
        """
        Extracts the mode, shared secret, and initialization
        factor IV (if mode is CBC) from the data.

        @param data:
            Bytes of the encrypted Transaction data

        @return: mode, secret, iv
        """
        mode, secret, iv = data[53], None, None
        secret = _extract_bytes_from_data(data=data, byte_map=SHARED_KEY_BYTE_MAPPING)
        if mode == CBC_FLAG:
            iv = _extract_bytes_from_data(data=data, byte_map=INIT_FACTOR_BYTE_MAPPING)
        return mode, secret, iv

    def restore_original_bytes(data: bytearray, mode: int):
        if mode == CBC_FLAG:
            original_bytes = data[-33:]  # Last 33 bytes (IV, mode, secret)
            counter = 0

            for position in INIT_FACTOR_BYTE_MAPPING:
                data[position] = original_bytes[counter]
                counter += 1

            data[MODE_CBC_BYTE_MAPPING[0]] = original_bytes[counter]
            counter += 1

            for position in SHARED_KEY_BYTE_MAPPING:
                data[position] = original_bytes[counter]
                counter += 1

        elif mode == ECB_FLAG:
            original_bytes = data[-17:]  # Last 17 bytes (mode, secret)
            counter = 0

            data[MODE_ECB_BYTE_MAPPING[0]] = original_bytes[counter]
            counter += 1

            for position in SHARED_KEY_BYTE_MAPPING:
                data[position] = original_bytes[counter]
                counter += 1

    def process_transaction(request: Transaction):
        """
        Processes the transaction by checking if it has expired
        and verifying the digital signature.

        @param request:
            A Transaction object

        @return: None
        """
        nonlocal counter
        if request.is_expired():
            os.remove(file_path)
        elif request.is_verified():
            counter += 1
            request.received_by = self.ip
            self.pending_transactions.append(request)
            self.peer_dict[request.ip_addr] = [request.first_name, request.last_name, shared_key,
                                               iv, mode, STATUS_PENDING, file_path, request.role]
        else:
            os.remove(file_path)
            print(TRANSACTION_INVALID_SIG_MSG.format(request.ip_addr))
    # ===============================================================================

    # Create 'data/transactions' directory if it does not exist
    create_directory(path=TRANSACTIONS_DIR)

    if not is_directory_empty(path=TRANSACTIONS_DIR):
        counter = 0
        for file_name in os.listdir(TRANSACTIONS_DIR):
            file_path = os.path.join(TRANSACTIONS_DIR, file_name)

            if os.path.isfile(file_path):
                with open(file_path, 'rb') as file:
                    content = bytearray(file.read())

                    mode, shared_key, iv = extract_mode_secret_iv(data=content)
                    restore_original_bytes(data=content, mode=mode)

                    try:
                        if mode == CBC_FLAG:
                            decrypted_data = AES_decrypt(data=content[:-33], key=shared_key, mode=CBC, iv=iv)
                            mode = CBC
                        else:
                            decrypted_data = AES_decrypt(data=content[:-17], key=shared_key, mode=ECB)
                            mode = ECB
                    except ValueError:
                        print(TAMPER_DETECTED_MSG.format(file_path))
                        os.remove(file_path)
                        continue

                    transaction = pickle.loads(decrypted_data)
                    process_transaction(request=transaction)

        print(f"[+] OPERATION SUCCESS: {counter} pending connection requests have been successfully "
              f"verified and loaded!")


def revoke_connection_request(self: object):
    """
    Revokes a specific connection request.

    @attention peer_socket == None
        It is 'None' if you disconnect from application while
        having any pending connection requests from requesting
        peers (No initial sockets)

    @param self:
        A reference to the calling class object (Node)

    @return: None
    """
    def revoke_helper(peer_socket: socket.socket | None):
        try:
            if peer_socket is None:  # Attempt reconnection
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.settimeout(5)  # 5-second timeout
                peer_socket.connect((request.ip_addr, APPLICATION_PORT))

            # Get pending peer info
            _, _, secret_key, iv, mode, _, file_path, _ = get_pending_peer_info(self.peer_dict, ip=request.ip_addr)

            # Remove peer socket from pending list (prevent select-related errors)
            if peer_socket in self.fd_pending:
                self.fd_pending.remove(peer_socket)
                time.sleep(1)

            # Send encrypted rejection response, close connection and remove pending peer information
            peer_socket.send(AES_encrypt(data=RESPONSE_REJECTED.encode(), key=secret_key, mode=mode, iv=iv))

        except (socket.error, socket.timeout, OSError):
            return None
        finally:
            remove_pending_peer(self, peer_socket, ip=request.ip_addr)
    # ===============================================================================

    if len(self.pending_transactions) == 0:
        print("[+] REVOKE ERROR: There are currently no pending connection requests to revoke!")
        return None

    # Print current Transactions and get a specific Transaction from the List
    view_pending_connection_requests(self, do_prompt=False)
    command = get_user_command_option(opt_range=tuple(range(2)), prompt=REVOKE_REQUEST_INITIAL_PROMPT)

    # Perform the command
    if command == 0:
        return None
    if command == 1:
        request = get_transaction(req_list=self.pending_transactions,
                                  prompt=REVOKE_REQUEST_PROMPT.format(len(self.pending_transactions)))
        if request is not None:
            peer_sock = _get_pending_peer_socket(self.fd_pending, ip=request.ip_addr)
            revoke_helper(peer_sock)

        print("[+] REVOKE SUCCESSFUL: The selected connection request has been successfully revoked!")


def approve_connection_request(self: object):
    """
    Approves a specific connection request.

    @attention Status (Connected vs. Not Connected):
        If the user is connected to network, they need to send the request
        to an elevated peer (ADMIN or DELEGATE); otherwise, the user approves
        the connection request on their own and initiates a Consensus by
        sending over their own connection request to the pending peer for
        verification (Zero-Trust Policy).

    @param self:
        A reference to the calling class object (Node)

    @return: None
    """
    def is_connected_approve_helper():
        """
        A utility helper function that handles approving
        peers when host peer is connected to the P2P network.

        @return: None
        """
        print("[+] Do something")

    def not_connected_approve_helper(pending_peer_sock: socket.socket | None):
        """
        A utility helper function that handles approving peers
        when host peer is not connected to the P2P network
        (or anyone).

        @param pending_peer_sock:
            A pending peer socket object

        @return: None
        """
        print(APPROVE_NOT_CONNECTED_MSG.format(request.ip_addr))
        try:
            if pending_peer_sock is None:  # Attempt reconnection
                pending_peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                pending_peer_sock.settimeout(5)  # 5-second timeout
                pending_peer_sock.connect((request.ip_addr, APPLICATION_PORT))
                print(f"[+] Successfully reconnected to requesting peer (IP: {request.ip_addr})!")

            # Get pending peer info
            _, _, secret_key, iv, mode, _, file_path, _ = get_pending_peer_info(self.peer_dict, ip=request.ip_addr)

            # Remove peer socket from pending list (prevent select-related errors)
            if pending_peer_sock in self.fd_pending:
                self.fd_pending.remove(pending_peer_sock)
                time.sleep(1)

            # Send APPROVED signal to pending peer
            pending_peer_sock.send(AES_encrypt(data=RESPONSE_APPROVED.encode(), key=secret_key, mode=mode, iv=iv))

            # Wait for ACK (for synchronization)
            pending_peer_sock.recv(1024)

            # Send Status - [Not Connected]
            pending_peer_sock.send(AES_encrypt(data=STATUS_NOT_CONNECTED.encode(), key=secret_key, mode=mode, iv=iv))

            # Create own connection request and submit for consensus
            own_request = None
            while own_request is None:
                own_request = create_transaction(self)

            # Sign the transaction
            sign_transaction(self, own_request)

            # Process data for Consensus (add pending peer socket)
            temp_list = [pending_peer_sock]

            # Initiate Consensus and Wait for Pending Peer's Vote
            from models.Consensus import Consensus
            consensus = Consensus(request=own_request, mode=MODE_INITIATOR, peer_list=temp_list,
                                  peer_dict=self.peer_dict, is_connected=False)
            final_decision = consensus.start()

            # Evaluate and handle the decision
            if final_decision == CONSENSUS_SUCCESS:
                print(APPROVED_PEER_MSG.format(request.ip_addr))

                # Compare application timestamp and determine who gets delegate (if not admin)
                if self.role == ROLE_PEER and request.role == ROLE_PEER:
                    is_delegate = determine_delegate_status(pending_peer_sock, self.app_timestamp,
                                                            mode=MODE_INITIATOR, enc_mode=mode,
                                                            secret=secret_key, iv=iv)
                    if is_delegate:
                        print("[+] PROMOTION: You have been promoted to 'Delegate' node!")
                        self.is_promoted = True
                    else:
                        change_peer_role(self.peer_dict, ip=request.ip_addr, role=ROLE_DELEGATE)

                # Perform finishing steps
                self.fd_list.append(pending_peer_sock)
                change_peer_status(self.peer_dict, ip=request.ip_addr, status=STATUS_APPROVED)
                delete_transaction(self.pending_transactions, request.ip_addr, file_path)
                self.is_connected = True
                print(ESTABLISHED_NETWORK_SUCCESS_MSG.format(pending_peer_sock.getpeername()[0]))

            if final_decision == CONSENSUS_FAILURE:
                print(REQUEST_REFUSED_MSG)
                delete_transaction(self.pending_transactions, request.ip_addr, request_path=file_path)
                remove_pending_peer(self, pending_peer_sock, ip=request.ip_addr)

        except (socket.error, socket.timeout, OSError):
            print("[+] APPROVE ERROR: Cannot re-establish connection with the requesting peer!")
            remove_pending_peer(self, pending_peer_sock, ip=request.ip_addr)
    # ===============================================================================
    if len(self.pending_transactions) == 0:
        print("[+] APPROVE ERROR: There are currently no pending connection requests to approve!")
        return None

    # Print current Transactions and get a specific Transaction from the List
    view_pending_connection_requests(self, do_prompt=False)
    command = get_user_command_option(opt_range=tuple(range(2)), prompt=APPROVE_REQUEST_INITIAL_PROMPT)

    if command == 0:
        return None

    if command == 1:
        request = get_transaction(req_list=self.pending_transactions,
                                  prompt=APPROVE_REQUEST_PROMPT.format(len(self.pending_transactions)))
        if request:
            print(f"[+] Now approving request from peer (IP: {request.ip_addr}); please wait...")
            if self.is_connected:
                is_connected_approve_helper()
                print("[+] Select an admin/delegate from fd_list -> get socket -> Send Transaction object for approval")
            else:
                peer_sock = _get_pending_peer_socket(self.fd_pending, ip=request.ip_addr)
                not_connected_approve_helper(peer_sock)
        else:
            print("[+] APPROVE ERROR: The selected request has expired; please try again!")


def _obfuscate(data: bytes, shared_secret: bytes, mode: str, iv: bytes = None):
    """
    Takes the shared secret and IV (if CBC mode) and
    assigns them to random byte positions within the
    bytes of the encrypted Transaction object.

    @param data:
        Bytes containing the Transaction object (encrypted)

    @param shared_secret:
        Bytes containing the shared secret between two peers

    @param mode:
        A string representing the cipher mode used for secure
        communication

    @param iv:
        Bytes containing the IV between peers (default=None)

    @return: None
    """
    def update_data_with_mapping(transaction_data: bytearray, item: bytearray,
                                 byte_map: dict, replaced_bytes: bytearray):
        """
        Updates the bytes of the encrypted Transaction data with
        bytes from a byte-map table.

        @param transaction_data:
            A byte array containing the encrypted Transaction data

        @param item:
            A byte array containing bytes from a shared secret or IV

        @param byte_map:
            A dictionary containing a specific byte mappings

        @param replaced_bytes:
            A byte array containing the original bytes that
            will be replaced

        @return: None
        """
        for (pos, _), byte in zip(byte_map.items(), item):
            byte_map[pos] = byte
        for pos, byte in byte_map.items():
            replaced_bytes.append(transaction_data[pos])
            transaction_data[pos] = byte

    def add_mode_flag(transaction_data: bytearray,
                      mode_map: tuple,
                      replaced_bytes: bytearray):
        """
        Updates a specific byte at a byte position in the
        Transaction data for the cipher mode.

        @param transaction_data:
            A byte array containing the encrypted Transaction data
        @param mode_map:
            A tuple containing the byte mapping for the cipher mode
        @param replaced_bytes:
            A byte array containing the original bytes
        @return: None
        """
        position, byte = mode_map
        replaced_bytes.append(transaction_data[position])
        transaction_data[position] = byte
    # ===============================================================================

    data_array = bytearray(data)  # Transaction data
    secret_array = bytearray(shared_secret)  # Shared Secret
    original_bytes = bytearray()  # Replaced Bytes

    # Hide IV data in Transaction data (if CBC)
    if mode == CBC:
        iv_array = bytearray(iv)
        update_data_with_mapping(data_array, iv_array, INIT_FACTOR_BYTE_MAPPING, original_bytes)
        add_mode_flag(data_array, MODE_CBC_BYTE_MAPPING, original_bytes)
    else:
        add_mode_flag(data_array, MODE_ECB_BYTE_MAPPING, original_bytes)

    # Hide the Shared Secret in Transaction data
    update_data_with_mapping(data_array, secret_array, SHARED_KEY_BYTE_MAPPING, original_bytes)

    # Append the replaced bytes to the end of Transaction data
    data_array.extend(original_bytes)
    return data_array


def _get_pending_peer_socket(pending_list: list[socket.socket], ip: str):
    """
    Gets a pending peer socket based on an IP address.

    @attention Return None:
        If the pending peer socket not found in memory, then
        the user machine must have disconnected, but still has
        the connection request of the pending peer.

    @param pending_list:
        A list of pending peers' sockets

    @param ip:
        A string for the IP address to be searched

    @return: sock or None
        The pending peer socket if exists; otherwise, None.
    """
    for sock in pending_list:
        if sock.getpeername()[0] == ip:
            return sock
    return None
