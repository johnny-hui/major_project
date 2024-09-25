"""
Description:
This Python file contains utility functions for the Node class.

"""
import os
import pickle
import select
import socket
import threading
import time
from typing import TextIO
from prettytable import PrettyTable
from exceptions.exceptions import (RequestAlreadyExistsError, TransactionNotFoundError, InvalidTokenError,
                                   PeerRefusedBlockError, PeerInvalidBlockchainError, InvalidBlockchainError,
                                   InvalidBlockError)
from models.Block import Block
from models.Blockchain import Blockchain
from models.Peer import Peer
from models.Token import Token
from models.Transaction import Transaction
from utility.client_server.blockchain import send_block, receive_block, send_blockchain, receive_blockchain, \
    exchange_blockchain_index, compare_latest_hash
from utility.crypto.aes_utils import AES_decrypt, AES_encrypt
from utility.crypto.ec_keys_utils import hash_data
from utility.crypto.token_utils import verify_token
from utility.general.constants import (MENU_TITLE, MENU_FIELD_OPTION, MENU_FIELD_DESC, MENU_OPTIONS_CONNECTED,
                                       MENU_OPTIONS, PEER_TABLE_TITLE, PEER_TABLE_FIELD_PERSON, PEER_TABLE_FIELD_IP,
                                       PEER_TABLE_FIELD_CIPHER_MODE, PEER_TABLE_FIELD_SECRET, PEER_TABLE_FIELD_IV,
                                       ROLE_DELEGATE, DELEGATE_MENU_OPTIONS, ROLE_ADMIN, ADMIN_MENU_OPTIONS, ROLE_PEER,
                                       CBC, INIT_FACTOR_BYTE_MAPPING, MODE_CBC_BYTE_MAPPING, MODE_ECB_BYTE_MAPPING,
                                       SHARED_KEY_BYTE_MAPPING, DEFAULT_TRANSACTIONS_DIR, SAVE_TRANSACTION_SUCCESS,
                                       CBC_FLAG, ECB_FLAG, ECB, INVALID_MENU_SELECTION, MENU_ACTION_START_MSG,
                                       INVALID_INPUT_MENU_ERROR, TRANSACTION_INVALID_SIG_MSG, STATUS_PENDING,
                                       PEER_TABLE_FIELD_STATUS, VIEW_REQUEST_FURTHER_ACTION_PROMPT, VIEW_PHOTO_PROMPT,
                                       REVOKE_REQUEST_PROMPT, REVOKE_REQUEST_INITIAL_PROMPT, RESPONSE_REJECTED,
                                       APPLICATION_PORT, TAMPER_DETECTED_MSG, APPROVE_REQUEST_INITIAL_PROMPT,
                                       APPROVE_REQUEST_PROMPT, RESPONSE_APPROVED, STATUS_NOT_CONNECTED, MODE_INITIATOR,
                                       CONSENSUS_SUCCESS, CONSENSUS_FAILURE, REQUEST_REFUSED_MSG, APPROVED_PEER_MSG,
                                       STATUS_APPROVED, PEER_TABLE_FIELD_ROLE, ESTABLISHED_NETWORK_SUCCESS_MSG,
                                       APPROVE_NOT_CONNECTED_MSG, SELECT_ADMIN_DELEGATE_PROMPT,
                                       PURPOSE_REQUEST_APPROVAL, MODE_VOTER, REQUEST_APPROVAL_SIGNAL, CONSENSUS_SIGNAL,
                                       REMOVE_PEER_SIGNAL, PROMOTION_SIGNAL, FORMAT_STRING, STATUS_CONNECTED,
                                       SEND_TOKEN_SUCCESS, BLOCK_SIZE, ACK, SEND_PEER_DICT_SUCCESS,
                                       CONSENSUS_PEER_WIN_MSG, CONSENSUS_PEER_LOSE_MSG, REQ_BUFFER_TIME_INITIAL,
                                       MONITOR_APPROVAL_TOKENS_INTERVAL, SELECT_PEER_SEND_MSG_PROMPT,
                                       UPDATE_NEW_PROMOTED_PEER_SIGNAL, HAS_BLOCKCHAIN_SIGNAL, NO_BLOCKCHAIN_SIGNAL,
                                       MODE_RECEIVER, ERROR_BLOCK, ERROR_BLOCKCHAIN)
from utility.general.utils import create_directory, is_directory_empty, write_to_file, get_img_path, load_image, \
    get_user_command_option, delete_file, create_transaction_table, determine_delegate_status
from utility.node.node_init import get_current_timestamp


def process_name(first_name: str, last_name: str) -> str:
    """
    Concatenates first name and last name into one string.

    @param first_name:
        A string for the first name

    @param last_name:
        A string for the last name

    @return: name:
        A string for the entire name
    """
    return first_name + " " + last_name


def verify_admin_or_delegate(peer_dict: dict[str, Peer], ip: str):
    """
    Verifies an admin or delegate in the peer dictionary
    given an IP address.

    @param peer_dict:
        A dictionary containing peer information

    @param ip:
        A string for the input IP address to be searched

    @return: Boolean (T/F)
        True if IP belongs to admin/delegate node, False otherwise
    """
    try:
        if ip in peer_dict:
            if peer_dict[ip].role in (ROLE_ADMIN, ROLE_DELEGATE):
                return True
            return False
    except KeyError as e:
        print(f"[+] ERROR: Cannot verify admin or delegate based on the provided IP! [REASON: {e}]")
        return False


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


def monitor_peer_approval_token_expiry(self: object, event: threading.Event):
    """
    Checks the peer dictionary for any pending peers with approval tokens
    in the peer dictionary, and if expired, removes them.

    @attention Use Case:
        This can happen when peers that have passed consensus voting
        and are issued an approval token suddenly disconnect, therefore
        causing them to expire.

        The token must be presented upon joining other peers in
        the network.

    @param self:
        A reference to the calling class object (Node, DelegateNode, AdminNode)

    @param event:
        A Threading Event object

    @return: None
    """
    while not self.is_promoted:
        if self.terminate is True:
            break

        if self.is_connected and not len(self.peer_dict) == 0:
            print("[+] APPROVAL TOKEN CHECK: Checking for any pending peers with expired approval tokens...")
            peers_to_remove = []

            for ip, peer in self.peer_dict.items():
                if peer.token is not None and peer.token.has_expired():
                    peers_to_remove.append(ip)

            for ip in peers_to_remove:
                del self.peer_dict[ip]
                print(f"[+] A pending peer been removed due to an expired approval token! [IP: {ip}]")

            if len(peers_to_remove) == 0:
                print("[+] CHECK COMPLETE: There are currently no pending peers with expired tokens!")

        event.wait(MONITOR_APPROVAL_TOKENS_INTERVAL)  # => 3 minutes (180 seconds)


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
        file_path = self.peer_dict[ip].transaction_path  # get the file path to remove from 'data/transactions/'
        del self.peer_dict[ip]
        self.fd_pending.remove(peer_sock)
    except (KeyError, ValueError):
        pass
    finally:
        delete_transaction(self.pending_transactions, ip=ip, request_path=file_path)
        peer_sock.close()
        print(f"[+] REMOVE PENDING PEER: Pending peer (IP: {ip}) has been successfully removed!")


def remove_approved_peer(self: object, peer_to_remove: Peer):
    """
    Removes an approved peer from the network.

    @param self:
        A reference to the calling class object (Node, DelegateNode, AdminNode)

    @param peer_to_remove:
        The peer to remove

    @return: None
    """
    del self.peer_dict[peer_to_remove.ip]
    self.fd_list.remove(peer_to_remove)
    time.sleep(1.2)
    peer_to_remove.socket.close()


def get_specific_peer_prompt(self: object, prompt: str) -> Peer | None:
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
                _, peer = list(self.peer_dict.items())[client_index - 1]
                return peer

            except (ValueError, TypeError) as e:
                print(f"[+] ERROR: An invalid selection provided ({e}); please enter again.")
    else:
        print("[+] ERROR: There are currently no connected peers to perform the selected option!")
        return None


def get_info_admins_and_delegates(self: object):
    """
    Retrieves and returns a list of admins and delegate peers.

    @param self:
        A reference to the calling class object (Node)

    @return: admin_delegate_list
        A list of connected admins and delegate Peers
    """
    admin_delegate_list = []

    for sock in self.fd_list[1:]:  # ignore first index == own socket
        ip = sock.getpeername()[0]
        if self.peer_dict[ip].role in (ROLE_ADMIN, ROLE_DELEGATE):  # => do quick lookup
            admin_delegate_list.append(self.peer_dict[ip])

    if len(admin_delegate_list) == 0:  # => if no admin or delegates
        return None

    return admin_delegate_list


def select_admin_or_delegate_menu(admin_delegate_list: list[Peer]):
    """
    Prompts the user to select an admin or delegate from a list
    of admins and delegates.

    @param admin_delegate_list:
        A list of information regarding admins and delegate peers

    @return: peer
        The chosen admin or delegate peer
    """
    # Check if list empty
    if admin_delegate_list is None:
        print("[+] ERROR: There are currently no Admins or Delegate peers to perform the selected option!")
        return None

    # Instantiate PrettyTable and define title & columns
    table = PrettyTable()
    table.title = PEER_TABLE_TITLE
    table.field_names = [PEER_TABLE_FIELD_PERSON, PEER_TABLE_FIELD_IP, PEER_TABLE_FIELD_ROLE]

    # Fill table and print info on each admin/delegate in the list
    for peer in admin_delegate_list:
        table.add_row([process_name(peer.first_name, peer.last_name), peer.ip, peer.role])
    print(table)

    # Prompt user for a specific admin or delegate to select (index)
    index = get_user_command_option(opt_range=tuple(range(1, len(admin_delegate_list) + 1)),
                                    prompt=SELECT_ADMIN_DELEGATE_PROMPT.format(len(admin_delegate_list)))

    # Get the corresponding admin or delegate peer
    peer = admin_delegate_list[index - 1]
    return peer


def peer_exists(peer_dict: dict[str, Peer], ip: str, msg: str = None):
    """
    Determines if a peer already exists within the network
    (based on an input IP address).

    @param peer_dict:
        A dictionary containing peer information

    @param ip:
        The IP address used to search for an existing peer

    @param msg:
        A string for the message to be printed if peer exists

    @return: Boolean (T/F)
        True if peer exists; False otherwise
    """
    if ip in peer_dict:
        print(msg) if msg else None
        return True
    else:
        return False


def get_peer(peer_dict: dict[str, Peer], ip: str) -> Peer | None:
    """
    Returns a Peer object based on an input IP address.

    @param peer_dict:
        A dictionary containing Peer objects

    @param ip:
        A string for the target IP to index

    @return: peer or None
        A Peer object (if exists), None otherwise
    """
    try:
        peer = peer_dict[ip]
        return peer
    except KeyError as e:
        print(f"[+] GET PEER ERROR: The peer with IP ({ip}) does not exist! [REASON: {e}]")


def add_peer_to_dict(peer_dict: dict[str, Peer], peer: Peer):
    """
    Adds a Peer entry in the peer dictionary.

    @param peer_dict:
        A dictionary containing Peer objects

    @param peer:
        A Peer object

    @return: None
    """
    peer_dict[peer.ip] = peer


def remove_peer_from_dict(peer_dict: dict[str, Peer], ip: str):
    """
    Removes a Peer entry from the peer dictionary.
    @param peer_dict:
        A dictionary containing Peer objects

    @param ip:
        A string for the target IP to remove

    @return: None
    """
    try:
        del peer_dict[ip]
    except KeyError as e:
        print(f"[+] ERROR: An error has occurred while removing a Peer from the dictionary! [REASON: {e}]")


def clear_security_params_from_peer_dict(peer_dict: dict[str, Peer]):
    """
    Clears security parameters for each peer in the peer dictionary.
    (secret, iv, mode, token, socket)

    @param peer_dict:
        A dictionary containing Peer objects

    @return: None
    """
    for peer in peer_dict.values():
        peer.socket, peer.secret, peer.iv, peer.mode, peer.token = None, None, None, None, None


def update_peer_dict(own_peer_dict: dict[str, Peer], new_peer_dict: dict[str, Peer]):
    """
    Updates the entries of own peer dictionary with another
    peer dictionary received from another peer.

    @param own_peer_dict:
        A dictionary containing Peer objects

    @param new_peer_dict:
        A dictionary containing Peer objects

    @return: None
    """
    for ip, peer in new_peer_dict.items():
        own_peer_dict[ip] = peer


def remove_all_pending_peers(peer_dict: dict[str, Peer]):
    """
    Filters peer dictionary by removing all pending peers
    and returning approved ones only.

    @param peer_dict:
        A dictionary containing Peer objects

    @return: None
    """
    for ip, peer in peer_dict.items():
        if peer.status == STATUS_PENDING:
            del peer_dict[ip]


def remove_all_approved_peers(peer_dict: dict[str, Peer]):
    """
    Filters peer dictionary by removing all approved peers
    and returning pending ones only.

    @attention Use Case:
        Used when an InvalidTokenError occurs in a newly
        approved peer (reset state)

    @param peer_dict:
        A dictionary containing Peer objects

    @return: None
    """
    for ip, peer in peer_dict.items():
        if peer.status == STATUS_APPROVED:
            del peer_dict[ip]


def save_pending_peer_info(self: object, peer_socket: socket.socket, peer_ip: str,
                           first_name: str, last_name: str, shared_secret: bytes, mode: str,
                           file_path: str, role: str, peer_iv: bytes = None):
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
    self.peer_dict[peer_ip] = Peer(ip=peer_ip, first_name=first_name, last_name=last_name, role=role,
                                   secret=shared_secret, iv=peer_iv, status=STATUS_PENDING, mode=mode,
                                   transaction_path=file_path, socket=peer_socket)


def change_peer_role(peer_dict: dict[str, Peer], ip: str, role: str):
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
        peer_dict[ip].role = role
    else:
        print("[+] CHANGE PEER ROLE ERROR: Invalid role provided!")


def change_peer_status(peer_dict: dict[str, Peer], ip: str, status: str):
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
        peer_dict[ip].status = status
    else:
        print("[+] CHANGE PEER STATUS ERROR: Invalid status provided!")


def delete_transaction(pending_transactions: list[Transaction], ip: str, request_path: str = None):
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
        to the pending peer to be removed (String - Optional)

    @return: None
    """
    if len(pending_transactions) == 0:
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
    if request_path:
        delete_file(file_path=request_path)


def add_new_transaction(self: object, peer_request: Transaction, set_stamp: bool):
    """
    Adds a new Transaction (connection request) object
    to the Node's pending_transaction list by ensuring
    no duplicates.

    @param self:
        A reference to the calling class object (Node)

    @param peer_request:
        A Transaction object

    @param set_stamp:
        A boolean flag to set the 'received_by' attribute
        of the Transaction object

    @return: None
    """
    for request in self.pending_transactions:
        if peer_request.ip_addr == request.ip_addr:
            raise RequestAlreadyExistsError(ip=peer_request.ip_addr)

    if set_stamp:
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
    transaction.set_timestamp(timestamp=get_current_timestamp(FORMAT_STRING))
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
    # Instantiate table and define title & columns
    table = PrettyTable()
    table.title = PEER_TABLE_TITLE
    table.field_names = [PEER_TABLE_FIELD_PERSON, PEER_TABLE_FIELD_IP,
                         PEER_TABLE_FIELD_CIPHER_MODE, PEER_TABLE_FIELD_SECRET,
                         PEER_TABLE_FIELD_IV, PEER_TABLE_FIELD_STATUS, PEER_TABLE_FIELD_ROLE]

    # Fill table with data
    if len(self.fd_list) > 1 or len(self.fd_pending) > 0:
        for ip, peer in self.peer_dict.items():
            table.add_row(
                [
                    process_name(peer.first_name, peer.last_name),
                    ip,
                    peer.mode.upper() if peer.mode else None,
                    hash_data(peer.secret),
                    hash_data(peer.iv),
                    peer.status,
                    peer.role
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
    connection requests and performs expiry checks.

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


def get_transaction(req_list: list[Transaction], prompt: str = None,
                    ip: str = None, for_consensus: bool = False):
    """
    Prompts the user to select a specific Transaction
    (connection request) from the pending connections
    list.

    @attention Alternative Use Case:
        Can be used to get a Transaction object without prompt
        based on IP

    @raise TransactionNotFoundError:
        If an IP is provided and a corresponding Transaction
        object is not found within the list.

    @param req_list:
        A list of Transaction (requests) objects

    @param prompt:
        A string for the printed prompt

    @param ip:
        An optional parameter to get a Transaction from the
        list (based on an IP address)

    @param for_consensus:
        An optional parameter to get a Transaction for consensus
        (which requires the checking for an initial buffer time
        before expiry for the chosen Transaction object)

    @return: req_list[index] or None
        The Transaction object if not expired; otherwise, None
    """
    if ip is not None:  # => get transaction from ip
        for transaction in req_list:
            if transaction.ip_addr == ip:
                return transaction
        raise TransactionNotFoundError(ip)

    while True:         # => get transaction from prompt
        try:
            index = int(input(prompt)) - 1  # => adjust for zero-based indexing
            if index in tuple(range(len(req_list))):
                if for_consensus:
                    return req_list[index] if not req_list[index].is_near_expiry(REQ_BUFFER_TIME_INITIAL) else None
                else:
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


def send_message_to_specific_peer(self: object):
    """
    Sends a message to a specific peer.

    @param self:
        A reference to the calling class object (Node, DelegateNode, AdminNode)

    @return: None
    """
    while True:
        peer = get_specific_peer_prompt(self, prompt=SELECT_PEER_SEND_MSG_PROMPT)
        if peer.status != STATUS_PENDING:
            break
        print("[+] SEND MESSAGE ERROR: You cannot send message to a pending peer; please try again!")

    message = input(f"[+] Enter a message to send to ({peer.ip}): ")
    send_message(peer.socket, peer.secret, peer.iv, peer.mode, message)


def send_message(sock: socket.socket, secret: bytes, iv: bytes | None, mode: str, msg: str):
    """
    Prompts user for a plaintext message, encrypts it and
    sends it to a target socket.

    @param sock:
        The target socket

    @param mode:
        A string for the encryption mode

    @param secret:
        Bytes of the shared secret

    @param iv:
        Bytes of the initialization factor (IV) or None (if mode=ECB)

    @param msg:
        A string for the message to be sent

    @return: None
    """
    if sock is not None:
        cipher_text = AES_encrypt(data=msg.encode(), mode=mode, key=secret, iv=iv)
        sock.send(cipher_text)
        print(f"[+] Your message has been successfully sent to (IP: {sock.getpeername()[0]})!")


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
    def find_latest_transaction_number(path: str = DEFAULT_TRANSACTIONS_DIR):
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

    create_directory(path=DEFAULT_TRANSACTIONS_DIR)
    new_data = obfuscate(data, shared_secret, mode, iv)

    if is_directory_empty(path=DEFAULT_TRANSACTIONS_DIR):
        file_path = os.path.join(DEFAULT_TRANSACTIONS_DIR, "request_1.json")
        write_to_file(file_path, new_data)
    else:
        latest_transaction_number = find_latest_transaction_number() + 1
        new_file_name = "request_" + str(latest_transaction_number) + ".json"
        file_path = os.path.join(DEFAULT_TRANSACTIONS_DIR, new_file_name)
        write_to_file(file_path, new_data)

    print(SAVE_TRANSACTION_SUCCESS.format(file_path))
    return file_path


def load_transactions_from_file(self: object):
    """
    Loads and decrypts Transactions (pending connection requests)
    from files within the 'data/transactions/' directory and
    stores them into a list.

    @param self:
        Reference to the calling class object (Node)

    @return: None
    """
    def extract_bytes_from_data(data: bytearray, byte_map: dict):
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
        secret = extract_bytes_from_data(data=data, byte_map=SHARED_KEY_BYTE_MAPPING)
        if mode == CBC_FLAG:
            iv = extract_bytes_from_data(data=data, byte_map=INIT_FACTOR_BYTE_MAPPING)
        return mode, secret, iv

    def restore_original_bytes(data: bytearray, mode_flag: int):
        if mode_flag == CBC_FLAG:
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

        elif mode_flag == ECB_FLAG:
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
            self.peer_dict[request.ip_addr] = Peer(ip=request.ip_addr, first_name=request.first_name,
                                                   last_name=request.last_name, secret=shared_key, iv=iv,
                                                   mode=mode, status=STATUS_PENDING, transaction_path=file_path,
                                                   role=request.role)
        else:
            os.remove(file_path)
            print(TRANSACTION_INVALID_SIG_MSG.format(request.ip_addr))
    # ===============================================================================

    # Create 'data/transactions' directory if it does not exist
    create_directory(path=DEFAULT_TRANSACTIONS_DIR)

    if not is_directory_empty(path=DEFAULT_TRANSACTIONS_DIR):
        counter = 0
        for file_name in os.listdir(DEFAULT_TRANSACTIONS_DIR):
            file_path = os.path.join(DEFAULT_TRANSACTIONS_DIR, file_name)

            if os.path.isfile(file_path):
                with open(file_path, 'rb') as file:
                    content = bytearray(file.read())  # => Create a mutable copy of file bytes

                    mode, shared_key, iv = extract_mode_secret_iv(data=content)
                    restore_original_bytes(data=content, mode_flag=mode)

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

            # Remove peer socket from pending list (prevent select-related errors)
            if peer_socket in self.fd_pending:
                self.fd_pending.remove(peer_socket)
                time.sleep(1)

            # Send encrypted rejection response, close connection and remove pending peer information
            peer_socket.send(AES_encrypt(data=RESPONSE_REJECTED.encode(), key=peer.secret, mode=peer.mode, iv=peer.iv))

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
            peer = get_peer(self.peer_dict, ip=request.ip_addr)
            if peer:
                revoke_helper(peer.socket)  # => perform if responsible peer
            else:
                delete_transaction(self.pending_transactions, ip=request.ip_addr)

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
    def is_connected_approve_helper(peer_request: Transaction):
        """
        A utility function that facilitates the approval of peers when the
        host peer is connected to the P2P network.

        @attention: How It Works
            This involves selecting an admin or delegate peer and forwarding
            a pending peer's connection request to them, so that they can initiate
            a consensus within the P2P network.

        @param peer_request:
            A Transaction object

        @return: None
        """
        from utility.client_server.client_server import send_request
        print(f"[+] Now sending request from (IP: {request.ip_addr}) to an admin or delegate; please wait...")
        selected_peer = select_admin_or_delegate_menu(admin_delegate_list=get_info_admins_and_delegates(self))

        # Send request to admin/delegate node
        if not request.is_expired():
            send_request(selected_peer.socket, selected_peer.ip, selected_peer.secret,
                         selected_peer.mode, PURPOSE_REQUEST_APPROVAL, peer_request, selected_peer.iv)

        # Delete the transaction (request) - prevent duplicates when consensus
        delete_transaction(self.pending_transactions, request.ip_addr, peer.transaction_path)
        peer.transaction_path = None
        print("[+] The selected admin/delegate will commence a consensus voting for the requesting peer shortly...")

    def not_connected_approve_helper(pending_peer_sock: socket.socket | None):
        """
        A utility helper function that handles approving peers
        when host peer is not connected to the P2P network
        (or anyone).

        @param pending_peer_sock:
            A pending peer socket object

        @return: None
        """
        print(f"[+] Now approving request for peer (IP: {request.ip_addr}); please wait...")
        print(APPROVE_NOT_CONNECTED_MSG.format(request.ip_addr))
        exceptions = (socket.error, socket.timeout, OSError, PeerRefusedBlockError,
                      PeerInvalidBlockchainError, InvalidBlockchainError)

        try:
            if pending_peer_sock is None:  # Attempt reconnection
                pending_peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                pending_peer_sock.settimeout(5)  # 5-second timeout
                pending_peer_sock.connect((request.ip_addr, APPLICATION_PORT))
                print(f"[+] Successfully reconnected to requesting peer (IP: {request.ip_addr})!")

            # Remove peer socket from pending list (prevent select-related errors)
            if pending_peer_sock in self.fd_pending:
                self.fd_pending.remove(pending_peer_sock)
                time.sleep(1)

            # Send APPROVED signal to pending peer
            pending_peer_sock.send(AES_encrypt(data=RESPONSE_APPROVED.encode(), key=peer.secret,
                                               mode=peer.mode, iv=peer.iv))

            # Wait for ACK (for synchronization)
            pending_peer_sock.recv(1024)

            # Send Status - [Not Connected]
            pending_peer_sock.send(AES_encrypt(data=STATUS_NOT_CONNECTED.encode(),
                                               key=peer.secret, mode=peer.mode, iv=peer.iv))

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
            consensus = Consensus(request=own_request, mode=MODE_INITIATOR,
                                  sock_list=temp_list, peer_dict=self.peer_dict,
                                  is_connected=False, event=self.consensus_event)
            final_decision = consensus.start()

            # Evaluate and handle the decision
            if final_decision == CONSENSUS_SUCCESS:
                print(APPROVED_PEER_MSG.format(request.ip_addr))

                # Compare application timestamp and determine who gets delegate (if not admin)
                if self.role == ROLE_PEER and request.role == ROLE_PEER:
                    is_delegate = determine_delegate_status(pending_peer_sock, self.app_timestamp,
                                                            mode=MODE_INITIATOR, enc_mode=peer.mode,
                                                            secret=peer.secret, iv=peer.iv)
                    if is_delegate:
                        print("[+] PROMOTION: You have been promoted to 'Delegate' node!")
                        self.is_promoted = True
                    else:
                        change_peer_role(self.peer_dict, ip=request.ip_addr, role=ROLE_DELEGATE)

                # Synchronize blockchain with requesting peer
                from utility.blockchain.utils import save_blockchain_to_file
                synchronize_blockchain(self, pending_peer_sock, peer.secret,
                                       enc_mode=peer.mode, mode=MODE_INITIATOR, iv=peer.iv)
                save_blockchain_to_file(self.blockchain, self.pvt_key, self.pub_key)

                # Perform finishing steps
                self.fd_list.append(pending_peer_sock)
                change_peer_status(self.peer_dict, ip=request.ip_addr, status=STATUS_APPROVED)
                delete_transaction(self.pending_transactions, request.ip_addr, peer.transaction_path)
                self.is_connected = True
                print(ESTABLISHED_NETWORK_SUCCESS_MSG.format(pending_peer_sock.getpeername()[0]))

            if final_decision == CONSENSUS_FAILURE:
                print(REQUEST_REFUSED_MSG)
                delete_transaction(self.pending_transactions, request.ip_addr, request_path=peer.transaction_path)
                remove_pending_peer(self, pending_peer_sock, ip=request.ip_addr)

        except exceptions as e:
            print(f"[+] APPROVE ERROR: An error has occurred while approving peer! [REASON: {e}]")
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
            if self.is_connected:
                peer = get_peer(self.peer_dict, ip=request.ip_addr)
                is_connected_approve_helper(request)
            else:
                peer = get_peer(self.peer_dict, ip=request.ip_addr)
                not_connected_approve_helper(peer.socket)
        else:
            print("[+] APPROVE ERROR: The selected request has expired; please try again!")


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
        from utility.client_server.utils import receive_request_handler

        # Define signals for all roles
        signals_if_admin_delegate = {
            CONSENSUS_SIGNAL: lambda: perform_consensus_signal(self, peer),
            REQUEST_APPROVAL_SIGNAL: lambda: receive_request_handler(self, peer_sock, peer_ip, peer.secret,
                                                                     peer.mode, peer.iv, save_info=False,
                                                                     save_file=False, set_stamp=False),
            REMOVE_PEER_SIGNAL: lambda: handle_kicked_peer(self, peer),
            UPDATE_NEW_PROMOTED_PEER_SIGNAL: lambda: handle_new_promoted_peer(self, peer),
        }
        signals_if_regular_peer = {
            CONSENSUS_SIGNAL: lambda: perform_consensus_signal(self, peer),
            REMOVE_PEER_SIGNAL: lambda: handle_kicked_peer(self, peer),
            PROMOTION_SIGNAL: lambda: perform_promotion(self, peer),
            UPDATE_NEW_PROMOTED_PEER_SIGNAL: lambda: handle_new_promoted_peer(self, peer),
        }

        # Grab the signal
        if self.role in (ROLE_ADMIN, ROLE_DELEGATE):
            signal = signals_if_admin_delegate.get(signal, default_action)
        else:
            signal = signals_if_regular_peer.get(signal, default_action)

        # Perform the function associate with signal
        if signal:
            signal()
    # ===============================================================================================

    # Remove socket (to prevent select interference)
    self.fd_list.remove(peer_sock)
    peer_ip = peer_sock.getpeername()[0]

    # Receive data and decrypt, then handle signal
    data = peer_sock.recv(1024)
    if data:
        peer = get_peer(self.peer_dict, ip=peer_ip)
        decrypted_signal = AES_decrypt(data=data, key=peer.secret, mode=peer.mode, iv=peer.iv).decode()
        signal_handler(signal=decrypted_signal)
        self.fd_list.append(peer_sock)
    else:
        disconnect_handler(peer_sock, self.peer_dict)


def perform_consensus_signal(self: object, peer: Peer):
    """
    Performs a consensus to vote for a specific connection request
    when invoked by a signal from an Admin/Delegate peer and performs
    follow-up tasks dependent on the result.

    @attention Responsible Peer:
        A responsible peer is one who initially received the
        connection request before sending it to an admin/delegate peer
        and have full socket connection with the requesting peer.

    @param self:
        A reference to the calling class object (Node)

    @param peer:
        The admin/delegate Peer object

    @return: None
    """
    if verify_admin_or_delegate(self.peer_dict, peer.ip):
        from utility.client_server.utils import receive_request_handler

        # Receive a connection request from admin/delegate for consensus
        request, _ = receive_request_handler(self, peer.socket, peer.ip, peer.secret, peer.mode,
                                             peer.iv, save_info=False, save_file=False, set_stamp=False)

        # Vote for the request
        from models.Consensus import Consensus
        consensus = Consensus(request=request,
                              mode=MODE_VOTER,
                              peer_socket=peer.socket,
                              peer_dict=self.peer_dict,
                              is_connected=self.is_connected,
                              event=self.consensus_event)
        final_decision = consensus.start()

        # Perform follow-up (receive token & block from admin/delegate + other tasks)
        if final_decision == CONSENSUS_SUCCESS:
            print(CONSENSUS_PEER_WIN_MSG.format(request.ip_addr))

            # Receive token and block
            token = receive_approval_token(peer.socket, peer.secret, peer.mode, peer.iv)
            new_block = receive_block(self, peer.socket, 0, peer.secret, peer.mode, peer.iv, do_add=False)

            if request.received_by == self.ip:                                          # => if responsible peer
                perform_responsible_peer_tasks(self, request, final_decision, token, new_block)
            else:
                new_peer = Peer(ip=request.ip_addr, first_name=request.first_name,
                                last_name=request.last_name, role=request.role,
                                status=STATUS_PENDING, token=token, block=new_block)
                add_peer_to_dict(self.peer_dict, new_peer)
                delete_transaction(self.pending_transactions, request.ip_addr)

        if final_decision == CONSENSUS_FAILURE:
            print(CONSENSUS_PEER_LOSE_MSG.format(request.ip_addr))
            if request.received_by == self.ip:                                          # => if responsible peer
                perform_responsible_peer_tasks(self, request, final_decision)
            else:
                delete_transaction(self.pending_transactions, request.ip_addr)
    else:
        print(f"[+] INVALID PROTOCOL [Consensus]: Insufficient privileges to start action (from peer {peer.ip})!")


def handle_kicked_peer(self: object, peer: Peer):
    """
    Handles a kicked peer (as signaled by an Admin).

    @param self:
        A reference to the calling class object (Node)

    @param peer:
        A peer object representing the AdminNode

    @return: None
    """
    if verify_admin_or_delegate(self.peer_dict, peer.ip):
        print(f"[+] Received a signal from admin (IP: {peer.ip}) to kick a peer...")
        peer.socket.send(AES_encrypt(data=ACK.encode(), key=peer.secret, mode=peer.mode, iv=peer.iv))
        kicked_peer_ip = AES_decrypt(data=peer.socket.recv(1024), key=peer.secret, mode=peer.mode, iv=peer.iv).decode()
        remove_approved_peer(self, peer_to_remove=get_peer(self.peer_dict, ip=kicked_peer_ip))
        peer.socket.send(AES_encrypt(data=ACK.encode(), key=peer.secret, mode=peer.mode, iv=peer.iv))
        print(f"[+] Peer (IP: {kicked_peer_ip}) has been removed from the P2P network!")
    else:
        print(f"[+] INVALID PROTOCOL [Kick Peer]: Insufficient privileges to start action (from peer {peer.ip})!")


def perform_promotion(self: object, peer: Peer):
    """
    Performs a promotion to delegate peer (as appointed by an AdminNode).

    @param self:
        A reference to the calling class object (Node)

    @param peer:
        A peer object representing the AdminNode

    @return: None
    """
    if verify_admin_or_delegate(self.peer_dict, peer.ip):
        print(f"[+] PROMOTION: Congratulations, you have been promoted by admin peer (IP: {peer.ip}) to delegate role!")
        peer.socket.send(AES_encrypt(data=ACK.encode(), key=peer.secret, mode=peer.mode, iv=peer.iv))
        self.is_promoted = True
    else:
        print(f"[+] INVALID PROTOCOL [Promotion]: Insufficient privileges to start action (from peer {peer.ip})!")


def handle_new_promoted_peer(self: object, peer: Peer):
    """
    Handles the newly promoted peer by updating their role to delegate,
    as signaled by an Admin.

    @param self:
        A reference to the calling class object (Node)

    @param peer:
        A peer object representing the AdminNode

    @return: None
    """
    if verify_admin_or_delegate(self.peer_dict, peer.ip):
        print(f"[+] Received a signal from admin (IP: {peer.ip}) about a newly-approved peer...")
        peer.socket.send(AES_encrypt(data=ACK.encode(), key=peer.secret, mode=peer.mode, iv=peer.iv))
        promoted_peer_ip = AES_decrypt(data=peer.socket.recv(1024), key=peer.secret, mode=peer.mode, iv=peer.iv).decode()
        change_peer_role(self.peer_dict, ip=promoted_peer_ip, role=ROLE_DELEGATE)
        peer.socket.send(AES_encrypt(data=ACK.encode(), key=peer.secret, mode=peer.mode, iv=peer.iv))
        print(f"[+] Peer (IP: {promoted_peer_ip}) has been recently promoted to delegate by admin (IP: {peer.ip})!")
    else:
        print(f"[+] INVALID PROTOCOL [Update Promoted Peer]: Insufficient privileges to start action (from peer {peer.ip})!")


def send_approval_token(peer_socket: socket.socket, token: Token, secret: bytes, mode: str, iv: bytes = None):
    """
    Sends an approval token to a selected peer.

    @raise InvalidTokenError:
        Exception is thrown if the receiving target peer sends a
        rejection after sending the token

    @param peer_socket:
        A socket object of the initiating peer

    @param token:
        The approval Token to be sent over

    @param secret:
        Bytes of the shared secret

    @param iv:
        Bytes of the initialization factor (IV)

    @param mode:
        A string representing the encryption mode (ECB or CBC)

    @return: None
    """
    print(f"[+] Sending approval token to {peer_socket.getpeername()[0]}...")

    # Set blocking (in case multiprocessing module sets to False)
    peer_socket.setblocking(True)

    # Serialize and encrypt the token
    serialized_token = pickle.dumps(token)
    encrypted_token = AES_encrypt(data=serialized_token, key=secret, mode=mode, iv=iv)

    # Send the size of the token
    size = len(encrypted_token).to_bytes(4, byteorder='big')
    peer_socket.sendall(AES_encrypt(data=size, key=secret, mode=mode, iv=iv))

    # Send the encrypted token
    peer_socket.sendall(encrypted_token)

    # Wait for results
    response = AES_decrypt(data=peer_socket.recv(1024), key=secret, mode=mode, iv=iv).decode()
    if response == ACK:
        print(SEND_TOKEN_SUCCESS.format(token.peer_ip, peer_socket.getpeername()[0]))
        return None
    else:
        raise InvalidTokenError(ip="host")  # => thrown if token that is sent is invalid


def  receive_approval_token(peer_socket: socket.socket, secret: bytes, mode: str, iv: bytes = None):
    """
    Performs the retrieval and verification of an approval token
    issued by an admin/delegate peer.

    @raise InvalidTokenError:
        Exception is thrown if the received Token contains
        an invalid signature after verifying

    @param peer_socket:
        A socket object of the initiating peer

    @param secret:
        Bytes of the shared secret

    @param iv:
        Bytes of the initialization factor (IV)

    @param mode:
        A string representing the encryption mode (ECB or CBC)

    @return: token
        A Token object
    """
    print(f"[+] Now receiving an approval token from admin/delegate (IP: {peer_socket.getpeername()[0]})...")
    peer_socket.send(AES_encrypt(data=ACK.encode(), key=secret, iv=iv, mode=mode))

    # Receive the length of the serialized data
    data = AES_decrypt(data=peer_socket.recv(BLOCK_SIZE), key=secret, mode=mode, iv=iv)
    size = int.from_bytes(data, byteorder='big')

    # Receive the token data
    serialized_data = peer_socket.recv(size)

    # Decrypt the token data
    decrypted_data = AES_decrypt(data=serialized_data, key=secret, mode=mode, iv=iv)
    token = pickle.loads(decrypted_data)

    # Verify the token
    try:
        if verify_token(token):
            peer_socket.send(AES_encrypt(data=ACK.encode(), key=secret, mode=mode, iv=iv))
            print("[+] OPERATION SUCCESS: Successfully received the approval token!")
            return token
    except InvalidTokenError:
        print(f"[+] APPROVAL REJECTED: Peer socket connection has been terminated ({peer_socket.getpeername()})")
        peer_socket.send(AES_encrypt(data=RESPONSE_REJECTED.encode(), key=secret, iv=iv, mode=mode))
        raise InvalidTokenError(ip=peer_socket.getpeername()[0])


def send_peer_dictionary(target_peer: Peer, peer_dict: dict[str, Peer]):
    """
    Sends the peer dictionary to the target peer.

    @param peer_dict:
        A peer dictionary containing Peer objects

    @param target_peer:
        The peer to send the dictionary to

    @return: None
    """
    print(f"[+] Sending peer dictionary to {target_peer.ip}...")

    # Set blocking (in case multiprocessing module sets to False)
    target_peer.socket.setblocking(True)

    # Serialize and encrypt the peer dictionary
    serialized_dict = pickle.dumps(peer_dict)
    encrypted_dict = AES_encrypt(data=serialized_dict, key=target_peer.secret, mode=target_peer.mode, iv=target_peer.iv)

    # Send size of dictionary
    size = len(encrypted_dict).to_bytes(4, byteorder='big')
    target_peer.socket.sendall(AES_encrypt(data=size, key=target_peer.secret, mode=target_peer.mode, iv=target_peer.iv))

    # Send the encrypted dictionary
    target_peer.socket.sendall(encrypted_dict)

    # Wait for ACK
    target_peer.socket.recv(1024)
    print(SEND_PEER_DICT_SUCCESS.format(target_peer.ip))


def receive_peer_dictionary(peer_socket: socket.socket, secret: bytes, iv: bytes, mode: str):
    """
    Performs the retrieval of the peer dictionary from a target peer.

    @param peer_socket:
        A socket object of the initiating peer

    @param secret:
        Bytes of the shared secret

    @param iv:
        Bytes of the initialization factor (IV)

    @param mode:
        A string representing the encryption mode (ECB or CBC)

    @return: peer_dict
        A skeleton peer dictionary containing peers within P2P network (still require info)
    """
    print(f"[+] Now receiving peer dictionary (info) from target peer (IP: {peer_socket.getpeername()[0]})...")

    # Receive the length of the serialized data
    data = AES_decrypt(data=peer_socket.recv(BLOCK_SIZE), key=secret, mode=mode, iv=iv)
    size = int.from_bytes(data, byteorder='big')

    # Receive the dictionary data
    serialized_data = peer_socket.recv(size)

    # Decrypt the dictionary data
    decrypted_data = AES_decrypt(data=serialized_data, key=secret, mode=mode, iv=iv)
    peer_dict = pickle.loads(decrypted_data)

    # Send ACK
    print("[+] OPERATION SUCCESS: Successfully received the peer dictionary!")
    peer_socket.send(AES_encrypt(data=ACK.encode(), key=secret, mode=mode, iv=iv))
    return peer_dict


def create_copy_peer_dict(self: object, own_peer_dict: dict[str, Peer], ip_to_remove: str):
    """
    Creates a copy of a peer dictionary with only approved peers,
    and security parameters cleared.

    @attention Use Case:
        This is used by a responsible peer when sending over a
        filtered copy of their own peer dictionary

    @attention Security Params:
        They encompass the shared secret, initialization factor (IV),
        socket, approval token, and encryption mode

    @param self:
        A reference to the calling class object (Node, AdminNode, DelegateNode)

    @param own_peer_dict:
        Host's own peer dictionary containing Peer objects

    @param ip_to_remove:
        A string for the IP to remove from dictionary

    @return: copy_dict
    """
    copy_dict = {}
    for ip, peer in own_peer_dict.items():
        if peer.status == STATUS_APPROVED and peer.ip != ip_to_remove:      # => Exclude any pending peers + new peer
            copy_peer = Peer(ip=peer.ip, first_name=peer.first_name,
                             last_name=peer.last_name, role=peer.role,
                             status=peer.status)
            copy_dict[ip] = copy_peer

    own_self = Peer(ip=self.ip, first_name=self.first_name,                 # => add yourself to the copy dict
                    last_name=self.last_name, role=self.role,
                    status=STATUS_APPROVED)
    copy_dict[self.ip] = own_self
    return copy_dict


def perform_responsible_peer_tasks(self: object, request: Transaction, consensus_result: str,
                                   token: Token = None, block: Block = None):
    """
    Performs tasks of a responsible peer.

    @attention What is a Responsible Peer?
        A responsible peer is one who initially received the
        Transaction object and only has the socket connection
        with the requesting peer; thus, they're in-charge of
        helping them set up after being approved.

    @param self:
        A reference to the calling class object (Node, AdminNode, DelegateNode)

    @param request:
        A Transaction object

    @param consensus_result:
        A string representing the consensus result (CONSENSUS_SUCCESS, CONSENSUS_FAILURE)

    @param token:
        An approval Token object (optional; used if CONSENSUS_SUCCESS)

    @param block:
        An approval Block object issued for the approved peer (optional; used if CONSENSUS_SUCCESS)

    @return: None
    """
    if consensus_result == CONSENSUS_SUCCESS:
        # Responsible peers already have pending peer in dictionary (from initial request)
        pending_peer = get_peer(self.peer_dict, request.ip_addr)
        pending_peer.token = token
        pending_peer.block = block

        # Remove peer socket from pending list (prevent select-related errors)
        if pending_peer.socket in self.fd_pending:
            self.fd_pending.remove(pending_peer.socket)
            time.sleep(1)

        # Send approved signal and is_connected status
        pending_peer.socket.send(AES_encrypt(data=RESPONSE_APPROVED.encode(), key=pending_peer.secret,
                                             mode=pending_peer.mode, iv=pending_peer.iv))
        pending_peer.socket.recv(1024)
        pending_peer.socket.send(AES_encrypt(data=STATUS_CONNECTED.encode(), key=pending_peer.secret,
                                             mode=pending_peer.mode, iv=pending_peer.iv))

        # Wait for ACK
        pending_peer.socket.recv(1024)

        # Sync your blockchain with the pending peer
        synchronize_blockchain(self, pending_peer.socket, pending_peer.secret, pending_peer.mode,
                               MODE_INITIATOR, pending_peer.iv, do_init=False)

        # Send token to the pending peer
        send_approval_token(peer_socket=pending_peer.socket, token=token, secret=pending_peer.secret,
                            mode=pending_peer.mode, iv=pending_peer.iv)

        # Send block to pending peer
        send_block(pending_peer.socket, block, pending_peer.secret, enc_mode=pending_peer.mode,
                   iv=pending_peer.iv, do_wait=True)

        # Create a copy of own peer dictionary (exclude security info)
        copy_dict = create_copy_peer_dict(self, own_peer_dict=self.peer_dict, ip_to_remove=pending_peer.ip)

        # Send the copy of the peer dictionary over
        send_peer_dictionary(target_peer=pending_peer, peer_dict=copy_dict)
        del copy_dict

        # Await for final ACK (to ensure pending peer has completed initialization tasks)
        pending_peer.socket.settimeout(180)  # => 3 minutes
        try:
            pending_peer.socket.recv(1024)
            pending_peer.status = STATUS_APPROVED
            pending_peer.token, pending_peer.block = None, None
            self.fd_list.append(pending_peer.socket)
            self.blockchain.add_block(new_block=block)
            if self.blockchain.is_valid():
                from utility.blockchain.utils import save_blockchain_to_file
                save_blockchain_to_file(self.blockchain, self.pvt_key, self.pub_key)
            delete_transaction(self.pending_transactions, request.ip_addr, pending_peer.transaction_path)
        except socket.timeout as e:
            print(f"ERROR: An error has occurred while waiting for peer to complete initialization tasks [REASON: {e}]")

    if consensus_result == CONSENSUS_FAILURE:
        pending_peer = get_peer(self.peer_dict, request.ip_addr)

        if pending_peer.socket in self.fd_pending:
            self.fd_pending.remove(pending_peer.socket)
            time.sleep(1)

        pending_peer.socket.send(AES_encrypt(data=RESPONSE_REJECTED.encode(), key=pending_peer.secret,
                                             mode=pending_peer.mode, iv=pending_peer.iv))
        remove_pending_peer(self, pending_peer.socket, pending_peer.ip)
        delete_transaction(self.pending_transactions, request.ip_addr, pending_peer.transaction_path)


def synchronize_blockchain(self: object, peer_sock: socket.socket, secret: bytes, enc_mode: str, mode: str,
                           iv: bytes = None, initiators_request: Transaction = None, peer_request: Transaction = None,
                           do_init: bool = True):
    """
    Synchronizes the blockchain by exchanging blockchain info with the
    target peer to determine whether individual blocks should be sent
    to allow the peer to sync with the network blockchain or send the
    entire blockchain.

    @attention Use Case:
        When two non-connected peers join one another

    @attention: Different Scenarios
        1) Target peer does not have a blockchain and must receive one
        2) Target peer does have a blockchain, and must receive remaining blocks
           to sync up with network
        3) Target peer does have a blockchain that belongs to a different local P2P network
           and must receive an entire new blockchain in order to join the target network

    @param self:
        A reference to the calling class object (Node, AdminNode, DelegateNode)

    @param peer_sock:
        A socket object

    @param secret:
        Bytes containing the shared secret

    @param enc_mode:
        The encryption mode (CBC or ECB)

    @param mode:
        A string determining the receiver or initiator

    @param iv:
        Bytes of the initialization factor IV (optional)

    @param initiators_request:
        The initiating peer's request (required for init blocks)

    @param peer_request:
        The request of the requesting peer (required for init blocks)

    @param do_init:
        A boolean flag to turn on the creation of init blocks for two
        non-connected peers that create a network together
        (default = True)

    @return: None
    """
    def create_init_blocks(request_1: Transaction, request_2: Transaction):
        """
        Creates two blocks that include both the initiator
        and requester as they initialize to create a new
        P2P network.

        @attention Use Case:
            Only used to synchronize the blockchains between
            two non-connected peers when they want to connect
            to each other

        @return: tuple(block_1, block_2)
        """
        block_1 = Block(ip=request_1.ip_addr, first_name=request_1.first_name,
                        last_name=request_1.last_name, public_key=self.pub_key)
        block_1.set_image(request_1.image)
        block_2 = Block(ip=request_2.ip_addr, first_name=request_2.first_name,
                        last_name=request_2.last_name, public_key=self.pub_key)
        block_2.set_image(request_2.image)
        return block_1, block_2

    def add_init_blocks(mode: str, is_sending: bool = False, response_check: bool = False):
        """
        Performs the addition of two init blocks to the blockchain
        which denotes two non-connected peers have joined the network
        together.

        @attention What are Init Blocks?:
            They're blocks that contain information of both peers
            when they're both not connected to a local P2P network
            and want to establish/start a network together

        @param mode:
            A string to denote whether the calling class should
            receive or initiate the addition of init blocks process

        @param is_sending:
            A boolean to determine if to send the init blocks (default=False)

        @param response_check:
            A boolean to turn on response check from peer (default=False)

        @return: None
        """
        if mode == MODE_INITIATOR:  # => sender
            from utility.node.admin_utils import sign_block
            for init_block in create_init_blocks(initiators_request, peer_request):
                sign_block(self, new_block=init_block,
                           new_index=self.blockchain.get_latest_block().index + 1,
                           previous_hash=self.blockchain.get_latest_block().hash)
                self.blockchain.add_block(init_block)

                if is_sending:
                    send_block(peer_sock, self.blockchain.get_latest_block(), secret, enc_mode, iv)

                if response_check:
                    response = AES_decrypt(data=peer_sock.recv(1024), key=secret, mode=enc_mode, iv=iv).decode()
                    if response == ACK:
                        print(f"[+] BLOCK RECEIVED: Block {init_block.index} has been successfully received!")
                    elif response == ERROR_BLOCK:
                        raise PeerRefusedBlockError(init_block)
                    elif response == ERROR_BLOCKCHAIN:
                        raise PeerInvalidBlockchainError

        if mode == MODE_RECEIVER:  # => receiver
            try:
                for i in range(2):
                    receive_block(self, peer_sock, self.blockchain.get_latest_block().index + 1, secret, enc_mode, iv)
            except (InvalidBlockError, InvalidBlockchainError) as error:
                raise error
    # =================================================================================================
    print(f"[+] Now synchronizing blockchain with (IP: {peer_sock.getpeername()[0]})...")
    if mode == MODE_INITIATOR:

        # SCENARIO 1: You have a blockchain
        if self.blockchain:
            print("[+] BLOCKCHAIN FOUND: An existing blockchain is found in your system!")
            peer_sock.send(AES_encrypt(data=HAS_BLOCKCHAIN_SIGNAL.encode(), key=secret, mode=enc_mode, iv=iv))
            peer_status = AES_decrypt(data=peer_sock.recv(1024), key=secret, mode=enc_mode, iv=iv).decode()

            if peer_status == HAS_BLOCKCHAIN_SIGNAL:  # => A) Both have an existing blockchain
                print("[+] The requesting peer has an existing blockchain, now determining how many blocks to send...")

                # Exchange blockchain current index
                own_index = self.blockchain.get_latest_block().index
                peer_current_block_idx = exchange_blockchain_index(self, peer_sock, secret, enc_mode, iv, mode=MODE_INITIATOR)

                # a) Compare block index (requesting peer is behind in blocks)
                if own_index > peer_current_block_idx:
                    print(f"[+] Peer is missing {own_index - peer_current_block_idx} blocks; now sending...")
                    try:
                        for i in range(peer_current_block_idx, (own_index + 1)):
                            block = self.blockchain.get_specific_block(i)
                            send_block(peer_sock, block, secret, enc_mode, iv)

                            # Await response before sending the next block
                            response = AES_decrypt(data=peer_sock.recv(1024), key=secret, mode=enc_mode, iv=iv).decode()

                            if response == ACK:
                                print(f"[+] BLOCK SUCCESSFULLY RECEIVED: Block {i} has been successfully received!")
                                continue

                            if response == ERROR_BLOCK:  # => error in sent block (close connection)
                                raise PeerRefusedBlockError(block)

                            if response == ERROR_BLOCKCHAIN:  # => peer has an invalid blockchain (close connection)
                                raise PeerInvalidBlockchainError

                        # Once target peer's blockchain is valid, add init blocks to blockchain & send each to target
                        if do_init:
                            add_init_blocks(mode=MODE_INITIATOR, is_sending=True, response_check=True)

                        print("[+] SYNCHRONIZATION SUCCESSFUL: Your blockchain has been successfully synchronized with peer!")
                        return None
                    except (PeerRefusedBlockError, PeerInvalidBlockchainError) as error:
                        raise error

                # b) Compare block index (requesting peer has the same number of blocks)
                elif peer_current_block_idx == own_index:
                    print("[+] The peer is up-to-date with their blockchain; now sending two initialization blocks...")
                    try:
                        if do_init:
                            add_init_blocks(mode=MODE_INITIATOR, is_sending=True, response_check=True)
                        else:
                            compare_latest_hash(self, peer_sock, secret, enc_mode, iv, mode=MODE_INITIATOR)
                        print("[+] SYNCHRONIZATION SUCCESSFUL: Your blockchain has been successfully synchronized with peer!")
                        return None
                    except (PeerRefusedBlockError, PeerInvalidBlockchainError) as err:
                        raise err

                # c) Compare block index (requesting peer has the more blocks == invalid blockchain)
                else:
                    print("[+] SYNCHRONIZATION FAILED: The requesting peer has a blockchain that belongs to another network!")
                    raise PeerInvalidBlockchainError

            if peer_status == NO_BLOCKCHAIN_SIGNAL:     # => B) Requesting peer has no blockchain
                try:
                    print("[+] BLOCKCHAIN REQUESTED: The requesting peer has no blockchain!")
                    if do_init:
                        add_init_blocks(mode=MODE_INITIATOR, is_sending=False, response_check=False)
                    send_blockchain(self, peer_sock, secret, enc_mode, iv)
                    print("[+] SYNCHRONIZATION SUCCESSFUL: Your blockchain has been successfully synchronized with peer!")
                    return None
                except PeerInvalidBlockchainError as e:
                    raise e

        # SCENARIO 2: You have no blockchain
        else:
            print("[+] MISSING BLOCKCHAIN: No blockchain was detected in your current system!")
            peer_sock.send(AES_encrypt(data=NO_BLOCKCHAIN_SIGNAL.encode(), key=secret, mode=enc_mode, iv=iv))
            peer_status = AES_decrypt(data=peer_sock.recv(1024), key=secret, mode=enc_mode, iv=iv).decode()

            if peer_status == HAS_BLOCKCHAIN_SIGNAL:  # receive blockchain from the other peer
                print("[+] BLOCKCHAIN REQUESTED: The requesting peer has an existing blockchain!")
                try:
                    self.blockchain = receive_blockchain(peer_sock, secret, enc_mode, iv)
                    print("[+] SYNCHRONIZATION SUCCESSFUL: Your blockchain has been successfully synchronized with peer!")
                    return None
                except InvalidBlockchainError as e:
                    raise e

            if peer_status == NO_BLOCKCHAIN_SIGNAL:  # start a new blockchain
                print("[+] The requesting peer also has no blockchain; now creating a new blockchain for the network...")
                try:
                    self.blockchain = Blockchain()
                    add_init_blocks(mode=MODE_INITIATOR, is_sending=False, response_check=False)
                    send_blockchain(self, peer_sock, secret, enc_mode, iv)
                    print("[+] SYNCHRONIZATION SUCCESSFUL: Your blockchain has been successfully synchronized with peer!")
                    return None
                except PeerInvalidBlockchainError as e:
                    raise e

    if mode == MODE_RECEIVER:
        # Wait for target peer's blockchain status
        peer_status = AES_decrypt(data=peer_sock.recv(1024), key=secret, mode=enc_mode, iv=iv).decode()

        if peer_status == HAS_BLOCKCHAIN_SIGNAL:
            print("[+] The target peer has an existing blockchain, now determining how many blocks to receive...")

            # SCENARIO 1: You and the target peer have a blockchain
            if self.blockchain:  # => If you have a blockchain already, exchange block index
                peer_sock.send(AES_encrypt(data=HAS_BLOCKCHAIN_SIGNAL.encode(), key=secret, mode=enc_mode, iv=iv))

                # Exchange blockchain current index
                own_index = self.blockchain.get_latest_block().index
                peer_current_block_idx = exchange_blockchain_index(self, peer_sock, secret, enc_mode, iv, mode=MODE_RECEIVER)

                # a) Compare block index (target peer has more blocks -> receive blocks to catch up)
                if peer_current_block_idx > own_index:
                    print(f"[+] You are missing {own_index - peer_current_block_idx} blocks; now receiving...")
                    try:
                        for index in range(own_index, (peer_current_block_idx + 1)):
                            receive_block(self, peer_sock, index, secret, enc_mode, iv)

                        # Once the blockchain is in sync, receive two init blocks and add to blockchain
                        if do_init:
                            add_init_blocks(mode=MODE_RECEIVER)

                        print("[+] SYNCHRONIZATION SUCCESSFUL: Blockchain has been successfully synchronized with peer!")
                        return None
                    except (InvalidBlockError, InvalidBlockchainError) as error:  # => closes connection
                        raise error

                # b) Compare block index (target peer has the same number of blocks)
                elif own_index == peer_current_block_idx:
                    print("[+] Your blockchain is up-to-date; now receiving two initialization blocks...")
                    try:
                        if do_init:
                            add_init_blocks(mode=MODE_RECEIVER)
                        else:
                            compare_latest_hash(self, peer_sock, secret, enc_mode, iv, mode=MODE_RECEIVER)
                        print("[+] SYNCHRONIZATION SUCCESSFUL: Your blockchain has been successfully synchronized with peer!")
                        return None
                    except (InvalidBlockError, InvalidBlockchainError) as error:  # => closes connection
                        raise error

                else:  # If you have more blocks than target peer, then close connection
                    print("[+] SYNCHRONIZATION FAILED: You have a blockchain that belongs to another network!")
                    raise InvalidBlockchainError(reason="You have a blockchain that belongs to another network!")

            # SCENARIO 2: Target peer has a blockchain and you do not
            else:
                print("[+] MISSING BLOCKCHAIN: No blockchain was detected in your current system!")
                peer_sock.send(AES_encrypt(data=NO_BLOCKCHAIN_SIGNAL.encode(), key=secret, mode=enc_mode, iv=iv))
                try:
                    print("[+] BLOCKCHAIN REQUESTED: You have requested for the target peer's blockchain!")
                    self.blockchain = receive_blockchain(peer_sock, secret, enc_mode, iv)
                    print("[+] SYNCHRONIZATION SUCCESSFUL: Your blockchain has been successfully synchronized with peer!")
                    return None
                except InvalidBlockchainError as error:
                    raise error

        if peer_status == NO_BLOCKCHAIN_SIGNAL:
            if self.blockchain:
                print("[+] BLOCKCHAIN FOUND: An existing blockchain is found in your system!")
                peer_sock.send(AES_encrypt(data=HAS_BLOCKCHAIN_SIGNAL.encode(), key=secret, mode=enc_mode, iv=iv))
                try:
                    print("[+] BLOCKCHAIN REQUESTED: The target peer has no blockchain!")
                    if do_init:
                        add_init_blocks(mode=MODE_INITIATOR, is_sending=False, response_check=False)
                    send_blockchain(self, peer_sock, secret, enc_mode, iv)
                    print(
                        "[+] SYNCHRONIZATION SUCCESSFUL: Your blockchain has been successfully synchronized with peer!")
                    return None
                except PeerInvalidBlockchainError as e:
                    raise e

            else:
                peer_sock.send(AES_encrypt(data=NO_BLOCKCHAIN_SIGNAL.encode(), key=secret, mode=enc_mode, iv=iv))
                print("[+] The target peer also has no blockchain; now waiting for a new blockchain initialization...")
                try:
                    self.blockchain = receive_blockchain(peer_sock, secret, enc_mode, iv)
                    print("[+] SYNCHRONIZATION SUCCESSFUL: Your blockchain has been successfully synchronized with peer!")
                    return None
                except InvalidBlockchainError as e:
                    raise e


def obfuscate(data: bytes, shared_secret: bytes, mode: str, iv: bytes = None):
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

    def add_mode_flag(transaction_data: bytearray, mode_map: tuple, replaced_bytes: bytearray):
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

    data_array = bytearray(data)                # Transaction data
    secret_array = bytearray(shared_secret)     # Shared Secret
    original_bytes = bytearray()                # Replaced Bytes

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
