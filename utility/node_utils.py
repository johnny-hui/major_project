"""
Description:
This Python file contains utility functions for the Node class.

"""
import os
import pickle
import socket
from prettytable import PrettyTable
from models.CustomCipher import CustomCipher
from models.Transaction import Transaction
from utility.aes_utils import AES_decrypt
from utility.constants import (MENU_TITLE, MENU_FIELD_OPTION, MENU_FIELD_DESC, MENU_OPTIONS_CONNECTED, MENU_OPTIONS,
                               CONNECTION_INFO_TITLE, CONNECTION_INFO_FIELD_NAME,
                               CONNECTION_INFO_FIELD_IP, CONNECTION_INFO_FIELD_CIPHER_MODE,
                               CONNECTION_INFO_FIELD_SECRET, CONNECTION_INFO_FIELD_IV,
                               ROLE_DELEGATE, DELEGATE_MENU_OPTIONS, ROLE_ADMIN, ADMIN_MENU_OPTIONS, ROLE_PEER, CBC,
                               INIT_FACTOR_BYTE_MAPPING,
                               MODE_CBC_BYTE_MAPPING, MODE_ECB_BYTE_MAPPING, SHARED_KEY_BYTE_MAPPING,
                               SAVE_TRANSACTIONS_DIR,
                               SAVE_TRANSACTION_SUCCESS, CBC_FLAG, ECB_FLAG, ECB, TRANSACTION_INVALID_SIG_MSG,
                               TRANSACTION_EXPIRED_MSG)
from utility.utils import create_directory, is_directory_empty, write_to_file


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


def view_current_connections(self: object):
    """
    Displays information of all current connections.

    @param self:
        A reference to the calling class object

    @return: None
    """
    # Instantiate table and define title & columns
    table = PrettyTable()
    table.title = CONNECTION_INFO_TITLE
    table.field_names = [CONNECTION_INFO_FIELD_NAME, CONNECTION_INFO_FIELD_IP,
                         CONNECTION_INFO_FIELD_CIPHER_MODE, CONNECTION_INFO_FIELD_SECRET,
                         CONNECTION_INFO_FIELD_IV]

    # Fill table with data
    if len(self.fd_list) > 1:
        for ip, information in self.client_dict.items():  # Format: (Name, IP, Mode, Shared Secret, IV)
            table.add_row([information[0], ip, information[3].upper(), information[1],
                           information[2].hex() if information[2] else None])
        print(table)
    else:
        print("[+] VIEW CURRENT CONNECTIONS: There are no current connections to view!")


def close_application(self: object):
    """
    Terminates the application by setting a termination flag to
    end all current threads.

    @param self:
        A reference to the calling class object

    @return: None
    """
    print("[+] CLOSE APPLICATION: Now closing the application...")
    self.terminate = True  # Set a terminate flag to terminate all threads
    print("[+] Application has been successfully terminated!")


def send_message(sock: socket.socket, cipher: CustomCipher):
    """
    Prompts user for a plaintext message, encrypts it
    and sends it to a target socket.

    @param sock:
        The target socket

    @param cipher:
        A CustomCipher object

    @return: None
    """
    if sock is not None:
        ip = sock.getpeername()[0]
        message = input(f"[+] Enter a message to send to ({ip}): ")
        cipher_text = cipher.encrypt(message)
        sock.send(cipher_text)
        print("[+] Your message has been successfully sent!")


def get_specific_peer(self: object, prompt: str):
    """
    Prompts user to choose a specific peer to
    send a message to.

    @param self:
        A reference to the calling class object

    @param prompt:
        A string containing the prompt

    @return: tuple(socket, shared_secret, iv)
        A tuple containing the client socket, shared secret and
        the initialization vector
    """
    if len(self.fd_list) > 1:
        view_current_connections(self)

        while True:
            try:
                # Prompt user selection for a specific client
                client_index = int(input(prompt.format(1, len(self.client_dict))))

                while client_index not in range(1, (len(self.client_dict) + 1)):
                    print("[+] ERROR: Invalid selection range; please enter again.")
                    client_index = int(input(prompt.format(1, len(self.client_dict))))

                # Get information of the client (from dictionary)
                ip, info = list(self.client_dict.items())[client_index - 1]
                name = info[0]

                # Iterate over the list of sockets and find the corresponding one
                for sock in self.fd_list[1:]:
                    if sock.getpeername()[0] == ip:
                        return sock, ip, name, None  # TODO: Define return info for peer

            except (ValueError, TypeError) as e:
                print(f"[+] ERROR: An invalid selection provided ({e}); please enter again.")
    else:
        print("[+] ERROR: There are currently no connected peers to perform the selected option!")
        return None, None, None, None


def obfuscate(data: bytes, shared_secret: bytes,
              mode: str, iv: bytes = None):
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

    data_array = bytearray(data)  # Transaction data
    secret_array = bytearray(shared_secret)  # Shared Secret
    original_bytes = bytearray()  # Replaced Bytes

    # ===============================================================================

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


def save_transaction(data: bytes, shared_secret: bytes,
                     mode: str, iv: bytes = None):
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

    @return: None
    """

    def find_latest_transaction_number(path: str = SAVE_TRANSACTIONS_DIR):
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

    create_directory(path=SAVE_TRANSACTIONS_DIR)
    new_data = obfuscate(data, shared_secret, mode, iv)

    if is_directory_empty(path=SAVE_TRANSACTIONS_DIR):
        file_path = os.path.join(SAVE_TRANSACTIONS_DIR, "request_1.json")
        write_to_file(file_path, new_data)
    else:
        latest_transaction_number = find_latest_transaction_number() + 1
        new_file_name = "request_" + str(latest_transaction_number) + ".json"
        file_path = os.path.join(SAVE_TRANSACTIONS_DIR, new_file_name)
        write_to_file(file_path, new_data)

    print(SAVE_TRANSACTION_SUCCESS.format(file_path))


def load_transactions(self: object):
    """
    Loads and decrypts Transactions (pending connection requests)
    from files within the 'data/transactions/' directory and
    stores them into a list.

    @param self:
        Reference to the calling class object

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
            self.pendingTransactions.append(transaction)
        else:
            os.remove(file_path)
            print(TRANSACTION_INVALID_SIG_MSG.format(request.ip_addr))

    # ===============================================================================

    if not is_directory_empty(path=SAVE_TRANSACTIONS_DIR):
        counter = 0
        for file_name in os.listdir(SAVE_TRANSACTIONS_DIR):
            file_path = os.path.join(SAVE_TRANSACTIONS_DIR, file_name)

            if os.path.isfile(file_path):
                with open(file_path, 'rb') as file:
                    content = bytearray(file.read())

                    mode, shared_key, iv = extract_mode_secret_iv(data=content)
                    restore_original_bytes(data=content, mode=mode)

                    if mode == CBC_FLAG:
                        decrypted_data = AES_decrypt(data=content[:-33], key=shared_key, mode=CBC, iv=iv)
                    else:
                        decrypted_data = AES_decrypt(data=content[:-17], key=shared_key, mode=ECB)

                    transaction = pickle.loads(decrypted_data)
                    process_transaction(request=transaction)

        print(f"[+] OPERATION SUCCESS: {counter} pending connection requests have been successfully "
              f"verified and loaded!")
