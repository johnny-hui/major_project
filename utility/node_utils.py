"""
Description:
This Python file contains utility functions for the Node class
"""
import socket

from prettytable import PrettyTable

from models.CustomCipher import CustomCipher
from utility.constants import MENU_TITLE, MENU_FIELD_OPTION, MENU_FIELD_DESC, MENU_OPTIONS_CONNECTED, \
    MENU_OPTIONS, CONNECTION_INFO_TITLE, CONNECTION_INFO_FIELD_NAME, \
    CONNECTION_INFO_FIELD_IP, CONNECTION_INFO_FIELD_CIPHER_MODE, CONNECTION_INFO_FIELD_SECRET, CONNECTION_INFO_FIELD_IV, \
    ROLE_DELEGATE, DELEGATE_MENU_OPTIONS, ROLE_ADMIN, ADMIN_MENU_OPTIONS, ROLE_PEER


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


def get_specific_client(self: object, prompt: str):
    """
    Prompts user to choose a specific client to
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
        view_current_connections(self, is_server=True)

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
        print("[+] ERROR: There are currently no connected clients to perform the selected option!")
        return None, None, None, None
