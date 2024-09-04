import select
import socket
import sys
import threading
from utility.general.constants import NODE_INIT_MSG, NODE_INIT_SUCCESS_MSG, USER_INPUT_THREAD_NAME, \
    USER_INPUT_START_MSG, \
    INPUT_PROMPT, MIN_MENU_ITEM_VALUE, MAX_MENU_ITEM_VALUE, SELECT_CLIENT_SEND_MSG_PROMPT, \
    ROLE_PEER, MONITOR_PENDING_PEERS_THREAD_NAME, MONITOR_PENDING_PEERS_START_MSG, APPLICATION_PORT, \
    ACCEPT_PEER_HANDLER_THREAD_NAME, PEER_ACTIVITY_HANDLER_THREAD_NAME, ROLE_DELEGATE, DELEGATE_MIN_MENU_ITEM_VALUE, \
    DELEGATE_MAX_MENU_ITEM_VALUE, ROLE_ADMIN, ADMIN_MAX_MENU_ITEM_VALUE, ADMIN_MIN_MENU_ITEM_VALUE
from utility.crypto.ec_keys_utils import generate_keys
from utility.client_server.client_server import (accept_new_peer_handler,
                                                 connect_to_P2P_network,
                                                 approved_peer_activity_handler)
from utility.node.node_init import parse_arguments, initialize_socket, get_current_timestamp
from utility.node.node_utils import (display_menu, view_current_peers, close_application, send_message,
                                     get_specific_peer_info, get_user_menu_option, monitor_pending_peers,
                                     load_transactions, view_pending_connection_requests, approve_connection_request,
                                     revoke_connection_request)


class Node:
    """
    A class representing a P2P Node.

    Attributes:
        ip - The ip address
        port - The port number (default=323)
        name - The name of the Node
        role - The role of the Node (default=PEER)
        mode - A string for the encryption mode (default=ECB)
        own_socket - The socket object for the Node
        pvt_key - The private key generated by ECDH (via. brainpoolP256r1)
        pub_key - The public key generated by ECDH (via. brainpoolP256r1)
        fd_list - A list of file descriptors to monitor (using select() function)
        fd_pending - A list that stores sockets of pending peers awaiting consensus
        peer_dict - A dictionary containing information about each connected peer
        pending_transactions - A list containing pending Transaction objects of requesting peers
        app_timestamp - A string containing the timestamp (from NTP Server) of when the Node application was started
        is_connected - A boolean flag indicating whether the Node is connected
        is_promoted - A boolean flag indicating whether the Node is promoted to DelegateNode
        terminate - A boolean flag that determines if the server should terminate
    """
    def __init__(self):
        """
        A constructor for the Node class object.
        """
        print(NODE_INIT_MSG)
        self.first_name, self.last_name, self.mode, self.ip = parse_arguments()
        self.port = APPLICATION_PORT
        self.role = ROLE_PEER
        self.own_socket = initialize_socket(self.ip, self.port)
        self.pvt_key, self.pub_key = generate_keys()
        self.fd_list = [self.own_socket]  # => Monitored by select()
        self.fd_pending = []  # => Stores pending peer sockets awaiting consensus (waiting room)
        self.peer_dict = {}  # => Format {IP: [f_name, l_name, shared_secret, IV, cipher mode, status, file_path, role]}
        self.pending_transactions = []
        self.app_timestamp = get_current_timestamp()
        self.is_connected = False
        self.is_promoted = False
        self.terminate = False
        load_transactions(self)
        print(f"[+] Application Timestamp: {self.app_timestamp}")
        print(NODE_INIT_SUCCESS_MSG.format(self.role))

    def start(self):
        """
        Starts the Node and monitors/listens for any
        incoming connection requests and messages from
        new and existing peers.

        @return: None
        """
        def __start_socket_handler_thread(target_sock: socket.socket, handler, thread_name: str):
            """
            Handles each socket activity on a new thread.
            @return: None
            """
            thread = threading.Thread(target=handler, args=(self, target_sock), name=thread_name)
            thread.start()
        # =========================================================================================
        self.__start_user_menu_thread()
        self.__start_monitor_pending_peers_thread()

        while not self.is_promoted:
            if self.terminate is True:
                break

            readable, _, _ = select.select(self.fd_list, [], [], 1)

            for sock in readable:
                if sock is self.own_socket:
                    __start_socket_handler_thread(target_sock=self.own_socket,
                                                  handler=accept_new_peer_handler,
                                                  thread_name=ACCEPT_PEER_HANDLER_THREAD_NAME)
                else:
                    __start_socket_handler_thread(target_sock=sock,
                                                  handler=approved_peer_activity_handler,
                                                  thread_name=PEER_ACTIVITY_HANDLER_THREAD_NAME)

    def __start_user_menu_thread(self):
        """
        Starts a thread for handling user input
        for the menu.
        @return: None
        """
        role_menu_values = {
            ROLE_PEER: (MIN_MENU_ITEM_VALUE, MAX_MENU_ITEM_VALUE),
            ROLE_DELEGATE: (DELEGATE_MIN_MENU_ITEM_VALUE, DELEGATE_MAX_MENU_ITEM_VALUE),
            ROLE_ADMIN: (ADMIN_MIN_MENU_ITEM_VALUE, ADMIN_MAX_MENU_ITEM_VALUE)
        }

        thread = threading.Thread(target=self._menu,
                                  args=(role_menu_values.get(self.role)),
                                  name=USER_INPUT_THREAD_NAME)
        thread.start()
        print(USER_INPUT_START_MSG)

    def __start_monitor_pending_peers_thread(self):
        """
        Stores and monitors pending peers and their
        corresponding socket objects for any timeouts
        or disconnections.

        @return: None
        """
        thread = threading.Thread(target=monitor_pending_peers, args=(self,),
                                  name=MONITOR_PENDING_PEERS_THREAD_NAME)
        thread.start()
        print(MONITOR_PENDING_PEERS_START_MSG)

    def _menu(self, min_menu_value: int, max_menu_value: int):
        """
        Displays the menu and handles user input
        using stdin and select().

        @param min_menu_value:
            An integer for the minimum menu value allowed

        @param max_menu_value:
            An integer for the maximum menu value allowed

        @return: None
        """
        inputs = [sys.stdin]
        print("=" * 100)
        display_menu(role=self.role, is_connected=self.is_connected)
        print(INPUT_PROMPT)

        while not self.is_promoted:
            if self.terminate is True:
                print("=" * 100)
                break

            readable, _, _ = select.select(inputs, [], [], 1)

            # Get User Command from the Menu and perform the task
            for fd in readable:
                if fd == sys.stdin:
                    command = get_user_menu_option(fd, min_menu_value, max_menu_value)
                    self._handle_command(command, max_menu_value)


    def _handle_command(self, command: int, max_menu_value: int):
        """
        Handles and performs user menu command options.

        @param command:
            An integer representing the menu option
            to be performed

        @param max_menu_value:
            An integer for the maximum menu value allowed

        @return: None
        """
        def send_message_to_specific_peer():
            client_sock, _, secret, iv, mode = get_specific_peer_info(self, prompt=SELECT_CLIENT_SEND_MSG_PROMPT)
            send_message(client_sock, mode, secret, iv)

        def perform_post_action_steps():
            if command == max_menu_value:  # If terminate application, don't print the menu again
                return None
            display_menu(role=self.role, is_connected=self.is_connected)
            print(INPUT_PROMPT)
        # ===============================================================================================

        # Define Actions
        actions_when_not_connected = {
            1: lambda: connect_to_P2P_network(self),
            2: lambda: approve_connection_request(self),
            3: lambda: revoke_connection_request(self),
            4: lambda: None,
            5: lambda: view_pending_connection_requests(self),
            6: lambda: view_current_peers(self),
            7: lambda: close_application(self)
        }
        actions_when_connected = {
            1: lambda: send_message_to_specific_peer(),
            2: lambda: approve_connection_request(self),
            3: lambda: None,
            4: lambda: None,
            5: lambda: view_pending_connection_requests(self),
            6: lambda: view_current_peers(self),
            7: lambda: close_application(self),
        }

        # Grab action
        if self.is_connected and len(self.fd_list) > 1:
            action = actions_when_connected.get(command)
        else:
            action = actions_when_not_connected.get(command)

        # Perform action
        if action:
            action()
            perform_post_action_steps()
