import multiprocessing
import select
import socket
import sys
import threading
from app.api.APIServer import WebSocket
from models.Peer import Peer
from utility.blockchain.utils import load_blockchain_from_file, view_blockchain
from utility.client_server.client_server import accept_new_peer_handler, connect_to_P2P_network
from utility.crypto.ec_keys_utils import generate_keys
from utility.general.constants import (NODE_INIT_MSG, NODE_INIT_SUCCESS_MSG, USER_INPUT_THREAD_NAME,
                                       USER_INPUT_START_MSG,
                                       INPUT_PROMPT, MIN_MENU_ITEM_VALUE, MAX_MENU_ITEM_VALUE, ROLE_PEER,
                                       MONITOR_PENDING_PEERS_THREAD_NAME, MONITOR_PENDING_PEERS_START_MSG,
                                       APPLICATION_PORT, ACCEPT_PEER_HANDLER_THREAD_NAME,
                                       PEER_ACTIVITY_HANDLER_THREAD_NAME,
                                       ROLE_DELEGATE, DELEGATE_MIN_MENU_ITEM_VALUE, DELEGATE_MAX_MENU_ITEM_VALUE,
                                       ROLE_ADMIN, ADMIN_MAX_MENU_ITEM_VALUE, ADMIN_MIN_MENU_ITEM_VALUE, FORMAT_STRING,
                                       MONITOR_APPROVAL_TOKENS_START_MSG, MONITOR_APPROVAL_TOKENS_THREAD_NAME,
                                       WEBSOCKET_THREAD_NAME)
from utility.node.node_api import monitor_websocket_events
from utility.node.node_init import parse_arguments, initialize_socket, get_current_timestamp
from utility.node.node_utils import (display_menu, view_current_peers, close_application, get_user_menu_option,
                                     monitor_pending_peers, load_transactions_from_file,
                                     view_pending_connection_requests,
                                     approve_connection_request, revoke_connection_request,
                                     approved_peer_activity_handler,
                                     monitor_peer_approval_token_expiry, send_message_to_specific_peer)


class Node:
    """
    A class representing a P2P Node.

    Attributes:
        ip - The ip address
        port - The port number (default=323)
        first_name - The first name of the Node user
        last_name - The last name of the Node user
        blockchain - A list of Block objects (default=None)
        role - The role of the Node (default=PEER)
        mode - A string for the encryption mode (default=ECB)
        own_socket - The socket object for the Node
        pvt_key - The private key generated by ECDH (via. brainpoolP256r1)
        pub_key - The public key generated by ECDH (via. brainpoolP256r1)
        fd_list - A list of file descriptors to monitor (using select() function)
        fd_pending - A list that stores sockets of pending peers awaiting consensus
        peer_dict - A dictionary containing information about each peer (APPROVED and PENDING)
        pending_transactions - A list containing pending Transaction objects of requesting peers
        app_timestamp - A string containing the timestamp (from NTP Server) of when the Node application was started
        consensus_event - A threading Event object that is used to communicate with main thread when consensus starts/ends
        is_connected - A boolean flag indicating whether the Node is connected
        is_promoted - A boolean flag indicating whether the Node is promoted to DelegateNode
        terminate - A boolean flag that determines if the server should terminate
        app_flag = A boolean flag that determines if the Node should be initialized to run an API server
    """
    def __init__(self):
        """
        A constructor for the Node class object.
        """
        print("=" * 100)
        print(NODE_INIT_MSG)
        self.first_name, self.last_name, self.mode, self.ip, self.app_flag = parse_arguments()
        self.blockchain = None
        self.port = APPLICATION_PORT
        self.role = ROLE_PEER
        self.pvt_key, self.pub_key = generate_keys()
        self.own_socket = initialize_socket(self.ip, self.port)
        self.fd_list = [self.own_socket]  # => Stores approved peer sockets
        self.fd_pending = []  # => Stores pending peer sockets awaiting consensus (waiting room)
        self.peer_dict: dict[str, Peer] = {}  # => Format {IP: [Peer Objects]}
        self.pending_transactions = []
        self.app_timestamp = get_current_timestamp(FORMAT_STRING)
        self.consensus_event = threading.Event()
        self.is_connected, self.is_promoted, self.terminate = False, False, False
        if self.app_flag:
            self.queue = multiprocessing.Queue()
            self.socketIO = WebSocket(self.queue, self.ip, self.first_name, self.last_name, self.role)
        self.__load_initial_data()

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
            thread.daemon = True
            thread.start()
        # =========================================================================================
        self.__print_role_message()
        self.__print_app_timestamp()
        self.__start_monitor_pending_peers_thread()
        self.__start_monitor_peers_with_approved_tokens_thread()
        self.__start_user_menu_thread()

        # Starts websocket (for front-end app)
        self.__start_websocket() if self.app_flag else None

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
        Starts a thread for handling user input for the menu.
        @return: None
        """
        role_menu_values = {
            ROLE_PEER: (MIN_MENU_ITEM_VALUE, MAX_MENU_ITEM_VALUE),
            ROLE_DELEGATE: (DELEGATE_MIN_MENU_ITEM_VALUE, DELEGATE_MAX_MENU_ITEM_VALUE),
            ROLE_ADMIN: (ADMIN_MIN_MENU_ITEM_VALUE, ADMIN_MAX_MENU_ITEM_VALUE)
        }
        thread = threading.Thread(target=self.__menu,
                                  args=(role_menu_values.get(self.role)),
                                  name=USER_INPUT_THREAD_NAME)
        thread.daemon = True
        thread.start()
        print(USER_INPUT_START_MSG)

    def __start_monitor_pending_peers_thread(self):
        """
        Starts a thread that stores and monitors pending peers and their
        corresponding socket objects for any timeouts or disconnections.

        @return: None
        """
        thread = threading.Thread(target=monitor_pending_peers, args=(self,),
                                  name=MONITOR_PENDING_PEERS_THREAD_NAME)
        thread.daemon = True
        thread.start()
        print(MONITOR_PENDING_PEERS_START_MSG)

    def __start_monitor_peers_with_approved_tokens_thread(self):
        """
        Starts a thread that monitors all pending peers that have been
        issued approval tokens to the network and checks if they have
        been expired.

        @attention Check Interval:
            Every 3 minutes

        @return: None
        """
        thread = threading.Thread(target=monitor_peer_approval_token_expiry,
                                  args=(self, threading.Event()),
                                  name=MONITOR_APPROVAL_TOKENS_THREAD_NAME)
        thread.daemon = True
        thread.start()
        print(MONITOR_APPROVAL_TOKENS_START_MSG)

    def __start_websocket(self):
        """
        Starts a thread that monitors the API server for any requests
        from the front-end React application and handles them
        appropriately.

        @attention: Note
            This is similar to the user menu, but user commands are
            executed using API requests from the front-end app

        @return: None
        """
        self.socketIO.start()
        thread = threading.Thread(target=monitor_websocket_events,
                                  args=(self, self.queue),
                                  name=WEBSOCKET_THREAD_NAME)
        thread.daemon = True
        thread.start()
        print("[+] A websocket thread has been started to monitor front-end UI events!")

    def __menu(self, min_menu_value: int, max_menu_value: int):
        """
        Displays the menu and handles user input
        using stdin and select().

        @param min_menu_value:
            An integer for the minimum menu value allowed

        @param max_menu_value:
            An integer for the maximum menu value allowed

        @return: None
        """
        print("=" * 100)
        display_menu(role=self.role, is_connected=self.is_connected)
        print(INPUT_PROMPT)

        while not self.is_promoted:
            if self.terminate is True:
                print("=" * 100)
                break

            # If consensus event, then wait until cleared (to prevent menu input interference)
            while self.consensus_event.is_set():
                self.consensus_event.wait(timeout=1)

            readable, _, _ = select.select([sys.stdin], [], [], 1)

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
        def perform_post_action_steps():
            if command == max_menu_value:  # => If terminate application, don't print the menu again
                return None
            display_menu(role=self.role, is_connected=self.is_connected)
            print(INPUT_PROMPT)
        # ===============================================================================================

        # Define Actions
        actions_when_not_connected = {
            1: lambda: connect_to_P2P_network(self),
            2: lambda: approve_connection_request(self),
            3: lambda: revoke_connection_request(self),
            4: lambda: view_blockchain(self),
            5: lambda: view_pending_connection_requests(self),
            6: lambda: view_current_peers(self),
            7: lambda: close_application(self)
        }
        actions_when_connected = {
            1: lambda: send_message_to_specific_peer(self),
            2: lambda: approve_connection_request(self),
            3: lambda: revoke_connection_request(self),
            4: lambda: view_blockchain(self),
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

    def __load_initial_data(self):
        """
        Loads transactions and blockchain data from files.
        @return: None
        """
        load_transactions_from_file(self)
        load_blockchain_from_file(self)

    def __print_role_message(self):
        """
        Prints a message based on the node's role.
        @return: None
        """
        role_message = NODE_INIT_SUCCESS_MSG.format(self.role)
        print(role_message)

    def __print_app_timestamp(self):
        """
        Prints the timestamp of when the application has started.

        @attention Use Case:
            The app's timestamp is used to resolve a stalemate when two
            peers that are not yet connected to a network connect with
            each other, determining who gets to become the DelegateNode.

        @return:
        """
        print(f"[+] Application Timestamp: {self.app_timestamp}")