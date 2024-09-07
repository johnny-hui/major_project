from models.Node import Node
from utility.client_server.client_server import connect_to_P2P_network
from utility.general.constants import (ROLE_DELEGATE, SELECT_CLIENT_SEND_MSG_PROMPT, INPUT_PROMPT,
                                       NODE_INIT_SUCCESS_MSG, NODE_INIT_MSG)
from utility.node.node_utils import (get_specific_peer_info, send_message, close_application, display_menu,
                                     approve_connection_request, revoke_connection_request,
                                     view_pending_connection_requests, view_current_peers)


class DelegateNode(Node):
    """
    A class representing a P2P Delegate Node.

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
    def __init__(self, original_data: list):
        """
        A constructor for the DelegateNode class object.

        @param original_data:
            A list of the original class attributes from
            Node class before promotion
        """
        print(NODE_INIT_MSG)
        self._set_attributes_from_old_node(original_data)
        self.role = ROLE_DELEGATE
        self.is_promoted = False
        print(NODE_INIT_SUCCESS_MSG.format(self.role))

    def _handle_command(self, command: int, max_menu_value: int):
        """
        An override function that handles and performs user
        menu command options (as a Delegate).

        @param command:
            An integer representing the menu option
            to be performed

        @return: None
        """
        def send_message_to_specific_peer():
            client_sock, _, secret, iv, mode = get_specific_peer_info(self, prompt=SELECT_CLIENT_SEND_MSG_PROMPT)
            send_message(client_sock, mode, secret, iv)

        def perform_post_action_steps():
            actions_list = actions_when_connected if self.is_connected else actions_when_not_connected
            if command == len(actions_list):
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
            2: lambda: print("[+] Broadcast a message"),
            3: lambda: print("[+] Initiate consensus"),
            4: lambda: revoke_connection_request(self),
            5: lambda: None,
            6: lambda: view_pending_connection_requests(self),
            7: lambda: view_current_peers(self),
            8: lambda: close_application(self)
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

    def _set_attributes_from_old_node(self, original_data: list):
        for attr_name, value in original_data:
            setattr(self, attr_name, value)
