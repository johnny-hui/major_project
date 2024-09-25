"""
Description:
This Python file provides utility functions for the DelegateNode class.

"""
import time
from models.Block import Block
from models.Consensus import Consensus
from utility.client_server.blockchain import send_block
from utility.crypto.token_utils import generate_approval_token
from utility.general.constants import INITIATE_CONSENSUS_PROMPT, CONSENSUS_SELECT_REQUEST_PROMPT, MODE_INITIATOR, \
    CONSENSUS_SUCCESS, CONSENSUS_SUCCESS_TOKEN_MSG, SEND_TOKEN_MULTIPROCESS_MSG, STATUS_PENDING, CONSENSUS_FAILURE, \
    CONSENSUS_PEER_LOSE_MSG, CONSENSUS_REQ_NEAR_EXPIRY_MSG, SEND_BLOCK_MULTIPROCESS_MSG
from utility.general.utils import perform_cleanup, get_user_command_option, transfer_items_to_list, \
    set_blocking_all_sockets, start_parallel_operation
from utility.node.admin_utils import sign_block
from utility.node.node_utils import view_pending_connection_requests, get_transaction, send_approval_token, \
    perform_responsible_peer_tasks, add_peer_to_dict, delete_transaction


def promotion_preparation(node: object):
    """
    Prepares existing Node data for transfer to Delegate
    Node (due to promotion).

    @param node:
        A reference to the Node object to be promoted

    @return: attributes
        A list of tuples containing the class attribute name
        and its value prior to promotion
    """
    attributes = [(attribute, value) for attribute, value in vars(node).items()]
    return attributes


def get_delegate_node(old_node: object):
    """
    A factory method to create a DelegateNode from a
    promoted regular Node.

    @param old_node:
        An instance of the promoted regular Node

    @return: DelegateNode
        A DelegateNode instance
    """
    from models.DelegateNode import DelegateNode
    original_attributes = promotion_preparation(node=old_node)
    perform_cleanup(old_node)
    return DelegateNode(original_data=original_attributes)


def initiate_consensus(self: object):
    """
    Initiates a consensus vote on a pending connection request
    among others in the network.

    @param self:
        A reference to the calling class object (AdminNode, DelegateNode)

    @return: None
    """
    if len(self.pending_transactions) == 0:
        print("[+] INITIATE CONSENSUS ERROR: There are currently no pending connection requests to approve!")
        return None

    if not self.is_connected:
        print("[+] INITIATE CONSENSUS ERROR: You are not currently connected to a P2P network!")
        return None

    # Print current Transactions and get a specific Transaction from the List
    view_pending_connection_requests(self, do_prompt=False)
    command = get_user_command_option(opt_range=tuple(range(2)), prompt=INITIATE_CONSENSUS_PROMPT)

    if command == 0:
        return None

    if command == 1:
        request = get_transaction(req_list=self.pending_transactions,
                                  prompt=CONSENSUS_SELECT_REQUEST_PROMPT.format(len(self.pending_transactions)),
                                  for_consensus=True)
        if request:
            temp_list = []
            transfer_items_to_list(_to=temp_list, _from=self.fd_list, idx_start=1)  # idx=1 to ignore own socket
            time.sleep(1.2)  # => wait for select() in main thread to see the changes

            # Start consensus among other approved peers in the network
            consensus = Consensus(request=request,
                                  mode=MODE_INITIATOR,
                                  sock_list=temp_list,
                                  peer_dict=self.peer_dict,
                                  is_connected=True,
                                  event=self.consensus_event)
            final_decision = consensus.start()

            # Set all sockets to blocking mode
            set_blocking_all_sockets(temp_list)

            # Perform final tasks depending on the decision
            try:
                if final_decision == CONSENSUS_SUCCESS:
                    print(CONSENSUS_SUCCESS_TOKEN_MSG)
                    token = generate_approval_token(self.pvt_key, self.pub_key, request.ip_addr)

                    # Process peer info for parallel sending of token (multiprocessing)
                    peer_info_list = []
                    for sock in temp_list:
                        peer = self.peer_dict[sock.getpeername()[0]]
                        peer_info_list.append((peer.socket, token, peer.secret, peer.mode, peer.iv))

                    # Send token to all connected peers (in parallel)
                    start_parallel_operation(task=send_approval_token,
                                             task_args=peer_info_list,
                                             num_processes=len(peer_info_list),
                                             prompt=SEND_TOKEN_MULTIPROCESS_MSG)

                    # Create and sign a new block
                    new_block = Block(ip=request.ip_addr, first_name=request.first_name,
                                      last_name=request.last_name, public_key=self.pub_key)
                    sign_block(self, new_block,
                               new_index=self.blockchain.get_latest_block().index + 1,
                               previous_hash=self.blockchain.get_latest_block().hash)

                    # Process peer info for parallel sending of the block (multiprocessing)
                    peer_info_list = []
                    for sock in temp_list:
                        peer = self.peer_dict[sock.getpeername()[0]]
                        peer_info_list.append((peer.socket, new_block, peer.secret, peer.mode, peer.iv, True))

                    # Send the new block to all connected peers (in parallel)
                    start_parallel_operation(task=send_block,
                                             task_args=peer_info_list,
                                             num_processes=len(peer_info_list),
                                             prompt=SEND_BLOCK_MULTIPROCESS_MSG)

                    # Perform finishing tasks
                    if request.received_by == self.ip:
                        perform_responsible_peer_tasks(self, request, final_decision, token, new_block)
                    else:
                        from models.Peer import Peer
                        new_peer = Peer(ip=request.ip_addr, first_name=request.first_name,
                                        last_name=request.last_name, role=request.role,
                                        status=STATUS_PENDING, token=token, block=new_block)
                        add_peer_to_dict(self.peer_dict, new_peer)
                        delete_transaction(self.pending_transactions, request.ip_addr)

                if final_decision == CONSENSUS_FAILURE:
                    print(CONSENSUS_PEER_LOSE_MSG.format(request.ip_addr))
                    if request.received_by == self.ip:
                        perform_responsible_peer_tasks(self, request, final_decision)
                    else:
                        delete_transaction(self.pending_transactions, request.ip_addr)
            finally:
                transfer_items_to_list(_to=self.fd_list, _from=temp_list)  # => Re-add sockets back to fd_list
                time.sleep(1.2)
                set_blocking_all_sockets(self.fd_list)
                print("[+] OPERATION COMPLETE: A consensus has been completed!")
        else:
            print(CONSENSUS_REQ_NEAR_EXPIRY_MSG)
            delete_transaction(self.pending_transactions, request.ip_addr)
