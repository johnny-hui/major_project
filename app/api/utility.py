"""
Description:
This python file is responsible for providing the WebSocket process
with functions that allow it to interact with the Node class.

"""
import json
import pickle
import time
from queue import Empty

# EVENT CONSTANTS
EVENT_NODE_SEND_BLOCKCHAIN = "sendBlockchain"
EVENT_NODE_ADD_BLOCK = "addBlock"
EVENT_NODE_ADD_PENDING_PEER = "addPendingPeer"
EVENT_NODE_ADD_APPROVED_PEER = "addApprovedPeer"
EVENT_NODE_REMOVE_PENDING_PEER = "remPendingPeer"
EVENT_NODE_REMOVE_APPROVED_PEER = "remApprovedPeer"


def monitor_node_events(self: object):
    """
    Monitors and handles events generated from the Node class and
    propagates any data over to front-end application (via. websockets).

    @attention Usage:
        This function is used only by the WebSocket class to
        monitor Node events

    @param self:
        A reference to the calling class object (WebSocket)

    @return: None
    """
    while True:
        try:
            event = self.back_queue.get()

            # Listen for Send Blockchain Event
            if event == EVENT_NODE_SEND_BLOCKCHAIN:
                response = self.back_queue.get()
                if response:
                    blockchain = pickle.loads(response)
                    self.socketio.emit('blockchain_data', blockchain.to_json())
                else:
                    self.socketio.emit('blockchain_data', "None")

            # Listen for Add New Block Event
            elif event == EVENT_NODE_ADD_BLOCK:
                response = self.back_queue.get()
                if response:
                    block = pickle.loads(response)
                    self.socketio.emit('add_block', json.dumps(block.to_dict()))
                else:
                    self.socketio.emit('add_block', "None")

            # Listen for New Pending Peer Event
            elif event == EVENT_NODE_ADD_APPROVED_PEER:
                response = self.back_queue.get()
                approved_peer = pickle.loads(response)
                self.socketio.emit('new_approved_peer', approved_peer)

            # Listen for Remove Pending Peer Event
            elif event == EVENT_NODE_REMOVE_APPROVED_PEER:
                ip_to_remove = self.back_queue.get()
                self.socketio.emit('remove_approved_peer', ip_to_remove)

            # Listen for New Pending Peer Event
            elif event == EVENT_NODE_ADD_PENDING_PEER:
                response = self.back_queue.get()
                pending_peer = pickle.loads(response)
                self.socketio.emit('new_pending_peer', pending_peer)

            # Listen for Remove Pending Peer Event
            elif event == EVENT_NODE_REMOVE_PENDING_PEER:
                ip_to_remove = self.back_queue.get()
                self.socketio.emit('remove_pending_peer', ip_to_remove)

        except Empty:
            time.sleep(0.1)
