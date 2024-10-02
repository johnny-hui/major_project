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


def monitor_node_events(self: object):
    """
    Monitors and handles events generated from the Node class and
    propagates any data over to front-end application (via. websockets).

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

        except Empty:
            time.sleep(0.1)
