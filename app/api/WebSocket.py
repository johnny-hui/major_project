import logging
import pickle
import threading
from multiprocessing import Process, Queue
from flask import Flask
from flask_socketio import SocketIO

from app.api.utility import monitor_node_events

# CONSTANTS
LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 5000
EVENT_ONCONNECT = "onConnect"
EVENT_BLOCKCHAIN_REQUEST = "blockchainRequest"


class WebSocket(Process):
    """
    A class that runs a Websocket API server for the Node class.

    @attention Use Case:
        This API server is only used to handle requests (events)
        from a front-end UI application and relay them to the Node
        class to perform P2P functions.

        Since loopback IP is used, no external data can be
        received or sent to the API server except for the
        localhost who is using the front-end UI.

    Attributes:
        app - A Flask application object
        front_queue - A queue used to handle front-end requests and propagate them to the Node class
        back_queue - A queue used to listen to and receive Node events and propagate them to the front-end
        ip_addr - The ip address of the node
        port - The port of the node
    """
    def __init__(self, front_queue: Queue, back_queue: Queue, ip: str,
                 first_name: str, last_name: str, role: str):
        """
        A constructor for a Flask API server.
        """
        super().__init__()
        self.app = Flask(__name__)
        self.ip = ip
        self.first_name = first_name
        self.last_name = last_name
        self.role = role
        self.front_queue = front_queue
        self.back_queue = back_queue
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        logging.getLogger('werkzeug').setLevel(logging.WARNING)

    def run(self):
        """
        Overrides the run() function from Process class.
        """

        # Define listening events from frontend
        @self.socketio.on('connect')
        def handle_onConnect():
            try:
                # Send event to Node class using Queues
                self.front_queue.put(EVENT_ONCONNECT)

                # Wait for response from Node class
                response = self.front_queue.get()

                # Handle response
                if response:
                    user = pickle.loads(response)
                    self.socketio.emit('init_data', user.to_json())
                else:
                    self.socketio.emit('init_data', "None")
            except TypeError:
                pass

        @self.socketio.on('request_blockchain_data')
        def handle_blockchainRequest():
            try:
                self.front_queue.put(EVENT_BLOCKCHAIN_REQUEST)
                response = self.front_queue.get()
                if response:
                    blockchain = pickle.loads(response)
                    self.socketio.emit('blockchain_data', blockchain.to_json())
                else:
                    self.socketio.emit('blockchain_data', "None")
            except TypeError:
                pass

        print("[+] WebsocketIO has started; now listening for front-end requests...")
        self.__start_monitor_node_events_thread()
        self.socketio.run(self.app, host=LOCAL_HOST, port=LOCAL_PORT, allow_unsafe_werkzeug=True)

    def __start_monitor_node_events_thread(self):
        """
        Starts a thread that monitors back-end events from the Node class.
        @return: None
        """
        thread = threading.Thread(target=monitor_node_events, args=(self,))
        thread.daemon = True
        thread.start()
