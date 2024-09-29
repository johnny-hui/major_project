import logging
import pickle
from multiprocessing import Process, Queue
from flask import Flask
from flask_socketio import SocketIO

# CONSTANTS
LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 5000
EVENT_ONCONNECT = "onConnect"

class WebSocket(Process):
    """
    A class that runs an API server and WebSocket for the Node class
    in a separate process.

    @attention Use Case:
        This API server is only used to handle requests (events)
        from a front-end UI application and relay them to the Node
        class to perform P2P functions.

        Since loopback IP is used, no external data can be
        received or sent to the API server except for the
        localhost who is using the front-end UI.

    Attributes:
        app - A Flask application object
        user_queue - A queue used to handle front-end requests to the Node class, wait, receive
                     and send data back to front-end UI
        node_queue - A queue used to listen to and receive Node events and store the response in memory
                     for front-end calls
        ip_addr - The ip address of the node
        port - The port of the node
    """
    def __init__(self, queue: Queue, ip: str, first_name: str, last_name: str, role: str):
        """
        A constructor for a Flask API server.
        """
        super().__init__()
        self.app = Flask(__name__)
        self.ip = ip
        self.first_name = first_name
        self.last_name = last_name
        self.role = role
        self.queue = queue
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        logging.getLogger('werkzeug').setLevel(logging.WARNING)

    def run(self):
        """
        Overrides the run() function from Process class.
        """

        # Define APIs
        @self.socketio.on('connect')
        def handle_onConnect():
            # Send event to Node class using Queues
            self.queue.put(EVENT_ONCONNECT)

            # Wait for response from Node class
            response = self.queue.get()

            # Handle response
            if response:
                blockchain = pickle.loads(response)
                self.socketio.emit('blockchain_data', blockchain.to_json())
            else:
                self.socketio.emit('blockchain_data', "None")

        print("[+] WebsocketIO has started; now listening for front-end requests...")
        self.socketio.run(self.app, host=LOCAL_HOST, port=LOCAL_PORT, allow_unsafe_werkzeug=True)
