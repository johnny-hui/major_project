"""
Description:
This python file is responsible for providing a websocket interface
to the Node and all of its children classes to enable them to
communicate with the front-end application.

"""
import pickle
import time
from multiprocessing import Queue
from app.api.WebSocket import EVENT_ONCONNECT, EVENT_BLOCKCHAIN_REQUEST
from models.Peer import Peer


def websocket_interface(self: object):
    """
    Monitors and handles websocket events through a Flask API
    server using thread-safe queues.

    @param self:
        A reference to the calling class object

    @return: None
    """
    while not self.is_promoted:
        if self.terminate is True:
            break

        # Monitor front queue for front-end events
        if not self.front_queue.empty():
            event = self.front_queue.get()

            # Listen for Connect Request (on connect)
            if event == EVENT_ONCONNECT:
                print("[+] EVENT: Front-end has just connected to the websocket; sending initialization data...")
                user = Peer(ip=self.ip, first_name=self.first_name,
                            last_name=self.last_name, role=self.role,
                            status=self.is_connected)
                self.front_queue.put(pickle.dumps(user))
                print("[+] OPERATION COMPLETED: Data has been successfully sent!")

            # Listen for Blockchain Request
            if event == EVENT_BLOCKCHAIN_REQUEST:
                print("[+] EVENT: Front-end requested blockchain data, now sending data...")
                if self.blockchain:
                    self.front_queue.put(pickle.dumps(self.blockchain))
                    print("[+] OPERATION COMPLETED: Data has been successfully sent!")
                else:
                    self.front_queue.put(None)
                    print("[+] OPERATION COMPLETED: Data has been successfully sent!")


def send_event_to_websocket(queue: Queue, event: str, data: bytes):
    """
    Sends an event to invoke the Websocket API server to handle and propagate
    event data to the front-end application.

    @param queue:
        A multiprocessing.Queue() object (used for IPC)

    @param event:
        A string for the event

    @param data:
        Event data (bytes)

    @return: None
    """
    queue.put(event)
    time.sleep(1)
    queue.put(data)
