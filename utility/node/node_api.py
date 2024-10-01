import pickle
from multiprocessing.queues import Queue
from app.api.APIServer import EVENT_ONCONNECT, EVENT_BLOCKCHAIN_REQUEST
from models.Peer import Peer


def monitor_websocket_events(self: object, queue: Queue):
    """
    Monitors and handles websocket events through a Flask API
    server using thread-safe queues.

    @param self:
        A reference to the calling class object

    @param queue:
        A multiprocessing.Queue object

    @return: None
    """
    while not self.is_promoted:
        if self.terminate is True:
            break

        # Get event from API server
        if not self.queue.empty():
            event = self.queue.get()

            # Listen for Connect Request (on connect)
            if event == EVENT_ONCONNECT:
                print("[+] EVENT: Front-end has just connected to the websocket; sending initialization data...")
                user = Peer(ip=self.ip, first_name=self.first_name,
                            last_name=self.last_name, role=self.role,
                            status=self.is_connected)
                queue.put(pickle.dumps(user))
                print("[+] OPERATION COMPLETED: Data has been successfully sent!")

            # Listen for Blockchain Request
            if event == EVENT_BLOCKCHAIN_REQUEST:
                print("[+] EVENT: Front-end requested blockchain data, now sending data...")
                if self.blockchain:
                    queue.put(pickle.dumps(self.blockchain))
                    print("[+] OPERATION COMPLETED: Data has been successfully sent!")
                else:
                    queue.put(None)
