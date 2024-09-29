import pickle
from multiprocessing.queues import Queue
from app.api.APIServer import EVENT_ONCONNECT


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
    while True:
        event = self.queue.get()  # => a hanging call

        if event == EVENT_ONCONNECT:
            print("[+] EVENT: Front-end has just connected to the websocket; sending initialization data...")
            if self.blockchain:
                queue.put(pickle.dumps(self.blockchain))
                print("[+] Data has been successfully sent!")
            else:
                queue.put(None)
