import threading
import time


def worker(some_event: threading.Event):
    print("[+] WORKER: Doing some work...")
    some_event.set()
    time.sleep(5)
    some_event.clear()
    print("[+] WORKER: Done!")


if __name__ == '__main__':
    event = threading.Event()
    thread = threading.Thread(target=worker, args=(event,))
    thread.start()

    while True:
        time.sleep(1)

        while event.is_set():
            event.wait(timeout=1)

        print("[+] MAIN: Doing work in main thread...")
