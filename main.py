"""
Description:
This Python file executes the program.

"""
import socket
import time

from models.Node import Node
from utility.constants import CONNECTION_AWAIT_TIMEOUT_MSG

if __name__ == '__main__':
    client_socket = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('10.0.0.74', 323))
        s.listen(5)

        client_socket, addr = s.accept()
        client_socket.settimeout(10)
        print(f"[+] Accepted connection from {addr}")

        while True:
            data = client_socket.recv(1024)
            if not data:
                client_socket.close()
                print("[+] Client disconnected; connection has been closed!")
            print(data.decode())
            time.sleep(10)

    except socket.timeout:  # => Client disconnection
        print(CONNECTION_AWAIT_TIMEOUT_MSG)
        client_socket.close()

    except (socket.error, ConnectionResetError, BrokenPipeError) as e:  # => Server Disconnection (due to error)
        print(f"[+] Connection closed (REASON: {e})")
        client_socket.close()
