"""
Description:
This python file contains utility functions used by
the larger functions in client_server.py

"""
import multiprocessing
import socket
from utility.constants import (APPLICATION_PORT, FIND_HOST_TIMEOUT,
                               CONNECTION_TIMEOUT_ERROR, CONNECTION_ERROR)
from utility.node.node_utils import peer_exists


def _connect_to_target_peer(ip: str,
                            port: int = APPLICATION_PORT,
                            timeout: int = FIND_HOST_TIMEOUT,
                            stop_event: multiprocessing.Event = None,
                            verbose: bool = True):
    """
    Connects to a target peer using socket connection.

    @attention stop_event (Use Case):
        Exclusively used for parallel host search

    @param ip:
        The IP address of the target peer

    @param port:
        The port number of the target peer (default = 323)

    @param timeout:
        An integer (in seconds) before a connection
        timeout is thrown

    @param stop_event:
        A multiprocessing event signal used to signal other processes
        executing function to stop if target host found
        (Optional; default = None)

    @param verbose:
        A boolean to switch on verbose mode (default=True)

    @return: target_sock or None
        A target socket object if successful; otherwise None
    """
    try:
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.settimeout(timeout)

        if stop_event is not None and stop_event.is_set():
            return None

        print(f"[+] Now attempting to connect to IP: {ip}...")
        target_sock.connect((ip, port))  # a hanging function

        if stop_event is not None:
            stop_event.set()

        print(f"[+] CONNECTION EVENT: An available peer has been found ({ip}, {port})!")
        target_sock.setblocking(True)
        return target_sock
    except socket.timeout:
        print(CONNECTION_TIMEOUT_ERROR.format(ip)) if verbose else None
        return None
    except (socket.error, OSError):
        print(CONNECTION_ERROR.format(ip, port)) if verbose else None
        return None


def _generate_new_ip_from_octet(host_ip: str, new_octet: int):
    """
    Generates a new IP address from the host machine's
    IP address by replacing the last octet.
    (Ex: 10.0.0.123 -> 10.0.0.321)

    @param host_ip:
        A string for the host machine's IP address (and subnet mask)

    @param new_octet:
        An integer representing the octet to be added

    @return: new_ip
        A string for the new IP address
    """
    octets = host_ip.split('.')
    octets[-1] = str(new_octet)
    new_ip = '.'.join(octets)
    return new_ip


def _perform_iterative_host_search(peer_dict: dict, host_ip: str,
                                   event: multiprocessing.Event,
                                   start: int, end: int):
    """
    A utility function that iteratively attempts to find an
    available host (based on a given start & end octet range).

    @param peer_dict:
        A dictionary containing peer information

    @param host_ip:
        A string for the host machine's IP address (and subnet mask)

    @param event:
        A process-shared flag that is used to signal to other
        processes to stop if a target host is found

    @param start:
        An integer for the IP octet to start from

    @param end:
        An integer for the IP octet to end at

    @return: peer_sock or None
        The target peer socket object (if connected); otherwise None
    """
    for octet in range(start, end + 1):
        target_ip = _generate_new_ip_from_octet(host_ip, octet)

        if target_ip != host_ip and not peer_exists(peer_dict, target_ip):
            peer_sock = _connect_to_target_peer(ip=target_ip, port=APPLICATION_PORT,
                                                stop_event=event, verbose=False)
            if peer_sock is not None:
                return peer_sock
