"""
Description:
This Python file contains initialization functions for
the Node class.

"""
import getopt
import ipaddress
import socket
import sys
from _socket import SO_REUSEADDR
from ssl import SOL_SOCKET
from utility.constants import (INVALID_SRC_IP_ARG_ERROR, MIN_PORT_VALUE,
                               MAX_PORT_VALUE, INVALID_SRC_PORT_RANGE, INVALID_FORMAT_SRC_PORT_ARG_ERROR)


def parse_arguments():
    """
    Parse the command line for arguments.

    @return name, src_ip, src_port:
        Strings containing name, source IP address and source port
    """
    # Initialize variables
    name, is_client, src_ip, src_port = "", "", "", ""
    arguments = sys.argv[1:]
    opts, user_list_args = getopt.getopt(arguments, 'n:s:p:')

    if len(opts) == 0:
        sys.exit("[+] INIT ERROR: No arguments were provided!")

    for opt, argument in opts:
        if opt == '-n':  # For name
            name = argument

        if opt == '-s':  # For source IP
            try:
                src_ip = str(ipaddress.ip_address(argument))
            except ValueError as e:
                sys.exit(INVALID_SRC_IP_ARG_ERROR.format(e))

        if opt == '-p':  # For source port
            try:
                src_port = int(argument)
                if not (MIN_PORT_VALUE <= src_port < MAX_PORT_VALUE):
                    sys.exit(INVALID_SRC_PORT_RANGE)
            except ValueError as e:
                sys.exit(INVALID_FORMAT_SRC_PORT_ARG_ERROR.format(e))

    # Check if parameters are provided
    if len(name) == 0:
        sys.exit("[+] INIT ERROR: A name was not provided! (-n option)")
    if len(src_ip) == 0:
        sys.exit("[+] INIT ERROR: A source IP was not provided! (-s option)")
    if len(str(src_port)) == 0:
        sys.exit("[+] INIT ERROR: A source port was not provided! (-p option)")

    return name, src_ip, src_port


def initialize_socket(ip: str, port: int):
    """
    Creates and initializes a Socket object.

    @param ip:
        The IP address of the Node

    @param port:
        The port number of the Node

    @return: sock
        The target socket
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock.bind((ip, port))
        sock.listen(5)  # Listen for incoming connections (maximum 5 clients in the queue)
        print(f"[+] Socket has been initialized and is now listening on {ip} | (Port {port})")
        return sock
    except socket.error as e:
        sys.exit("[+] INIT ERROR: An error has occurred while creating socket object ({})".format(e))
