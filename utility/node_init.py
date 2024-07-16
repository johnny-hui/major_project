"""
Description:
This Python file contains initialization functions for
the Node class.

"""
import getopt
import ipaddress
import re
import socket
import sys
from _socket import SO_REUSEADDR
from datetime import datetime
from ssl import SOL_SOCKET
from time import ctime
import ntplib
from utility.constants import (INVALID_SRC_IP_ARG_ERROR, MIN_PORT_VALUE,
                               MAX_PORT_VALUE, INVALID_SRC_PORT_RANGE, INVALID_FORMAT_SRC_PORT_ARG_ERROR,
                               INVALID_FIRST_NAME_ERROR, INVALID_LAST_NAME_ERROR)


def parse_arguments():
    """
    Parse the command line for arguments.

    @return name, src_ip, src_port:
        Strings containing name, source IP address and source port
    """
    # Initialize variables
    first_name, last_name, src_ip, src_port = "", "", "", ""
    arguments = sys.argv[1:]
    opts, user_list_args = getopt.getopt(arguments, 'f:l:s:p:')
    pattern = re.compile("^[a-zA-Z]+$")  # For string validation

    if len(opts) == 0:
        sys.exit("[+] INIT ERROR: No arguments were provided!")

    for opt, argument in opts:
        if opt == '-f':  # For first name
            if bool(pattern.match(argument)):
                first_name = argument
            else:
                sys.exit(INVALID_FIRST_NAME_ERROR)

        if opt == '-l':  # For last name
            if bool(pattern.match(argument)):
                last_name = argument
            else:
                sys.exit(INVALID_LAST_NAME_ERROR)

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
    if len(first_name) == 0:
        sys.exit("[+] INIT ERROR: A first name was not provided! (-f option)")
    if len(last_name) == 0:
        sys.exit("[+] INIT ERROR: A last name was not provided! (-l option)")
    if len(src_ip) == 0:
        sys.exit("[+] INIT ERROR: A source IP was not provided! (-s option)")
    if len(str(src_port)) == 0:
        sys.exit("[+] INIT ERROR: A source port was not provided! (-p option)")

    return first_name, last_name, src_ip, src_port


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


def get_application_timestamp():
    """
    Gets the current timestamp of when P2P Node application
    was started (from validated NTP server); if no internet
    connection, then system time.

    @attention Use Case
        This is used to determine which Node is designated as
        "delegate" if two Nodes whom have not yet established
        a connection to a P2P server and want to connect to one
        another.

    @return: timestamp
        A string containing the current timestamp of the time
        when the application was started
    """
    try:
        response = ntplib.NTPClient().request('pool.ntp.org', timeout=5)
        ntp_time = ctime(response.tx_time)  # Convert response into ctime
        ntp_datetime = datetime.strptime(ntp_time, '%a %b %d %H:%M:%S %Y')  # Convert ctime to DateTime
        timestamp = ntp_datetime.strftime('%Y-%m-%d %I:%M:%S %p')  # Format the timestamp

    except (ntplib.NTPException, socket.timeout, socket.gaierror):
        print("[+] ERROR: Failed to receive response from NTP server; using system time instead.")
        system_time = datetime.now()
        timestamp = system_time.strftime('%Y-%m-%d %I:%M:%S %p')

    except Exception as e:
        print(f"[+] ERROR: An error occurred while receiving an official timestamp from NTP server: {e}")
        return None

    return timestamp
