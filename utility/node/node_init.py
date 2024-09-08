"""
Description:
This Python file contains initialization functions for
the Node class.

"""
import getopt
import ipaddress
import ntplib
import re
import socket
import sys
from _socket import SO_REUSEADDR
from datetime import datetime
from ssl import SOL_SOCKET
from time import ctime
from utility.general.constants import (INVALID_SRC_IP_ARG_ERROR, INVALID_FIRST_NAME_ERROR, INVALID_LAST_NAME_ERROR, ECB,
                                       CBC, TIMESTAMP_FORMAT, FORMAT_STRING, FORMAT_DATETIME)


def parse_arguments():
    """
    Parse the command line for arguments.

    @return first_name, last_name, mode, src_ip:
        Strings containing the first & last name, encryption mode,
        IP address of the host
    """
    # Initialize variables
    first_name, last_name, mode, src_ip = "", "", "", ""
    arguments = sys.argv[1:]
    opts, user_list_args = getopt.getopt(arguments, 'f:l:m:s:')
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

        if opt == '-m':  # For mode
            if argument.lower() in (ECB, CBC):
                mode = argument.lower()
            else:
                sys.exit("[+] INIT ERROR: An invalid mode was provided! (must choose "
                         "either 'ECB' or 'CBC' mode for -m option)")

        if opt == '-s':  # For source IP
            try:
                src_ip = str(ipaddress.ip_address(argument))
            except ValueError as e:
                sys.exit(INVALID_SRC_IP_ARG_ERROR.format(e))

    # Check if parameters are provided
    if len(first_name) == 0:
        sys.exit("[+] INIT ERROR: A first name was not provided! (-f option)")
    if len(last_name) == 0:
        sys.exit("[+] INIT ERROR: A last name was not provided! (-l option)")
    if len(mode) == 0:
        mode = ECB
    if len(src_ip) == 0:
        sys.exit("[+] INIT ERROR: A source IP was not provided! (-s option)")

    return first_name, last_name, mode, src_ip


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


def get_current_timestamp(return_format: str = None):
    """
    Gets the current timestamp of when P2P Node application
    was started (from validated NTP server); if no internet
    connection, then system time.

    @attention Use Case
        This is used to determine which Node is designated as
        "delegate" if two Nodes whom have not yet established
        a connection to a P2P server and want to connect to one
        another.

    @param return_format:
        A string representing the return format (String or Datetime)

    @return: timestamp
        A string containing the current timestamp of the time
        when the application was started
    """
    try:
        response = ntplib.NTPClient().request('pool.ntp.org', timeout=5)
        ntp_time = ctime(response.tx_time)  # Convert response into ctime
        ntp_datetime = datetime.strptime(ntp_time, '%a %b %d %H:%M:%S %Y')  # Convert ctime to DateTime

        if return_format == FORMAT_DATETIME:
            return datetime.strptime(ntp_time, '%a %b %d %H:%M:%S %Y')
        if return_format == FORMAT_STRING:
            return ntp_datetime.strftime(TIMESTAMP_FORMAT)

    except (ntplib.NTPException, socket.timeout, socket.gaierror):
        print("[+] ERROR: Failed to receive response from NTP server; using system time instead.")
        system_time = datetime.now()
        return system_time.strftime(TIMESTAMP_FORMAT)

    except Exception as e:
        print(f"[+] ERROR: An error occurred while receiving an official timestamp from NTP server: {e}")
        return None
