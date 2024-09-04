"""
Description:
This Python file provides general utility functions.

"""
import gc
import ipaddress
import multiprocessing
import os
import socket
import threading
import time
from datetime import datetime
from prettytable import PrettyTable
from models.Transaction import Transaction
from utility.crypto.aes_utils import AES_encrypt, AES_decrypt
from utility.crypto.ec_keys_utils import compress_pub_key, compress_signature
from utility.general.constants import ENTER_IP_PROMPT, INVALID_IP_ERROR, OWN_IP_ERROR_MSG, MAX_IP_VALUE, \
    CONN_REQUEST_TABLE_TITLE, CONN_REQUEST_TABLE_FIELD_IP, CONN_REQUEST_TABLE_FIELD_PORT, \
    CONN_REQUEST_TABLE_FIELD_PERSON, CONN_REQUEST_TABLE_FIELD_ROLE, CONN_REQUEST_TABLE_FIELD_SIGNATURE, \
    CONN_REQUEST_TABLE_FIELD_PUB_KEY, CONN_REQUEST_TABLE_FIELD_RECEIVED_BY, CONN_REQUEST_TABLE_FIELD_TIMESTAMP, \
    MODE_INITIATOR, MODE_RECEIVER, MEMORY_CLEANUP_SUCCESS


def convert_to_datetime(timestamp: str):
    """
    Converts a timestamp to a datetime object.

    @param timestamp:
        A string for the timestamp

    @return: datetime.strptime()
        A DateTime object for the converted timestamp
    """
    return datetime.strptime(timestamp, '%Y-%m-%d %I:%M:%S %p')


def compare_timestamps(timestamp_1: str, timestamp_2: str):
    """
    Compares two timestamps and determines which one is older.

    @param timestamp_1:
        A DateTime object of the first timestamp

    @param timestamp_2:
        A DateTime object of the second timestamp

    @return: timestamp
        The older timestamp (String)
    """
    converted_timestamp_1 = convert_to_datetime(timestamp_1)
    converted_timestamp_2 = convert_to_datetime(timestamp_2)

    if converted_timestamp_1 < converted_timestamp_2:
        return timestamp_1
    elif converted_timestamp_1 > converted_timestamp_2:
        return timestamp_2
    else:
        return None


def determine_delegate_status(target_sock: socket.socket, own_timestamp: str,
                              mode: str, enc_mode: str, secret: bytes, iv: bytes = None):
    """
    Determines 'delegate' status by exchanging application timestamps
    between the host machine and the target peer and comparing them
    for the oldest.

    @attention Use Case:
        Used during connection to the P2P network between
        two unconnected peers to determine which gets promoted
        to the 'DELEGATE' role

    @param target_sock:
        The target socket object

    @param own_timestamp:
        A string for the application timestamp

    @param mode:
        A string for the initiator or receiver

    @param enc_mode:
        The encryption mode (ECB or CBC)

    @param secret:
        Bytes of the shared secret

    @param iv:
        Bytes of the initialization vector (IV)

    @return: Boolean (T/F)
        True if Delegate, False otherwise
    """
    # ===============================================================================
    print("[+] Now comparing the application timestamp with the target peer to determine the 'Delegate' role"
          "for establishment of new P2P network...")
    peer_timestamp = None
    target_sock.setblocking(True)  # setBlocking everytime sockets are used for multiprocessing

    # Exchange timestamps (based on mode)
    if mode == MODE_INITIATOR:
        target_sock.send(AES_encrypt(data=own_timestamp.encode(), key=secret, mode=enc_mode, iv=iv))
        peer_timestamp = AES_decrypt(data=target_sock.recv(1024), key=secret, mode=enc_mode, iv=iv).decode()

    if mode == MODE_RECEIVER:
        peer_timestamp = AES_decrypt(data=target_sock.recv(1024), key=secret, mode=enc_mode, iv=iv).decode()
        target_sock.send(AES_encrypt(data=own_timestamp.encode(), key=secret, mode=enc_mode, iv=iv))

    # Compare the timestamps to determine the oldest
    return compare_timestamps(own_timestamp, peer_timestamp) == own_timestamp


def get_img_path():
    """
    An prompt for an image path.

    @attention Use Case:
        Prompt is used during the creation
        of Transaction object

    @return: img_path
        A string containing the image path
    """
    img_path = input("[+] Enter the path of the face photo to be "
                     "submitted as part of your connection request: ")
    return img_path


def load_image(path: str):
    """
    Loads an image from a file path.

    @param path:
        A string representing the path to
        the chosen image

    @return: img_bytes
        A byte representation of the chosen image
    """
    try:
        with open(path, 'rb') as f:
            img_bytes = f.read()
            return img_bytes
    except FileNotFoundError:
        raise FileNotFoundError(f"FileNotFoundError: An invalid image path was provided ({path})!")
    except IOError:
        raise IOError(f"IOError: An invalid image path was provided ({path})!")


def create_directory(path: str):
    """
    Creates a directory at a specified path
    (only if it does not exist).

    @param path:
        A string representing the directory path to be
        created

    @return: None
    """
    if not os.path.exists(path):
        os.makedirs(path)
        print(f"[+] The following directory has been successfully created: {path}")


def write_to_file(file_path: str, data: bytes):
    """
    Writes content to a file (if exists).

    @param file_path:
        A string for the text file path

    @param data:
        A string containing data to be written to file

    @return: None
    """
    try:
        with open(file_path, 'wb') as file:
            file.write(data)
        print(f"[+] OPERATION COMPLETED: The file has been successfully saved to '{file_path}'")
    except IOError as e:
        print(f"[+] WRITE FILE ERROR: An error occurred while writing to the file {file_path}: {e}")
        return None


def delete_file(file_path: str):
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"[+] The following file has been deleted: {file_path}")


def is_directory_empty(path: str):
    """
    Checks if a directory is empty.
    @param path:
        A string containing the directory path
    @return: Boolean (T/F)
        A boolean indicating if the directory is empty
    """
    return len(os.listdir(path)) == 0


def perform_cleanup(node: object):
    """
    Performs memory cleanup by deleting reference to the
    given Node object.

    @param node:
        A Node object

    @raise NameError:
        Raised when the reference to the Node object
        is successfully deleted

    @return: None
    """
    try:
        del node
        print(node)  # => Raises NameError
    except NameError:
        gc.collect()
        print(MEMORY_CLEANUP_SUCCESS)


def get_user_command_option(opt_range: tuple, prompt: str):
    """
    Prompts a user for a command option.

    @param opt_range:
        A tuple containing the minimum and maximum
        values for command options (ex: tuple(range(3))

    @param prompt:
        A string representing the message (prompt) to be printed

    @return: command
        An integer for the command option to be executed
    """
    while True:
        try:
            command = int(input(prompt))
            if command in opt_range:
                break
            else:
                print("[+] ERROR: Invalid option provided; please try again.")
        except (ValueError, TypeError) as e:
            print(f"[+] ERROR: Invalid option selected; please try again! ({e})")
    return command


def get_target_ip(self: object):
    """
    Gets a target IP address from user, while
    checking if it is valid.

    @return: input_ip
        A string representing the IP address
    """
    while True:
        try:
            input_ip = str(ipaddress.ip_address(input(ENTER_IP_PROMPT)))
            if input_ip == self.ip:
                raise ConnectionError
            return input_ip
        except ValueError as e:
            print(INVALID_IP_ERROR.format(e))
        except ConnectionError:
            print(OWN_IP_ERROR_MSG)


def divide_subnet_search(num_threads: int):
    """
    Divides the IP subnet search into chunks
    according to the number of threads available
    on the host system.

    @param num_threads:
        An integer representing the number of worker
        threads available

    @return: ranges
        A list of tuples [(start, end)] per each
        worker thread
    """
    ranges = []
    chunk_size = MAX_IP_VALUE // num_threads
    remainder = MAX_IP_VALUE % num_threads

    # Calculate the (start, end) ranges per worker thread
    start = 0
    for i in range(num_threads):
        end = start + chunk_size - 1
        if remainder > 0:
            end += 1
            remainder -= 1
        ranges.append((start, end))
        start = end + 1
    return ranges


def create_transaction_table(req_list: list[Transaction]):
    """
    Constructs a PrettyTable that displays Transaction
    objects (connection requests).

    @param req_list:
        A list of Transaction objects

    @return: table
        A PrettyTable object
    """
    def process_name(first_name: str, last_name: str) -> str:
        return first_name + " " + last_name
    # ===============================================================================
    table = PrettyTable()
    table.title = CONN_REQUEST_TABLE_TITLE
    table.field_names = [CONN_REQUEST_TABLE_FIELD_IP, CONN_REQUEST_TABLE_FIELD_PORT,
                         CONN_REQUEST_TABLE_FIELD_PERSON, CONN_REQUEST_TABLE_FIELD_ROLE,
                         CONN_REQUEST_TABLE_FIELD_PUB_KEY, CONN_REQUEST_TABLE_FIELD_SIGNATURE,
                         CONN_REQUEST_TABLE_FIELD_RECEIVED_BY, CONN_REQUEST_TABLE_FIELD_TIMESTAMP]

    # Print each transaction object into rows of table
    for transaction in req_list:
        table.add_row(
            [
                transaction.ip_addr, transaction.port,
                process_name(transaction.first_name, transaction.last_name),
                transaction.role, compress_pub_key(transaction.pub_key),
                compress_signature(transaction.signature),
                transaction.received_by, transaction.timestamp
            ]
        )
    return table


def timer(time_limit: int, interval: int, prompt: str, stop_event: threading.Event):
    """
    A live timer that prints the time-elapsed per interval
    until a time limit (or event) is reached.

    @attention Use Case:
        Used to notify the user of the time remaining against
        a time limit

    @param time_limit:
        An integer representing the time limit (in seconds)

    @param interval:
        An integer representing the print interval (in seconds)

    @param prompt:
        A string representing the message to be printed

    @param stop_event:
        An event object that terminates the function
        once set

    @return: None
    """
    print(prompt.format(time_limit))
    start_time = time.time()
    end_time = start_time + time_limit

    while True:
        if stop_event.is_set():
            print("[+] TIMER STOPPED: A stop event has been set; timer has been terminated!")
            return None

        current_time = time.time()
        elapsed_time = current_time - start_time

        # Print elapsed time if the interval has passed
        if elapsed_time // interval * interval == elapsed_time:
            print(f"[+] Time Elapsed: {int(elapsed_time)} seconds")

        # Check if the time limit has been reached
        if current_time >= end_time:
            break

        # Sleep briefly to reduce CPU usage
        time.sleep(1)

    print(f"[+] TIME EXPIRED: Time limit of {time_limit} seconds has been reached!")


def start_parallel_operation(task, task_args: list,
                             num_processes: int, prompt: str):
    """
    Executes a function in parallel using the multiprocessing module.

    @param task:
        The task/function to be executed in parallel

    @param task_args:
        A list containing arguments for the defined function

    @param num_processes:
        An integer for number of threads to spawn

    @param prompt:
        A string representing the message to be printed

    @return: results
        A list of returned values (according to task return)
    """
    with multiprocessing.Pool(processes=num_processes) as pool:
        print(prompt + f" [{num_processes} threads being used]")
        results = pool.starmap(func=task, iterable=task_args)
        pool.close()
        pool.join()
    return results


def set_blocking_all_sockets(sock_list: list[socket.socket]):
    """
    Set all sockets in a list to blocking mode.

    @attention Use Case:
        This function is used primarily after sockets have
        been operated by functions under multiprocessing
        module since they will be set to blocking mode
        automatically for some strange reason.

    @param sock_list:
        A list of sockets

    @return: None
    """
    for sock in sock_list:
        sock.setblocking(True)
