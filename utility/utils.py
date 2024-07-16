"""
Description:
This Python file provides general utility functions.

"""
import os
from utility.constants import SAVE_TRANSACTIONS_DIR, SAVE_TRANSACTION_SUCCESS


def load_image(path: str):
    """
    Loads an image from a file path.

    @param path:
        A string representing the path to
        the chosen image

    @return: img_bytes
        A byte representation of the chosen image
    """
    with open(path, 'rb') as f:
        img_bytes = f.read()
        return img_bytes


def create_directory(path: str):
    """
    Creates a directory.

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


def is_directory_empty(path: str):
    """
    Checks if a directory is empty.
    @param path:
        A string containing the directory path
    @return: Boolean (T/F)
        A boolean indicating if the directory is empty
    """
    return len(os.listdir(path)) == 0


def find_latest_transaction_number(path: str = SAVE_TRANSACTIONS_DIR):
    """
    Finds the latest transaction (connection request) number
    from the 'data/transactions/' directory.

    @param path:
        A string defining the directory path to 'data/transactions/'

    @return: max(file_numbers)
        An integer containing the latest transaction number
    """
    file_numbers = []
    for filename in os.listdir(path):
        if filename.startswith('request_') and filename.endswith('.json'):
            try:
                file_number = int(filename.split('_')[1].split('.')[0])
                file_numbers.append(file_number)
            except ValueError:
                continue
    return max(file_numbers)


def save_transaction(data: bytes):
    """
    Saves a Transaction object (pending connection request)
    to a file within the 'data/transactions/' directory.

    @param data:
        Bytes containing the Transaction object (encrypted)

    @return: None
    """
    create_directory(path=SAVE_TRANSACTIONS_DIR)

    if is_directory_empty(path=SAVE_TRANSACTIONS_DIR):
        file_path = os.path.join(SAVE_TRANSACTIONS_DIR, "request_1.json")
        write_to_file(file_path, data)
    else:
        latest_transaction_number = find_latest_transaction_number() + 1
        new_file_name = "request_" + str(latest_transaction_number) + ".json"
        file_path = os.path.join(SAVE_TRANSACTIONS_DIR, new_file_name)
        write_to_file(file_path, data)

    print(SAVE_TRANSACTION_SUCCESS.format(file_path))
