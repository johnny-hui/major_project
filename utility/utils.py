"""
Description:
This Python file provides general utility functions.

"""
import ipaddress
import os
from utility.constants import ENTER_IP_PROMPT, INVALID_IP_ERROR, OWN_IP_ERROR_MSG


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
        raise FileNotFoundError(f"FileNotFoundError: Invalid image path provided ({path})")
    except IOError:
        raise IOError(f"IOError: Invalid image path ({path})")


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
