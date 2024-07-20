"""
Description:
This Python file provides general utility functions.

"""
import os


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
