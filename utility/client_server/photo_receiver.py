"""
Description:
A module that provides a function handler for nodes to securely
receive photos from the P2P camera app.

"""
import os
import socket

from tqdm import tqdm

from utility.crypto.aes_utils import AES_decrypt, AES_encrypt
from utility.general.constants import BLOCK_SIZE
from utility.general.utils import create_directory, is_directory_empty, write_to_file


# CONSTANTS
DEFAULT_PHOTO_DIR = "data/photos/"
RECEIVED_SUCCESS_MSG = "[+] Photo received and saved as {} in the current directory!"
DEFAULT_IMAGE_NAME = "photo_1.png"
DEFAULT_BYTE_SIZE = 4
DEFAULT_CHUNK_SIZE = 4096
ACK_SUCCESS = "ACK"
ERROR_SIGNAL = "ERROR"


def receive_photo(peer_sock: socket.socket, secret: bytes, mode: str, iv: bytes = None):
    """
    A utility function that performs the receiving of the
    image bitmap (in bytes) from the P2P camera app.

    @param peer_sock:
        A socket object of the initiating peer

    @param secret:
        Bytes of the shared secret

    @param mode:
        A string for the encryption mode (ECB or CBC)

    @param iv:
        Bytes of the initialization vector (IV) - Optional

    @return: None
    """
    def find_latest_photo_number(path: str = DEFAULT_PHOTO_DIR) -> int | None:
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
            if filename.startswith('photo_') and filename.endswith('.png'):
                try:
                    file_number = int(filename.split('_')[1].split('.')[0])
                    file_numbers.append(file_number)
                except ValueError:
                    continue
        if file_numbers:
            return max(file_numbers)
        else:
            return None
    # ===============================================================================

    try:
        print("[+] RECEIVE PHOTO: Received signal to receive photo from P2P app...")
        create_directory(path=DEFAULT_PHOTO_DIR)

        # a) Receive size of the photo
        data = AES_decrypt(data=peer_sock.recv(BLOCK_SIZE), key=secret, mode=mode, iv=iv)
        photo_size = int.from_bytes(data, byteorder='big')
        print(f"[+] Receiving photo of size: {photo_size} bytes...")

        # Initialize the progress bar
        progress_bar = tqdm(total=photo_size, unit='B', unit_scale=True, desc='Receiving Photo (from app)')

        # b) Receive photo (bitmap) data
        received_data_buffer = bytearray()
        while len(received_data_buffer) < photo_size:
            chunk = peer_sock.recv(min(photo_size - len(received_data_buffer), DEFAULT_CHUNK_SIZE))
            if not chunk:
                break
            received_data_buffer += chunk
            progress_bar.update(len(chunk))

        # Close the progress bar
        progress_bar.close()

        # b) Decrypt the data
        decrypted_data = AES_decrypt(data=received_data_buffer, key=secret, mode=mode, iv=iv)

        # c) Save the bitmap data to 'data/photos/' directory
        if is_directory_empty(path=DEFAULT_PHOTO_DIR):
            new_file_name = "photo_1.png"
        else:
            latest_photo_number = find_latest_photo_number()
            new_file_name = f"photo_{latest_photo_number + 1}.png" if latest_photo_number else DEFAULT_IMAGE_NAME

        # Save the decrypted data to the file
        file_path = os.path.join(DEFAULT_PHOTO_DIR, new_file_name)
        write_to_file(file_path, decrypted_data)

        print("[+] PHOTO SAVED: The photo has been successfully decrypted and received!")
    except Exception as e:
        print(f"[+] An error occurred: {e}")
        peer_sock.send(AES_encrypt(data=ERROR_SIGNAL.encode(), key=secret, mode=mode, iv=iv))
    finally:
        peer_sock.send(AES_encrypt(data=ACK_SUCCESS.encode(), key=secret, mode=mode, iv=iv))
