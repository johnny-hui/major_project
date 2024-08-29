"""
Description:
This Python file contains utility functions for AES
encryption and decryption.

"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from utility.general.constants import CBC, ECB


def __generate_AES_cipher(mode: str, key: bytes, iv: bytes = None):
    """
    Instantiates an appropriate AES cipher according
    to the encryption mode (ECB or CBC)

    @param mode:
        A string representing the encryption mode

    @param key:
        Bytes representing a shared key

    @param iv:
        Bytes representing the initialization vector IV (default=None)

    @return: AES
        An AES cipher
    """
    if mode == CBC:
        return AES.new(mode=AES.MODE_CBC, key=key, iv=iv)
    elif mode == ECB:
        return AES.new(mode=AES.MODE_ECB, key=key)
    else:
        raise ValueError("[+] AES ERROR: Invalid encryption mode was provided!")


def AES_encrypt(data: bytes, mode: str, key: bytes, iv: bytes = None):
    """
    Encrypts data using the provided encryption mode.

    @param data:
        Data to be encrypted (bytes)

    @param mode:
        A string representing the encryption mode

    @param key:
        Bytes representing a shared key

    @param iv:
        Bytes representing the initialization vector IV (default=None)

    @return: encrypted_data
        Bytes representing encrypted data
    """
    cipher = __generate_AES_cipher(mode, key, iv)
    encrypted_data = cipher.encrypt(pad(data, block_size=AES.block_size))
    return encrypted_data


def AES_decrypt(data: bytes, mode: str, key: bytes, iv: bytes = None):
    """
    Decrypts the data using the provided encryption mode.

    @param data:
        Data to be decrypted (bytes)

    @param mode:
        A string representing the decryption mode

    @param key:
        Bytes representing a shared key

    @param iv:
        Bytes representing the initialization vector IV (default=None)

    @return: decrypted_data
        Bytes representing the decrypted data
    """
    cipher = __generate_AES_cipher(mode, key, iv)
    decrypted_data = unpad(cipher.decrypt(data), block_size=AES.block_size)
    return decrypted_data
