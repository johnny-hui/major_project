"""
Description:
This python file contains utility functions that allow the Node class
to interact with the Blockchain class.

"""
import os
import pickle
import secrets
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from models.Blockchain import Blockchain
from utility.crypto.aes_utils import AES_encrypt, AES_decrypt
from utility.crypto.ec_keys_utils import (hash_data, create_signature, serialize_public_key, generate_keys,
                                          derive_shared_secret, verify_signature, deserialize_public_key)
from utility.general.constants import (BLOCK_SIZE, DEFAULT_BLOCKCHAIN_DIR, SAVE_BLOCKCHAIN_SUCCESS,
                                       SHARED_KEY_BYTE_MAPPING, INIT_FACTOR_BYTE_MAPPING, CBC_FLAG,
                                       MODE_CBC_BYTE_MAPPING, ECB_FLAG, MODE_ECB_BYTE_MAPPING, CBC,
                                       ECB, TAMPER_DETECTED_MSG, INVALID_SIG_BLOCKCHAIN_MSG,
                                       LOAD_BLOCKCHAIN_SUCCESS)
from utility.general.utils import create_directory, write_to_file, is_directory_empty
from utility.node.node_utils import obfuscate


# CONSTANTS
SIGNATURE_MARKER = b'\n--SIGNATURE--\n'
PUB_KEY_MARKER = b'\n--PUBLIC_KEY--\n'
BLOCKCHAIN_FILE_NAME = "blockchain.json"


def prepare_blockchain_data(blockchain_data: bytes, pvt_key: EllipticCurvePrivateKey,
                            pub_key: EllipticCurvePublicKey, shared_secret: bytes,
                            mode: str, iv: bytes = None):
    """
    Prepares the blockchain data for saving to file or transmission over the network
    by creating an ECDSA digital signature and embedding it with the public key for
    future verification of the blockchain; encryption is also performed.

    @param blockchain_data:
        Bytes of the blockchain data

    @param pvt_key:
        A private key generated under the 'brainpoolP256r1' elliptic curve

    @param pub_key:
        A point (x,y) in the field of 'brainpoolP256r1' elliptic curve

    @param shared_secret:
        Bytes of the shared secret

    @param mode:
        A string containing the cipher mode (CBC or ECB)

    @param iv:
        Bytes of the initialization vector (IV)

    @return:
    """
    def embed_signature_and_pub_key(data: bytearray, _signature: bytes, _pub_key_bytes: bytes):
        data.extend(SIGNATURE_MARKER)
        data.extend(len(_signature).to_bytes(4, 'big'))
        data.extend(_signature)

        data.extend(PUB_KEY_MARKER)
        data.extend(len(_pub_key_bytes).to_bytes(4, 'big'))
        data.extend(_pub_key_bytes)
    # ========================================================================================
    content = bytearray(blockchain_data)  # => create mutable copy

    # Generate hash of the data
    generated_hash = hash_data(content)

    # Create signature: Sign the hash using private key
    signature = create_signature(data=generated_hash.encode(), pvt_key=pvt_key)

    # Serialize public key into bytes
    pub_key_bytes = serialize_public_key(pub_key)

    # Embed the signature and public key to the end of the file bytes
    embed_signature_and_pub_key(data=content, _signature=signature, _pub_key_bytes=pub_key_bytes)

    # Encrypt the data
    encrypted_data = AES_encrypt(data=content, key=shared_secret, iv=iv, mode=mode)
    return encrypted_data


def extract_signature_and_pub_key(blockchain_data: bytearray):
    """
    Extracts signature and public key bytes from prepared blockchain data.

    @param blockchain_data:
        The blockchain data to be verified

    @return: None
    """
    signature_start = blockchain_data.rfind(SIGNATURE_MARKER)                  # Extract signature
    signature_len_start = signature_start + len(SIGNATURE_MARKER)
    signature_len = int.from_bytes(blockchain_data[signature_len_start:signature_len_start + 4], 'big')
    extracted_signature = blockchain_data[signature_len_start + 4:signature_len_start + 4 + signature_len]

    public_key_start = blockchain_data.rfind(PUB_KEY_MARKER)                   # Extract public key
    public_key_len_start = public_key_start + len(PUB_KEY_MARKER)
    public_key_len = int.from_bytes(blockchain_data[public_key_len_start:public_key_len_start + 4], 'big')
    public_key_bytes = blockchain_data[public_key_len_start + 4:public_key_len_start + 4 + public_key_len]

    # Get original data without the signature and public key bytes
    orig_data = blockchain_data[:signature_start]
    return orig_data, extracted_signature, public_key_bytes


def save_blockchain_to_file(blockchain: Blockchain, pvt_key: EllipticCurvePrivateKey, pub_key: EllipticCurvePublicKey):
    """
    Encrypts and saves the blockchain data to a file.

    @attention When is this called?
        Scenario 1 - The moment you join P2P network (entire blockchain encrypted and sent from responsible peer)
        Scenario 2 - You join P2P network but already have some parts of blockchain, and are
                     receiving more from responsible peer upon joining)
        Scenario 3 - The moment you receive a new block from admin/delegate (after a peer is approved)

    @param blockchain:
        A Blockchain object

    @param pvt_key:
        A private key generated under the 'brainpoolP256r1' elliptic curve

    @param pub_key:
        A point (x,y) in the field of 'brainpoolP256r1' elliptic curve

    @return: None
    """
    # Convert blockchain to bytes
    blockchain_data = pickle.dumps(blockchain)

    # Derive a new shared secret from a new public key and generate an IV (for encryption)
    _, random_pub_key = generate_keys(verbose=False)
    shared_secret = derive_shared_secret(pvt_key, random_pub_key)
    iv = secrets.token_bytes(BLOCK_SIZE)

    # Prepare blockchain data by creating a signature, including own public key, and encrypting it
    encrypted_content = prepare_blockchain_data(blockchain_data, pvt_key, pub_key, shared_secret, mode=CBC, iv=iv)

    # Encrypt the data and obfuscate key and IV (Use CBC by default)
    new_data = obfuscate(encrypted_content, shared_secret, mode=CBC, iv=iv)

    # Save data to file
    try:
        create_directory(path=DEFAULT_BLOCKCHAIN_DIR)
        file_path = os.path.join(DEFAULT_BLOCKCHAIN_DIR, BLOCKCHAIN_FILE_NAME)
        write_to_file(file_path, new_data)
        print(SAVE_BLOCKCHAIN_SUCCESS.format(file_path))
    except Exception as e:
        print(f"[+] ERROR: An error has occurred while saving blockchain to file! [REASON: {e}]")


def load_blockchain_from_file(self: object):
    """
    Loads and verifies a Blockchain from an encrypted file.

    @param self:
        A reference to the calling class object (Node)

    @return: None
    """
    def extract_bytes_from_data(data: bytearray, byte_map: dict):
        item = bytearray()
        for (position, _) in byte_map.items():
            item.append(data[position])
        return bytes(item)

    def extract_mode_secret_iv(data: bytearray):
        """
        Extracts the mode, shared secret, and initialization
        factor IV (if mode is CBC) from the data.

        @param data:
            Bytes of the encrypted Transaction data

        @return: mode, secret, iv
        """
        mode, secret, iv = data[53], None, None
        secret = extract_bytes_from_data(data=data, byte_map=SHARED_KEY_BYTE_MAPPING)
        if mode == CBC_FLAG:
            iv = extract_bytes_from_data(data=data, byte_map=INIT_FACTOR_BYTE_MAPPING)
        return mode, secret, iv

    def restore_original_bytes(data: bytearray, mode_flag: int):
        if mode_flag == CBC_FLAG:
            original_bytes = data[-33:]  # Last 33 bytes (IV, mode, secret)
            counter = 0

            for position in INIT_FACTOR_BYTE_MAPPING:
                data[position] = original_bytes[counter]
                counter += 1

            data[MODE_CBC_BYTE_MAPPING[0]] = original_bytes[counter]
            counter += 1

            for position in SHARED_KEY_BYTE_MAPPING:
                data[position] = original_bytes[counter]
                counter += 1

        elif mode_flag == ECB_FLAG:
            original_bytes = data[-17:]  # Last 17 bytes (mode, secret)
            counter = 0

            data[MODE_ECB_BYTE_MAPPING[0]] = original_bytes[counter]
            counter += 1

            for position in SHARED_KEY_BYTE_MAPPING:
                data[position] = original_bytes[counter]
                counter += 1
    # =========================================================================================
    # Create 'data/transactions' directory if it does not exist
    create_directory(path=DEFAULT_BLOCKCHAIN_DIR)

    if not is_directory_empty(path=DEFAULT_BLOCKCHAIN_DIR):
        file_path = os.path.join(DEFAULT_BLOCKCHAIN_DIR, BLOCKCHAIN_FILE_NAME)

        if os.path.isfile(file_path):
            with open(file_path, 'rb') as file:
                content = bytearray(file.read())  # => Create a mutable copy of file bytes

                mode, shared_key, iv = extract_mode_secret_iv(data=content)
                restore_original_bytes(data=content, mode_flag=mode)

                try:
                    if mode == CBC_FLAG:
                        decrypted_data = AES_decrypt(data=content[:-33], key=shared_key, mode=CBC, iv=iv)
                    else:
                        decrypted_data = AES_decrypt(data=content[:-17], key=shared_key, mode=ECB)
                except ValueError:
                    print(TAMPER_DETECTED_MSG.format(file_path))
                    os.remove(file_path)
                    return None

                # Extract signature and public key for verification of signature
                original_data, signature, signers_pub_key_bytes = extract_signature_and_pub_key(decrypted_data)
                signers_pub_key = deserialize_public_key(signers_pub_key_bytes)
                generated_hash = hash_data(original_data)

                # Verify signature and the entire blockchain
                if verify_signature(signature, generated_hash.encode(), signers_pub_key):
                    blockchain = pickle.loads(original_data)
                    if blockchain.is_valid():
                        self.blockchain = blockchain
                        print(LOAD_BLOCKCHAIN_SUCCESS.format(file_path))
                    else:
                        os.remove(file_path)
                        return None
                else:
                    print(INVALID_SIG_BLOCKCHAIN_MSG.format(file_path))
                    os.remove(file_path)
                    return None
