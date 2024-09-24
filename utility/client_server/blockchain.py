"""
Description:
This python file contains utility functions that involve client/server
socket communication, and both the Blockchain and Block classes

"""
import pickle
import socket
from exceptions.exceptions import InvalidBlockError, InvalidBlockchainError, PeerInvalidBlockchainError
from models.Block import Block
from models.Blockchain import Blockchain
from utility.crypto.aes_utils import AES_encrypt, AES_decrypt
from utility.crypto.ec_keys_utils import deserialize_public_key, hash_data, verify_signature
from utility.general.constants import BLOCK_SIZE, ERROR_BLOCK, ACK, ERROR_BLOCKCHAIN


def send_block(target_sock: socket.socket, input_block: Block,
               secret: bytes, enc_mode: str, iv: bytes = None):
    """
    Encrypts and sends a block object to a target peer.

    @param target_sock:
        A Socket object

    @param input_block:
        The block to be sent (Block)

    @param secret:
        Bytes of the shared secret key

    @param enc_mode:
        A string for the encryption mode (CBC or ECB)

    @param iv:
        Bytes of the initialization factor IV (optional)

    @return: None
    """
    print(f"[+] Sending block {input_block.index}...")
    block_bytes = pickle.dumps(input_block)
    encrypted_block = AES_encrypt(data=block_bytes, key=secret, mode=enc_mode, iv=iv)
    size = len(encrypted_block).to_bytes(4, byteorder='big')
    target_sock.sendall(AES_encrypt(data=size, key=secret, mode=enc_mode, iv=iv))
    target_sock.sendall(encrypted_block)


def receive_block(self: object, target_sock: socket.socket, index: int,
                  secret: bytes, enc_mode: str, iv: bytes = None):
    """
    Receives a block from a target peer.

    @attention: Block = Valid, but Blockchain != Valid
        A False status is returned, which will prompt user if they
        want to assimilate (replace their blockchain) with target
        peers in order to join the network

    @raise InvalidBlockError:
        This is thrown if the block received has an invalid signature

    @raise InvalidBlockchainError:
        This is thrown if the added block causes the entire blockchain
        to become invalid

    @param self:
        A reference to the calling class object (Node, AdminNode, DelegateNode)

    @param target_sock:
        A Socket object

    @param index:
        The index of the block to be received

    @param secret:
        Bytes of the shared secret key

    @param enc_mode:
        A string for the encryption mode (CBC or ECB)

    @param iv:
        Bytes of the initialization factor IV (optional)

    @return: status (T/F)
        True if block and blockchain are valid, False otherwise
    """
    print(f"[+] Receiving block {index}...")
    buffer = bytearray()

    # Receive block size
    data = AES_decrypt(data=target_sock.recv(BLOCK_SIZE), key=secret, mode=enc_mode, iv=iv)
    block_size = int.from_bytes(data, byteorder='big')

    # Receive block data
    while len(buffer) < block_size:
        chunk = target_sock.recv(min(block_size - len(buffer), 4096))
        if not chunk:
            break
        buffer += chunk

    # Decrypt block data
    decrypted_data = AES_decrypt(data=buffer, key=secret, mode=enc_mode, iv=iv)
    block = pickle.loads(decrypted_data)

    # Verify block's signature
    try:
        if not block.is_verified():
            target_sock.send(AES_encrypt(data=ERROR_BLOCK.encode(), key=secret, mode=enc_mode, iv=iv))
            raise InvalidBlockError(index=block.index)  # closes connection

        # Add block to blockchain and validate the entirety of the blockchain
        self.blockchain.add_block(block)
        if self.blockchain.is_valid():
            target_sock.send(AES_encrypt(data=ACK.encode(), key=secret, mode=enc_mode, iv=iv))
            print(f"[+] BLOCK RECEIVED: Successfully received block {index}!")

    except InvalidBlockchainError as error:
        invalid_block_index = self.blockchain.get_latest_block().index
        del self.blockchain.chain[invalid_block_index]
        target_sock.send(AES_encrypt(data=ERROR_BLOCKCHAIN.encode(), key=secret, mode=enc_mode, iv=iv))
        raise error  # closes connection


def send_blockchain(self: object, target_sock: socket.socket, secret: bytes, enc_mode: str, iv: bytes = None):
    """
    Sends a blockchain to a target peer.

    @raise PeerRefusedBlockchainError:
        Raised if any response other than ACK is received
        after sending the blockchain

    @param self:
        A reference to the calling class object (Node, AdminNode, DelegateNode)

    @param target_sock:
        A Socket object

    @param secret:
        Bytes of the shared secret key

    @param enc_mode:
        A string for the encryption mode (CBC or ECB)

    @param iv:
        Bytes of the initialization factor IV (optional)

    @return: None
    """
    from utility.blockchain.utils import prepare_blockchain_data
    print(f"[+] Now sending blockchain to (IP: {target_sock.getpeername()[0]})...")

    # Prepare the blockchain and send it
    blockchain_bytes = pickle.dumps(self.blockchain)
    encrypted_blockchain = prepare_blockchain_data(blockchain_bytes, self.pvt_key, self.pub_key, secret, enc_mode, iv)
    blockchain_size = len(encrypted_blockchain).to_bytes(4, byteorder='big')
    target_sock.sendall(AES_encrypt(data=blockchain_size, key=secret, mode=enc_mode, iv=iv))
    target_sock.sendall(encrypted_blockchain)

    # Wait for status
    status = AES_decrypt(data=target_sock.recv(1024), key=secret, mode=enc_mode, iv=iv)
    if status == ACK:
        print(f"[+] Your blockchain has been successfully sent and received by peer (IP: {target_sock.getpeername()[0]})!")
        return None
    elif status == ERROR_BLOCKCHAIN:
        raise PeerInvalidBlockchainError


def receive_blockchain(target_sock: socket.socket, secret: bytes, enc_mode: str, iv: bytes = None) -> Blockchain:
    """
    Receives and validates the blockchain from a target peer.

    @raise InvalidBlockchainError:
        Raised if the blockchain is invalid

    @param target_sock:
        A Socket object

    @param secret:
        Bytes of the shared secret key

    @param enc_mode:
        A string for the encryption mode (CBC or ECB)

    @param iv:
        Bytes of the initialization factor IV (optional)

    @return: Blockchain
    """
    print(f"[+] Now receiving blockchain from IP ({target_sock.getpeername()[0]})..")
    buffer = bytearray()

    # Receive blockchain size
    size = AES_decrypt(data=target_sock.recv(BLOCK_SIZE), key=secret, mode=enc_mode, iv=iv)
    blockchain_size = int.from_bytes(size, byteorder='big')

    # Receive blockchain data
    while len(buffer) < blockchain_size:
        chunk = target_sock.recv(min(size - len(buffer), 4096))
        if not chunk:
            break
        buffer += chunk

    # Decrypt blockchain data
    from utility.blockchain.utils import extract_signature_and_pub_key
    decrypted_data = AES_decrypt(data=buffer, key=secret, mode=enc_mode, iv=iv)
    original_data, signature, signers_pub_key_bytes = extract_signature_and_pub_key(decrypted_data)
    signers_pub_key = deserialize_public_key(signers_pub_key_bytes)
    generated_hash = hash_data(original_data)

    # Verify blockchain's signature and its entirety
    try:
        if verify_signature(signature, generated_hash.encode(), signers_pub_key):
            blockchain = pickle.loads(original_data)
            if blockchain.is_valid():
                target_sock.send(AES_encrypt(data=ACK.encode(), key=secret, mode=enc_mode, iv=iv))
                print(f"[+] Successfully received blockchain from IP ({target_sock.getpeername()[0]})!")
                return blockchain
    except InvalidBlockchainError as error:
        target_sock.send(AES_encrypt(data=ERROR_BLOCKCHAIN.encode(), key=secret, mode=enc_mode, iv=iv))
        raise error
