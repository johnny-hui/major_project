"""
Description:
This python file contains utility functions that involve client/server
socket communication, and both the Blockchain and Block classes

"""
import pickle
import socket

from tqdm import tqdm

from app.api.utility import EVENT_NODE_SEND_BLOCKCHAIN, EVENT_NODE_ADD_BLOCK
from exceptions.exceptions import InvalidBlockError, InvalidBlockchainError, PeerInvalidBlockchainError, \
    PeerRefusedBlockError
from models.Block import Block
from models.Blockchain import Blockchain
from utility.crypto.aes_utils import AES_encrypt, AES_decrypt
from utility.crypto.ec_keys_utils import deserialize_public_key, hash_data, verify_signature
from utility.general.constants import BLOCK_SIZE, ERROR_BLOCK, ACK, ERROR_BLOCKCHAIN, MODE_INITIATOR, MODE_RECEIVER
from utility.node.node_api import send_event_to_websocket


def exchange_blockchain_index(self: object, peer_sock: socket.socket, secret: bytes, enc_mode: str, iv, mode: str):
    """
    Performs a blockchain index exchange process between two peers
    for their most recent block.

    @attention Use Case:
        This is used to allow the initiator and receiver how many
        blocks should be sent/received to sync their blockchains
        with each other

    @param self:
        A reference to the calling class object (Node, AdminNode, DelegateNode)

    @param peer_sock:
        A socket object

    @param secret:
        Bytes containing the shared secret

    @param enc_mode:
        The encryption mode (CBC or ECB)

    @param mode:
        A string to denote whether calling class should
        receive or initiate the index exchange process

    @param iv:
        Bytes of the initialization factor IV (optional)

    @return: peer_current_block_index
        An integer representing the peer's current blockchain index
    """
    if mode == MODE_INITIATOR:
        print("[+] Now exchanging blockchain indexes with the requesting peer...")

        # Send own current block index
        current_index = self.blockchain.get_latest_block().index
        peer_sock.send(AES_encrypt(
            data=current_index.to_bytes(4, byteorder='big'),
            key=secret,
            mode=enc_mode,
            iv=iv
        ))

        # Receive peer's current block index
        data = AES_decrypt(data=peer_sock.recv(BLOCK_SIZE), key=secret, mode=enc_mode, iv=iv)
        peer_current_block_index = int.from_bytes(data, byteorder='big')
        return peer_current_block_index

    if mode == MODE_RECEIVER:
        print("[+] Now exchanging blockchain indexes with the target peer...")

        # Receive target peer's current block index
        data = AES_decrypt(data=peer_sock.recv(BLOCK_SIZE), key=secret, mode=enc_mode, iv=iv)
        peer_current_block_index = int.from_bytes(data, byteorder='big')

        # Send own current block index
        current_index = self.blockchain.get_latest_block().index
        peer_sock.send(AES_encrypt(
            data=current_index.to_bytes(4, byteorder='big'),
            key=secret,
            mode=enc_mode,
            iv=iv
        ))
        return peer_current_block_index


def compare_latest_hash(self: object, peer_sock: socket.socket, secret: bytes, enc_mode: str, iv, mode: str):
    """
    Compares the latest block's hash between two peers to ensure
    blockchain compatibility.

    @attention Use Case:
        This is used to allow the initiator to determine if
        the receiver's blockchain is the same

    @raise PeerInvalidBlockchainError, InvalidBlockchainError:
        Thrown if the hashes are not the same; hence - difference in
        blockchains

    @param self:
        A reference to the calling class object (Node, AdminNode, DelegateNode)

    @param peer_sock:
        A socket object

    @param secret:
        Bytes containing the shared secret

    @param enc_mode:
        The encryption mode (CBC or ECB)

    @param mode:
        A string to denote whether calling class should
        receive or initiate the index exchange process

    @param iv:
        Bytes of the initialization factor IV (optional)

    @return: None
    """
    if mode == MODE_INITIATOR:
        print("[+] Now comparing the latest hash with the requesting peer to test blockchain compatibility...")

        # Send own current block index
        latest_block_hash = self.blockchain.get_latest_block().hash
        peer_sock.send(AES_encrypt(data=latest_block_hash.encode(), key=secret, mode=enc_mode, iv=iv))

        # Receive peer's current block index
        peer_latest_block_hash = AES_decrypt(data=peer_sock.recv(1024), key=secret, mode=enc_mode, iv=iv).decode()

        # Compare the hashes
        if peer_latest_block_hash != latest_block_hash:
            print("[+] BLOCKCHAIN INVALID: The requesting peer's blockchain is incompatible with yours!")
            raise PeerInvalidBlockchainError
        else:
            print("[+] BLOCKCHAIN COMPATIBLE: The requesting peer's blockchain is valid!")
            return None

    if mode == MODE_RECEIVER:
        print("[+] Now comparing the latest hash with the target peer to test blockchain compatibility...")

        # Receive target peer's current block index
        peer_latest_block_hash = AES_decrypt(data=peer_sock.recv(1024), key=secret, mode=enc_mode, iv=iv).decode()

        # Send own current block index
        latest_block_hash = self.blockchain.get_latest_block().hash
        peer_sock.send(AES_encrypt(data=latest_block_hash.encode(), key=secret, mode=enc_mode, iv=iv))

        # Compare the hashes
        if peer_latest_block_hash != latest_block_hash:
            print("[+] BLOCKCHAIN INVALID: Your blockchain is incompatible as it belongs to another network!")
            raise InvalidBlockchainError(reason="Your blockchain is incompatible as it belongs to another network!")
        else:
            print("[+] BLOCKCHAIN COMPATIBLE: Your blockchain is valid!")
            return None


def send_multiple_blocks(self: object, target_sock: socket.socket, secret: bytes,
                         mode: str, own_block_index: int, peer_block_index: int, iv: bytes = None):
    """
    Sends multiple blocks specified by indexes to the intended target.

    @raise PeerRefusedBlockError:
        Raised if the sent block contains an invalid signature
        when being verified on the receiving side

    @raise PeerInvalidBlockchainError:
        Raised if the sent block results in an error
        in the Blockchain when the receiving side
        verifies after adding the block

    @param self:
        A reference to the calling class object (Node, AdminNode, DelegateNode)

    @param target_sock:
        A socket object

    @param secret:
        Bytes containing the shared secret

    @param mode:
        The encryption mode (CBC or ECB)

    @param own_block_index:
        An integer for the calling class's current block index

    @param peer_block_index:
        An integer for the target peer's current block index

    @param iv:
        Bytes of the initialization factor IV (optional)

    @return: None
    """
    for i in range( peer_block_index + 1, (own_block_index + 1)):
        block = self.blockchain.get_specific_block(i)
        send_block(target_sock, block, secret, mode, iv)

        # Await response before sending the next block
        response = AES_decrypt(data=target_sock.recv(1024), key=secret, mode=mode, iv=iv).decode()

        if response == ACK:
            print(f"[+] BLOCK SUCCESSFULLY RECEIVED: Block {i} has been successfully received!")
            continue

        if response == ERROR_BLOCK:  # => error in sent block (close connection)
            raise PeerRefusedBlockError(block)

        if response == ERROR_BLOCKCHAIN:  # => peer has an invalid blockchain (close connection)
            raise PeerInvalidBlockchainError


def send_block(target_sock: socket.socket, input_block: Block,
               secret: bytes, enc_mode: str, iv: bytes = None, do_wait: bool = False):
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

    @param do_wait:
        A boolean to force calling class to wait for a response
        before proceeding

    @return: None
    """
    print(f"[+] Sending block {input_block.index} to {target_sock.getpeername()[0]}...")

    # Set blocking (in case multiprocessing module sets to False)
    target_sock.setblocking(True)

    # Serialize and encrypt the block
    block_bytes = pickle.dumps(input_block)
    encrypted_block = AES_encrypt(data=block_bytes, key=secret, mode=enc_mode, iv=iv)

    # Prepare to send the size of the encrypted block (4 bytes)
    size = len(encrypted_block).to_bytes(4, byteorder='big')

    # Encrypt and send the size
    encrypted_size = AES_encrypt(data=size, key=secret, mode=enc_mode, iv=iv)
    target_sock.sendall(encrypted_size)

    # Initialize progress bar
    total_size = len(encrypted_block)
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc='[+] Sending block')

    # Send the encrypted block in chunks with progress
    chunk_size = 1024
    sent_bytes = 0
    while sent_bytes < total_size:
        chunk = encrypted_block[sent_bytes:sent_bytes + chunk_size]
        target_sock.sendall(chunk)
        sent_bytes += len(chunk)
        progress_bar.update(len(chunk))
    progress_bar.close()

    # Wait for a response if required
    if do_wait:
        target_sock.recv(1024)  # Waiting for a response
        print(f"[+] BLOCK SENT: Block {input_block.index} has been successfully sent and received!")


def receive_block(self: object, target_sock: socket.socket, index: int,
                  secret: bytes, enc_mode: str, iv: bytes = None, do_add: bool = True):
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

    @param do_add:
        A boolean to add the received block to blockchain

    @return: status (T/F)
        True if block and blockchain are valid, False otherwise
    """
    buffer = bytearray()
    if index != 0:
        print(f"[+] Receiving block {index}...")
    else:
        print("[+] Receiving an approval block issued for new peer from admin/delegate...")

    # Receive the encrypted block size (4 bytes)
    encrypted_size = target_sock.recv(BLOCK_SIZE)  # Adjust buffer size as needed
    block_size = int.from_bytes(AES_decrypt(data=encrypted_size, key=secret, mode=enc_mode, iv=iv), byteorder='big')

    # Initialize the progress bar
    progress_bar = tqdm(total=block_size, unit='B', unit_scale=True, desc='[+] Receiving block')

    # Receive the block data
    while len(buffer) < block_size:
        chunk_size = min(block_size - len(buffer), 4096)
        chunk = target_sock.recv(chunk_size)
        if not chunk:
            break
        buffer += chunk
        progress_bar.update(len(chunk))

    # Close the progress bar
    progress_bar.close()

    # Decrypt the received block
    decrypted_data = AES_decrypt(data=buffer, key=secret, mode=enc_mode, iv=iv)
    block = pickle.loads(decrypted_data)

    # Verify block's signature
    try:
        if not block.is_verified():
            target_sock.send(AES_encrypt(data=ERROR_BLOCK.encode(), key=secret, mode=enc_mode, iv=iv))
            raise InvalidBlockError(index=block.index)  # closes connection

        # Add block to blockchain and validate the entirety of the blockchain
        if do_add:
            self.blockchain.add_block(block)
            if self.blockchain.is_valid():
                send_event_to_websocket(queue=self.back_queue,
                                        event=EVENT_NODE_ADD_BLOCK,
                                        data=pickle.dumps(block))
                target_sock.send(AES_encrypt(data=ACK.encode(), key=secret, mode=enc_mode, iv=iv))
                print(f"[+] BLOCK RECEIVED: Successfully received block {index}!")
        else:
            target_sock.send(AES_encrypt(data=ACK.encode(), key=secret, mode=enc_mode, iv=iv))
            print(f"[+] BLOCK RECEIVED: Successfully received the approval block!")
            return block

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

    # Serialize and encrypt the blockchain
    blockchain_bytes = pickle.dumps(self.blockchain)
    encrypted_blockchain = prepare_blockchain_data(blockchain_bytes, self.pvt_key, self.pub_key, secret, enc_mode, iv)

    # Get the size of the encrypted blockchain and send it
    blockchain_size = len(encrypted_blockchain).to_bytes(4, byteorder='big')
    target_sock.sendall(AES_encrypt(data=blockchain_size, key=secret, mode=enc_mode, iv=iv))

    # Initialize the progress bar
    total_size = len(encrypted_blockchain)
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc='[+] Sending blockchain')

    # Send the encrypted blockchain in chunks
    chunk_size = 4096
    sent_bytes = 0
    while sent_bytes < total_size:
        chunk = encrypted_blockchain[sent_bytes:sent_bytes + chunk_size]
        target_sock.sendall(chunk)
        sent_bytes += len(chunk)
        progress_bar.update(len(chunk))

    # Close the progress bar
    progress_bar.close()

    # Wait for status
    status = AES_decrypt(data=target_sock.recv(1024), key=secret, mode=enc_mode, iv=iv)
    if status == ACK:
        print(f"[+] Your blockchain has been successfully sent and received by peer (IP: {target_sock.getpeername()[0]})!")
        return None
    elif status == ERROR_BLOCKCHAIN:
        raise PeerInvalidBlockchainError


def receive_blockchain(self: object, target_sock: socket.socket,
                       secret: bytes, enc_mode: str, iv: bytes = None) -> Blockchain:
    """
    Receives and validates the blockchain from a target peer.

    @raise InvalidBlockchainError:
        Raised if the blockchain is invalid

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

    @return: Blockchain
    """
    print(f"[+] Now receiving blockchain from IP ({target_sock.getpeername()[0]})..")
    buffer = bytearray()

    # Receive blockchain size
    size = AES_decrypt(data=target_sock.recv(BLOCK_SIZE), key=secret, mode=enc_mode, iv=iv)
    blockchain_size = int.from_bytes(size, byteorder='big')

    # Initialize the progress bar
    progress_bar = tqdm(total=blockchain_size, unit='B', unit_scale=True, desc='[+] Receiving blockchain')

    # Receive the blockchain data
    while len(buffer) < blockchain_size:
        chunk_size = min(blockchain_size - len(buffer), 4096)
        chunk = target_sock.recv(chunk_size)
        if not chunk:
            break
        buffer += chunk
        progress_bar.update(len(chunk))

    # Close the progress bar
    progress_bar.close()

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
                send_event_to_websocket(queue=self.back_queue,
                                        event=EVENT_NODE_SEND_BLOCKCHAIN,
                                        data=pickle.dumps(self.blockchain))
                target_sock.send(AES_encrypt(data=ACK.encode(), key=secret, mode=enc_mode, iv=iv))
                print(f"[+] Successfully received blockchain from IP ({target_sock.getpeername()[0]})!")
                return blockchain
    except InvalidBlockchainError as error:
        target_sock.send(AES_encrypt(data=ERROR_BLOCKCHAIN.encode(), key=secret, mode=enc_mode, iv=iv))
        raise error
