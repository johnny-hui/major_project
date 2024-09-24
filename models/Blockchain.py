from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from exceptions.exceptions import InvalidBlockchainError
from models.Block import Block


class Blockchain:
    """
    A class representing a Blockchain.

    Attributes:
        chain - A list of Block objects
    """
    def __init__(self):
        """
        A constructor for a Blockchain object.
        """
        self.chain = [Block.create_genesis_block()]

    def get_latest_block(self) -> Block:
        """
        Returns the last, most recent block in the Blockchain.
        @return block
        """
        return self.chain[-1]

    def get_specific_block(self, index: int = None, ip: str = None) -> Block | None:
        """
        Returns the block at the provided index or returns the most
        recent block from the provided IP address.

        @param index:
            An integer for the block index (Optional)

        @param ip:
            A string for the IP address of the block to find (Optional)

        @return: Block
        """
        if index is not None and 0 <= index < len(self.chain):           # OPTION 1: Index-based search
            return self.chain[index]
        if ip:                                                           # OPTION 2: IP-based search
            for block in reversed(self.chain):
                if block.ip_addr == ip:
                    return block
            print(f"[+] ERROR: No block was found for the provided IP address! ({ip})")
            return None

    def get_blocks_from_ip(self, ip: str, n_blocks: int = None, return_all: bool = None) -> list[Block] | None:
        """
        Returns a list of the most-recent blocks based on
        the provided IP address.

        @param ip:
            The IP address of the blocks to find

        @param n_blocks:
            An integer for the number of blocks to return (Optional)

        @param return_all:
            A boolean to return all blocks based on given IP (Optional)

        @return: block_list or None
        """
        if not n_blocks and not return_all:
            print("[+] ERROR: Either 'n_blocks' or 'return_all' must be specified!")
            return None

        block_list = []
        for block in reversed(self.chain):
            if block.ip_addr == ip:
                block_list.append(block)
                if not return_all and len(block_list) == n_blocks:
                    break

        if not block_list:
            print(f"[+] ERROR: No blocks were found for the provided IP address {ip}!")
            return None

        return block_list

    def add_block(self, new_block: Block, signers_ip: str = None, signers_role: str = None,
                  signers_pvt_key: EllipticCurvePrivateKey = None, is_signing: bool = False):
        """
        Adds a new Block object to the Blockchain and optionally signs a block.

        @attention Private Key:
            The private key should always be from an admin/delegate
            since they have authority to add blocks to blockchain.

        @attention If signing:
            If you are signing the block, you have to provide
            signers ip, role, private key, and is_signing=True
            as parameter

        @param new_block:
            A new Block object to be added

        @param signers_ip:
            The IP address of the signer

        @param signers_role:
            The signer's role

        @param signers_pvt_key:
            A private key generated under the 'brainpoolP256r1' elliptic curve

        @param is_signing:
            A boolean to indicate if the block should be signed
            when adding it to the blockchain

        @return: None
        """
        new_block.index = self.get_latest_block().index + 1
        new_block.previous_hash = self.get_latest_block().hash

        if is_signing:
            new_block.set_signers_ip(signers_ip)
            new_block.set_signers_role(signers_role)
            if new_block.hash is None:
                new_block.set_hash()
            new_block.sign_block(signers_pvt_key)

        self.chain.append(new_block)

    def is_valid(self) -> bool:
        """
        Verifies the entire blockchain by verifying every block.

        @attention Genesis Block
            This block is generally ignored

        @return: Boolean (T/F)
            True if valid, False otherwise
        """
        try:
            for i in range(1, len(self.chain)):
                current_block = self.chain[i]
                previous_block = self.chain[i - 1]

                if previous_block.hash != Block.calculate_hash(previous_block):
                    raise InvalidBlockchainError(reason=f"An invalid hash found in Block {previous_block.index}!")
                if current_block.previous_hash != previous_block.hash:
                    raise InvalidBlockchainError(reason=f"Block {current_block.index}'s previous hash does not match "
                                                        f"the hash of Block {previous_block.index}!")
                if not current_block.is_verified():
                    raise InvalidBlockchainError(reason=f"Block {current_block.index} has an invalid signature!")

            return True
        except InvalidBlockchainError as msg:
            print(msg)
            return False

    def __str__(self):
        """
        Returns the string representation of the Blockchain object.

        @attention Override:
            This function overrides the default toString() for object class

        @return: None
        """
        return '\n'.join(str(block) for block in self.chain)
