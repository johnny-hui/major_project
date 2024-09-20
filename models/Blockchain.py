from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from models.Block import Block


class Blockchain:
    """
    A class representing a Blockchain object.
    """
    def __init__(self):
        """
        A constructor for a Blockchain object.
        """
        self.chain = [Block.create_genesis_block()]

    def get_latest_block(self):
        """
        Returns the last, most recent block in the Blockchain.
        @return block
        """
        return self.chain[-1]

    def get_specific_block(self, index: int) -> Block | None:
        """
        Returns the block at the provided index.

        @param index:
            An integer for the block index

        @return: Block
        """
        if index < 0 or index >= len(self.chain):
            print(f"[+] ERROR: Cannot get Block object at the specified index! [Index: {index}]")
        else:
            return self.chain[index]

    def add_block(self, new_block: Block, signers_ip: str, signers_role: str, signers_pvt_key: EllipticCurvePrivateKey):
        """
        Signs and adds a new Block object to the Blockchain.

        @attention Private Key
            The private key should always be from an admin/delegate
            since they have authority to add blocks to blockchain.

        @param new_block:
            A new Block object to be added

        @param signers_ip:
            The IP address of the signer

        @param signers_role:
            The signer's role

        @param signers_pvt_key:
            A private key generated under the 'brainpoolP256r1' elliptic curve

        @return: None
        """
        new_block.index = self.get_latest_block().index + 1
        new_block.previous_hash = self.get_latest_block().hash
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
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if previous_block.hash != Block.calculate_hash(previous_block):
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
            if not current_block.is_verified():
                return False
        return True
