"""
Description:
This Python file tests the Blockchain class.

"""
import unittest
from models.Block import Block
from models.Blockchain import Blockchain
from utility.crypto.ec_keys_utils import generate_keys
from utility.general.constants import ROLE_ADMIN, GENESIS_INDEX

# INIT CONSTANTS
FIRST_NAMES = [None, "Teresa", "Bob", "Eric"]
LAST_NAMES = [None, "Villanueva", "Simpleton", "Newman"]
IP_ADDRESSES = [None, "10.0.0.1", "10.0.0.2", "10.0.0.3"]


class TestBlockchain(unittest.TestCase):
    def setUp(self):
        self.blockchain = Blockchain()

    def testGenerationOfGenesisBlock(self):
        """
        Test if the blockchain is instantiated properly with the genesis block.
        @return: None
        """
        genesis_block = self.blockchain.chain[0]
        self.assertEqual(genesis_block.index, 0)
        self.assertEqual(genesis_block.ip_addr, "")
        self.assertEqual(genesis_block.first_name, "")
        self.assertEqual(genesis_block.last_name, "")
        self.assertEqual(genesis_block.previous_hash, ("0" * 64))
        self.assertEqual(genesis_block.image, None)
        self.assertEqual(genesis_block.pub_key, None)
        self.assertEqual(genesis_block.signature, None)
        self.assertTrue(self.blockchain.is_valid())

    def testAddBlock(self):
        """
        Tests the functionality of adding a new block to the blockchain.
        @return: None
        """
        pvt_key, pub_key = generate_keys()
        signers_ip, signers_role = "10.0.0.153", ROLE_ADMIN
        new_block = Block(first_name="Tom", last_name="Wheeler", ip="10.0.0.132", public_key=pub_key)
        self.blockchain.add_block(new_block, signers_ip, signers_role, pvt_key)

        self.assertEqual(len(self.blockchain.chain), 2)
        self.assertEqual(new_block.index, 1)
        self.assertEqual(new_block.signers_ip, signers_ip)
        self.assertEqual(new_block.signers_role, signers_role)
        self.assertEqual(self.blockchain.get_latest_block().is_verified(), True)
        self.assertTrue(self.blockchain.is_valid())

    def testAddMultipleBlocks(self):
        """
        Tests the functionality of adding multiple blocks to the blockchain.
        @return: None
        """
        pvt_key, pub_key = generate_keys()
        signers_ip, signers_role = "10.0.0.153", ROLE_ADMIN

        for i in range(1, 4): # => Add 3 new blocks
            new_block = Block(
                first_name=FIRST_NAMES[i],
                last_name=LAST_NAMES[i],
                ip=IP_ADDRESSES[i],
                public_key=pub_key
            )
            self.blockchain.add_block(new_block, signers_ip, signers_role, pvt_key)

        self.assertEqual(len(self.blockchain.chain), 4)
        self.assertEqual(self.blockchain.chain[0].index, 0)
        self.assertEqual(self.blockchain.chain[1].index, 1)
        self.assertEqual(self.blockchain.chain[2].index, 2)
        self.assertEqual(self.blockchain.chain[3].index, 3)
        self.assertEqual(self.blockchain.is_valid(), True)

    def testBlockchainValidityAfterDataTamperOfGenesisBlock(self):
        """
        Tests the blockchain's validity after adding a block and tampering
        with the genesis block.

        @return: None
        """
        pvt_key, pub_key = generate_keys()
        signers_ip, signers_role = "10.0.0.153", ROLE_ADMIN

        new_block = Block(first_name=FIRST_NAMES[1], last_name=LAST_NAMES[1],
                          ip=IP_ADDRESSES[1], public_key=pub_key)
        self.blockchain.add_block(new_block, signers_ip, signers_role, pvt_key)
        self.assertEqual(self.blockchain.is_valid(), True)

        # Manually tamper with the genesis block
        gen_block = self.blockchain.get_specific_block(index=GENESIS_INDEX)
        gen_block.ip_addr = "10.0.0.68"
        self.assertEqual(self.blockchain.is_valid(), False)

    def testBlockchainValidityAfterDataTamperOfAnyBlock(self):
        """
        Tests the blockchain's validity after adding a block and tampering
        with the genesis block.

        @return: None
        """
        pvt_key, pub_key = generate_keys()
        signers_ip, signers_role = "10.0.0.153", ROLE_ADMIN

        for i in range(1, 4): # => Add 3 new blocks
            new_block = Block(
                first_name=FIRST_NAMES[i],
                last_name=LAST_NAMES[i],
                ip=IP_ADDRESSES[i],
                public_key=pub_key
            )
            self.blockchain.add_block(new_block, signers_ip, signers_role, pvt_key)
        self.assertEqual(self.blockchain.is_valid(), True)

        # Manually tamper with the 3rd block
        block = self.blockchain.get_specific_block(index=2)
        block.signers_role = "Bobby"
        self.assertEqual(self.blockchain.is_valid(), False)

    def testPreviousHashConsistency(self):
        """
        Tests the 'previous_hash' field of each block and
        whether it matches with the hash of the block
        before it.
        @return: None
        """
        pvt_key, pub_key = generate_keys()
        signers_ip, signers_role = "10.0.0.153", ROLE_ADMIN

        for i in range(1, 4): # => Add 3 new blocks
            new_block = Block(
                first_name=FIRST_NAMES[i],
                last_name=LAST_NAMES[i],
                ip=IP_ADDRESSES[i],
                public_key=pub_key
            )
            self.blockchain.add_block(new_block, signers_ip, signers_role, pvt_key)

        for i in range(1, len(self.blockchain.chain)):
            current_block = self.blockchain.chain[i]
            previous_block = self.blockchain.chain[i - 1]
            self.assertEqual(current_block.previous_hash, previous_block.hash)

if __name__ == "__main__":
    unittest.main()
