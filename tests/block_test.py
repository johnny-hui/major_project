"""
Description:
This Python file tests the Block class.

"""
import unittest
from models.Block import Block
from utility.crypto.ec_keys_utils import generate_keys
from utility.general.constants import ROLE_ADMIN, ROLE_PEER
from utility.general.utils import get_img_path, load_image


# INIT CONSTANTS
pvt_key, pub_key = generate_keys()
ip, first_name, last_name = "127.0.0.1", "Thompson", "Tristan"
signers_ip, signers_role = "10.0.0.153", ROLE_ADMIN

class TestBlockchain(unittest.TestCase):
    def testCreationOfGenesisBlock(self):
        genesis_block = Block.create_genesis_block()
        self.assertEqual(genesis_block.index, 0)
        self.assertEqual(genesis_block.ip_addr, "")
        self.assertEqual(genesis_block.first_name, "")
        self.assertEqual(genesis_block.last_name, "")
        self.assertEqual(genesis_block.previous_hash, ("0" * 64))
        self.assertEqual(genesis_block.image, None)
        self.assertEqual(genesis_block.pub_key, None)
        self.assertEqual(genesis_block.signature, None)

    def testCreationOfRegularBlock(self):
        img_path = get_img_path()
        img = load_image(path=img_path)
        block = Block(ip=ip, first_name=first_name, last_name=last_name, public_key=pub_key)
        block.index = 1
        block.set_image(img)
        block.set_signers_ip(signers_ip)
        block.set_signers_role(signers_role)
        block.set_hash()
        block.sign_block(pvt_key)
        self.assertEqual(block.is_verified(), True)

    def testBlockWithDataTampering(self):
        block = Block(ip=ip, first_name=first_name, last_name=last_name, public_key=pub_key)
        block.index = 2
        block.set_signers_ip(signers_ip)
        block.set_signers_role(signers_role)
        block.set_hash()
        block.sign_block(pvt_key)
        self.assertEqual(block.is_verified(), True)

        block.index = 3
        block.ip_addr = "123.123.123.123"
        self.assertEqual(block.is_verified(), False)

    def testAssignSignersRole(self):
        with self.assertRaises(ValueError):
            block = Block(ip=ip, first_name=first_name, last_name=last_name, public_key=pub_key)
            block.index = 3
            block.set_signers_ip(signers_ip)
            block.set_signers_role(ROLE_ADMIN)
            block.set_hash()
            block.sign_block(pvt_key)

            # Change roles
            block.set_signers_role(ROLE_PEER)

if __name__ == "__main__":
    unittest.main()