"""
Description:
This Python file tests the Diffie-Hellman key exchange process, the derivation
of shared secret and encryption/decryption properties.

"""
import secrets
import unittest
from utility.crypto.aes_utils import AES_encrypt, AES_decrypt
from utility.crypto.ec_keys_utils import generate_keys, derive_shared_secret
from utility.general.constants import BLOCK_SIZE, CBC, ECB


class TestDHKeyExchange(unittest.TestCase):
    def setUp(self):
        self.pvt_key_alice, self.pub_key_alice = generate_keys()  # => Alice
        self.pvt_key_bob, self.pub_key_bob = generate_keys()      # => Bob
        self.shared_secret = derive_shared_secret(self.pvt_key_bob, self.pub_key_alice)


    def testDerivationOfSharedSecret(self):
        """
        Tests if the EC keys generated are able to produce a
        symmetric shared secret key.
        @return: None
        """
        shared_secret_alice = derive_shared_secret(self.pvt_key_alice, self.pub_key_bob)  # Alice's secret
        shared_secret_bob = derive_shared_secret(self.pvt_key_bob, self.pub_key_alice)    # Bob's secret
        self.assertEqual(shared_secret_alice, shared_secret_bob)


    def testEncryptionCBC(self):
        """
        Tests if the shared secret can be used to properly encrypt a
        string with AES cipher operating in CBC mode.
        @return: None
        """
        iv = secrets.token_bytes(BLOCK_SIZE)
        plaintext = "Hello World"
        cipher_text = AES_encrypt(data=plaintext.encode(), mode=CBC, key=self.shared_secret, iv=iv)
        self.assertIsInstance(cipher_text, bytes)
        self.assertNotEqual(cipher_text, plaintext)

    def testEncryptionECB(self):
        """
        Tests if the shared secret can be used to properly encrypt a
        string with AES cipher operating in ECB mode.
        @return: None
        """
        plaintext = "Hello World"
        cipher_text = AES_encrypt(data=plaintext.encode(), mode=ECB, key=self.shared_secret)
        self.assertIsInstance(cipher_text, bytes)
        self.assertNotEqual(cipher_text, plaintext)


    def testDecryptionCBC(self):
        """
        Tests if the shared secret can be used to properly decrypt a
        string with AES cipher operating in CBC mode.
        @return: None
        """
        iv = secrets.token_bytes(BLOCK_SIZE)
        plaintext = "Hello World"
        cipher_text = AES_encrypt(data=plaintext.encode(), mode=CBC, key=self.shared_secret, iv=iv)
        decrypted_text = AES_decrypt(data=cipher_text, mode=CBC, key=self.shared_secret, iv=iv).decode()
        self.assertEqual(decrypted_text, plaintext)


    def testDecryptionECB(self):
        """
        Tests if the shared secret can be used to properly encrypt a
        string with AES cipher operating in ECB mode.
        @return: None
        """
        plaintext = "Hello World"
        cipher_text = AES_encrypt(data=plaintext.encode(), mode=ECB, key=self.shared_secret)
        decrypted_text = AES_decrypt(data=cipher_text, mode=ECB, key=self.shared_secret).decode()
        self.assertEqual(decrypted_text, plaintext)
