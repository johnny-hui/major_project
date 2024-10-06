"""
Description:
This Python file tests the Token dataclass object.

"""
import secrets
import time
import unittest
from exceptions.exceptions import InvalidTokenError
from models.Token import Token
from utility.crypto.ec_keys_utils import generate_keys
from utility.crypto.token_utils import generate_approval_token, verify_token
from utility.general.constants import FORMAT_DATETIME
from utility.node.node_init import get_current_timestamp


class TestToken(unittest.TestCase):
    def setUp(self):
        self.pvt_key, self.pub_key = generate_keys()


    def testInstantiation(self):
        """
        Tests if the Token object can be properly instantiated.
        @return: None
        """
        token = generate_approval_token(self.pvt_key, self.pub_key, peer_ip="127.0.0.1")
        self.assertIsInstance(token, Token)
        self.assertEqual(token.peer_ip, "127.0.0.1")
        self.assertEqual(verify_token(token), True)
        self.assertEqual(token.has_expired(), False)
        self.assertNotEqual(token.signature, None)
        self.assertNotEqual(token.issued_time, None)
        self.assertNotEqual(token.expiry_time, None)

    def testDataTamperIP(self):
        """
        Tests if Token's signature becomes invalidated after
        manipulating the IP address field.
        @return: None
        """
        token = generate_approval_token(self.pvt_key, self.pub_key, peer_ip="127.0.0.1")
        self.assertEqual(verify_token(token), True)   # => No data tamper

        # Change IP Field
        token.peer_ip = "123.456.123.21"
        with self.assertRaises(InvalidTokenError):
            verify_token(token) # => Verifying w/ data tamper

    def testDataTamperIssuedTime(self):
        """
        Tests if Token's signature becomes invalidated after
        manipulating the issued time field.
        @return: None
        """
        token = generate_approval_token(self.pvt_key, self.pub_key, peer_ip="127.0.0.1")
        self.assertEqual(verify_token(token), True)   # => No data tamper

        # Change Issued Time
        time.sleep(3)
        token.issued_time = get_current_timestamp(FORMAT_DATETIME)
        with self.assertRaises(InvalidTokenError):
            verify_token(token)

    def testDataTamperExpiryTime(self):
        """
        Tests if Token's signature becomes invalidated after
        manipulating the expiry time field.
        @return: None
        """
        token = generate_approval_token(self.pvt_key, self.pub_key, peer_ip="127.0.0.1")
        self.assertEqual(verify_token(token), True)   # => No data tamper

        # Change Expiry Time (normally 5 minutes ahead of current time)
        token.expiry_time = get_current_timestamp(FORMAT_DATETIME)
        with self.assertRaises(InvalidTokenError):
            verify_token(token)

    def testDataTamperToken(self):
        """
        Tests if Token's signature becomes invalidated after
        manipulating the token hash field.
        @return: None
        """
        token = generate_approval_token(self.pvt_key, self.pub_key, peer_ip="127.0.0.1")
        self.assertEqual(verify_token(token), True)   # => No data tamper

        # Change token hash string
        token.token = secrets.token_hex(32)
        with self.assertRaises(InvalidTokenError):
            verify_token(token)
