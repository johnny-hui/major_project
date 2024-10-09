"""
Description:
This Python file is used to test the Transaction class
and the verification of ECDSA signatures.

"""
import time
import unittest
from models.Transaction import Transaction
from utility.crypto.ec_keys_utils import generate_keys
from utility.general.constants import TIMESTAMP_FORMAT, ROLE_ADMIN, ROLE_DELEGATE, TRANSACTION_EXPIRY_TIME_SECONDS
from utility.general.utils import load_image
from utility.node.node_init import get_current_timestamp
from utility.node.node_utils import create_transaction, sign_transaction


class TestTransaction(unittest.TestCase):
    def setUp(self):
        self.pvt_key, self.pub_key = generate_keys()
        self.ip, self.port = "10.0.0.16", 126
        self.first_name, self.last_name, self.role = "Thompson", "Tristan", ROLE_ADMIN
        self.request = Transaction(ip=self.ip, port=self.port, first_name=self.first_name,
                                   last_name=self.last_name, public_key=self.pub_key)
        self.request.role = self.role
        self.request.image = load_image("data/photos/photo_1.png")
        sign_transaction(self, self.request)

    def testInstantiation(self):
        request = create_transaction(self)
        self.assertNotEqual(request.image, None)
        self.assertEqual(request.signature, None)
        self.assertEqual(request.is_expired(), False)
        self.assertEqual(request.is_near_expiry(), False)
        self.assertEqual(request.first_name, self.first_name)
        self.assertEqual(request.last_name, self.last_name)
        self.assertEqual(request.role, self.role)
        self.assertEqual(request.ip, self.ip)
        self.assertEqual(request.port, self.port)

    def testSignature(self):
        self.assertNotEqual(self.request.signature, None)
        self.assertEqual(self.request.is_verified(), True)

    def testDataTamperIPField(self):
        self.request.ip_addr = "123.123.123.123"
        self.assertEqual(self.request.is_verified(), False)

    def testDataTamperPortField(self):
        self.request.port = 123
        self.assertEqual(self.request.is_verified(), False)

    def testDataTamperRoleField(self):
        self.request.role = ROLE_DELEGATE
        self.assertEqual(self.request.is_verified(), False)

    def testDataTamperFirstNameField(self):
        self.request.first_name = "Bob"
        self.assertEqual(self.request.is_verified(), False)

    def testDataTamperLastNameField(self):
        self.request.last_name = "Ross"
        self.assertEqual(self.request.is_verified(), False)

    def testDataTamperTimestampField(self):
        time.sleep(2)
        self.request.timestamp = get_current_timestamp(TIMESTAMP_FORMAT)
        self.assertEqual(self.request.is_verified(), False)

    def testDataTamperImageField(self):
        self.request.image = b"IMAGE"
        self.assertEqual(self.request.is_verified(), False)

    def testTransactionExpiresAfterFiveMinutes(self):
        time.sleep(TRANSACTION_EXPIRY_TIME_SECONDS)  # 300 seconds = 5 minutes
        self.assertEqual(self.request.is_expired(), "Transaction should expire after 5 minutes")

    def testTransactionExpiresJustBeforeFiveMinutes(self):
        time.sleep(TRANSACTION_EXPIRY_TIME_SECONDS - 1)  # 299 seconds = 4 minutes 59 seconds
        self.assertFalse(self.request.is_expired(), "Transaction should not expire 1 second before 5 minutes.")
