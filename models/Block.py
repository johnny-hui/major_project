import pickle
from base64 import b64encode
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from utility.crypto.ec_keys_utils import (public_key_to_string, hash_data, create_signature,
                                          load_public_key_from_string, verify_signature,
                                          compress_public_key, compress_signature)
from utility.general.constants import (BLOCK_TO_STRING, TIMESTAMP_FORMAT, ROLE_ADMIN,
                                       ROLE_DELEGATE, GENESIS_INDEX, GENESIS_PREV_HASH)


class Block:
    """
    A class representing a Block object from a Blockchain.

    Attributes:
        index = An integer for the index of the Block
        ip - A string for the ip address
        first_name - A string for the first name of the approved peer
        last_name - A string for the last name of the approved peer
        image - Bytes of the peer's image
        timestamp - A string for the timestamp of the Block (i.e, time of joining network)
        pub_key - The signer's public key (from an admin/delegate)
        previous_hash - A string for the hash of the previous block
        hash - A string for the hash of the current Block
        signers_ip - A string for the IP address of the signing admin/delegate
        signers_role - A string for the signer's role
        signature - Bytes of the signer's signature (from an admin/delegate)
    """
    def __init__(self, ip: str, first_name: str, last_name: str,
                 public_key: EllipticCurvePublicKey = None):
        """
        A constructor for a Block object.

        @param ip:
            A string for the peer's IP address
        @param first_name:
            A string for the peer's first name
        @param last_name:
            A string for the peer's last name
        @param public_key:
            The signer's public key generated under 'brainpoolP256r1' elliptic curve
        """
        try:
            self.index = None
            self.ip_addr = ip
            self.first_name = first_name
            self.last_name = last_name
            self.image = None
            self.timestamp = datetime.now().strftime(TIMESTAMP_FORMAT)
            self.pub_key = public_key_to_string(public_key) if public_key else None
            self.previous_hash = None
            self.hash = None
            self.signers_ip = None
            self.signers_role = None
            self.signature = None
        except Exception as e:
            print(f"[+] BLOCK INIT ERROR: An error has occurred while creating Block object! [REASON: {e}]")

    def sign_block(self, pvt_key: EllipticCurvePrivateKey):
        """
        Creates an ECDSA digital signature for the Block object.

        @param pvt_key:
            A private key generated under 'brainpoolP256r1' elliptic curve

        @return: None
        """
        self.signature = create_signature(pvt_key, data=self.hash.encode())

    def is_verified(self):
        """
        Verifies the ECDSA signature of the Block object using
        the signer's public key.

        @return: Boolean (T/F)
            True if the block is verified, False otherwise
        """
        # Recalculate the hash (in case of data tampering)
        recalculated_hash = Block.calculate_hash(self)

        # Pre-check: Verify the calculated hash against the one saved to object
        if self.hash != recalculated_hash:
            return False

        # Verify the signature
        pub_key = load_public_key_from_string(self.pub_key)
        if verify_signature(pub_key=pub_key, signature=self.signature, data=self.hash.encode()):
            return True
        else:
            return False

    def set_image(self, image_bytes: bytes):
        """
        Set the image attribute.

        @param image_bytes:
            Bytes of the image

        @raise ValueError:
            The required image must be larger than 1 MB in size

        @return: None
        """
        self.image = image_bytes

    def set_hash(self):
        """
        Calculates and sets the hash of the Block object.
        @return: None
        """
        self.hash = Block.calculate_hash(self)

    def set_signers_role(self, role: str):
        """
        Sets the signer's role for the current Block.

        @raise ValueError:
            Exception raised if role is not ADMIN or DELEGATE

        @param role:
            A string for the signer's role (ADMIN/DELEGATE only)

        @return: None
        """
        if role in (ROLE_ADMIN, ROLE_DELEGATE):
            self.signers_role = role
        else:
            raise ValueError(f"ERROR: The provided role {role} is not eligible for signing the block!")

    def set_signers_ip(self, ip: str):
        """
        Sets the signer's IP address for the current Block.
        @param ip:
            The IP address of the signer
        @return: None
        """
        self.signers_ip = ip

    @staticmethod
    def calculate_hash(block):
        """
        Calculates a SHA3-256 hash for a given block.

        @return: hash
            A SHA3-256 hash of the block
        """
        block_data = {
            'index': block.index,
            'ip_addr': block.ip_addr,
            'first_name': block.first_name,
            'last_name': block.last_name,
            'image': b64encode(block.image).decode() if block.image else None,
            'timestamp': block.timestamp,
            'pub_key': block.pub_key,
            'previous_hash': block.previous_hash,
            'signers_ip': block.signers_ip,
            'signers_role': block.signers_role,
        }
        serialized_data = pickle.dumps(block_data)
        return hash_data(serialized_data)

    @staticmethod
    def create_genesis_block():
        """
        Instantiates a genesis block.

        @attention Default Attributes:
            Has no public key, image, and signature

        @return: genesis_block
        """
        genesis_block = Block(ip="", first_name="", last_name="")
        genesis_block.index = GENESIS_INDEX
        genesis_block.previous_hash = GENESIS_PREV_HASH
        genesis_block.set_hash()
        return genesis_block

    def __str__(self):
        """
        Returns the string representation of the Transaction object.

        @attention Override:
            This function overrides the default toString() for object class

        @return: None
        """
        hashed_pub_key = None
        hashed_signature = None

        if self.index != GENESIS_INDEX:
            pub_key = load_public_key_from_string(self.pub_key)
            hashed_pub_key = compress_public_key(pub_key)
            hashed_signature = compress_signature(self.signature)

        return BLOCK_TO_STRING.format(
            self.index, self.ip_addr, self.first_name, self.last_name,
            self.timestamp, hashed_pub_key, self.previous_hash,
            self.hash, self.signers_ip, self.signers_role, hashed_signature
        )
