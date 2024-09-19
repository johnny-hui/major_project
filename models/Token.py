from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from tinyec.ec import Point

from utility.crypto.ec_keys_utils import load_public_key_from_string, compress_public_key, compress_signature
from utility.general.constants import FORMAT_DATETIME, TOKEN_TO_STRING
from utility.node.node_init import get_current_timestamp


@dataclass
class Token:
    """
    A dataclass that represents a Token.

    @attention Use Case:
        This is used to hold data for a token.
        It is generated, signed, and issued by an admin
        or delegate peer when an approved peer has been
        approved by a majority in the P2P network.

    @attention Expiry Time:
        Always 5 minutes ahead of issued time
    """
    token: str
    peer_ip: str
    issued_time: datetime
    expiry_time: datetime
    issuers_pub_key: str
    signature: bytes = None

    def has_expired(self) -> bool:
        """
        Checks if the token has expired.

        @return: Boolean (T/F)
            True if the token has expired, False otherwise.
        """
        if get_current_timestamp(FORMAT_DATETIME) > self.expiry_time:
            print(f"[+] TOKEN EXPIRED: The token issued for {self.peer_ip} has expired!")
            return True
        else:
            return False

    def __str__(self):
        """
        Returns the string representation of the Token object.

        @attention Override:
            This function overrides the default toString() for object class

        @return: None
        """
        pub_key = load_public_key_from_string(self.issuers_pub_key)
        hashed_pub_key = compress_public_key(pub_key)
        hashed_signature = compress_signature(self.signature)
        return (TOKEN_TO_STRING.format(self.token, self.peer_ip, self.issued_time,
                                       self.expiry_time, hashed_pub_key, hashed_signature))
