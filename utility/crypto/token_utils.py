"""
Description:
This Python file contains utility functions that exclusively
interacts with the Token dataclass object such as generating,
managing, and signing of Tokens.

"""
import pickle
import secrets
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey

from exceptions.exceptions import InvalidTokenError
from models.Token import Token
from utility.crypto.ec_keys_utils import create_signature, verify_signature, load_public_key_from_string, \
    public_key_to_string
from utility.general.constants import FORMAT_DATETIME, TOKEN_EXPIRY_TIME
from utility.node.node_init import get_current_timestamp


def generate_approval_token(pvt_key: EllipticCurvePrivateKey, pub_key: EllipticCurvePublicKey, peer_ip: str):
    """
    A factory method that generates, signs and returns an approval Token.

    @param pvt_key:
        A random integer selected within 'brainpoolP256r1'
        elliptic curve's field

    @param pub_key:
        A point (x, y) on the elliptic curve

    @param peer_ip:
        A string for the approved peer's IP address

    @return: token
        A signed Token dataclass object
    """
    # Generate a 32-byte random token
    random_token = secrets.token_hex(32)

    # Issue a timestamp (from NTP server) and set an expiry
    timestamp = get_current_timestamp(FORMAT_DATETIME)
    expiration = timestamp + timedelta(minutes=TOKEN_EXPIRY_TIME)

    # Instantiate Token object
    token = Token(token=random_token, peer_ip=peer_ip,
                  issued_time=timestamp, expiry_time=expiration,
                  issuers_pub_key=public_key_to_string(pub_key))

    # Create an ECDSA signature of the token using private key
    _sign_token(token, pvt_key)
    print(f"[+] APPROVAL TOKEN GENERATED: An approval token issued for peer (IP: {peer_ip}) has been generated!")
    return token


def verify_token(token: Token):
    """
    Verifies the Token.

    @raise InvalidTokenError:
        Exception is thrown if the Token's signature
        cannot be verified

    @param token:
        A Token object

    @return: Boolean (T/F)
        True if signature is valid, False otherwise
    """
    # Get data to be signed (dictionary)
    data = {
        'token': token.token,
        'peer_ip': token.peer_ip,
        'issued_time': token.issued_time,
        'expiry_time': token.expiry_time,
        "issuers_pub_key": token.issuers_pub_key,
    }

    # Preprocess the data by serialization
    serialized_data = pickle.dumps(data)

    # Load the public key
    pub_key = load_public_key_from_string(token.issuers_pub_key)

    # Verify the signature
    if verify_signature(pub_key=pub_key, signature=token.signature, data=serialized_data):
        print("[+] The provided access token is valid!")
        return True
    else:
        raise InvalidTokenError(ip=token.peer_ip)


def _sign_token(token: Token, pvt_key: EllipticCurvePrivateKey):
    """
    Creates and sets an ECDSA signature from the data in the
    Token dataclass.

    @param token:
        A Token object

    @param pvt_key:
        A random integer generated by the Node

    @return: None
    """
    # Define the data to be signed
    data = {
        'token': token.token,
        'peer_ip': token.peer_ip,
        'issued_time': token.issued_time,
        'expiry_time': token.expiry_time,
        "issuers_pub_key": token.issuers_pub_key,
    }

    # Preprocess the data by serialization
    serialized_data = pickle.dumps(data)

    # Sign the data & set signature
    token.signature = create_signature(pvt_key, data=serialized_data)
