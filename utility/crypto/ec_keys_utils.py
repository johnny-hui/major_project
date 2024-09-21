"""
Description:
This Python file contains functions that assist in creating
and managing EC (elliptic curve) keys.

"""
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from utility.general.constants import BLOCK_SIZE


def compress_public_key(public_key: EllipticCurvePublicKey):
    """
    Compresses a key generated by ECDH key exchange protocol
    into a hex representation of 65 hex digits.

    @param public_key:
        A point (x, y) under an Elliptic Curve

    @return: Compressed Key
        A compressed key represented as a hex string
    """
    pub_key_bytes = serialize_public_key(public_key)
    hasher = hashlib.sha3_256()
    hasher.update(pub_key_bytes)
    return hasher.hexdigest()


def compress_private_key(private_key: EllipticCurvePrivateKey):
    """
    Compresses a key generated by ECDH key exchange protocol
    into a hex representation of 65 hex digits.

    @param private_key:
        A random integer within the field of 'brainpoolP256r1'
        elliptic curve

    @return: Compressed Key
        A compressed key represented as a hex string
    """
    pvt_key_bytes = serialize_private_key(private_key)
    hasher = hashlib.sha3_256()
    hasher.update(pvt_key_bytes)
    return hasher.hexdigest()


def compress_signature(signature: bytes):
    """
    Compresses the hash signature into a printable format.

    @param signature:
        A hashed ECDSA signature

    @return: signature_hash
        A string containing the hash of the signature
    """
    return signature.hex()


def compress_shared_secret(secret: bytes):
    """
    Compresses the shared secret.

    @param secret:
        Bytes containing the shared secret

    @return: secret.hex()
        Hex representation of the shared secret
    """
    return secret.hex()


def compress_iv(iv: bytes | None):
    """
    Compresses an initialization factor (IV).

    @param iv:
        Bytes of the initialization factor

    @return: iv.hex() | None
        Hex representation of the shared secret
    """
    if iv:
        return iv.hex()
    return None


def hash_data(data: bytes | None):
    """
    Utilizes SHA3-256 to hash any given data.

    @param data:
        Bytes containing the data to be hashed

    @return: hasher.hexdigest()
        A string containing the hashed data
    """
    if data:
        hasher = hashlib.sha3_256()
        hasher.update(data)
        return hasher.hexdigest()
    return None


def serialize_private_key(private_key: EllipticCurvePrivateKey) -> bytes:
    """
    Serializes a private key into a byte string.

    @attention Use Case:
        Use this function to convert the private key into bytes
        for over-the-network transmission

    @param private_key:
        A random integer under the 'brainpoolP256r1' elliptic curve

    @return: private_key (in bytes)
        The serialized public key
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(public_key: EllipticCurvePublicKey) -> bytes:
    """
    Serializes a public key into a byte string.

    @attention Use Case:
        Use this function to convert the public key into bytes
        for over-the-network transmission

    @param public_key:
        A point (x, y) under an Elliptic Curve

    @return: public_key (in bytes)
        The serialized public key
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_private_key(pvt_key_bytes: bytes):
    """
    Deserializes a private key from byte string into an
    EllipticCurvePrivateKey object.

    @param pvt_key_bytes:
        A bytearray containing bytes of the private key

    @return: EllipticCurvePrivateKey
        A random integer generated under an Elliptic Curve
    """
    return serialization.load_pem_private_key(pvt_key_bytes, password=None)


def deserialize_public_key(pub_key_bytes: bytes):
    """
    Deserializes a public key from byte string into an
    EllipticCurvePublicKey object.

    @param pub_key_bytes:
        A bytearray containing bytes of the public key

    @return: EllipticCurvePublicKey
        A public key generated under an Elliptic Curve
    """
    return serialization.load_pem_public_key(pub_key_bytes)


def public_key_to_string(public_key: EllipticCurvePublicKey) -> str:
    """
    Converts and PEM encodes an EllipticCurvePublicKey to a string.

    @param public_key:
        A public key generated under the 'brainpoolP256r1' elliptic curve

    @return: public_key (String)
        A string representation of the public key
    """
    return public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def load_public_key_from_string(public_key_str: str):
    """
    Loads an elliptic curve public key from a PEM-encoded key string.

    @param public_key_str:
        The string containing the public key (PEM-encoded)

    @return: EllipticCurvePublicKey
        An EllipticCurvePublicKey object
    """
    return serialization.load_pem_public_key(public_key_str.encode())


def derive_shared_secret(pvt_key: EllipticCurvePrivateKey, pub_key: EllipticCurvePublicKey) -> bytes:
    """
    Derives the shared secret between a private key and another
    host's public key by performing ECC point multiplication.

    @param pvt_key:
        An owning host's private key

    @param pub_key:
        The other host's public key

    @return: shared_secret
        A 16-byte shared key derived from the 'brainpoolP256r1' elliptic curve
    """
    shared_key_bytes = pvt_key.exchange(ec.ECDH(), pub_key)
    shared_key_hash = hashlib.sha3_256(shared_key_bytes).digest()
    return shared_key_hash[:BLOCK_SIZE]


def generate_keys(verbose: bool = True) -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """
    Generates a public/private key pair using the
    'brainpoolP256r1' elliptic curve.

    @param verbose:
        A boolean flag to toggle verbose mode (default=True/On)

    @return: private_key, public_key
    """
    private_key = ec.generate_private_key(ec.BrainpoolP256R1())
    public_key = private_key.public_key()
    if verbose:
        print("[+] ECDH Private/Public Key pairs have been successfully generated!")
        print(f"[+] Your private key: {compress_private_key(private_key)}")
        print(f"[+] Your public key: {compress_public_key(public_key)}")
    return private_key, public_key


def create_signature(pvt_key: EllipticCurvePrivateKey, data: bytes) -> bytes:
    """
    Creates an SHA3-256 ECDSA hash signature for a defined set of data.

    @note Information Source:
        https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages

    @param pvt_key:
        A random integer selected within 'brainpoolP256r1'
        elliptic curve's field

    @param data:
        The data to be signed (in bytes)

    @return: signature
        Bytes containing the ECDSA signature
    """
    signature = pvt_key.sign(data, ec.ECDSA(hashes.SHA3_256()))
    return signature


def verify_signature(signature: bytes, data: bytes, pub_key: EllipticCurvePublicKey) -> bool:
    """
    Verifies a hash signature created by an ECDSA algorithm.

    @note Information Source:
        https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages

    @param signature:
        Bytes of the hashed signature

    @param data:
        The data to be verified (in bytes)

    @param pub_key:
        A point (x, y) on the elliptic curve

    @return: Boolean (T/F)
        True if the signature is valid, False otherwise
    """
    try:
        pub_key.verify(signature, data, ec.ECDSA(hashes.SHA3_256()))
        return True
    except InvalidSignature:
        return False


def generate_shared_secret() -> bytes:
    """
    Generates a random shared secret key using ECDH key exchange
    and the 'brainpoolP256r1' elliptic curve.

    @attention Use Case:
        Only used by CipherPlayground class (for generation of
        main key and avalanche effect analysis SKAC in Cipher
        Playground)

    @return: hash_object[:block_size]
        A hash of the shared secret (according to a block size)
    """
    print("[+] GENERATING SHARED EC KEY: Now generating an elliptic curve shared key...")
    pvt_key_1, pub_key_1 = generate_keys()
    pvt_key_2, pub_key_2 = generate_keys()
    shared_secret = derive_shared_secret(pvt_key_1, pub_key_2)
    print(f"[+] OPERATION SUCCESSFUL: The main key for cipher playground is {shared_secret.hex()}")
    return shared_secret
