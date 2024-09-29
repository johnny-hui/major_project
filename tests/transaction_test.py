"""
Description:
This Python file is used to test the Transaction class
and the verification of ECDSA signatures.

"""
import pickle
import secrets
import sys
from datetime import datetime
from models.Transaction import Transaction
from utility.crypto.aes_utils import AES_encrypt, AES_decrypt
from utility.crypto.ec_keys_utils import generate_keys, generate_shared_secret
from utility.general.constants import BLOCK_SIZE, TIMESTAMP_FORMAT, ECB
from utility.general.utils import load_image, get_img_path

if __name__ == '__main__':
    ip, port, first_name, last_name = "10.0.0.16", 126, "Thompson", "Tristan"
    pvt_key, pub_key = generate_keys()

    obj = Transaction(ip=ip, port=port, first_name=first_name,
                      last_name=last_name, public_key=pub_key)

    img_path = get_img_path()

    try:
        img = load_image(path=img_path)
        obj.set_role("ADMIN")
        obj.set_image(img)
        obj.set_timestamp(datetime.now().strftime(TIMESTAMP_FORMAT))
        obj.sign_transaction(pvt_key=pvt_key)
        obj.set_received_by("10.0.0.153")
    except (ValueError, FileNotFoundError, IOError) as e:
        sys.exit(str(e))

    print(obj)

    # ConnectToNetwork to Client: Key Exchange Simulation and Generation of Secret
    shared_key = generate_shared_secret()
    iv = secrets.token_bytes(BLOCK_SIZE)

    # Encrypt transaction data using AES and send to peer
    data = pickle.dumps(obj)
    encrypted_object = AES_encrypt(data=data, key=shared_key, mode=ECB, iv=iv)

    # Test decryption
    decrypted_object = pickle.loads(AES_decrypt(data=encrypted_object, key=shared_key, mode=ECB, iv=iv))
    print(f"Decrypted: {decrypted_object}")

    # Test Verification: No data manipulation
    print(decrypted_object.is_verified())

    # Test Verification: With data manipulation
    decrypted_object.ip_addr = "10.0.0.1"
    print(decrypted_object.is_verified())
