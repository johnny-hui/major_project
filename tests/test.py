"""
Description:
This Python file is used to test functions.

"""
import pickle
import secrets
import sys
from datetime import datetime
from models.Transaction import Transaction
from utility.crypto.aes_utils import AES_encrypt
from utility.general.constants import BLOCK_SIZE, TIMESTAMP_FORMAT, ECB
from utility.crypto.ec_keys_utils import generate_keys, generate_shared_secret
from utility.node.node_utils import save_transaction_to_file, load_transactions
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

    # Connect to Client: Key Exchange Simulation and Generation of Secret
    shared_key = generate_shared_secret()
    iv = secrets.token_bytes(BLOCK_SIZE)

    # Encrypt using AES and send to peer
    data = pickle.dumps(obj)
    encrypted_object = AES_encrypt(data=data, key=shared_key, mode=ECB, iv=iv)

    # The other peer receives it and saves it to a file (encrypted only!)
    save_transaction_to_file(data=encrypted_object, shared_secret=shared_key, iv=iv, mode=ECB)

    # Load Transactions
    transaction = load_transactions()
