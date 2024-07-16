"""
Description:
This Python file is used to test functions.

"""
import pickle
import secrets

from models.CustomCipher import CustomCipher
from models.Transaction import Transaction
from utility.constants import BLOCK_SIZE, CBC, FORMAT_FILE
from utility.ec_keys_utils import generate_keys, generate_shared_secret
from utility.utils import load_image, save_transaction

if __name__ == '__main__':
    ip, port, first_name, last_name = "10.0.0.74", 69, "Bob", "Ross"
    pvt_key, pub_key = generate_keys()

    obj = Transaction(ip=ip, port=port, first_name=first_name, last_name=last_name, public_key=pub_key)
    img = load_image(path="data/photos/received_image.png")
    obj.set_role("ADMIN")
    obj.set_image(img)
    obj.sign_transaction(pvt_key=pvt_key)
    print(obj)

    shared_key = generate_shared_secret()
    iv = secrets.token_bytes(BLOCK_SIZE)
    cipher = CustomCipher(key=shared_key, mode=CBC, iv=iv)

    # Encrypt and send to peer
    data = pickle.dumps(obj)
    encrypted_object = cipher.encrypt(data, format=FORMAT_FILE)

    # Other peer receives it and saves it to a file (encrypted only!)
    save_transaction(data=encrypted_object)
    decrypted_object = cipher.decrypt(encrypted_object, format=FORMAT_FILE)
    decrypted_data = pickle.loads(decrypted_object)
    if decrypted_data.is_verified():
        print("[+] VERIFIED!")
    else:
        print("[!] NOT VERIFIED!")

