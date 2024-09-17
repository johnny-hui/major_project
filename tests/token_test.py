from exceptions.exceptions import InvalidTokenError
from utility.crypto.ec_keys_utils import generate_keys
from utility.crypto.token_utils import generate_approval_token, verify_token

if __name__ == '__main__':
    pvt_key, pub_key = generate_keys()
    token = generate_approval_token(pvt_key, pub_key, peer_ip="127.0.0.1")

    try:
        # Test Verification: No data alterations
        is_valid = verify_token(token)
        print("[+] Token:", token)
        print(f"[+] Is Valid: {is_valid}\n")

        # Test Verification: Data Manipulated
        token.peer_ip = "127.0.0.2"
        is_valid = verify_token(token)
        print("[+] Token:", token)
        print(f"[+] Is Valid: {is_valid}")

    except InvalidTokenError as e:
        print(f"[+] ERROR: An error has occurred [REASON: {e}]")
