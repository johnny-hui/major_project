from utility.crypto.ec_keys_utils import generate_keys
from utility.crypto.token_utils import generate_approval_token, verify_token

if __name__ == '__main__':
    pvt_key, pub_key = generate_keys()
    token = generate_approval_token(pvt_key, pub_key, peer_ip="127.0.0.1")

    # No data alterations
    is_valid = verify_token(token)
    print("[+] Token:", token)
    print(f"[+] Is Valid: {is_valid}\n")

    # With data alterations
    token.peer_ip = "127.0.0.2"
    is_valid = verify_token(token)
    print("[+] Token:", token)
    print(f"[+] Is Valid: {is_valid}")
