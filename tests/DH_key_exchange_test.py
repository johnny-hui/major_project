"""
Description:
This Python file tests the Diffie-Hellman key exchange process, the derivation
of shared secret and encryption/decryption properties.

"""
from utility.client_server.client_server import establish_secure_parameters
from utility.crypto.aes_utils import AES_decrypt, AES_encrypt
from utility.crypto.ec_keys_utils import generate_keys
from utility.general.constants import MODE_RECEIVER
from utility.node.node_init import initialize_socket

if __name__ == '__main__':
    pvt_key, pub_key = generate_keys()
    sock = initialize_socket(ip="10.0.0.75", port=69)

    # Wait for connection and establish shared secret
    peer_socket, peer_address = sock.accept()
    print(f"[+] NEW CONNECTION REQUEST: Accepted a peer connection from ({peer_address[0]}, {peer_address[1]})!")
    shared_secret, session_iv, mode = establish_secure_parameters(pvt_key, pub_key, peer_socket, mode=MODE_RECEIVER)

    # Get encrypted data and decrypt
    encrypted_data = peer_socket.recv(1024)
    decrypted_data = AES_decrypt(data=encrypted_data, key=shared_secret, iv=session_iv, mode=mode).decode()
    print(f"[+] Decrypted Data: {decrypted_data}")

    # Send encrypted data
    test = AES_encrypt(data="Hello whoever you are!! :)".encode(), key=shared_secret, iv=session_iv, mode=mode)
    peer_socket.sendall(test)
