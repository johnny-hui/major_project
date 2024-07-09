import hashlib
import secrets
from utility.cipher_utils import (pad_block, encrypt_block, decrypt_block,
                                  unpad_block, get_subkeys_from_user, get_default_subkeys,
                                  is_sub_keys_generated)
from utility.constants import (CIPHER_INIT_MSG, ROUNDS, BLOCK_SIZE, DEFAULT_ROUND_KEYS,
                               OP_ENCRYPT, OP_DECRYPT, INIT_SUCCESS_MSG, FORMAT_FILE,
                               FORMAT_PICTURE, FORMAT_AVALANCHE, ECB, CBC, S_BOX)


class CustomCipher:
    """ A class representing the custom Feistel cipher.

    Attributes:
        mode - The encryption mode of the cipher (default=ECB)
        rounds - The number of rounds the cipher should run (default=8)
        block_size - The block size in bytes (default=8)
        key - The main key used for encryption/decryption
        iv - A randomly generated 8-byte initialization vector for CBC mode (default=None)
        sub_keys - A list containing sub-keys
    """

    def __init__(self, key, mode=ECB, iv=None):
        """
        A constructor for a CustomCipher class object.
        """
        print('=' * 160)
        print(CIPHER_INIT_MSG)
        self.mode = mode
        self.rounds = ROUNDS
        self.block_size = BLOCK_SIZE
        self.key = key
        self.iv = iv
        self.sub_keys = []
        self.__generate_subkeys()
        print(INIT_SUCCESS_MSG)
        print('=' * 160)

    def round_function(self, right_block: bytes, key: bytes, round_num: int):
        """
        Transforms the right block (8 bytes) by substituting the
        bytes with bytes from a pre-defined S-Box and then performing
        permutation through bit shifting and changing the byte order.

        @param right_block:
            An array of bytes containing the right block

        @param key:
            An array of bytes representing the subkey

        @param round_num:
            An integer representing the round iteration

        @return: result
            An 8-byte transformed right block
        """
        def substitute(byte: int):
            """
            Substitution of a byte in the right block
            by performing an S-box lookup based on the
            byte's value and the round number.

            @param byte:
                A byte containing 8-bits

            @return: substituted_byte
                The substituted byte
            """
            # Ensure byte value is within bounds of GF(2^8)
            byte = byte % 256

            # Apply S-box substitution based on the byte value and round number
            substituted_byte = S_BOX[(byte + round_num) % len(S_BOX)]
            return substituted_byte

        def permutation(block: bytes):
            """
            Permutates the right block by performing bit
            shuffling per byte and byte shuffling.

            @param block:
                A bytes object containing the right block

            @return: shifted block
                The transformed block
            """
            # Define bit-rotation amount and byte position table
            BIT_SHIFT_BOX = [3, 1, 6, 1, 4, 5, 7, 2]
            P_BOX = [3, 0, 6, 1, 7, 5, 4, 2]

            # BIT-WISE PERMUTATION: Left & right-bit rotation per byte based on round number and the byte's value
            shifted_block = bytearray(block)
            for i, byte in enumerate(shifted_block):
                shift_amount = BIT_SHIFT_BOX[(round_num + byte) % len(BIT_SHIFT_BOX)]
                shifted_block[i] = ((byte << shift_amount) ^ (byte >> (8 - shift_amount))) & 0xFF

            # BYTE-WISE PERMUTATION: Shuffle the byte positions from P-BOX
            permuted_block = bytearray(len(shifted_block))
            for i in range(len(permuted_block)):
                permuted_block[i] = shifted_block[P_BOX[i % len(P_BOX)] % len(shifted_block)]
            return bytes(permuted_block)

        # SUBSTITUTION: Each byte of right block
        new_right_block = bytes(substitute(byte) for byte in right_block)

        # PERMUTATION: Change the order of bits per byte, and the byte position
        new_right_block = permutation(new_right_block)

        # Byte-wise addition with the bytes of the right block and key
        result = new_right_block + key

        # Take the SHA3-256 hash of the result as final product
        hashed_result = hashlib.sha3_256(result).digest()

        # Take the 8-bytes between 23rd and 31st byte (as new R block)
        return hashed_result[23:31]

    def encrypt(self, plaintext: str | bytes, format=None,
                playground=False, avalanche=False, verbose=True):
        """
        Encrypts plaintext to ciphertext using a 16-round
        Feistel architecture.

        @attention: Avalanche Analysis
            Only performable when verbose mode is on and
            is executed only in ECB mode

        @param plaintext:
            The plaintext to be encrypted (string)

        @param format:
            A string representing the format to be encrypted
            (FORMAT_USER_INPUT, FORMAT_TEXT_FILE, FORMAT_PICTURE or
            FORMAT_AVALANCHE)

        @param playground:
            A boolean that determines whether playground mode is on
            (default=False)

        @param avalanche:
            An optional boolean flag to turn on avalanche mode;
            which only performs 1 round of ECB encryption (default=False)

        @param verbose:
            A boolean flag to turn on verbose mode (default=True)

        @return: ciphertext or round_data
            The encrypted plaintext (bytes[]); or if verbose
            mode is on return intermediate round_data (list[])
        """
        # Initialize Variables
        ciphertext = b''

        if is_sub_keys_generated(self.sub_keys, operation=OP_ENCRYPT) is False:
            return None

        # Encode plaintext to bytes (if the format is a string)
        if format not in {FORMAT_FILE, FORMAT_PICTURE, FORMAT_AVALANCHE}:
            plaintext = plaintext.encode()

        if self.mode == ECB:
            if verbose:
                print("[+] ECB ENCRYPTION: Now encrypting plaintext in ECB mode...")

            # Partition the plaintext into blocks and encrypt each block
            for i in range(0, len(plaintext), self.block_size):
                block = plaintext[i:i + self.block_size]

                if len(block) < self.block_size:  # Pad block to 64 bits
                    block = pad_block(self.block_size, block)

                if avalanche:  # For avalanche analysis (1 block only)
                    round_data = encrypt_block(self, block, avalanche=True)
                    round_data.append(self.key)
                    return round_data

                ciphertext += encrypt_block(self, block)

        if self.mode == CBC:
            if verbose:
                print("[+] CBC ENCRYPTION: Now encrypting plaintext in CBC mode...")

            # If in playground mode, generate IV
            if playground:
                self.iv = secrets.token_bytes(self.block_size)

            previous_block = self.iv

            for i in range(0, len(plaintext), self.block_size):
                block = plaintext[i:i + self.block_size]

                if len(block) < self.block_size:
                    block = pad_block(self.block_size, block)

                block = bytes([a ^ b for a, b in zip(previous_block, block)])  # XOR with previous block
                encrypted_block = encrypt_block(self, block)

                ciphertext += encrypted_block
                previous_block = encrypted_block

        return ciphertext

    def decrypt(self, ciphertext: bytes, playground=False, format=None, verbose=True):
        """
        Decrypts ciphertext back into plaintext (or bytes)
        using a 16-round Feistel architecture.

        @param ciphertext:
            The ciphertext to be decrypted (bytes)

        @param playground:
            A boolean determining whether playground mode is on

        @param format:
            A string representing the format to be encrypted
            (FORMAT_USER_INPUT, FORMAT_TEXT_FILE, or FORMAT_PICTURE)

        @param verbose:
            A boolean flag to turn on verbose mode (default=True)

        @return: plaintext
            The decrypted plaintext (string)
        """
        # Initialize Variables
        plaintext_bytes = b''

        if is_sub_keys_generated(self.sub_keys, operation=OP_DECRYPT) is False:
            return None

        if self.mode == ECB:
            if verbose:
                print("[+] ECB DECRYPTION: Now decrypting plaintext in ECB mode...")

            # Partition the ciphertext into blocks and decrypt each block
            for i in range(0, len(ciphertext), self.block_size):
                block = ciphertext[i:i + self.block_size]
                decrypted_block = decrypt_block(self, block)
                plaintext_bytes += decrypted_block

        if self.mode == CBC:
            if verbose:
                print("[+] CBC DECRYPTION: Now decrypting ciphertext in CBC mode...")

            # Get IV from class attribute
            previous_block = self.iv

            for i in range(0, len(ciphertext), self.block_size):
                block = ciphertext[i:i + self.block_size]
                decrypted_block = decrypt_block(self, block)
                decrypted_block = bytes([a ^ b for a, b in zip(previous_block, decrypted_block)])
                plaintext_bytes += decrypted_block
                previous_block = block

            # If in playground mode, reset IV for next encryption
            if playground:
                self.iv = None

        if len(plaintext_bytes) % self.block_size == 0:
            if format in {FORMAT_FILE, FORMAT_PICTURE}:
                return unpad_block(plaintext_bytes)  # => Return bytes
            else:
                return unpad_block(plaintext_bytes).decode()  # => Return string

    def __generate_subkeys(self):
        """
        Generates a set of sub-keys from the main key on a
        per-round basis based on a permutation scheme.

        @attention: Permutation Scheme
            - a) Expand the main key from 16 bytes to 32 bytes (Expansive Permutation)
            - b) Permutate the 32-bytes using byte positions defined by a P-Box
            - c) Take the transformed 32-byte key and pass it through a SHA3-256 hash
            - e) From the SHA3-256 hash, take only 16-bytes (from bytes 23 to 31) as round key
            - f) Take the 32-byte hash and repeat steps b) to e) to generate the other round keys (Snowball Effect)

        @return: None
        """
        print("[+] SUBKEY GENERATION: Now processing sub-keys...")
        print(f"[+] Generating sub-keys from the following main key: {self.key.hex()}")

        def expansion(key: bytes):
            EP_BOX = [
                15, 4, 13, 1,
                5, 11, 2, 8,
                3, 10, 9, 2,
                5, 15, 0, 7,
            ]
            expanded_key = bytearray(32)  # => Initialize empty bytearray
            key_array = bytearray(key)  # => 16-byte main key
            for p in range(32):
                factor = key_array[p % len(key)]  # => A byte from some position p of the original key
                expanded_key[p] = key_array[EP_BOX[(p + factor) % len(EP_BOX)]] ^ factor  # => Derive new byte by XOR
            return bytes(expanded_key)

        def permutate_key(expanded_key: bytes, round_number: int):
            P_BOX = [
                11, 4, 13, 1, 22, 15, 11, 8,
                3, 10, 31, 12, 5, 17, 0, 7,
                1, 14, 8, 27, 6, 2, 29, 15,
                16, 9, 7, 3, 10, 5, 19, 24
            ]
            permuted_key = bytearray(len(expanded_key))  # => Initialize empty bytearray
            key_array = bytearray(expanded_key)  # => 32-byte expanded key
            for m in range(len(expanded_key)):
                permuted_key[m] = key_array[P_BOX[((m * round_number) + (round_number * round_number)) % len(P_BOX)]]
            return bytes(permuted_key)

        # Ensure the main key is of sufficient size
        if len(self.key) < self.block_size:
            self.key = (self.key * (self.block_size // len(self.key) + 1))[:self.block_size]

        # Expand the initial key (from 16 bytes to 32 bytes)
        initial_key = expansion(self.key)

        # Round-key generation
        for i in range(self.rounds):
            permuted_key = permutate_key(initial_key, round_number=i+1)
            initial_key = hashlib.sha3_256(permuted_key).digest()
            self.sub_keys.append(initial_key[23:31])
            print(f"[+] Round {i + 1}: {initial_key[23:31].hex()}")

    def process_subkey_generation(self, menu_option=None):
        """
        Generates sub-keys in various ways based on
        user command from the Cipher Playground.

        @attention Main Key (Type Requirement)
            The main key must be in bytes[]

        @attention Use Case
            Used in Cipher Playground when user
            'regenerate sub-keys'.

        @param menu_option:
            An optional parameter used when function
            is called by CipherPlayground class (default=None)

        @return: None
        """
        if menu_option is not None:
            self.sub_keys.clear()
            if menu_option == 1:
                self.__generate_subkeys()
            if menu_option == 2:
                self.sub_keys = get_default_subkeys(DEFAULT_ROUND_KEYS)
            if menu_option == 3:
                self.sub_keys = get_subkeys_from_user(self.block_size, self.rounds)

        print(f"[+] OPERATION SUCCESSFUL: {self.rounds} new sub-keys have been added!")
