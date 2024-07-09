"""
Description:
This Python file contains utility functions used by CustomCipher and
CipherPlayground classes.

"""
import os
from typing import TextIO
from prettytable import PrettyTable
from utility.constants import OP_DECRYPT, OP_ENCRYPT, NO_SUBKEYS_ENCRYPT_MSG, \
    NO_SUBKEYS_DECRYPT_MSG, INVALID_MENU_SELECTION, MENU_ACTION_START_MSG, INVALID_INPUT_MENU_ERROR, ECB, CBC, \
    CHANGE_KEY_PROMPT, REGENERATE_SUBKEY_PROMPT, REGENERATE_SUBKEY_OPTIONS, USER_ENCRYPT_OPTIONS_PROMPT, \
    USER_ENCRYPT_OPTIONS, USER_ENCRYPT_INPUT_PROMPT, FORMAT_USER_INPUT, PENDING_OP_TITLE, PENDING_OP_COLUMNS, \
    USER_DECRYPT_OPTIONS_PROMPT, USER_DECRYPT_OPTIONS, FORMAT_FILE, FORMAT_PICTURE, \
    USER_ENCRYPT_FILE_PATH_PROMPT, CIPHER_INIT_CONFIG_ATTRIBUTES, USER_ENCRYPT_IMAGE_PATH_PROMPT, \
    REGENERATE_SUBKEY_OPTIONS_PROMPT, FORMAT_TEXT
from utility.ec_keys_utils import generate_shared_secret


def is_valid_key(key: str, block_size: int):
    """
    Checks if the given key is of valid length
    based on block size.

    @param key:
        The key provided by the user

    @param block_size:
        The block size of the custom cipher

    @return: Boolean (T/F)
        True if valid; false otherwise
    """
    if len(key) < block_size:
        print(f"[+] INVALID KEY: An invalid key was provided (key must be at least {block_size} characters)!")
        return False
    else:
        return True


def is_sub_keys_generated(subkeys: list, operation: str):
    """
    Checks if sub-keys are generated; this function is
    called before encryption or decryption is performed.

    @param subkeys:
        A list containing sub-keys from the calling class

    @param operation:
        A string denoting the operation to be performed

    @return: Boolean (T/F)
        True if sub-keys are generated; false otherwise
    """
    if operation == OP_ENCRYPT:
        if len(subkeys) == 0:
            print(NO_SUBKEYS_ENCRYPT_MSG)
            return False
    if operation == OP_DECRYPT:
        if len(subkeys) == 0:
            print(NO_SUBKEYS_DECRYPT_MSG)
            return False
    return True


def pad_block(block_size: int, block: bytes):
    """
    Pads the given block according to the block size with a
    character based on the padding length (based on the PKCS#7
    padding scheme).

    @param block_size:
        An integer representing the block size

    @param block:
        An array of bytes representing the block to be padded

    @return: padded_block
        The padded block (String)
    """
    pad_len = block_size - len(block)
    return block + bytes([pad_len] * pad_len)


def unpad_block(block: bytes):
    """
    Removes padding from any given block (based on
    the PKCS#7 padding scheme).

    @param block:
        An array of bytes representing the block to be unpadded

    @return: unpadded_block
        The unpadded block (Bytes[])
    """
    pad_len = block[-1]
    return block[:-pad_len]


def encrypt_block(self: object, block: bytes, avalanche=False):
    """
    Encrypts the given block on a per round basis.

    @attention Avalanche Effect
        The 'verbose' keyword is to gather data for
        avalanche effect analysis

    @param self:
        A reference to the calling class object

    @param block:
        An array of bytes representing the block to be encrypted

    @param avalanche:
        An optional boolean flag to encrypt 1 block for
        avalanche analysis (default=False)

    @return: encrypted_block
        The encrypted left and right halves concatenated (string)
    """
    # Add initial block for verbose mode
    round_data = [block] if avalanche else None

    # Split block into two halves (64-bits each)
    half_length = len(block) // 2
    left_half, right_half = block[:half_length], block[half_length:]

    # Apply per round encryption
    for i, subkey in enumerate(self.sub_keys):
        temp = left_half
        left_half = right_half

        # XOR the result of round function and left half together
        right_half = bytes([a ^ b for a, b in zip(temp, self.round_function(right_half, subkey, round_num=i+1))])

        if avalanche:  # Add intermediate cipher blocks (if verbose)
            round_data.append(left_half + right_half)

    # Swap halves for final ciphertext
    final_cipher = right_half + left_half

    if avalanche:  # Add final ciphertext
        round_data.append(final_cipher)
        return round_data

    return final_cipher


def decrypt_block(self: object, block: bytes):
    """
    Decrypts the given block on a per-round basis.

    @param self:
        A reference to the calling class object

    @param block:
        An array of bytes representing the block to be decrypted

    @return: decrypted_block
        The decrypted left and right halves concatenated (string)
    """
    # Split the block into two halves
    half_length = len(block) // 2
    left_half, right_half = block[:half_length], block[half_length:]

    # Apply per round decryption
    counter = self.block_size
    for subkey in reversed(self.sub_keys):
        temp = left_half
        left_half = right_half

        # XOR the result of round function and left half together
        right_half = bytes([a ^ b for a, b in zip(temp, self.round_function(right_half, subkey, round_num=counter))])
        counter -= 1

    # Swap halves for final plaintext
    return right_half + left_half


def get_user_command_option(opt_range: tuple, msg: str):
    """
    Prompts a user for a command option.

    @param opt_range:
        A tuple containing the minimum and maximum
        values for command options

    @param msg:
        A string representing the message (prompt) to be printed

    @return: command
        An integer for the command option to be executed
    """
    while True:
        try:
            command = int(input(msg))
            if command in opt_range:
                break
            else:
                print("[+] ERROR: Invalid command provided; please try again.")
        except (ValueError, TypeError) as e:
            print(f"[+] ERROR: Invalid option selected; please try again! ({e})")
    return command


def get_subkeys_from_user(block_size: int, rounds: int):
    """
    Prompts the user to provide an X number of sub-keys
    based on the number of rounds.

    @param block_size:
        An integer representing the block size

    @param rounds:
        An integer representing the number of rounds

    @return: subkeys
        A list of strings containing per-round sub-keys
    """
    subkeys = []
    print(f"[+] USER-SPECIFIED KEYS: Please provide your own set of {rounds} sub-keys")
    print("[+] NOTE: Your provided sub-keys will be converted into hexadecimal strings")
    for i in range(rounds):
        while True:
            subkey = input(f"[+] ROUND {i + 1} - Enter a key: ")
            if is_valid_key(subkey, block_size):
                print(f"[+] ROUND {i + 1} => {subkey.encode().hex()}")
                subkeys.append(subkey.encode())
                break
    return subkeys


def get_default_subkeys(default_keys: list[int]):
    """
    Fetches default sub-keys (in hex), converts them
    to strings and puts them into a list.

    @param default_keys:
        A list of default sub-keys (in hex)

    @return: sub_keys
        A list containing the default sub-keys (strings)
    """
    sub_keys = []
    print(f"[+] DEFAULT SUBKEYS: Fetching default subkeys...")
    print("[+] NOTE: The default subkeys will be converted into hexadecimal strings")
    for round, key in enumerate(default_keys):
        round += 1
        subkey = hex(key)[2:].encode()  # => convert into bytes
        print(f"[+] ROUND {round}: {hex(key)} <=> {subkey.hex()}")
        sub_keys.append(subkey)
    return sub_keys


def make_table(title: str, columns: list[str], content: list):
    """
    Constructs a PrettyTable.

    @param title:
        A string containing the title of the table

    @param columns:
        A list of strings containing the columns(fields) of the table

    @param content:
        A list containing the contents of the table

    @return: table
        A PrettyTable object.
    """
    table = PrettyTable()
    table.title = title
    table.field_names = columns
    for item in content:
        table.add_row(item)
    return table


# ============================== // CIPHER PLAYGROUND FUNCTIONS // ==============================
def get_user_menu_option(fd: TextIO, min_num_options: int, max_num_options: int):
    """
    Gets the user selection for the menu.

    @param fd:
        The file descriptor for stdin

    @param min_num_options:
        The minimum number of options possible

    @param max_num_options:
        The maximum number of options possible

    @return: command
        An integer representing the selection
    """
    while True:
        try:
            command = int(fd.readline().strip())
            while not (min_num_options <= command <= max_num_options):
                print(INVALID_MENU_SELECTION.format(min_num_options, max_num_options))
                command = int(fd.readline().strip())
            print(MENU_ACTION_START_MSG.format(command))
            return command
        except (ValueError, TypeError) as e:
            print(INVALID_INPUT_MENU_ERROR.format(e))
            print(INVALID_MENU_SELECTION.format(min_num_options, max_num_options))


def change_mode(cipher: object):
    """
    Toggles a change to the CustomCipher's mode.

    @attention: Use Case
        This function is called by CipherPlayground class

    @param cipher:
        A CustomCipher object

    @return: None
    """
    if cipher.mode == ECB:
        cipher.mode = CBC
    else:
        cipher.mode = ECB
    print(f"[+] MODE CHANGED TO -> {cipher.mode.upper()}")


def change_main_key(CipherPlayground: object, cipher: object):
    """
    Prompts the user for a new main key for
    the CustomCipher and replaces the old key.

    @attention Use Case:
        This function is only called by the CipherPlayground class

    @param CipherPlayground:
        A reference to the calling class object (CipherPlayground)

    @param cipher:
        A CustomCipher object

    @return: None
    """
    if len(CipherPlayground.pending_operations) > 0:
        print("[+] CHANGE KEY ERROR: Cannot change main key since there are pending decryption operations!")
        return None

    option = get_user_command_option(opt_range=tuple(range(3)), msg=REGENERATE_SUBKEY_OPTIONS_PROMPT)
    if option == 0:
        return None
    if option == 1:
        while True:
            key = input(CHANGE_KEY_PROMPT.format(cipher.block_size))
            if is_valid_key(key, cipher.block_size):
                print("[+] NOTE: The provided main key will be converted into a hexadecimal string")
                cipher.key = key.encode()
                print(f"[+] KEY CHANGED: The main key has been changed to -> '{cipher.key.hex()}'")
                break
    if option == 2:
        cipher.key = generate_shared_secret()
        print(f"[+] KEY CHANGED: The main key has been changed to -> '{cipher.key.hex()}'")
    print("[+] HINT: To generate sub-keys with this new main key, perform the 'Regenerate Sub-keys' command in menu")


def print_subkeys(subkeys: list, columns: int):
    """
    A utility function for printing sub-keys into
    columns for presentation.

    @param subkeys:
        A list of sub-keys (strings)

    @param columns:
        An integer for the number of columns to print

    @return: None
    """
    print("[+] Subkeys: ")
    for i, subkey in enumerate(subkeys):
        print(f"\t{subkey}", end=' ')

        # If number of columns per line is reached, then print new line
        if (i + 1) % columns == 0:
            print()


def print_config(self: object):
    """
    Prints the cipher's configuration.

    @attention Use Case:
        Used only by CustomCipher class

    @param self:
        A reference to the calling class object

    @return: None
    """
    # Initialize Variables
    print("=" * 160)
    attributes = vars(self)  # Get object attributes (CustomCipher)
    index = 0

    # Iterate through cipher configuration and put into a list for table
    for _, value in attributes.items():
        if index == 0:  # 0 == Mode
            print(f"[+] {CIPHER_INIT_CONFIG_ATTRIBUTES[index]}: {value.upper()}")
        elif index == 3:  # 3 == Main Key
            print(f"[+] {CIPHER_INIT_CONFIG_ATTRIBUTES[index]}: {value.hex()}")
        elif index == 4:  # 5 == IV
            print(f"[+] {CIPHER_INIT_CONFIG_ATTRIBUTES[index]}: {value.hex() if value else value}")
        elif index == 5:  # 6 == Sub-keys
            subkeys = [subkey.hex() if isinstance(subkey, bytes) else subkey for subkey in value]
            print_subkeys(subkeys, columns=4)
        else:
            print(f"[+] {CIPHER_INIT_CONFIG_ATTRIBUTES[index]}: {value}")
        index += 1


def regenerate_sub_keys(CipherPlayground: object, cipher: object):
    """
    Regenerates sub-keys by using either the main key,
    default sub-keys, or user-provided sub-keys.

    @attention Use Case:
        This function is only called by the CipherPlayground class

    @param CipherPlayground:
        A reference to the calling class object (CipherPlayground)

    @param cipher:
        A CustomCipher object

    @return: None
    """
    if len(CipherPlayground.pending_operations) > 0:
        print("[+] CHANGE KEY ERROR: Cannot change main key because there are pending decryption operations!")
        return None

    # Print options
    for item in REGENERATE_SUBKEY_OPTIONS:
        print(item)

    while True:
        try:
            option = int(input(REGENERATE_SUBKEY_PROMPT))
            if option == 0:
                return None
            elif option in (1, 2, 3):
                cipher.process_subkey_generation(menu_option=option)
                return None
            else:
                print("[+] Invalid option selected; please try again!")
        except (ValueError, TypeError) as e:
            print(f"[+] Invalid option selected; please try again! ({e})")


def view_pending_operations(CipherPlayground: object):
    """
    Prints the pending decryption operations that
    are available to the user.

    @attention Use Case:
        This function is only called by the CipherPlayground class

    @attention Removal of Bytes in Ciphertext
        This does not affect the original ciphertext saved, as this is
        performed to make the ciphertext more presentable to the user.

    @param CipherPlayground:
        A reference to the calling class object (CipherPlayground)

    @return: None
    """
    if len(CipherPlayground.pending_operations) == 0:
        print("[+] VIEW PENDING OPERATIONS: There are currently no pending operations!")
    else:
        content_list = []
        for key, (mode, ciphertext, iv) in CipherPlayground.pending_operations.items():
            content_list.append([key, mode, ciphertext, iv.hex() if iv else iv])
        print(make_table(title=PENDING_OP_TITLE, columns=PENDING_OP_COLUMNS, content=content_list))


def print_options(options: list):
    """
    Prints a list of options for the user.

    @attention Use Case:
        This function is only called by the CipherPlayground class

    @param options:
        A list of options

    @return: None
    """
    print('=' * 80)
    for item in options:
        print(item)
    print('=' * 80)


def read_text_file(file_path: str):
    """
    Opens a text file and reads the contents of the file.

    @param file_path:
        A string for the text file path

    @return: contents
        A string containing the contents of the text file (None if error)
    """
    try:
        if file_path.lower().endswith('.txt'):
            with open(file_path, 'rb') as file:
                return file.read()
        else:
            print(f"[+] TEXT FILE ERROR: The file path and type provided is not supported! ({file_path})")
            return None
    except FileNotFoundError:
        print("[+] READ FILE ERROR: File not found in the path provided ({})".format(file_path))
        return None


def write_to_file(file_path: str, data: bytes):
    """
    Writes content to a file (if exists).

    @param file_path:
        A string for the text file path

    @param data:
        A string containing data to be written to file

    @return: None
    """
    try:
        with open(file_path, 'wb') as file:
            file.write(data)
        print(f"[+] OPERATION COMPLETED: The file has been successfully saved to '{file_path}'")
    except IOError as e:
        print(f"[+] WRITE FILE ERROR: An error occurred while writing to the file {file_path}: {e}")
        return None


def is_bitmap(img_path: str):
    """
    Opens the image file and checks if it
    is in bitmap (.bmp) format.

    @param img_path:
        A string containing the path to the bitmap
        image

    @return: Boolean (T/F)
        True if the image is in bitmap, False otherwise
    """
    try:
        with open(img_path, 'rb') as file:
            header = file.read(2)
            return header == b'BM'
    except (FileNotFoundError, IsADirectoryError):
        print(f"[+] IMAGE FILE ERROR: The image not found in path provided ({img_path})")


def read_image(file_path: str):
    """
    Opens the image file, validates if it is a
    bitmap (.bmp) file and reads the contents
    in bytes.

    @param file_path:
        A string containing the path to the image

    @return: (header, data)
        The header of the .bmp image and data (Bytes)
    """
    try:
        if is_bitmap(file_path):
            with open(file_path, 'rb') as f:
                header = f.read(54)  # BMP header is 54 bytes
                data = f.read()
            return header, data
        print("[+] IMAGE FILE ERROR: The image provided is not in bitmap (.bmp) format!")
        return None, None
    except (FileNotFoundError, IsADirectoryError):
        print(f"[+] IMAGE FILE ERROR: The image not found in path provided ({file_path})")
        return None, None


def write_image(img_path: str, header: bytes, data: bytes):
    """
    Creates an image file at the specified path, and writes
    data to the file.

    @param img_path:
        A string containing the path to the image

    @param header:
        The header of the .bmp image (Bytes)

    @param data:
        The data to be written to the file (Bytes)

    @return: None
    """
    try:
        with open(img_path, 'wb') as f:
            f.write(header)
            f.write(data)
        print(f"[+] OPERATION COMPLETED: The file has been successfully saved to '{img_path}'")
    except IOError as e:
        print(f"[+] WRITE IMAGE ERROR: An error occurred while writing to the file ({img_path}): {e}")


def modify_save_path(file_path: str, tag: str,
                     mode: str, format: str):
    """
    Modifies the original file path and name to denote
    the newly encrypted or decrypted file.

    @param file_path:
        A string containing the original file path

    @param tag:
        A string containing the tag for the new path
        ('_encrypted' or '_decrypted')

    @param mode:
        A string containing the cipher mode

    @param format:
        A string denoting the file format

    @return: new_save_path
        A string containing the new file path and name
    """
    directory, filename = os.path.split(file_path)
    new_file_name = ""

    if format == "PICTURE":
        if tag == "_decrypted.bmp":  # => For decryption
            new_file_name = filename.replace("encrypted", "decrypted")
        else:
            new_file_name = filename.split('.')[0] + '_' + mode + tag

    if format == "TEXT":
        if tag == "_decrypted.txt":  # => For decryption
            new_file_name = filename.replace("encrypted", "decrypted")
        else:
            new_file_name = filename.split('.')[0] + '_' + mode + tag

    new_save_path = os.path.join(directory, new_file_name)
    return new_save_path


def save_to_pending_operations(CipherPlayground: object, cipher: object, format: str, payload: str):
    """
    Saves the cipher parameters from a single encrypted operation
    for future decryption operation.

    @attention Use Case:
        This function is only called by the CipherPlayground class

    @param CipherPlayground:
        A reference to the calling class object (CipherPlayground)

    @param cipher:
        A CustomCipher object

    @param format:
        A string denoting the payload's format (user input, text file
        or picture)

    @param payload:
        A string containing the payload (input or file path
        of .txt file/picture)

    @return: None
    """
    if cipher.mode == ECB:
        CipherPlayground.pending_operations[format] = (cipher.mode.upper(), payload, None)
    else:
        CipherPlayground.pending_operations[format] = (cipher.mode.upper(), payload, cipher.iv)


def encrypt(CipherPlayground: object, cipher: object):
    """
    Prompts the user on the type of encryption
    (user input, text file, or picture) and invokes
    on the cipher object to perform the encryption.

    @attention Use Case:
        This function is only called by the CipherPlayground class

    @param CipherPlayground:
        A reference to the calling class object (CipherPlayground)

    @param cipher:
        A CustomCipher object

    @return: encrypted_object
        The encrypted object (user input, text file, or picture)
    """
    # Print options
    print_options(options=USER_ENCRYPT_OPTIONS)

    option = get_user_command_option(opt_range=tuple(range(len(USER_ENCRYPT_OPTIONS))),
                                     msg=USER_ENCRYPT_OPTIONS_PROMPT)
    if option == 0:  # Quit
        return None

    if option == 1:  # For User Input (from stdin)
        _perform_user_input_operation(CipherPlayground, cipher, operation=OP_ENCRYPT)

    if option == 2:  # For Text File
        _perform_text_file_operation(CipherPlayground, cipher, operation=OP_ENCRYPT)

    if option == 3:  # For Picture (Bitmap)
        __perform_image_operation(CipherPlayground, cipher, operation=OP_ENCRYPT)


def decrypt(CipherPlayground: object, cipher: object):
    """
    Prompts the user on the type of decryption
    (user input, text file, or picture) and invokes
    on the cipher object to perform the decryption.

    @attention Use Case:
        This function is only called by the CipherPlayground class

    @param CipherPlayground:
        A reference to the calling class object (CipherPlayground)

    @param cipher:
        A CustomCipher object

    @return: decrypted_object
        The decrypted object (user input, text file, or picture)
    """
    # Print operations and user options
    view_pending_operations(CipherPlayground)

    # Print user options
    print_options(options=USER_DECRYPT_OPTIONS)

    # Get user option
    option = get_user_command_option(opt_range=tuple(range(len(USER_DECRYPT_OPTIONS))),
                                     msg=USER_DECRYPT_OPTIONS_PROMPT)
    try:
        if option == 0:  # Quit
            return None

        if option == 1:  # User Input
            _perform_user_input_operation(CipherPlayground, cipher, operation=OP_DECRYPT)

        if option == 2:  # Text File
            _perform_text_file_operation(CipherPlayground, cipher, operation=OP_DECRYPT)

        if option == 3:  # Picture
            __perform_image_operation(CipherPlayground, cipher, operation=OP_DECRYPT)

    except KeyError:
        print(f"[+] DECRYPT ERROR: The selected operation does not exist; please try again")


def _perform_user_input_operation(CipherPlayground: object, cipher: object, operation: str):
    """
    A helper function that performs encryption or
    decryption operations on user input (stdin).

    @param CipherPlayground:
        A reference to the calling class object (CipherPlayground)

    @param cipher:
        A CustomCipher object

    @param operation:
        A string to designate an ENCRYPTION or DECRYPTION operation

    @return: None
    """
    if operation == OP_ENCRYPT:
        user_text = input(USER_ENCRYPT_INPUT_PROMPT)
        ciphertext = cipher.encrypt(user_text, playground=True, format=FORMAT_USER_INPUT)
        save_to_pending_operations(CipherPlayground, cipher, format=FORMAT_USER_INPUT, payload=ciphertext)
        print(f"[+] OPERATION COMPLETED: The corresponding ciphertext -> {ciphertext}")

    if operation == OP_DECRYPT:
        # Get cipher data from pending_operations
        mode, ciphertext, iv = CipherPlayground.pending_operations[FORMAT_USER_INPUT]

        # Set cipher config
        cipher.mode = mode.lower()
        if cipher.mode == CBC:
            cipher.iv = iv

        # Perform decryption
        plaintext = cipher.decrypt(ciphertext, playground=True, format=FORMAT_USER_INPUT)
        print(f"[+] OPERATION COMPLETED: The corresponding plaintext -> {plaintext}")
        del CipherPlayground.pending_operations[FORMAT_USER_INPUT]


def _perform_text_file_operation(CipherPlayground: object, cipher: object, operation: str):
    """
    A helper function that performs encryption or
    decryption operations on a text file.

    @param CipherPlayground:
        A reference to the calling class object (CipherPlayground)

    @param cipher:
        A CustomCipher object

    @param operation:
        A string to designate an ENCRYPTION or DECRYPTION operation

    @return: None
    """
    if operation == OP_ENCRYPT:
        file_path = input(USER_ENCRYPT_FILE_PATH_PROMPT)

        # Open file, get contents, encrypt and save file to path
        plaintext_bytes = read_text_file(file_path)
        if plaintext_bytes is not None:
            ciphertext = cipher.encrypt(plaintext_bytes, playground=True, format=FORMAT_FILE)
            new_save_path = modify_save_path(file_path, tag="_encrypted.txt", mode=cipher.mode, format=FORMAT_TEXT)
            save_to_pending_operations(CipherPlayground, cipher, format=FORMAT_TEXT, payload=new_save_path)
            write_to_file(new_save_path, ciphertext)

    if operation == OP_DECRYPT:
        mode, file_path, iv = CipherPlayground.pending_operations[FORMAT_TEXT]
        ciphertext_bytes = read_text_file(file_path)

        if ciphertext_bytes is not None:
            if cipher.mode.lower() == CBC:
                cipher.iv = iv
            decrypted_bytes = cipher.decrypt(ciphertext_bytes, playground=True, format=FORMAT_FILE)
            new_save_path = modify_save_path(file_path, tag="_decrypted.txt", mode=cipher.mode, format=FORMAT_TEXT)
            write_to_file(new_save_path, decrypted_bytes)
            del CipherPlayground.pending_operations[FORMAT_TEXT]


def __perform_image_operation(CipherPlayground: object, cipher: object, operation: str):
    """
    A helper function that performs encryption or
    decryption operations on an image bitmap file.

    @param CipherPlayground:
        A reference to the calling class object (CipherPlayground)

    @param cipher:
        A CustomCipher object

    @param operation:
        A string to designate an ENCRYPTION or DECRYPTION operation

    @return: None
    """
    if operation == OP_ENCRYPT:
        img_path = input(USER_ENCRYPT_IMAGE_PATH_PROMPT)

        # Open image, get bytes, encrypt and save encrypted image to path
        header, image_data = read_image(img_path)
        if header is not None and image_data is not None:
            encrypted_data = cipher.encrypt(image_data, playground=True, format=FORMAT_PICTURE)
            new_save_path = modify_save_path(img_path, tag="_encrypted.bmp", mode=cipher.mode, format=FORMAT_PICTURE)
            save_to_pending_operations(CipherPlayground, cipher, format=FORMAT_PICTURE, payload=new_save_path)
            write_image(new_save_path, header, encrypted_data)

    if operation == OP_DECRYPT:
        mode, file_path, iv = CipherPlayground.pending_operations[FORMAT_PICTURE]
        header, encrypted_data = read_image(file_path)

        # Open image, get bytes, decrypt and save decrypted image to path
        if header is not None and encrypted_data is not None:
            if cipher.mode.lower() == CBC:
                cipher.iv = iv
            decrypted_data = cipher.decrypt(encrypted_data, playground=True, format=FORMAT_PICTURE)
            new_save_path = modify_save_path(file_path, tag="_decrypted.bmp", mode=cipher.mode, format=FORMAT_PICTURE)
            write_image(new_save_path, header, decrypted_data)
            del CipherPlayground.pending_operations[FORMAT_PICTURE]
