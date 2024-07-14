# GETOPTS CONSTANTS
MIN_PORT_VALUE = 1
MAX_PORT_VALUE = 65536
INVALID_SRC_IP_ARG_ERROR = ("[+] INIT ERROR: Invalid format for the source IP address was provided "
                            "(-s option): {}")
INVALID_SRC_PORT_RANGE = ("[+] INIT ERROR: The value provided for source port (-p option) is not "
                          "valid: (not between 1 and 65535)")
INVALID_FORMAT_SRC_PORT_ARG_ERROR = "[+] INIT ERROR: Invalid format provided for the source port (-p option): {}"


# CIPHER CONFIG CONSTANTS
BLOCK_SIZE = 16  # 16 bytes
ROUNDS = 16
DEFAULT_ROUND_KEYS = [
    0xdddddddddddddddd, 0xeeeeeeeeeeeeeeee, 0xaaaaaaaaaaaaaaaa, 0xdddddddddddddddd,
    0xbbbbbbbbbbbbbbbb, 0xeeeeeeeeeeeeeeee, 0xeeeeeeeeeeeeeeee, 0xffffffffffffffff
]
S_BOX = [  # 16 x 16 table
    0x06, 0x28, 0xf2, 0x18, 0xb2, 0x7a, 0xcf, 0xcc, 0xb8, 0x4c,
    0x83, 0xaa, 0x04, 0xc9, 0xed, 0x2a, 0x97, 0xd3, 0x84, 0x08,
    0x8f, 0x3d, 0x56, 0x23, 0xf7, 0xee, 0x72, 0x91, 0x90, 0xc3,
    0x3c, 0x29, 0xdb, 0x99, 0x1f, 0xfa, 0x4b, 0x20, 0xb7, 0xe3,
    0x9d, 0x11, 0x8c, 0xd6, 0xbb, 0x3a, 0x41, 0x33, 0xbc, 0x8e,
    0x54, 0xe1, 0xb6, 0x7e, 0x87, 0xd0, 0x0b, 0xfb, 0xba, 0xe6,
    0xf5, 0xc0, 0x9e, 0x0c, 0xc2, 0xa7, 0x13, 0x2f, 0xf4, 0x77,
    0xd5, 0xf6, 0xa0, 0x6e, 0xf3, 0x7f, 0x5a, 0x1e, 0xc6, 0xce,
    0x09, 0x34, 0x62, 0x75, 0xb6, 0x24, 0x02, 0x2b, 0xeb, 0xd9,
    0xb1, 0x78, 0xff, 0x03, 0x49, 0x0e, 0x94, 0x1c, 0xf1, 0x38,
    0xb0, 0x4e, 0xc7, 0x63, 0x26, 0xe2, 0x80, 0x9a, 0xfe, 0x95,
    0x01, 0x40, 0xc4, 0x17, 0x67, 0x10, 0x2c, 0x3e, 0x31, 0x5b,
    0x61, 0xfc, 0x48, 0x14, 0xda, 0xa9, 0xac, 0x45, 0xc1, 0x35,
    0x1b, 0x85, 0xea, 0xef, 0xd7, 0x3b, 0x36, 0x81, 0xe7, 0x92,
    0x68, 0x30, 0xb4, 0x47, 0x96, 0x2d, 0xf9, 0xbe, 0xd8, 0x44,
    0xf8, 0x25, 0x7d, 0xe0, 0x5f, 0x42, 0xde, 0x19, 0x05, 0x7c,
    0x6d, 0x64, 0x29, 0x3d, 0x0f, 0x8d, 0x65, 0xc5, 0xcd, 0xa3,
    0x98, 0xad, 0xe9, 0xa8, 0x4d, 0x69, 0x0a, 0x2e, 0x5e, 0x8a,
    0x52, 0xcb, 0x66, 0x27, 0x79, 0xbd, 0x39, 0x5c, 0x3f, 0x8b,
    0xdd, 0xbf, 0x51, 0x74, 0x07, 0x1d, 0xd2, 0xd4, 0x86, 0x6b,
    0xb3, 0xa6, 0x82, 0x71, 0xd1, 0x53, 0x57, 0xaf, 0x6c, 0x70,
    0x21, 0xe8, 0xdf, 0xa5, 0x50, 0x58, 0xec, 0x15, 0xdc, 0x59,
    0x16, 0x73, 0x1a, 0x55, 0x9b, 0xab, 0x12, 0xb9, 0xa2, 0xfd,
    0x37, 0x5d, 0xe5, 0x32, 0x93, 0x9c, 0xa4, 0xc8, 0x46, 0x22,
    0xf2, 0x9f, 0x6f, 0xf0, 0x4a, 0xa1, 0xca, 0xae, 0x6a, 0xb5,
    0x7b, 0x89, 0x4f, 0xe4, 0x43, 0x88
]
ECB = "ecb"
CBC = "cbc"


# CIPHER INIT CONSTANTS
CIPHER_INIT_MSG = "[+] Initializing cipher..."
CIPHER_INIT_SUCCESS_MSG = "[+] The cipher has been successfully initialized!"
CIPHER_INIT_CONFIG_TITLE = "Cipher Settings"
CIPHER_INIT_CONFIG_COLUMNS = ["Setting", "Value"]
CIPHER_INIT_CONFIG_ATTRIBUTES = [
    "Mode", "Number of Rounds", "Block Size (bytes)",
    "Main Key", "Initialization Vector(IV)", "Sub-keys"
]
GET_SUBKEY_USER_PROMPT = "[+] Enter 1 (to provide own sub-keys); Enter 2 (to use default sub-keys)"
FORMAT_USER_INPUT = "USER_INPUT"
FORMAT_FILE = "FILE"  # => Path to file
FORMAT_TEXT = "TEXT"
FORMAT_PICTURE = "PICTURE"  # => Path to file
FORMAT_AVALANCHE = "AVALANCHE"
FORMAT_STRING = "STRING"
FORMAT_BYTES = "BYTES"


# NODE INIT CONSTANTS
NODE_INIT_MSG = "[+] Now initializing your node..."
NODE_INIT_SUCCESS_MSG = "[+] Initialization Successful!"


# ROLE CONSTANTS
ROLE_PEER = "PEER"
ROLE_DELEGATE = "DELEGATE"
ROLE_ADMIN = "ADMIN"


# MENU CONSTANTS
MIN_MENU_ITEM_VALUE = 1
MAX_MENU_ITEM_VALUE = 7
MENU_TITLE = "Menu Options"
MENU_FIELD_OPTION = "Option"
MENU_FIELD_DESC = "Command"
INPUT_PROMPT = "[+] Select a menu option: "
MENU_OPTIONS = [
    ["1", "Connect to the P2P Network"],
    ["2", "Approve a Connection Request (Consensus)"],
    ["3", "Revoke Connection Request"],
    ["4", "View Blockchain (Network Connection History)"],
    ["5", "View Pending Connection Requests"],
    ["6", "View Current Peers"],
    ["7", "Disconnect (Close Application)"]
]
MENU_OPTIONS_CONNECTED = [
    ["1", "Send Message to a Peer"],
    ["2", "Send a Connection Request for Approval"],
    ["3", "Revoke a Connection Request"],
    ["4", "View Blockchain (Network Connection History)"],
    ["5", "View Pending Connection Requests"],
    ["6", "View Current Peers"],
    ["7", "Disconnect (Close Application)"]
]
USER_INPUT_START_MSG = "[+] User input (menu) thread has started!"
USER_INPUT_THREAD_NAME = "user_input_menu_thread"
USER_MENU_THREAD_TERMINATE = "[+] THREAD TERMINATION: User menu thread has been successfully terminated!"
SELECT_ONE_SECOND_TIMEOUT = 1
CIPHER_MODE_PROMPT = "[+] CHANGE CIPHER MODE: Enter 1 - CBC; Enter 2 - ECB; (or Enter 0 to quit) "
ACK = "ACK"


# ADMIN/DELEGATE MENU CONSTANTS (WHEN CONNECTED)
ADMIN_MIN_MENU_ITEM_VALUE = 1
ADMIN_MAX_MENU_ITEM_VALUE = 10
ADMIN_MENU_OPTIONS = [
    ["1", "Send Message to a Peer"],
    ["2", "Broadcast a Message"],
    ["3", "Approve a Connection Request (Consensus)"],
    ["4", "Revoke a Connection Request"],
    ["5", "View Blockchain (Network Connection History)"],
    ["6", "View Pending Connection Requests"],
    ["7", "View Current Peers"],
    ["8", "Promote a Peer (as Delegate)"],
    ["9", "Kick a Peer"],
    ["10", "Disconnect (Close Application)"]
]
DELEGATE_MIN_MENU_ITEM_VALUE = 1
DELEGATE_MAX_MENU_ITEM_VALUE = 8
DELEGATE_MENU_OPTIONS = [
    ["1", "Send Message to a Peer"],
    ["2", "Broadcast a Message"],
    ["3", "Approve a Connection Request (Consensus)"],
    ["4", "Revoke a Connection Request"],
    ["5", "View Blockchain (Network Connection History)"],
    ["6", "View Pending Connection Requests"],
    ["7", "View Current Peers"],
    ["8", "Disconnect (Close Application)"]
]


# USER MENU - REGENERATE SUBKEYS CONSTANTS
REGENERATE_SUBKEY_OPTIONS_PROMPT = ("[+] Enter 1 to enter own main key; Enter 2 to generate main key from "
                                    "an elliptic curve (brainpoolP256r1); (or Enter 0 to quit) ")
CHANGE_KEY_PROMPT = "[+] Please enter a new key ({} characters) for encryption: "
REGENERATE_SUBKEY_PROMPT = "[+] Please enter an option to generate new sub-keys: "
REGENERATE_SUBKEY_OPTIONS = [
    "[+] Enter 0 - Exit",
    "[+] Enter 1 - Generate Using Main Key",
    "[+] Enter 2 - Use Default Subkeys",
    "[+] Enter 3 - Provide Own Subkeys",
]


# USER MENU - ENCRYPTION CONSTANTS
USER_ENCRYPT_OPTIONS_PROMPT = "[+] Please select an option for encryption: "
USER_ENCRYPT_OPTIONS = [
    "[+] Enter 0 - Exit",
    "[+] Enter 1 - Encrypt User Input",
    "[+] Enter 2 - Encrypt a Text File",
    "[+] Enter 3 - Encrypt a Picture (Bitmap only)",
]
USER_ENCRYPT_INPUT_PROMPT = "[+] Please enter a plaintext string to encrypt: "
USER_ENCRYPT_FILE_PATH_PROMPT = "[+] Please enter the path of the text file to encrypt: "
USER_ENCRYPT_IMAGE_PATH_PROMPT = "[+] Please enter the path of the image file to encrypt: "


# USER MENU - DECRYPTION CONSTANTS
USER_DECRYPT_OPTIONS_PROMPT = "[+] Please select an option for decryption: "
USER_DECRYPT_OPTIONS = [
    "[+] Enter 0 - Exit",
    "[+] Enter 1 - Decrypt User Input",
    "[+] Enter 2 - Decrypt a Text File",
    "[+] Enter 3 - Decrypt a Picture (Bitmap only)"
]


# AVALANCHE ANALYSIS CONSTANTS
AVALANCHE_ANALYSIS_SPAC_PROMPT = ("[+] AVALANCHE ANALYSIS: Enter 1 to provide own plaintext message (128-bit or "
                                  "16 char only); Enter 2 to use generated plaintext message; or (Enter 0 to quit): ")
AVALANCHE_ANALYSIS_SKAC_PROMPT = ("[+] AVALANCHE ANALYSIS: Enter 1 to provide own key (128-bit or 16 char "
                                  "only); Enter 2 to use a randomly generated a key (from an Elliptic Curve: "
                                  "brainpoolP256r1); or (Enter 0 to quit): ")
AVALANCHE_ANALYSIS_USER_INPUT_KEY = "[+] Enter a key ({} characters only): "
AVALANCHE_ANALYSIS_USER_INPUT = "[+] Enter a plaintext message ({} characters only): "
AVALANCHE_TASK_SPAC_TITLE = "Encryption {} Bit Change in Plaintext (SPAC) - [Starting from MSB]"
AVALANCHE_TASK_SKAC_TITLE = ("Encrypting Ciphertext after {} Bit Changes in Key (SKAC) - {} 4th Bit Position "
                             "[Starting from MSB]")
NO_SUBKEYS_ENCRYPT_MSG = "[+] ENCRYPT ERROR: There are no sub-keys provided!"
NO_SUBKEYS_DECRYPT_MSG = "[+] DECRYPT ERROR: There are no sub-keys provided!"
GRAPH_LABEL_SPAC = ["1 Bit Change in Plaintext", "2 Bit Change in Plaintext", "3 Bit Change in Plaintext",
                    "4 Bit Change in Plaintext", "5 Bit Change in Plaintext", "6 Bit Change in Plaintext",
                    "7 Bit Change in Plaintext", "8 Bit Change in Plaintext", "9 Bit Change in Plaintext",
                    "10 Bit Change in Plaintext"]
GRAPH_LABEL_SKAC = ["1 Bit Change in Key", "2 Bit Change in Key", "3 Bit Change in Key",
                    "4 Bit Change in Key", "5 Bit Change in Key", "6 Bit Change in Key",
                    "7 Bit Change in Key", "8 Bit Change in Key", "9 Bit Change in Key",
                    "10 Bit Change in Key"]
SAVE_GRAPH_DIR = "data/graphs/{}"


# CONNECTION INFO CONSTANTS
CONNECTION_INFO_TITLE = "Current Connections"
CONNECTION_INFO_FIELD_NAME = "Name"
CONNECTION_INFO_FIELD_IP = "IP Address"
CONNECTION_INFO_FIELD_CIPHER_MODE = "Encryption Mode"
CONNECTION_INFO_FIELD_SECRET = "Shared Secret"
CONNECTION_INFO_FIELD_IV = "Initialization Vector (IV)"


# SEND MESSAGE CONSTANTS
SELECT_CLIENT_SEND_MSG_PROMPT = "\n[+] Select a specific client to send a message to (enter a number from {} to {}): "


# TRANSFER FILE CONSTANTS
SEND_FILE_MODE_PROMPT = ("[+] SEND FILE: Enter 1 to send in chunks; Enter 2 to send in bulk (as whole);"
                         " or (Enter 0 to quit): ")
SELECT_CLIENT_SEND_FILE_PROMPT = "\n[+] Select a specific client to transfer a file to (enter a number from {} to {}): "
TRANSFER_FILE_PATH_PROMPT = "[+] Please enter the path of the file to transfer: "
FILE_TRANSFER_SIGNAL = "FILE TRANSFER"
FILE_TRANSFER_BULK_SIGNAL = "FILE TRANSFER BULK"
END_OF_FILE = "EOF"


# TRANSACTION CONSTANTS
TRANSACTION_TO_STR = ("Transaction <Object>: ip_addr={}, port={}, role={}, pub_key={}, "
                      "first_name={}, last_name={}, timestamp={}, signature={}, received_by={}")


# OTHER CONSTANTS
OP_ENCRYPT = "ENCRYPTION"
OP_DECRYPT = "DECRYPTION"
SAVE_FILE_DIR = "data/received/{}"
THREE_MINUTES = 180

