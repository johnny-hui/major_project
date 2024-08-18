# APPLICATION CONSTANTS
APPLICATION_PORT = 323
MAX_IP_VALUE = 256  # => (0-255)

# GETOPTS CONSTANTS
MIN_PORT_VALUE = 1
MAX_PORT_VALUE = 65536
INVALID_SRC_IP_ARG_ERROR = ("[+] INIT ERROR: Invalid format for the source IP address was provided "
                            "(-s option): {}")
INVALID_SRC_PORT_RANGE = ("[+] INIT ERROR: The value provided for source port (-p option) is not "
                          "valid: (not between 1 and 65535)")
INVALID_FORMAT_SRC_PORT_ARG_ERROR = "[+] INIT ERROR: Invalid format provided for the source port (-p option): {}"
INVALID_FIRST_NAME_ERROR = "[+] INIT ERROR: First name must not contain any numbers or special characters (-f option)!"
INVALID_LAST_NAME_ERROR = "[+] INIT ERROR Last name must not contain any numbers or special characters (-l option)!"

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
MONITOR_PENDING_PEERS_THREAD_NAME = "monitor_pending_peers_thread"
MONITOR_PENDING_PEERS_START_MSG = "[+] Monitor pending peers thread has started!"
MONITOR_PENDING_PEERS_THREAD_TERMINATE = ("[+] THREAD TERMINATION: Monitor pending peers thread has been "
                                          "successfully terminated!")

# ROLE CONSTANTS
ROLE_PEER = "PEER"
ROLE_DELEGATE = "DELEGATE"
ROLE_ADMIN = "ADMIN"
STATUS_PENDING = "PENDING"
STATUS_APPROVED = "APPROVED"

# MENU CONSTANTS
MIN_MENU_ITEM_VALUE = 1
MAX_MENU_ITEM_VALUE = 7
MENU_TITLE = "Menu Options"
MENU_FIELD_OPTION = "Option"
MENU_FIELD_DESC = "Command"
INVALID_MENU_SELECTION = "[+] MENU SELECTION: Please enter a valid menu option ({} to {}): "
MENU_ACTION_START_MSG = "\n[+] ACTION SELECTED: Now performing menu item {}..."
INVALID_INPUT_MENU_ERROR = "[+] ERROR: Invalid input was provided to menu: {}"
INPUT_PROMPT = "[+] Select a menu option: "
MENU_OPTIONS = [
    ["1", "Connect to the P2P Network"],
    ["2", "Approve a Connection Request (Self-Vote)"],
    ["3", "Revoke Connection Request"],
    ["4", "View Blockchain (Network Connection History)"],
    ["5", "View Pending Connection Requests"],
    ["6", "View Current Peers"],
    ["7", "Disconnect (Close Application)"]
]
MENU_OPTIONS_CONNECTED = [
    ["1", "Send Message to a Peer"],
    ["2", "Send a Connection Request (for Approval)"],
    ["3", "Revoke Connection Request"],
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
    ["3", "Start a Consensus (Approve Connection Request)"],
    ["4", "Revoke Connection Request"],
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
    ["3", "Start a Consensus (Approve Connection Request)"],
    ["4", "Revoke Connection Request"],
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


# TRANSACTION (CONNECTION REQUESTS) CONSTANTS
TRANSACTION_TO_STRING = ("Transaction <Object>: ip_addr={}, port={}, role={}, pub_key={}, "
                         "first_name={}, last_name={}, timestamp={}, signature(r,s)={}, received_by={}")
TRANSACTION_EXPIRY_TIME = 180
TRANSACTIONS_DIR = "data/transactions/"
SAVE_TRANSACTION_SUCCESS = ("[+] REQUEST SAVED: The connection request has been successfully created and saved to the "
                            "following JSON file: {}")
TRANSACTION_INVALID_SIG_MSG = ("[+] A transaction (connection request) from {} has an invalid signature "
                               "and has been deleted!")
TRANSACTION_MAX_IMG_SIZE = 1048576
TIMESTAMP_FORMAT = "%Y-%m-%d %I:%M:%S %p"
SHARED_KEY_BYTE_MAPPING = {
    29267: None, 10123: None, 761: None, 6305: None,
    1021: None, 39727: None, 4812: None, 82123: None,
    20102: None, 3215: None, 92193: None, 21: None,
    8194: None, 44133: None, 9393: None, 569: None
}
INIT_FACTOR_BYTE_MAPPING = {
    73743: None, 29873: None, 65721: None, 17654: None,
    76523: None, 32457: None, 49128: None, 12058: None,
    57392: None, 60543: None, 781: None, 45932: None,
    10293: None, 62739: None, 50421: None, 94012: None
}
ECB_FLAG = 0x3A
CBC_FLAG = 0x7F
MODE_ECB_BYTE_MAPPING = (53, 0x3A)
MODE_CBC_BYTE_MAPPING = (53, 0x7F)


# KEY EXCHANGE CONSTANTS
MODE_RECEIVE = "RECEIVE"
MODE_INITIATE = "INITIATE"
SHARED_SECRET_SUCCESS_MSG = ("[+] KEY EXCHANGE SUCCESS: A shared secret has been derived for "
                             "the current session ({}) | Number of Bytes = {}")


# CLIENT/SERVER PROTOCOL SIGNALS
ACCEPT_PEER_HANDLER_THREAD_NAME = "accept_new_peer_thread"
PEER_ACTIVITY_HANDLER_THREAD_NAME = "peer_activity_handler_thread"
PHOTO_SIGNAL = "PHOTO"
REQUEST_SIGNAL = "REQUEST"
APPROVED_SIGNAL = "APPROVED"
RECEIVED_TRANSACTION_SUCCESS = ("[+] CONNECTION REQUEST RECEIVED: Successfully received and verified peer's "
                                "Transaction (connection request) from ({})")
CONNECTION_TIMEOUT_ERROR = ("[+] CONNECTION TIMEOUT: A timeout has occurred while attempting to establish a connection "
                            "with IP {} (host offline or experiencing congestion); please try again.")
CONNECTION_ERROR = "[+] CONNECTION ERROR: An error has occurred while connecting to (IP: {}, Port: {})!"
FIND_HOST_TIMEOUT = 3  # => in seconds
TARGET_DISCONNECT_MSG = ("[+] TARGET DISCONNECTED: The target peer has unexpectedly closed the connection "
                         "(or has disconnected); now terminating connection request...")
TARGET_RECONNECT_MSG = ("[+] TARGET DISCONNECTED: The target peer has unexpectedly closed the connection "
                        "(or has disconnected); now attempting to reconnect...")
TARGET_RECONNECT_SUCCESS = ("[+] CONNECTION RE-ESTABLISHED: The connection to target peer has been re-established; "
                            "now awaiting response...")
TARGET_RECONNECT_TIMEOUT = ("[+] RE-CONNECTION TIMEOUT: The target has failed to respond with a consensus decision "
                            "within allocated time; connection has been terminated!")
TARGET_UNSUCCESSFUL_RECONNECT = "[+] RE-CONNECTION FAILED: Failed to reconnect to the target peer!"


# CONNECT TO P2P NETWORK CONSTANTS
CONNECT_METHOD_PROMPT = ("[+] CONNECT OPTIONS: Enter '1' to connect to a specific host; "
                         "Enter '2' to find an available host within local network; "
                         "or (Enter '0' to quit): ")
ENTER_IP_PROMPT = "[+] Enter the IP address of the target peer you would like to connect to: "
INVALID_IP_ERROR = "[+] CONNECTION ERROR: Invalid IP address or format was provided. Please try again."
OWN_IP_ERROR_MSG = "[+] CONNECTION ERROR: Cannot connect to yourself! Please try again."
ACCEPT_NEW_PEER_TIMEOUT = 10  # => in seconds
SEND_REQUEST_MSG = "[+] Sending request to {}..."
SEND_REQUEST_SUCCESS = "[+] Your transaction (connection request) has been successfully sent!"
CONNECTION_AWAIT_RESPONSE_MSG = ("[+] AWAITING RESPONSE: Now awaiting consensus and decision from"
                                 " peers... [Time before expiry = {}]")
CONNECTION_AWAIT_TIMEOUT_MSG = ("[+] RESPONSE TIMEOUT: Wait-time has exceeded; unable to reach a consensus within the "
                                "wait-time allotted for your connection request. Please try again.")
NO_HOST_FOUND = "[+] NO HOSTS FOUND: No available hosts were found; please try again."


# RESPONSE CONSTANTS
RESPONSE_APPROVED = "APPROVED"
RESPONSE_REJECTED = "REJECTED"
RESPONSE_EXPIRED = "EXPIRED"
RESPONSE_EXISTS = "REQ_EXIST"
RESPONSE_INVALID_SIG = "INVALID_SIG"
REQUEST_APPROVED_MSG = "[+] REQUEST ACCEPTED: Your connection request was approved!"
REQUEST_ALREADY_EXISTS_MSG = ("[+] REQUEST REJECTED: Your connection request has been refused by target peer "
                              "[Reason: This current IP has already submitted a request; please try again!]")
REQUEST_REFUSED_MSG = ("[+] REQUEST REJECTED: Your connection request has been refused by the target peer "
                       "[Reason: Insufficient evidence provided or wrong identity!]")
REQUEST_INVALID_SIG_MSG = ("[+] REQUEST REJECTED: Your connection request has been refused by the target peer "
                           "[Reason: An invalid signature provided!]")
REQUEST_EXPIRED_MSG = ("[+] REQUEST REJECTED: Your connection request has been refused by the target peer "
                       "[Reason: The connection request has expired!]")


# VIEW CURRENT PEERS CONSTANTS
PEER_TABLE_TITLE = "Current Peers"
PEER_TABLE_FIELD_PERSON = "Person"
PEER_TABLE_FIELD_IP = "IP Address"
PEER_TABLE_FIELD_CIPHER_MODE = "Encryption Mode"
PEER_TABLE_FIELD_SECRET = "Shared Secret"
PEER_TABLE_FIELD_IV = "Initialization Vector (IV)"
PEER_TABLE_FIELD_STATUS = "Status"

# VIEW CONNECTION REQUESTS CONSTANTS
CONN_REQUEST_TABLE_TITLE = "Pending Connection Requests"
CONN_REQUEST_TABLE_FIELD_IP = "IP Address"
CONN_REQUEST_TABLE_FIELD_PORT = "Port"
CONN_REQUEST_TABLE_FIELD_PERSON = "Person"
CONN_REQUEST_TABLE_FIELD_ROLE = "Role"
CONN_REQUEST_TABLE_FIELD_PUB_KEY = "Public Key"
CONN_REQUEST_TABLE_FIELD_TIMESTAMP = "Timestamp"
CONN_REQUEST_TABLE_FIELD_RECEIVED_BY = "Received By"
CONN_REQUEST_TABLE_FIELD_SIGNATURE = "Signature"
VIEW_REQUEST_FURTHER_ACTION_PROMPT = ("[+] VIEW REQUEST OPTIONS: Enter 1 to select a specific request to view photo "
                                      "from or (Enter '0' to exit): ")
VIEW_PHOTO_PROMPT = "[+] VIEW PHOTO: Select a specific request's photo to view from [enter a value from 0 to {}]: "


# REVOKE CONNECTION REQUEST CONSTANTS
REVOKE_REQUEST_INITIAL_PROMPT = "[+] REVOKE REQUEST: Enter 1 to select revoke a request or (Enter '0' to quit): "
REVOKE_REQUEST_PROMPT = "[+] REVOKE REQUEST: Select a specific request to revoke [enter a value from 0 to {}]: "


# APPROVE CONNECTION REQUEST CONSTANTS


# OTHER CONSTANTS
OP_ENCRYPT = "ENCRYPTION"
OP_DECRYPT = "DECRYPTION"
SAVE_FILE_DIR = "data/received/{}"
