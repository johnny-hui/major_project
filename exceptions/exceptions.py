"""
Description:
This module contains various custom exceptions used in
this project.

"""
from models.Block import Block

# CONSTANTS
REQUEST_EXISTS_MSG = ("[+] REQUEST REFUSED: An existing request already exists for the current peer; "
                      "connection has been terminated! (IP: {})")
REQUEST_EXPIRED_MSG = ("[+] REQUEST EXPIRED: The received transaction (connection request) has expired "
                       "for the current peer; connection has been terminated! (IP: {})")
INVALID_SIGNATURE_MSG = ("[+] INVALID SIGNATURE: A transaction (connection request) from (IP: {}) contains "
                         "an invalid signature and has been deleted!; connection has been terminated!")
INVALID_PROTOCOL_MSG = "[+] ERROR: Invalid protocol; connection with peer has been terminated (IP: {})!"
TRANSACTION_NOT_FOUND_MSG = "[+] ERROR: Cannot find the Transaction object for the following IP ({})!"
CONSENSUS_INIT_ERROR_MSG = "[+] ERROR: Consensus cannot be started due to insufficient arguments provided! [REASON: {}]"
INVALID_TOKEN_ERROR_MSG = "Cannot verify the signature in the provided approval token [sent from IP: ({})]"
INVALID_BLOCK_ERROR_MSG = "Block {} has an invalid signature!"
INVALID_BLOCKCHAIN_ERROR_MSG = "[+] An error has occurred while validating a blockchain [REASON: {}]"
PEER_REFUSED_BLOCK_ERROR_MSG = "Peer has refused the sent block due to an invalid signature! ({})"
PEER_INVALID_BLOCKCHAIN_MSG = ("The requesting peer has an invalid blockchain! [REASON: blockchain belongs to another "
                               "local P2P network or tampering has occurred]")
PEER_INVALID_BLOCK_HASH_ERROR_MSG = ("[+] The connecting peer (IP: {}) has presented an invalid hash for the "
                                     "block they were issued upon approval into the network!")


class RequestAlreadyExistsError(Exception):
    """
    An exception that raises a RequestAlreadyExistsError.

    @attention Use Case:
        Thrown when request is refused

    @return: None
    """
    def __init__(self, ip: str):
        self.message = REQUEST_EXISTS_MSG.format(ip)
        super().__init__(self.message)


class RequestExpiredError(Exception):
    """
    An exception that raises a RequestExpiredError.

    @attention Use Case:
        Thrown when a connection request has expired

    @return: None
    """
    def __init__(self, ip: str):
        self.message = REQUEST_EXPIRED_MSG.format(ip)
        super().__init__(self.message)


class InvalidSignatureError(Exception):
    """
    An exception that raises an InvalidSignatureError.

    @attention Use Case:
        Thrown when an invalid signature is found
        in a received Transaction (connection request)

    @return: None
    """
    def __init__(self, ip: str):
        self.message = INVALID_SIGNATURE_MSG.format(ip)
        super().__init__(self.message)


class InvalidProtocolError(Exception):
    """
    An exception that raises an InvalidProtocolError.

    @attention Use Case:
        Thrown when connecting peer responds with
        invalid or unknown client/server protocol

    @return: None
    """
    def __init__(self, ip: str):
        self.message = INVALID_PROTOCOL_MSG.format(ip)
        super().__init__(self.message)


class TransactionNotFoundError(Exception):
    """
    An exception that raises a TransactionNotFoundError.

    @attention Use Case:
        Thrown when a Transaction object is not found
        in the 'pending_transactions' list of the Node
        class

    @return: None
    """
    def __init__(self, ip: str):
        self.message = TRANSACTION_NOT_FOUND_MSG.format(ip)
        super().__init__(self.message)


class ConsensusInitError(Exception):
    """
    An exception that raises a TransactionNotFoundError.

    @attention Use Case:
        Thrown when a Transaction object is not found
        in the 'pending_transactions' list of the Node
        class

    @return: None
    """
    def __init__(self, reason: str):
        self.message = CONSENSUS_INIT_ERROR_MSG.format(reason)
        super().__init__(self.message)


class InvalidTokenError(Exception):
    """
    An exception that raises a TransactionNotFoundError.

    @attention Use Case:
        Thrown when a Transaction object is not found
        in the 'pending_transactions' list of the Node
        class

    @return: None
    """
    def __init__(self, ip: str):
        self.message = INVALID_TOKEN_ERROR_MSG.format(ip)
        super().__init__(self.message)


class InvalidBlockError(Exception):
    """
    An exception that raises an InvalidBlockError.

    @attention Use Case:
        Thrown when a Block object has an invalid signature

    @return: None
    """
    def __init__(self, index: int):
        self.message = INVALID_BLOCK_ERROR_MSG.format(index)
        super().__init__(self.message)


class InvalidBlockchainError(Exception):
    """
    An exception that raises an InvalidBlockchainError.

    @attention Use Case:
        Thrown when validating a blockchain and an invalid
        hash or signature is found between one or more blocks.

    @return: None
    """
    def __init__(self, reason: str):
        self.message = INVALID_BLOCKCHAIN_ERROR_MSG.format(reason)
        super().__init__(self.message)


class PeerRefusedBlockError(Exception):
    """
    An exception that raises an PeerRefusedBlockError.

    @attention Use Case:
        Thrown when a peer refuses a block sent by
        another peer due to an invalid signature

    @return: None
    """
    def __init__(self, block: Block):
        self.message = PEER_REFUSED_BLOCK_ERROR_MSG.format(block)
        super().__init__(self.message)


class PeerInvalidBlockchainError(Exception):
    """
    An exception that raises an PeerInvalidBlockchainError.

    @attention Use Case:
        Thrown when a peer has an invalid blockchain (possibly due
        to tampering or blockchain belonging to a different local
        P2P network)

    @return: None
    """
    def __init__(self):
        self.message = PEER_INVALID_BLOCKCHAIN_MSG
        super().__init__(self.message)


class PeerInvalidBlockHashError(Exception):
    """
    An exception that raises an PeerInvalidBlockHashError.

    @attention Use Case:
        Thrown when a connecting peer presents an invalid hash
        for the block, they were issued upon being approved.

    @return: None
    """
    def __init__(self, ip: str):
        self.message = PEER_INVALID_BLOCK_HASH_ERROR_MSG.format(ip)
        super().__init__(self.message)
