"""
Description:
This module contains various custom exceptions used in
this project.

"""

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