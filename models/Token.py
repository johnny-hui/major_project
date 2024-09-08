from dataclasses import dataclass
from datetime import datetime
from tinyec.ec import Point
from utility.general.constants import FORMAT_DATETIME
from utility.node.node_init import get_current_timestamp


@dataclass
class Token:
    """
    A dataclass that represents a Token.

    @attention Use Case:
        This is used to hold data for a token.
        It is generated, signed, and issued by an admin
        or delegate peer when an approved peer has been
        approved by a majority in the P2P network.
    """
    token: str
    peer_ip: str
    issued_time: datetime
    expiry_time: datetime
    issuers_pub_key: Point
    signature: tuple = None

    def has_expired(self) -> bool:
        """
        Checks if the token has expired.

        @return: Boolean (T/F)
            True if the token has expired, False otherwise.
        """
        if get_current_timestamp(FORMAT_DATETIME) > self.expiry_time:
            print(f"[+] TOKEN EXPIRED: The token issued for {self.peer_ip} has expired!")
            return True
        else:
            return False
