import json
from dataclasses import dataclass
from socket import socket
from models.Block import Block
from models.Token import Token
from utility.crypto.ec_keys_utils import hash_data


@dataclass
class Peer:
    """
    A dataclass that represents a Peer.
    """
    ip: str
    first_name: str
    last_name: str
    role: str
    status: str
    transaction_path: str = None
    mode: str = None
    socket: socket = None
    secret: bytes = None
    iv: bytes = None
    token: Token = None
    block: Block = None

    def to_dict(self):
        return {
            "ip": self.ip,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "role": self.role,
            "status": self.status,
            "secret": hash_data(self.secret),
            "iv": hash_data(self.iv),
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=4)