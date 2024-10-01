import json
from dataclasses import dataclass, asdict
from socket import socket
from models.Block import Block
from models.Token import Token


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

    def to_json(self):
        return json.dumps(asdict(self), indent=4)
