from dataclasses import dataclass
from socket import socket


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
    transaction_path: str
    socket: socket = None
    secret: bytes = None
    iv: bytes = None
    mode: str = None
