"""
Description:
This python file is responsible for providing utility functions
to the Consensus class.

"""
import socket
from exceptions.exceptions import ConsensusInitError
from models.Transaction import Transaction
from utility.general.constants import REQ_BUFFER_TIME_VOTER, GET_PEER_VOTE_TIMEOUT_MSG, VOTE_NO, MODE_INITIATOR, \
    PEER_LIST_NOT_PROVIDED_ERROR, PEER_LIST_EMPTY_ERROR, INITIATOR_SOCK_NOT_PROVIDED_ERROR, PURPOSE_SEND_REQ, \
    PURPOSE_CONSENSUS, PURPOSE_GET_PEER_VOTES, MODE_VOTER, PURPOSE_VOTER_GET_PEER_INFO, PURPOSE_SEND_FINAL_DECISION
from utility.crypto.aes_utils import AES_decrypt, AES_encrypt


def get_vote_from_peer(peer_sock: socket.socket, request: Transaction,
                       ip: str, secret: bytes, mode: str, iv: bytes = None):
    """
    Gets a vote from a peer.

    @attention Use Case:
        Used by an initiator in parallel (multiprocessing)

    @param peer_sock:
        A peer socket object

    @param request:
        A Transaction object

    @param ip:
        The peer's IP address (String)

    @param secret:
        Bytes of the shared secret

    @param mode:
        A string for the peer's encryption mode

    @param iv:
        Bytes of the initialization factor (IV)

    @return: vote
        A string containing either (VOTE_NO, VOTE_YES)
    """
    try:
        peer_sock.settimeout(request.get_time_remaining() - REQ_BUFFER_TIME_VOTER)
        vote = AES_decrypt(data=peer_sock.recv(1024), key=secret, mode=mode, iv=iv).decode()
        print(f"[+] VOTE RECEIVED: Successfully received a '{vote}' vote from peer (IP: {ip})")
        return vote
    except socket.timeout:
        print(GET_PEER_VOTE_TIMEOUT_MSG.format(ip))
        return VOTE_NO


def send_decision_to_peer(peer_sock: socket.socket, decision: str, ip: str,
                          secret: bytes, mode: str, iv: bytes = None):
    """
    Sends the final consensus decision to a specific peer.

    @attention Use Case:
        Used by an initiator in parallel (multiprocessing)

    @param peer_sock:
        A peer socket object

    @param decision:
        A string containing the final consensus decision
        (CONSENSUS_SUCCESS/CONSENSUS_FAILURE)

    @param ip:
        The peer's IP address (String)

    @param secret:
        Bytes of the shared secret

    @param mode:
        A string for the peer's encryption mode

    @param iv:
        Bytes of the initialization factor (IV)

    @return: None
    """
    peer_sock.setblocking(True)
    peer_sock.send(AES_encrypt(data=decision.encode(), key=secret, mode=mode, iv=iv))
    print(f"[+] The final consensus decision has been successfully sent to peer (IP: {ip})!")


def arg_check(mode: str, peer_list: list[socket.socket], peer_sock: socket.socket):
    """
    Checks if proper arguments have been passed in
    to constructor.

    @raise ConsensusInitError:
        Raised if required arguments are not provided

    @return: None
    """
    if mode == MODE_INITIATOR:
        if peer_list is None:
            raise ConsensusInitError(reason=PEER_LIST_NOT_PROVIDED_ERROR)
        if len(peer_list) == 0:
            raise ConsensusInitError(reason=PEER_LIST_EMPTY_ERROR)

    if mode == MODE_VOTER:
        if peer_sock is None:
            raise ConsensusInitError(reason=INITIATOR_SOCK_NOT_PROVIDED_ERROR)


def check_peer_list_empty(self: object, msg: str):
    """
    Checks if peer list is empty.

    @attention Use Case:
        This function is only used by initiator in the
        event the peer list is empty (due to disconnections)

    @param self:
        A reference to the calling class object (Consensus)

    @param msg:
        A string for the error message to be displayed

    @return: None
    """
    if len(self.peer_list) == 0:
        print(msg)
        return True
    return False


def process_peer_info(self: object, purpose: str):
    """
    Processes peer information into arguments suitable for
    parallel operations using multiprocessing.pool.starmap()
    based on a purpose.

    @attention Use Case:
        Only used by an initiator

    @param self:
        A reference to the calling class object (Consensus)

    @param purpose:
        A string defining the peer information to be returned
        depending on the usage (send request or get peer votes)

    @return: info_list or (secret, iv, mode)
        A list of tuples containing information per peer
    """
    info_list = []

    if purpose == PURPOSE_SEND_REQ:
        for peer_sock in self.peer_list:
            ip = peer_sock.getpeername()[0]
            peer = self.peer_dict[ip]  # => get peer
            info_list.append((peer_sock, ip, peer.secret, peer.mode, PURPOSE_CONSENSUS, self.request, peer.iv))
        return info_list

    if purpose == PURPOSE_GET_PEER_VOTES:
        for peer_sock in self.peer_list:
            ip = peer_sock.getpeername()[0]
            peer = self.peer_dict[ip]
            info_list.append((peer_sock, self.request, ip, peer.secret, peer.mode, peer.iv))
        return info_list

    if purpose == PURPOSE_SEND_FINAL_DECISION:
        for peer_sock in self.peer_list:
            ip = peer_sock.getpeername()[0]
            peer = self.peer_dict[ip]
            info_list.append((peer_sock, self.final_decision, ip, peer.secret, peer.mode, peer.iv))
        return info_list

    if purpose == PURPOSE_VOTER_GET_PEER_INFO:
        ip = self.peer_socket.getpeername()[0]
        peer = self.peer_dict[ip]
        return peer.secret, peer.iv, peer.mode
