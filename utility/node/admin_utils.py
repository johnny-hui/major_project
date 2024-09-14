"""
Description:
This Python file provides utility functions for the AdminNode class.

"""
import socket
import time
from utility.crypto.aes_utils import AES_encrypt
from utility.general.constants import (PROMOTE_PEER_PROMPT, ROLE_PEER, PROMOTION_SIGNAL,
                                       UPDATE_NEW_PROMOTED_PEER_SIGNAL, STATUS_APPROVED,
                                       PROMOTE_PEER_SEND_SIGNAL_MSG, ROLE_DELEGATE, REMOVE_PEER_SIGNAL,
                                       KICK_PEER_PROMPT)
from utility.general.utils import start_parallel_operation
from utility.node.node_utils import get_specific_peer_prompt, remove_approved_peer


def kick_peer(self: object):
    if len(self.peer_dict) == 0:
        print("[+] KICK PEER ERROR: There are currently no peers to kick!")
        return None

    # Prompt user to select a peer to kick (exclude admins)
    while True:
        kicked_peer = get_specific_peer_prompt(self, prompt=PROMOTE_PEER_PROMPT)
        if kicked_peer.role in (ROLE_PEER, ROLE_DELEGATE) and kicked_peer.status == STATUS_APPROVED:
            break
        print("[+] KICK PEER ERROR: You cannot kick another admin peer (or pending peers); please try again!")

    # Close the socket connection and clear the information belonging to kicked peer
    remove_approved_peer(self, peer_to_remove=kicked_peer)

    # Get approved peer objects (excluding the promoted peer) and prepare arg_list for multiprocessing
    args_list = []
    for peer in list(self.peer_dict.values()):
        if peer.status == STATUS_APPROVED and peer.socket in self.fd_list:
            self.fd_list.remove(peer.socket)                                    # => to prevent select() interference
            args_list.append((kicked_peer.ip, peer.socket, peer.secret, peer.mode, peer.iv))

    # Wait 1.2 seconds for select() in the main thread to see the changes
    time.sleep(1.2)

    # Send a kick peer signal to every peer
    start_parallel_operation(task=_send_remove_peer_signal,
                             task_args=args_list,
                             num_processes=len(args_list),
                             prompt=KICK_PEER_PROMPT)

    # Re-add the sockets back to fd_list after processing
    for _, sock, _, _, _ in args_list:
        sock.setblocking(True)
        self.fd_list.append(sock)

    # Clear temp list from memory
    del args_list
    print(f"[+] PROMOTION COMPLETE: The selected peer (IP: {kicked_peer.ip}) has been successfully promoted!")


def promote_peer(self: object):
    """
    Promotes a connected peer to the delegate role.

    @param self:
        A reference to the calling class object (AdminNode)

    @return: None
    """
    if len(self.peer_dict) == 0:
        print("[+] PROMOTE PEER ERROR: There are currently no peers to promote!")
        return None

    # Prompt user to select a peer to promote (exclude delegates or admins)
    while True:
        promoted_peer = get_specific_peer_prompt(self, prompt=PROMOTE_PEER_PROMPT)
        if promoted_peer.role == ROLE_PEER and promoted_peer.status == STATUS_APPROVED:
            break
        print("[+] PROMOTE PEER ERROR: You cannot promote a delegate, admin (or any pending peers); please try again!")

    # Send Promotion Signal to Target Peer
    promoted_peer.socket.send(AES_encrypt(data=PROMOTION_SIGNAL.encode(),
                                          key=promoted_peer.secret,
                                          mode=promoted_peer.mode,
                                          iv=promoted_peer.iv))

    # Get approved peer objects (excluding the promoted peer) and prepare arg_list for multiprocessing
    args_list = []
    for peer in list(self.peer_dict.values()):
        if peer.status == STATUS_APPROVED and peer.ip != promoted_peer.ip:
            if peer.socket in self.fd_list:                               # => to prevent select() interference
                self.fd_list.remove(peer.socket)
            args_list.append((promoted_peer.ip, peer.socket, peer.secret, peer.mode, peer.iv))

    # Wait 1.2 seconds for select() in the main thread to see the changes
    time.sleep(1.2)

    # Send an Update signal to every peer regarding promotion (excluding promoted peer)
    start_parallel_operation(task=_send_update_delegate_signal,
                             task_args=args_list,
                             num_processes=len(args_list),
                             prompt=PROMOTE_PEER_SEND_SIGNAL_MSG)

    # Re-add the sockets back to fd_list after processing
    for _, sock, _, _, _ in args_list:
        sock.setblocking(True)
        self.fd_list.append(sock)

    # Clear temp list from memory
    del args_list
    print(f"[+] PROMOTION COMPLETE: The selected peer (IP: {promoted_peer.ip}) has been successfully promoted!")


def _send_update_delegate_signal(promoted_ip: str, peer_sock: socket.socket,
                                 secret: bytes, mode: str, iv: bytes = None):
    """
    A utility function that sends an update signal to all
    connected peers to update their peer dictionaries for
    the newly promoted delegate peer.

    @param promoted_ip:
        The IP address of the promoted peer (string)

    @param peer_sock:
        A peer socket object

    @param secret:
        Bytes of the shared secret

    @param mode:
        The encryption mode: ECB or CBC (string)

    @param iv:
        Bytes of the initialization factor (IV)

    @return: None
    """
    # Set socket to blocking
    peer_sock.setblocking(True)

    # Send update signal to peer
    peer_sock.send(AES_encrypt(data=UPDATE_NEW_PROMOTED_PEER_SIGNAL.encode(), key=secret, mode=mode, iv=iv))

    # Wait for ACK
    peer_sock.recv(1024)

    # Send the IP
    peer_sock.send(AES_encrypt(data=promoted_ip.encode(), key=secret, mode=mode, iv=iv))

    # Wait for ACK
    peer_sock.recv(1024)
    print(f"[+] A Peer update (promotion) have been successfully sent to peer (IP: {peer_sock.getpeername()[0]})")


def _send_remove_peer_signal(kicked_peer_ip: str, peer_sock: socket.socket,
                             secret: bytes, mode: str, iv: bytes = None):
    """
    A utility function that sends a remove peer signal to all
    connected peers to close the socket connection to the kicked
    peer and update their peer dictionaries.

    @param kicked_peer_ip:
        The IP address of the kicked peer (string)

    @param peer_sock:
        A peer socket object

    @param secret:
        Bytes of the shared secret

    @param mode:
        The encryption mode: ECB or CBC (string)

    @param iv:
        Bytes of the initialization factor (IV)

    @return: None
    """
    # Set socket to blocking
    peer_sock.setblocking(True)

    # Send update signal to peer
    peer_sock.send(AES_encrypt(data=REMOVE_PEER_SIGNAL.encode(), key=secret, mode=mode, iv=iv))

    # Wait for ACK
    peer_sock.recv(1024)

    # Send the IP
    peer_sock.send(AES_encrypt(data=kicked_peer_ip.encode(), key=secret, mode=mode, iv=iv))

    # Wait for ACK
    peer_sock.recv(1024)
    print(f"[+] A Peer update (promotion) have been successfully sent to peer (IP: {peer_sock.getpeername()[0]})")
