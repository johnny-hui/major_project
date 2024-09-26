import select
import socket
import sys
import threading

from models.Blockchain import Blockchain
from models.Transaction import Transaction
from utility.client_server.client_server import send_request
from utility.consensus.utils import (arg_check, check_sock_list_empty,
                                     process_peer_info, get_vote_from_peer,
                                     send_decision_to_peer)
from utility.crypto.aes_utils import AES_encrypt, AES_decrypt
from utility.deepface.utils import perform_facial_recognition_on_peer
from utility.general.constants import (VOTE_YES, VOTE_NO, CONSENSUS_SUCCESS, CONSENSUS_FAILURE, MODE_INITIATOR,
                                       VOTE_PROMPT, VOTE_YES_KEY, VOTE_NO_KEY, VOTE_SHOW_IMAGE_KEY, MODE_VOTER,
                                       REQ_BUFFER_TIME_VOTER, REQ_BUFFER_TIME_INITIATOR, VOTE_RESULTS_WAIT_MSG,
                                       INITIATOR_NO_PEER_SEND_REQ_ERROR, INITIATOR_NO_PEER_GET_VOTES_ERROR,
                                       INITIATOR_NO_PEER_SEND_RESULTS_ERROR, PURPOSE_SEND_REQ, PURPOSE_GET_PEER_VOTES,
                                       GET_PEER_VOTE_START_MSG, SEND_REQ_PEER_START_MSG, PURPOSE_VOTER_GET_PEER_INFO,
                                       CONSENSUS_INIT_SUCCESS_MSG, CONSENSUS_INIT_MSG, PURPOSE_SEND_FINAL_DECISION,
                                       SEND_FINAL_DECISION_START_MSG)
from utility.general.utils import create_transaction_table, start_parallel_operation


class Consensus:
    """
    A class for launching a Consensus.

    @attention:
        The arguments passed in constructor are through reference

    Attributes:
        votes - A dictionary that holds two values (VOTE_YES, VOTE_NO) and their tallies'
        request - The Transaction object to be voted on
        is_connected - A boolean flag indicating whether the Node is connected
        mode - A string indicating the role of the calling class (MODE_VOTER, MODE_INITIATOR)
        blockchain - A Blockchain that is used to verify peers using facial recognition module (DeepFace)
        peer_dict - A dictionary containing peers (APPROVED and PENDING)
        peer_socket - A socket object (Used by only the 'VOTER' to send their votes to)
        peer_list - A list of peer sockets (Used by the 'INITIATOR' to send the request to all connected peers
        final_decision - A string indicating consensus status; holds two values (CONSENSUS_FAILURE, CONSENSUS_SUCCESS)
        consensus_event - An threading Event object that is used to communicate with other threads
    """
    def __init__(self,
                 request: Transaction,
                 is_connected: bool,
                 mode: str, peer_dict: dict,
                 event: threading.Event,
                 peer_socket: socket.socket = None,
                 sock_list: list[socket.socket] = None,
                 blockchain: Blockchain = None):
        """
        A constructor for a Consensus class object.

        @param request:
            A Transaction object (must be signed beforehand)

        @param is_connected:
            A boolean to determine if host is connected to the network

        @param mode:
            A string to determine the host's mode of operation (VOTER or INITIATOR)

        @param peer_dict:
            A dictionary containing IP (key), information such as security params (required by BOTH)

        @param peer_socket:
            The initiating peer socket (required by the VOTER)

        @param sock_list:
            A list of peer sockets (required by the INITIATOR)

        @param blockchain:
            A Blockchain object (default=None)

        @return Consensus():
            A Consensus object
        """
        arg_check(mode, sock_list, peer_socket)
        print("=" * 160)
        print(CONSENSUS_INIT_MSG)
        self.votes = {VOTE_YES: 0, VOTE_NO: 0}
        self.request = request
        self.is_connected = is_connected
        self.mode = mode
        self.blockchain = blockchain
        self.peer_dict = peer_dict
        self.peer_socket = peer_socket
        self.sock_list = sock_list               # => socket list
        self.final_decision = CONSENSUS_FAILURE  # => default value
        self.consensus_event = event
        print(CONSENSUS_INIT_SUCCESS_MSG)

    def start(self):
        """
        Starts a consensus (as a voter or initiator).

        @return: final_decision
            A string that determines the consensus results (SUCCESS | FAILURE)
        """
        try:
            self.consensus_event.set()                          # => set event (to prevent main menu interference)
            if self.peer_socket and self.mode == MODE_VOTER:    # => VOTER
                vote = self.__perform_vote()
                if self.is_connected:
                    return self.__get_vote_results()
                return vote

            if self.sock_list and self.mode == MODE_INITIATOR:  # => INITIATOR
                self.__send_request_to_peers()
                self.__get_vote_results()

                # ONLY IF CONNECTED: Host must include their vote on the request
                self.__perform_vote() if self.is_connected else None

                # Tally and determine the results
                self.__determine_results()

                # ONLY IF CONNECTED: Send results back to all connected peers
                self.__send_final_decision() if self.is_connected else None
                return self.final_decision
        finally:
            print(f"[+] CONSENSUS ENDED: Consensus for requesting peer (IP: {self.request.ip_addr}) has been completed!")
            print("=" * 160)
            self.consensus_event.clear()


    def __add_vote(self, vote: str):
        if vote in self.votes:
            self.votes[vote] += 1

    def __determine_results(self):
        def get_total_votes():
            return self.votes[VOTE_YES] + self.votes[VOTE_NO]
        # ===============================================================================
        if get_total_votes() == 0:
            print("[+] CONSENSUS ERROR: There are currently no votes to determine results!")
            return None

        yes_percentage = (self.votes[VOTE_YES] / get_total_votes()) * 100
        no_percentage = (self.votes[VOTE_NO] / get_total_votes()) * 100

        if yes_percentage > 50:
            print(f"[+] MAJORITY VOTE: A majority consensus has been reached towards the request from "
                  f"IP ({self.request.ip_addr})")
            self.final_decision = CONSENSUS_SUCCESS
        elif no_percentage > 50:
            print(f"[+] MINORITY VOTE: A minority consensus has been reached; request from "
                  f"IP ({self.request.ip_addr}) will be revoked.")
            self.final_decision = CONSENSUS_FAILURE
        else:
            print(f"[+] CONSENSUS DRAW: A majority cannot be determined as a tie between 'Yes' and 'No' votes "
                  f"has occurred; request from IP ({self.request.ip_addr}) will be revoked.")
            self.final_decision = CONSENSUS_FAILURE

    def __perform_vote(self):
        """
        Initiates a vote on a specific request.
        @return: vote or None
            A string containing (VOTE_YES or VOTE_NO) or None
        """
        def get_vote(prompt: str):
            """
            Prompts the user to vote for the current request.

            @attention: Vote Timeout
                A timeout occurs if the user doesn't vote within
                the timeout timer; hence - an automatic 'NO' vote
                will be returned

            @param prompt:
                A string for the prompt to be printed

            @return: (VOTE_YES or VOTE_NO), and timeout_flag
                A string for a 'Yes' or 'No' vote, and a timeout flag
            """
            vote, buffer_time = None, None
            timeout_flag = False

            # Set buffer time to prevent request expiry
            if self.mode == MODE_INITIATOR:
                buffer_time = REQ_BUFFER_TIME_INITIATOR
            if self.mode == MODE_VOTER:
                buffer_time = REQ_BUFFER_TIME_VOTER

            while vote not in (VOTE_YES_KEY, VOTE_NO_KEY):
                print(prompt.format(self.request.get_time_remaining() - buffer_time), end='', flush=True)
                ready, _, _ = select.select([sys.stdin], [], [],
                                            self.request.get_time_remaining() - buffer_time)
                if ready:
                    vote = sys.stdin.readline().strip().lower()
                    if vote == VOTE_YES_KEY:
                        return VOTE_YES, timeout_flag
                    elif vote == VOTE_NO_KEY:
                        return VOTE_NO, timeout_flag
                    elif vote == VOTE_SHOW_IMAGE_KEY:
                        self.request.show_image()
                    else:
                        print("[+] An invalid input was provided; please try again!")
                else:
                    print("[+] TIMED OUT: A timeout has occurred while waiting for your vote ballot!")
                    timeout_flag = True
                    return VOTE_NO, timeout_flag  # Automatically vote 'NO' on timeout
        # ===============================================================================
        # Display the request on screen
        print(create_transaction_table(req_list=[self.request]))

        # Check if peer exists in the blockchain
        from utility.blockchain.utils import check_peer_exists_in_blockchain
        check_peer_exists_in_blockchain(self.blockchain, peer_ip=self.request.ip_addr)

        # Perform facial recognition on each block photo of the requesting peer against the request photo
        perform_facial_recognition_on_peer(self.blockchain, request=self.request)

        # Prompt for a vote
        vote, timeout = get_vote(VOTE_PROMPT)

        # Voter will send their vote
        if self.mode == MODE_VOTER:
            if not timeout:  # => dont send if timeout
                secret, iv, mode = process_peer_info(self, purpose=PURPOSE_VOTER_GET_PEER_INFO)
                self.peer_socket.send(AES_encrypt(data=vote.encode(), key=secret, mode=mode, iv=iv))
            return vote

        # Initiator will only add their vote to total
        if self.mode == MODE_INITIATOR:
            self.__add_vote(vote)

    def __send_request_to_peers(self):
        """
        A utility function that uses the multiprocessing
        module for the simultaneous sending of the request
        to be voted on by other peers.

        @attention Use Case:
            Function is used exclusively by initiators only

        @return: None
        """
        def remove_peer(index: int, ip_to_remove: str):
            """
            Helper method to close and remove a peer socket and its associated information.
            @param index:
                The current index of the peer socket list
            @param ip_to_remove:
                The IP address of the peer socket to be removed
            @return: None
            """
            self.sock_list[index].close()  # close socket
            del self.sock_list[index]  # remove socket from list
            del self.peer_dict[ip_to_remove]  # remove peer
            print(f"[+] PEER REMOVED: The following peer has been removed (IP: {ip_to_remove}) [REASON: Disconnected]")

        def perform_cleanup(result: list):
            """
            Performs cleanup if any peer disconnection occurs
            while sending requests by removing their saved peer
            info, removing socket from peer_list, and closing
            the socket.

            @param result:
                A list of values returned from send_request function
                [None or IP]

            @return: None
            """
            for ip_to_remove in result:
                if ip_to_remove is not None:
                    i = 0
                    while i < len(self.sock_list):
                        try:
                            peer_ip = self.sock_list[i].getpeername()[0]
                            if ip_to_remove == peer_ip:
                                remove_peer(i, ip_to_remove)
                                break
                            else:
                                i += 1
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            remove_peer(i, ip_to_remove)
                            break
        # ===============================================================================
        if not check_sock_list_empty(self, msg=INITIATOR_NO_PEER_SEND_REQ_ERROR):
            peer_info_list = process_peer_info(self, purpose=PURPOSE_SEND_REQ)

            # Use multiprocessing to send to request to multiple peers (in parallel)
            results = start_parallel_operation(task=send_request,
                                               task_args=peer_info_list,
                                               num_processes=len(self.sock_list),
                                               prompt=SEND_REQ_PEER_START_MSG)

            # Perform any cleanup (for any disconnections that may occur)
            perform_cleanup(results)

    def __get_vote_results(self):
        """
        Wait and gather individual vote results from peers (if initiator);
        Get consensus vote results from an initiator (if voter).

        @return: None or consensus_result
            None (if initiator); the consensus result (if voter)
        """
        def process_votes(result: list):
            for vote in result:
                self.__add_vote(vote)
        # ===============================================================================
        if self.mode == MODE_INITIATOR:
            if not check_sock_list_empty(self, msg=INITIATOR_NO_PEER_GET_VOTES_ERROR):
                peer_info_list = process_peer_info(self, purpose=PURPOSE_GET_PEER_VOTES)

                # Use multiprocessing to get votes from peers (in parallel)
                results = start_parallel_operation(task=get_vote_from_peer,
                                                   task_args=peer_info_list,
                                                   num_processes=len(self.sock_list),
                                                   prompt=GET_PEER_VOTE_START_MSG)
                # Gather and tally the votes
                process_votes(results)

        if self.mode == MODE_VOTER:
            print(VOTE_RESULTS_WAIT_MSG.format(self.request.get_time_remaining()))
            secret, iv, mode = process_peer_info(self, purpose=PURPOSE_VOTER_GET_PEER_INFO)
            consensus_result = AES_decrypt(data=self.peer_socket.recv(1024), key=secret, mode=mode, iv=iv).decode()
            return consensus_result

    def __send_final_decision(self):
        """
        A utility function that uses the multiprocessing
        module for the simultaneous sending of the final
        consensus decision to all connected peers.

        @attention Use Case:
            Function is used exclusively by initiators only

        @return: None
        """
        if not check_sock_list_empty(self, msg=INITIATOR_NO_PEER_SEND_RESULTS_ERROR):
            peer_info_list = process_peer_info(self, purpose=PURPOSE_SEND_FINAL_DECISION)

            # Use multiprocessing to get votes from peers (in parallel)
            start_parallel_operation(task=send_decision_to_peer,
                                     task_args=peer_info_list,
                                     num_processes=len(self.sock_list),
                                     prompt=SEND_FINAL_DECISION_START_MSG)
