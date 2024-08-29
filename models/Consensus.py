import select
import socket
import sys
from models.Transaction import Transaction
from utility.client_server.client_server import send_request
from utility.consensus.utils import (arg_check, check_peer_list_empty,
                                     process_peer_info, get_vote_from_peer,
                                     send_decision_to_peer)
from utility.crypto.aes_utils import AES_encrypt, AES_decrypt
from utility.general.constants import (VOTE_YES, VOTE_NO, CONSENSUS_SUCCESS, CONSENSUS_FAILURE, MODE_INITIATOR,
                                       VOTE_PROMPT, VOTE_YES_KEY, VOTE_NO_KEY, VOTE_SHOW_IMAGE_KEY, MODE_VOTER,
                                       REQ_BUFFER_TIME_VOTER, REQ_BUFFER_TIME_INITIATOR, VOTE_RESULTS_WAIT_MSG,
                                       INITIATOR_NO_PEER_SEND_REQ_ERROR, INITIATOR_NO_PEER_GET_VOTES_ERROR,
                                       INITIATOR_NO_PEER_SEND_RESULTS_ERROR, PURPOSE_SEND_REQ, PURPOSE_GET_PEER_VOTES,
                                       GET_PEER_VOTE_START_MSG, SEND_REQ_PEER_START_MSG, PURPOSE_VOTER_GET_PEER_INFO,
                                       CONSENSUS_INIT_SUCCESS_MSG, CONSENSUS_INIT_MSG, PURPOSE_SEND_FINAL_DECISION,
                                       SEND_FINAL_DECISION_START_MSG)
from utility.general.utils import create_transaction_table, start_parallel_operation


# NOTE: MUST TAKE OUT ALL PEER SOCKETS (to prevent interference with select() function)
# =======================================================================================================

class Consensus:
    """
    A class for launching a Consensus.

    @attention:
        The arguments passed in constructor are
        through reference
    """
    def __init__(self,
                 request: Transaction,
                 is_connected: bool,
                 mode: str, peer_dict: dict,
                 peer_socket: socket.socket = None,
                 peer_list: list[socket.socket] = None):
        """
        A constructor for a Consensus class object.

        @param request:
            A Transaction object (must be signed beforehand)

        @param is_connected:
            A boolean to determine if host is connected to the network

        @param mode:
            A string to determine the host's mode of operation (VOTER or INITIATOR)

        @param peer_dict:
            A dictionary containing IP (key), information such as security params (value)

        @param peer_socket:
            The initiating peer socket (required by the VOTER)

        @param peer_list:
            A list of peer sockets (required by the INITIATOR)

        @return Consensus:
            A Consensus object
        """
        arg_check(mode, peer_list, peer_socket)
        print(CONSENSUS_INIT_MSG)
        self.votes = {VOTE_YES: 0, VOTE_NO: 0}
        self.request = request
        self.is_connected = is_connected
        self.mode = mode
        self.peer_dict = peer_dict
        self.peer_socket = peer_socket
        self.peer_list = peer_list
        self.final_decision = None
        print(CONSENSUS_INIT_SUCCESS_MSG)

    def start(self):
        """
        Starts a consensus (as a voter or initiator).

        @return: final_decision
            A string that determines the consensus results (SUCCESS | FAILURE)
        """
        if self.peer_socket and self.mode == MODE_VOTER: # => VOTER
            vote = self.__perform_vote()
            if self.is_connected:
                return self.__get_vote_results()
            return vote

        if self.peer_list and self.mode == MODE_INITIATOR:  # => INITIATOR
            self.__send_request_to_peers()
            self.__get_vote_results()

            # ONLY IF CONNECTED: Host must include their vote on the request
            self.__perform_vote() if self.is_connected else None

            # Tally and determine the results
            self.__determine_results()

            # ONLY IF CONNECTED: Send results back to all connected peers
            self.__send_final_decision() if self.is_connected else None
            return self.final_decision

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
        # Display the request and prompt vote
        print(create_transaction_table(req_list=[self.request]))
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
            for item in result:
                if item is not None:  # item == ip_to_remove
                    i = 0
                    while i < len(self.peer_list):
                        ip = self.peer_list[i].getpeername()[0]
                        if ip == item:
                            self.peer_list[i].close()  # close socket
                            del self.peer_list[i]      # remove socket from list
                            del self.peer_dict[ip]     # remove peer info
                            print(f"[+] PEER REMOVED: The following peer has been removed {ip} [REASON: Disconnected]")
                            break
                        else:
                            i += 1
        # ===============================================================================
        if not check_peer_list_empty(self, msg=INITIATOR_NO_PEER_SEND_REQ_ERROR):
            peer_info_list = process_peer_info(self, purpose=PURPOSE_SEND_REQ)

            # Use multiprocessing to send to request to multiple peers (in parallel)
            results = start_parallel_operation(task=send_request,
                                               task_args=peer_info_list,
                                               num_processes=len(self.peer_list),
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
            if not check_peer_list_empty(self, msg=INITIATOR_NO_PEER_GET_VOTES_ERROR):
                peer_info_list = process_peer_info(self, purpose=PURPOSE_GET_PEER_VOTES)

                # Use multiprocessing to get votes from peers (in parallel)
                results = start_parallel_operation(task=get_vote_from_peer,
                                                   task_args=peer_info_list,
                                                   num_processes=len(self.peer_list),
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
        if not check_peer_list_empty(self, msg=INITIATOR_NO_PEER_SEND_RESULTS_ERROR):
            peer_info_list = process_peer_info(self, purpose=PURPOSE_SEND_FINAL_DECISION)

            # Use multiprocessing to get votes from peers (in parallel)
            start_parallel_operation(task=send_decision_to_peer,
                                     task_args=peer_info_list,
                                     num_processes=len(self.peer_list),
                                     prompt=SEND_FINAL_DECISION_START_MSG)
