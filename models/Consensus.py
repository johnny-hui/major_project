import multiprocessing
import select
import socket
import sys
from models.Transaction import Transaction
from utility.client_server.client_server import send_request
from utility.constants import (VOTE_YES, VOTE_NO, CONSENSUS_SUCCESS, CONSENSUS_FAILURE, MODE_INITIATOR,
                               VOTE_PROMPT, VOTE_YES_KEY, VOTE_NO_KEY, VOTE_SHOW_IMAGE_KEY, MODE_VOTER,
                               BUFFER_TIME_VOTER, BUFFER_TIME_INITIATOR, PURPOSE_CONSENSUS, VOTE_RESULTS_WAIT_MSG)
from utility.crypto.aes_utils import AES_encrypt
from utility.utils import create_transaction_table


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
            A string to determine the mode of operation (VOTER or INITIATOR)
        @param peer_dict:
            A dictionary containing IP (key), information such as security params (value)
        @param peer_socket:
            The initiating peer socket (required by the VOTER)
        @param peer_list:
            A list of peer sockets (required by the INITIATOR)
        """
        self.votes = {VOTE_YES: 0, VOTE_NO: 0}
        self.request = request
        self.is_connected = is_connected
        self.mode = mode
        self.peer_dict = peer_dict
        self.peer_socket = peer_socket
        self.peer_list = peer_list
        self.final_decision = None

    def start(self):
        """
        Starts a consensus.

        @return: final_decision
            A string that determines the consensus results (SUCCESS | FAILURE)
        """
        if self.peer_socket and self.mode == MODE_VOTER: # => VOTER
            vote = self.__vote_on_request()
            if self.is_connected:
                return self.__get_vote_results()  # => wait for consensus results
            else:
                return vote

        if self.peer_list and self.mode == MODE_INITIATOR:  # => INITIATOR
            self.__send_request_to_peers()
            self.__get_vote_results()

            # ONLY IF CONNECTED: Host must include their vote on the request
            self.__vote_on_request() if self.is_connected else None

            # Tally and determine the results
            self.__determine_results()

            # ONLY IF CONNECTED: Send results back to all connected peers
            self.__send_results_to_peers() if self.is_connected else None
            return self.final_decision

    def __add_vote(self, vote: str):
        if vote in self.votes:
            self.votes[vote] += 1

    def __get_total_votes(self):
        return self.votes[VOTE_YES] + self.votes[VOTE_NO]

    def __determine_results(self):
        if self.__get_total_votes() == 0:
            print("[+] CONSENSUS ERROR: There are currently no votes to determine results!")
            return None

        yes_percentage = (self.votes[VOTE_YES] / self.__get_total_votes()) * 100
        no_percentage = (self.votes[VOTE_NO] / self.__get_total_votes()) * 100

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

    def __vote_on_request(self):
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
                buffer_time = BUFFER_TIME_INITIATOR
            if self.mode == MODE_VOTER:
                buffer_time = BUFFER_TIME_VOTER

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
        # Display the request and get user vote
        print(create_transaction_table(req_list=[self.request]))
        vote, timeout = get_vote(VOTE_PROMPT)

        # Voter will send their vote (if no timeout)
        if self.mode == MODE_VOTER:
            if not timeout:
                peer_ip = self.peer_socket.getpeername()[0]
                secret, iv, mode = self.peer_dict[peer_ip][2:5]  # => get security params
                self.peer_socket.send(AES_encrypt(data=vote.encode(), key=secret, mode=mode, iv=iv))

        # Initiator will only add their vote to total
        if self.mode == MODE_INITIATOR:
            self.__add_vote(vote)

        return vote

    def __get_vote_results(self):
        if self.mode == MODE_INITIATOR:
            if len(self.peer_list) == 0:
                print("[+] CONSENSUS ERROR: There are currently no peers to get vote results from!")
                return None

            print("[+] Gather all vote results from all peers in list (using parallel multiprocessing)")
            print("[+] Use the BUFFER_TIME_VOTER and setSockTimeout on each peer socket; if timeout, then auto 'NO' vote")

        if self.mode == MODE_VOTER:
            print(VOTE_RESULTS_WAIT_MSG.format(self.request.get_time_remaining()))

    def __send_request_to_peers(self):
        """
        A utility function that uses the multiprocessing
        module for the sending of a request to be voted on
        by other peers.

        @return: None
        """
        def process_peer_info(request: Transaction):
            """
            Processes peer information into arguments suitable for
            multiprocessing.pool().

            @param request:
                A Transaction object

            @return: info_list
                A list of tuples containing information per peer
            """
            info_list = []
            for peer_sock in self.peer_list:
                ip = peer_sock.getpeername()[0]
                secret, iv, mode = self.peer_dict[ip][2:5]  # => get security params
                info_list.append((peer_sock, ip, secret, mode, PURPOSE_CONSENSUS, request, iv))
            return info_list

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
        if len(self.peer_list) == 0:
            print("[+] CONSENSUS ERROR: There are no peers to initiate a consensus and send a request to!")
            return None

        # Process peer information suitable for send_request()
        peer_info = process_peer_info(self.request)

        # Use multiprocessing to send to request to multiple peers (in parallel)
        with multiprocessing.Pool(processes=len(self.peer_list)) as pool:
            print(f"[+] Now sending the request to all peers... [{len(self.peer_list)} threads being used]")
            results = pool.starmap(func=send_request, iterable=peer_info)
            pool.close()
            pool.join()

        # Perform any cleanup (for any disconnections that may occur)
        perform_cleanup(results)


    def __send_results_to_peers(self):
        if len(self.peer_list) == 0:
            print("[+] CONSENSUS ERROR: There are currently no peers to send the consensus results to!")
            return None

        print("[+] IMPLEMENT using multiprocessing and send (self.final_decision)")
