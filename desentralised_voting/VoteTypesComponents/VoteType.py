from enum import Enum


class VoteType(int, Enum):
    init_message = 1
    enter_request = 2
    enter_vote = 3
    block = 4
    ask_for_chain = 5
    process_vote = 6