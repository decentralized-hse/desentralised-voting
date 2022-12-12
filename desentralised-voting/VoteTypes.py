from json import JSONEncoder
from enum import Enum
from typing import List

from Cryptodome import Random
from Utils import get_hash, get_time


class VoteType(int, Enum):
    enter_request = 1
    enter_vote = 2
    process_vote = 3
    are_hashes_valid_request = 4
    are_hashes_valid_response = 5
    old_message = 6
    init_message = 7
    ask_for_chain = 8
    response_chain_ask = 9


necessary_fields = {
    VoteType.enter_request: ['public_key', 'connecting_nodes'],
    VoteType.enter_vote: ['try_enter_name', 'try_enter_address', 'enter_vote'],
    VoteType.process_vote: [],
    VoteType.are_hashes_valid_request: [],
    VoteType.are_hashes_valid_response: [],
    VoteType.old_message: [],
    VoteType.ask_for_chain: ['public_key'],
    VoteType.response_chain_ask: ['blockchain'],
}


class VoteEncoder(JSONEncoder):
    def default(self, vote_object):
        return vote_object.__dict__


class MessageBuilder:
    def __init__(self, vote_type: VoteType, **kwargs):

        self.type = vote_type
        self.variables = kwargs
        self.signer = self.variables.pop('signer')

        try:
            self.body = self.build_base()
        except KeyError:
            print("Missing necessary fields")

        # self.body.update(kwargs)
        self.update_body_based_on_type()

    def build_base(self):
        message = {
            'type': self.type,
            'name': self.variables['name'],
            'start_time': get_time()
        }

        return message

    def update_body_based_on_type(self):
        try:
            first_message = self.type == VoteType.init_message
            for key in necessary_fields[self.type]:
                self.body[key] = self.variables[key]

            my_hash = self._get_proof_of_work_hash(first_message)
            self.update_hash_and_signature(my_hash)

        except KeyError:
            print("missing necessary fields")

    def _get_proof_of_work_hash(self, first_message=False):

        if not first_message:
            self.body['prev_hash'] = self.variables['prev_hash']

        while True:
            self.body['nonce'] = Random.get_random_bytes(8).hex()
            c_hash = get_hash(self.body)
            hexed = c_hash.hexdigest()

            if hexed.startswith('0'):
                return c_hash

    def update_hash_and_signature(self, my_hash):
        self.body['hash'] = my_hash.hexdigest()
        self.body['signature'] = self.signer.sign(my_hash).decode(encoding='latin1')
