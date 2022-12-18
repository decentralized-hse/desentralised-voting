from json import JSONEncoder
from enum import Enum
from typing import List, Dict, Any

from Crypto import Random
from Utils import get_hash, get_time


class VoteType(int, Enum):
    enter_request = 1
    enter_vote = 2
    init_message = 7
    ask_for_chain = 8
    response_chain_ask = 9


necessary_fields = {
    VoteType.init_message: [],
    VoteType.enter_request: ['public_key'],
    VoteType.enter_vote: ['try_enter_name', 'try_enter_address', 'enter_vote'],
    VoteType.ask_for_chain: ['public_key'],
    VoteType.response_chain_ask: ['blockchain'],
}


class VoteEncoder(JSONEncoder):
    def default(self, vote_object):
        return vote_object.__dict__


class Message:
    def __init__(self, vote_type: VoteType, variables: Dict[str, Any]):
        self.type = vote_type
        self.variables = variables
        self.signer = self.variables.pop('signer')
        self.body = None


class MessageBuilder:
    def __init__(self):
        pass

    def build_message(self, vote_type: VoteType, **kwargs):
        message = Message(vote_type, kwargs)

        try:
            message.body = self.build_base(message)
        except KeyError:
            print("Missing necessary fields")
            return None

        # message.update(kwargs)
        self.update_body_based_on_type(message)
        return message.body

    @staticmethod
    def build_base(message):
        base = {
            'type': message.type,
            'name': message.variables['name'],
            'start_time': get_time()
        }

        return base

    def update_body_based_on_type(self, message):
        try:
            first_message = message.type == VoteType.init_message
            for key in necessary_fields[message.type]:
                message.body[key] = message.variables[key]

            my_hash = self._get_proof_of_work_hash(message, first_message)
            self.update_hash_and_signature(message, my_hash)

        except KeyError:
            print("missing necessary fields")

    @staticmethod
    def _get_proof_of_work_hash(message, first_message=False):

        if not first_message:
            message.body['prev_hash'] = message.variables['prev_hash']

        while True:
            message.body['nonce'] = Random.get_random_bytes(8).hex()
            c_hash = get_hash(message.body)
            hexed = c_hash.hexdigest()

            if hexed.startswith('0'):
                return c_hash

    @staticmethod
    def update_hash_and_signature(message, my_hash):
        message.body['hash'] = my_hash.hexdigest()
        message.body['signature'] = message.signer.sign(my_hash).decode(encoding='latin1')
