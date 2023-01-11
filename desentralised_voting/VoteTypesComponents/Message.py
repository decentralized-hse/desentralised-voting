from .VoteType import VoteType
from typing import Dict, Any


class Message:
    def __init__(self, vote_type: VoteType, variables: Dict[str, Any]):
        self.type = vote_type
        self.variables = variables
        self.signer = self.variables.pop('signer')
        self.body = None
