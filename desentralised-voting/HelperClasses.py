from __future__ import annotations

from enum import Enum
import json
from typing import List
from MessageBuilder import VoteType


class BlockEncoder(json.JSONEncoder):
    def default(self, object_to_dict):
        return object_to_dict.__dict__


class ChainTransactionHashes:
    def __init__(self, self_hash, parent_hash):
        self.hash = self_hash
        self.parent_hash = parent_hash


class PeriodType(List[VoteType], Enum):
    Default = []
    Enter = [VoteType.enter_request, VoteType.ask_for_chain]
    Vote = [VoteType.enter_vote, VoteType.process_vote]


class ShortBlockInfo:
    def __init__(self, block_hash, branch_blocks_count):
        self.hash = block_hash
        self.blocks_count = branch_blocks_count
