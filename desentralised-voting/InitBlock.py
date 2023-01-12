from __future__ import annotations

import datetime
from MerkelTree import MerkelTree
from typing import Any
from ChainBlock import ChainBlock


class InitBlock(ChainBlock):
    def __init__(self,
                 node_hash: str,
                 nonce: str,
                 merkel_tree: MerkelTree,
                 content: Any):
        super().__init__(node_hash, nonce, None, merkel_tree, content, 0, 1)
        self.step_length_in_seconds = 4
        self.start_timestamp = content['start_time']
        start_datetime = datetime.datetime.fromtimestamp(self.start_timestamp)
        self.org_addr = content['org_addr']
        self.org_pub_key = content['org_pub_key']
        self.voting_start_time = f'{start_datetime.hour}:{start_datetime.minute}'
        self.enter_period_end = content['enter_end_time']
        self.vote_period_end = content['voting_end_time']
        self.voting_topic = "DECENT ELECTIONS"
        self.enter_period_options = ["Yes", "No"]
        self.voting_period_options = content['candidates']
