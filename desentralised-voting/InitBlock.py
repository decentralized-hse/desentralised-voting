from __future__ import annotations

import datetime
from MerkelTree import MerkelTree
from typing import Any
from ChainBlock import ChainBlock


class InitBlock(ChainBlock):
    def __init__(self,
                 node_hash: str,
                 merkel_tree: MerkelTree,
                 content: Any,
                 public_key: str):
        super().__init__(node_hash, None, merkel_tree, content, public_key, 0)
        self.step_length_in_seconds = 4
        self.start_timestamp = content['start_time']
        start_datetime = datetime.datetime.fromtimestamp(self.start_timestamp)
        self.org_addr = content['org_addr']
        self.org_pub_key = content['org_pub_key']
        self.voting_start_time = f'{start_datetime.hour}:{start_datetime.minute}'
        draft_time = datetime.datetime.now().replace(second=0, microsecond=0)
        enter_end = content['enter_end_time'].split(':')
        self.enter_period_end = draft_time.replace(hour=int(enter_end[0]) - 5,
                                                   minute=int(enter_end[1]))\
                                          .timestamp()
        voting_end = content['voting_end_time'].split(':')
        self.vote_period_end = draft_time.replace(hour=int(voting_end[0]) - 5,
                                                   minute=int(voting_end[1]))\
                                         .timestamp()
        self.voting_topic = "DECENT ELECTIONS"
        self.enter_period_options = ["Yes", "No"]
        self.voting_period_options = content['candidates']
