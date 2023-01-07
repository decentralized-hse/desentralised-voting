from __future__ import annotations

import datetime
import time
from enum import Enum
from threading import Lock
from collections import defaultdict
import json
import operator
from MerkelTree import MerkelTree
from Cryptodome import Random
from Cryptodome.Hash import SHA256
from typing import List, Dict, Any, Optional
import schedule
from VoteTypes import VoteType


class BlockEncoder(json.JSONEncoder):
    def default(self, blockchain_object: ChainBlock):
        return blockchain_object.__dict__


class ChainTransactionHashes:
    def __init__(self, self_hash, parent_hash):
        self.hash = self_hash
        self.parent_hash = parent_hash


class ChainBlock:
    def __init__(self,
                 node_hash: str,
                 nonce: str,
                 parent_hash: Optional[str],
                 merkel_tree: MerkelTree,
                 content: Any,
                 step: int,
                 branch_blocks_count: int):
        self.hash = node_hash
        self.nonce = nonce
        self.parent_hash = parent_hash
        self.merkel_tree = merkel_tree
        self.content = content
        self.step = step
        self.blocks_count = branch_blocks_count


class PeriodType(List[VoteType], Enum):
    Enter = [VoteType.enter_request, VoteType.ask_for_chain]
    Vote = [VoteType.enter_vote]


class InitBlock(ChainBlock):
    def __init__(self,
                 node_hash: str,
                 nonce: str,
                 merkel_tree: MerkelTree,
                 content: Any,
                 step: int,
                 branch_blocks_count: int):
        super().__init__(node_hash, nonce, None, merkel_tree, content, step, branch_blocks_count)
        self.step_length = datetime.timedelta(seconds=4)
        self.start_date = datetime.datetime.now()
        self.start_time = self.start_date.timestamp()
        self.enter_period = ["00:00", "12:00"]
        self.vote_period = ["12:00", "00:00"]
        self.current_period: PeriodType = PeriodType.Enter
        self.voting_topic = "DECENT ELECTIONS"
        self.enter_period_options = {"Yes", "No"}
        self.voting_period_options = {"Vladimir Putin", "Dmitriy Medvedev(wrong choice)", "I wanna go to jail"}


class ShortBlockInfo:
    def __init__(self, hash, branch_blocks_count):
        self.hash = hash
        self.blocks_count = branch_blocks_count


class Blockchain:
    def __init__(self, root_content=None, root_hash: str = '', pow_zeros=1):
        self._min_len = 1
        self._max_len = 1
        self._lock = Lock()
        self._pow_zeros = pow_zeros

        self._hash_to_block: Dict[str, ChainBlock] = dict()
        self._step_to_blocks_info = defaultdict(list)
        self._block_hashes_list: List[str] = []
        self.init_block: InitBlock

        if root_content is not None:
            init_block = self._get_init_block(root_content, root_hash)
            self._hash_to_block[init_block.hash] = init_block
            self._step_to_blocks_info[0].append(
                ShortBlockInfo(init_block.hash, init_block.blocks_count))
            self._block_hashes_list.append(init_block.hash)
            self.init_block = init_block

        self._pool_time_key: Dict[float, str] = dict()
        self._hash_to_content: Dict[str, Any] = dict()

    def _get_init_block(self, root_content, root_hash) -> InitBlock:
        merkle_tree = MerkelTree([root_hash])
        while True:
            nonce = Random.get_random_bytes(8).hex()
            pow = (merkle_tree.tree_top.value + nonce).encode('ascii')
            hexed = SHA256.new(data=pow).hexdigest()
            if hexed.startswith('0' * self._pow_zeros):
                break
        return InitBlock(hexed, nonce, merkle_tree, root_content, 0, 1)

    def add_transaction(self, content: Any, content_hash: str, time: float):
        with self._lock:
            self._hash_to_content[content_hash] = content
            self._pool_time_key[time] = content_hash

    def try_form_block(self, step: int):
        with self._lock:
            block_pool, self._pool_time_key = self._pool_time_key, dict()
            contents, self._hash_to_content = self._hash_to_content, dict()
        if len(block_pool) == 0:
            return
        block_hashes_ordered = [block_pool[t] for t in sorted(block_pool)]
        block_merkle_tree = MerkelTree(block_hashes_ordered)
        pow_hash, nonce, prev_block_info = \
            self._pow_block(block_merkle_tree.tree_top.value, step)

        block = ChainBlock(pow_hash,
                           nonce,
                           prev_block_info.hash,
                           block_merkle_tree,
                           contents,
                           step,
                           prev_block_info.blocks_count + 1)
        self._add_block_to_chain(block)

    def try_add_block(self, block: ChainBlock, skip_checks=False) -> bool:
        if not skip_checks and (not self._validate_hashes(block) or
                                not self._validate_parent(block)):
            return False
        self._add_block_to_chain(block)
        if block.parent_hash is None:
            self.init_block = block
        return True

    def _add_block_to_chain(self, block: ChainBlock):
        with self._lock:
            self._hash_to_block[block.hash] = block
            self._step_to_blocks_info[block.step].append(
                ShortBlockInfo(block.hash, block.blocks_count))
            self._block_hashes_list.append(block.hash)

    def _validate_hashes(self, block: ChainBlock) -> bool:
        if block.parent_hash is None:
            to_hash = block.merkel_tree['tree_top']['value'] + block.nonce
        else:
            to_hash = (block.merkel_tree['tree_top']['value'] +
                       block.parent_hash +
                       block.nonce)
        hashed = SHA256.new(data=to_hash.encode('ascii')).hexdigest()
        return hashed == block.hash and hashed not in self._hash_to_block

    def _validate_parent(self, block: ChainBlock) -> bool:
        if block.parent_hash is None:
            return True
        if block.parent_hash not in self._block_hashes_list:
            return False
        parent_block = self._hash_to_block[block.parent_hash]
        return (parent_block.step < block.step and
                parent_block.blocks_count + 1 == block.blocks_count)

    def _pow_block(self, merkle_root_hash: str, step: int) -> (str, str, ShortBlockInfo):
        while True:
            nonce = Random.get_random_bytes(8).hex()
            prev_block_info = self._appoint_previous_block_info(step)

            pow = (merkle_root_hash + prev_block_info.hash + nonce).encode('ascii')
            hexed_hash = SHA256.new(data=pow).hexdigest()
            if hexed_hash.startswith('0' * self._pow_zeros):
                return hexed_hash, nonce, prev_block_info

    def _appoint_previous_block_info(self, current_block_step: int) -> ShortBlockInfo:
        for step in range(current_block_step - 1, -1, -1):
            candidates = self._step_to_blocks_info[step]
            if len(candidates) > 0:
                return max(candidates, key=lambda c: c.blocks_count)

    def get_actual_chain_backwards(self):
        last_step = max(self._step_to_blocks_info)
        block_hash = sorted(self._step_to_blocks_info[last_step],
                            key=operator.attrgetter('blocks_count'),
                            reverse=True)[0].hash
        while True:
            if block_hash is None:
                return
            block = self._hash_to_block[block_hash]
            yield block.content
            block_hash = block.parent_hash

    def serialize_chain_blocks(self):
        for block_hash in self._block_hashes_list:
            block = self._hash_to_block[block_hash]
            yield json.dumps(block, cls=BlockEncoder).encode('ascii')

    @staticmethod
    def deserialize_block(byte_content):
        content = json.loads(byte_content.decode('ascii'))
        return ChainBlock(content['hash'],
                          content['nonce'],
                          content['parent_hash'],
                          content['merkel_tree'],
                          content['content'],
                          content['step'],
                          content['blocks_count'],)
