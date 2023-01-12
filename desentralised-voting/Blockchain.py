from __future__ import annotations

from threading import Lock, Event
from collections import defaultdict
import operator
from MerkelTree import MerkelTree
from Cryptodome import Random
from Cryptodome.Hash import SHA256
from typing import Dict, Any, Optional
from ChainBlock import ChainBlock
from InitBlock import InitBlock
from HelperClasses import *


class Blockchain:
    def __init__(self, root_content=None, root_hash: str = '', pow_zeros=1):
        self._min_len = 1
        self._max_len = 1
        self._lock = Lock()
        self._pow_zeros = pow_zeros

        self._hash_to_block: Dict[str, ChainBlock] = dict()
        self._step_to_blocks_info = defaultdict(list)
        self.init_block: InitBlock

        if root_content is not None:
            init_block = self._get_init_block(root_content, root_hash)
            self._hash_to_block[init_block.hash] = init_block
            self._step_to_blocks_info[0].append(
                ShortBlockInfo(init_block.hash, init_block.blocks_count))
            self.init_block = init_block

        self._pool_time_key: Dict[float, str] = dict()
        self._hash_to_content: Dict[str, Any] = dict()

    def _get_init_block(self, root_content, root_hash) -> InitBlock:
        merkle_tree = MerkelTree([root_hash])
        while True:
            nonce = Random.get_random_bytes(8).hex()
            proof_of_work = (merkle_tree.tree_top.value + nonce).encode('ascii')
            hexed = SHA256.new(data=proof_of_work).hexdigest()
            if hexed.startswith('0' * self._pow_zeros):
                break
        return InitBlock(hexed, nonce, merkle_tree, root_content)

    def add_transaction(self, content: Any, content_hash: str, time: float):
        with self._lock:
            self._hash_to_content[content_hash] = content
            self._pool_time_key[time] = content_hash

    def try_form_block(self, step: int, stopper: Event) -> Optional[ChainBlock]:
        with self._lock:
            block_pool, self._pool_time_key = self._pool_time_key, dict()
            contents, self._hash_to_content = self._hash_to_content, dict()
        if len(block_pool) == 0:
            return None
        block_hashes_ordered = [block_pool[t] for t in sorted(block_pool)]
        block_merkle_tree = MerkelTree(block_hashes_ordered)
        pow_hash, nonce, prev_block_info = \
            self._pow_block(block_merkle_tree.tree_top.value, step, stopper)
        if stopper.is_set():
            return None

        block = ChainBlock(pow_hash,
                           nonce,
                           prev_block_info.hash,
                           block_merkle_tree,
                           contents,
                           step,
                           prev_block_info.blocks_count + 1)
        self._add_block_to_chain(block)
        return block

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
        if block.parent_hash not in self._hash_to_block:
            return False
        parent_block = self._hash_to_block[block.parent_hash]
        return (parent_block.step < block.step and
                parent_block.blocks_count + 1 == block.blocks_count)

    def _pow_block(self, merkle_root_hash: str, step: int, stopper: Event) \
            -> (str, str, ShortBlockInfo):
        while True:
            if stopper.is_set():
                return None, None, None
            nonce = Random.get_random_bytes(8).hex()
            prev_block_info = self._appoint_previous_block_info(step)

            proof_of_work = (merkle_root_hash + prev_block_info.hash + nonce).encode('ascii')
            hexed_hash = SHA256.new(data=proof_of_work).hexdigest()
            if hexed_hash.startswith('0' * self._pow_zeros):
                return hexed_hash, nonce, prev_block_info

    def _appoint_previous_block_info(self, current_block_step: int) -> ShortBlockInfo:
        for step in range(current_block_step - 1, -1, -1):
            candidates = self._step_to_blocks_info[step]
            if len(candidates) > 0:
                return max(candidates, key=lambda c: c.blocks_count)

    def _get_tail_block_hash_naive(self) -> str:
        last_step = max(self._step_to_blocks_info)
        return sorted(self._step_to_blocks_info[last_step],
                      key=operator.attrgetter('blocks_count'),
                      reverse=True)[0].hash

    def try_find_transaction_hash_from(self, step: int, target_hash: str):
        block_hash = self._get_tail_block_hash_naive()
        block = self._hash_to_block[block_hash]
        while block.step >= step:
            for transaction_hash in block.content:
                if transaction_hash == target_hash:
                    return True
            block = self._hash_to_block[block.parent_hash]
        return False

    def get_actual_chain_forwards(self):
        hashes = []
        for block in self._get_main_chain_blocks_backwards():
            hashes.append(block.hash)
        for i in range(len(hashes) - 1, -1, -1):
            yield self._hash_to_block[hashes[i]].content

    def _get_main_chain_blocks_backwards(self):
        block_hash = self._get_tail_block_hash_naive()
        while True:
            if block_hash == self.init_block.hash:
                return
            block = self._hash_to_block[block_hash]
            yield block
            block_hash = block.parent_hash

    def serialize_chain_blocks(self):
        for block_hash in self._hash_to_block:
            block = self._hash_to_block[block_hash]
            yield json.dumps(block, cls=BlockEncoder).encode('ascii')

    @staticmethod
    def block_to_json(block: ChainBlock) -> str:
        return json.dumps(block, cls=BlockEncoder)

    @staticmethod
    def deserialize_block(byte_content: bytes):
        return Blockchain.deserialize_block_from_json(byte_content.decode('ascii'))

    @staticmethod
    def deserialize_block_from_json(json_content: str):
        content = json.loads(json_content)
        if content['step'] == 0:
            block = InitBlock(content['hash'],
                              content['nonce'],
                              content['merkel_tree'],
                              content['content'])
            block.step_length_in_seconds = content['step_length_in_seconds']
            block.org_addr = content['org_addr']
            block.org_pub_key = content['org_pub_key']
            block.start_timestamp = content['start_timestamp']
            block.voting_start_time = content['voting_start_time']
            block.enter_period_end = content['enter_period_end']
            block.vote_period_end = content['vote_period_end']
            block.voting_topic = content['voting_topic']
            block.enter_period_options = content['enter_period_options']
            block.voting_period_options = content['voting_period_options']
            return block
        return ChainBlock(content['hash'],
                          content['nonce'],
                          content['parent_hash'],
                          content['merkel_tree'],
                          content['content'],
                          content['step'],
                          content['blocks_count'], )
