from __future__ import annotations

from threading import Lock
from MerkelTree import MerkelTree
from Cryptodome.Hash import SHA256
from typing import Dict, Any, Optional
from ChainBlock import ChainBlock
from InitBlock import InitBlock
from HelperClasses import *


class Blockchain:
    def __init__(self, public_key: str, root_content=None, root_hash: str = '', pow_zeros=1):
        self._min_len = 1
        self._max_len = 1
        self._lock = Lock()
        self._pow_zeros = pow_zeros
        self._public_key = public_key

        self._hash_to_block: Dict[str, ChainBlock] = dict()
        self.init_block: InitBlock
        self.tail_block: Optional[ChainBlock] = None
        self._tail_candidate_blocks: Dict[str, ChainBlock] = dict()

        if root_content is not None:
            init_block = self._get_init_block(root_content, root_hash)
            self.init_block = init_block
            print('__init__')
            self._add_block_to_tail(init_block)

        self._pool_time_key: Dict[float, str] = dict()
        self._hash_to_content: Dict[str, Any] = dict()

    def _get_init_block(self, root_content, root_hash) -> InitBlock:
        merkle_tree = MerkelTree([root_hash])
        happy_hash = self._get_happy_hash(0)
        print(root_content)
        return InitBlock(happy_hash, merkle_tree, root_content, self._public_key)

    def add_transaction(self, content: Any, content_hash: str, time: float):
        with self._lock:
            self._hash_to_content[content_hash] = content
            self._pool_time_key[time] = content_hash

    def _try_form_block(self, step: int) -> Optional[ChainBlock]:
        with self._lock:
            block_pool, self._pool_time_key = self._pool_time_key, dict()
            contents, self._hash_to_content = self._hash_to_content, dict()
        if len(block_pool) == 0:
            return None
        block_hashes_ordered = [block_pool[t] for t in sorted(block_pool)]
        block_merkle_tree = MerkelTree(block_hashes_ordered)
        happy_hash = self._get_happy_hash(step)
        block = ChainBlock(happy_hash,
                           self.tail_block.hash,
                           block_merkle_tree,
                           contents,
                           self._public_key,
                           step)
        self.add_block_to_step_candidates(block)
        return block

    def _get_happy_hash(self, step: int):
        return self._get_happy_hash_with_key(self._public_key, step)

    def _get_happy_hash_with_key(self, public_key: str, step: int):
        if self.tail_block is None:
            hash_data = f'{public_key}{step}'
        else:
            hash_data = f'{self.tail_block.hash}{public_key}{step}'
        return SHA256.new(data=hash_data.encode('utf-8')).hexdigest()

    def try_add_block(self, block: ChainBlock, skip_checks=False) -> bool:
        if not skip_checks and (not self._validate_hashes(block) or
                                not self._validate_parent(block)):
            return False
        print('try_add_block')
        if block.parent_hash is None:
            self.init_block = block
        self._add_block_to_tail(block)
        return True

    def add_block_to_step_candidates(self, block: ChainBlock):
        if block.step <= self.tail_block.step:
            return
        if len(self._tail_candidate_blocks) == 0 or \
                list(self._tail_candidate_blocks.values())[0].step == block.step:
            if block.parent_hash == self.tail_block.hash:
                self._tail_candidate_blocks[block.hash] = block

    def step_chain_update(self, step: int) -> Optional[ChainBlock]:
        print('candidate blocks', self._tail_candidate_blocks)
        if len(self._tail_candidate_blocks) > 0:
            self._tail_candidate_blocks, candidates = \
                dict(), self._tail_candidate_blocks
            happiest_block = candidates[min(candidates)]
            print('choose_block_for_step')
            self._add_block_to_tail(happiest_block)
        return self._try_form_block(step)

    def _add_block_to_tail(self, block: ChainBlock):
        with self._lock:
            self._hash_to_block[block.hash] = block
            self.tail_block = block
            print(f'hash: {block.hash}, parent: {block.parent_hash}')
            for b in self._get_main_chain_blocks_backwards():
                print(b.hash)

    def _validate_hashes(self, block: ChainBlock) -> bool:
        hashed = self._get_happy_hash_with_key(block.public_key, block.step)
        return hashed == block.hash and hashed not in self._hash_to_block

    def _validate_parent(self, block: ChainBlock) -> bool:
        if block.parent_hash is None and self.tail_block is None:
            return True
        return block.parent_hash == self.tail_block.hash and \
               block.step > self.tail_block.step

    def try_find_transaction_hash_from(self, step: int, target_hash: str):
        block_hash = self.tail_block.hash
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

    def get_actual_chain_backwards(self):
        for block in self._get_main_chain_blocks_backwards():
            yield block.content

    def _get_main_chain_blocks_backwards(self):
        print('tail hash', self.tail_block.hash)
        block_hash = self.tail_block.hash
        while True:
            if block_hash == self.init_block.hash:
                return
            block = self._hash_to_block[block_hash]
            yield block
            block_hash = block.parent_hash

    def serialize_chain_blocks(self):
        for block_hash in self._hash_to_block:
            block = self._hash_to_block[block_hash]
            yield block_hash, json.dumps(block, cls=BlockEncoder).encode('ascii')

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
                              content['merkel_tree'],
                              content['content'],
                              content['public_key'])
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
                          content['parent_hash'],
                          content['merkel_tree'],
                          content['content'],
                          content['public_key'],
                          content['step'], )
