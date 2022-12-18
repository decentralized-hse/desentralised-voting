from __future__ import annotations

from threading import Thread, Lock
from collections import defaultdict
import json
from MerkelTree import MerkelTree
from VoteTypes import VoteEncoder
from Crypto import Random
from Crypto.Hash import SHA256
from typing import List, Dict


class BlockEncoder(json.JSONEncoder):
    def default(self, blockchain_object: ChainBlock):
        return blockchain_object.__dict__


class ChainTransactionHashes:
    def __init__(self, self_hash, parent_hash):
        self.hash = self_hash
        self.parent_hash = parent_hash


class ChainBlock:
    def __init__(self, node_hash, nonce, parent_hash, merkel_tree, content,
                 branch_blocks_count=None, branch_transactions_count=None):
        self.hash = node_hash
        self.nonce = nonce
        self.parent_hash = parent_hash
        self.merkel_tree = merkel_tree
        self.content = content
        self.branch_blocks_count = branch_blocks_count
        self.branch_transactions_count = branch_transactions_count


class ShortBlockInfo:
    def __init__(self, hash, branch_blocks_count, branch_transactions_count):
        self.hash = hash
        self.branch_blocks_count = branch_blocks_count
        self.branch_transactions_count = branch_transactions_count

    @staticmethod
    def get_zero() -> ShortBlockInfo:
        return ShortBlockInfo(None, 0, 0)


class Blockchain:
    def __init__(self, root_content, root_hash, fork_allowed_distance=3, pow_zeros=1):
        self._min_len = 1
        self._max_len = 1
        self._history_len = fork_allowed_distance
        self._leader_transaction_hash = root_hash
        self._lock = Lock()
        self._pow_zeros = pow_zeros

        self._hash_to_block_info = {None: ShortBlockInfo.get_zero()}
        self._local_transactions_pool = []
        self._prev_pool = defaultdict(list)
        self._last_local_block_num = 0
        self._pool_branch_len_to_hashes = defaultdict(list)
        self._pool_branch_len_to_hashes[1].append(ChainTransactionHashes(root_hash, None))
        self._temp_transaction_hash_to_content = {root_hash: root_content}
        self._last_transaction_to_block_hash = dict()
        self._hashes_list = []

        self._doubtful_pool = dict()

    def try_add_transaction(self, content, content_hash, parent_hash):
        current_pool = self._pool_branch_len_to_hashes.items()
        prev_pool = self._prev_pool.items()
        for branch_len, pool_hashes in current_pool:
            if self._try_add_transaction_to_tail(content, content_hash,
                                                 parent_hash, branch_len,
                                                 pool_hashes):
                return True
        for branch_len, pool_hashes in prev_pool:
            if self._try_add_transaction_to_tail(content, content_hash,
                                                 parent_hash, branch_len,
                                                 pool_hashes):
                return True
        return False

    def _try_add_transaction_to_tail(self, content, content_hash, parent_hash,
                                     branch_len, pool_hashes):
        for accepted_hash in pool_hashes:
            if parent_hash != accepted_hash.hash:
                continue
            hashes = ChainTransactionHashes(content_hash, parent_hash)
            with self._lock:
                new_len = branch_len + 1
                if new_len > self._max_len:
                    self._max_len = branch_len + 1
                    self._leader_transaction_hash = content_hash
                    if self._max_len - self._min_len > self._history_len:
                        del self._pool_branch_len_to_hashes[self._min_len]
                        self._min_len = min(
                            self._pool_branch_len_to_hashes.keys())
                self._pool_branch_len_to_hashes[new_len].append(hashes)
                self._temp_transaction_hash_to_content[content_hash] = content
                return True
        return False

    def try_form_block(self):
        with self._lock:
            block_pool = self._pool_branch_len_to_hashes
            self._prev_pool = self._pool_branch_len_to_hashes
            self._pool_branch_len_to_hashes = defaultdict(list)
        if len(block_pool) == 0:
            return
        max_len = max(block_pool.keys())
        blocks_with_max_branch_len = block_pool[max_len]

        if len(blocks_with_max_branch_len) > 1:
            doubtful_keys = self._doubtful_pool.keys()
            max_doubtful_key = max(self._doubtful_pool.keys()) if len(doubtful_keys) > 0 else 0
            block_num = max(self._last_local_block_num, max_doubtful_key) + 1
            self._doubtful_pool[block_num] = block_pool
            return

        # TODO deal with doubtful_pool
        block_hashes, prev_transaction_hash = \
            self._get_step_transactions_chain(block_pool, max_len)
        block_merkle_tree = MerkelTree(block_hashes)

        self._add_block_to_chain(block_hashes,
                                 block_merkle_tree,
                                 prev_transaction_hash)

    def serialize_chain_blocks(self):
        for block_hash in self._hashes_list:
            block = self._hash_to_block_info[block_hash]
            yield json.dumps(block, cls=BlockEncoder).encode('ascii')

    def deserialize_block(self, byte_content):
        content = json.loads(byte_content.decode('ascii'))
        return ChainBlock(content['hash'],
                          content['nonce'],
                          content['parent_hash'],
                          content['merkel_tree'],
                          content['content'],
                          content['branch_blocks_count'],
                          content['branch_transactions_count'],)

    def pow_block(self, merkle_root_hash: str, first_trsctn_parent: str):
        while True:
            nonce = Random.get_random_bytes(8).hex()
            if first_trsctn_parent is None:
                prev_block_hash = ''
            else:
                prev_block_hash = \
                    self._last_transaction_to_block_hash[first_trsctn_parent]

            pow = (merkle_root_hash + prev_block_hash + nonce).encode('ascii')
            hexed_hash = SHA256.new(data=pow).hexdigest()
            if hexed_hash.startswith('0' * self._pow_zeros):
                return hexed_hash, nonce, prev_block_hash

    def _form_block_content_from_transactions(self, block_hashes: List[str]) -> Dict[str, str]:
        content = dict()
        for transaction_hash in block_hashes:
            content[transaction_hash] =\
                self._temp_transaction_hash_to_content.pop(transaction_hash)
        return content

    def _add_block_to_chain(self, block_hashes, block_merkle_tree, prev_transaction_hash):
        pow_hash, nonce, parent_hash = self.pow_block(
            block_merkle_tree.tree_top.value, prev_transaction_hash)

        parent_block = ShortBlockInfo.get_zero() if parent_hash == '' \
            else self._hash_to_block_info[parent_hash]
        block_content = self._form_block_content_from_transactions(block_hashes)
        block = ChainBlock(pow_hash,
                           nonce,
                           parent_hash,
                           block_merkle_tree,
                           block_content)
        block.branch_blocks_count = parent_block.branch_blocks_count + 1
        block.branch_transactions_count = \
            parent_block.branch_transactions_count + len(block_hashes)
        self._hash_to_block_info[pow_hash] = block
        self._last_transaction_to_block_hash[block_hashes[-1]] = pow_hash
        self._hashes_list.append(pow_hash)

    def _get_step_transactions_chain(self,
                                     len_to_hashes: defaultdict,
                                     tail_len: int) -> (List[str], str):
        last_transaction = len_to_hashes[tail_len][0]
        block_parent_transaction_hash = last_transaction.parent_hash
        reversed_list = [last_transaction.hash]
        tail_len -= 1
        while True:
            step_transactions = len_to_hashes[tail_len]
            if len(step_transactions) == 0:
                break
            for prev_transaction in step_transactions:
                if prev_transaction.hash == last_transaction.parent_hash:
                    last_transaction = prev_transaction
                    reversed_list.append(last_transaction.hash)
                    block_parent_transaction_hash = \
                        last_transaction.parent_hash
            tail_len -= 1
        return list(reversed(reversed_list)), block_parent_transaction_hash

    def get_leader_transaction(self):
        with self._lock:
            return self._leader_transaction_hash

    def merge_with_tree(self, other_tree):
        for branch_len in sorted(other_tree.keys()):
            self_prev_blocks = self._branch_len_to_hashes.get(branch_len - 1)
            if self_prev_blocks is None:
                continue
            for other_block in other_tree[branch_len]:
                for parent_candidate in self_prev_blocks:
                    if parent_candidate.hash == other_block.parent_hash:
                        self._branch_len_to_hashes['branch_len'].append(other_block)
                        break
