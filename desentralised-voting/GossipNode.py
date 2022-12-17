from __future__ import annotations

import copy
import random
import socket
from threading import Thread, Lock
import time
from typing import Dict, Any

import ntplib
from collections import defaultdict
from Cryptodome import Random
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature.pkcs1_15 import PKCS115_SigScheme
import json
from MerkelTree import MerkelTree
from VoteTypes import VoteType, VoteEncoder, MessageBuilder
from Utils import get_hash, get_time


class ThreadWithReturn(Thread):
    def __init__(self, function):
        Thread.__init__(self)
        self.function = function
        self.value = None

    def run(self, *args):
        self.value = self.function(*args)


class ChainTransactionHashes:
    def __init__(self, self_hash, parent_hash):
        self.hash = self_hash
        self.parent_hash = parent_hash


class ChainBlock:
    def __init__(self, node_hash, nonce, parent_hash, merkel_tree,
                 branch_blocks_count = None, branch_transactions_count = None):
        self.hash = node_hash
        self.nonce = nonce
        self.parent_hash = parent_hash
        self.merkel_tree = merkel_tree
        self.branch_blocks_count = branch_blocks_count
        self.branch_transactions_count = branch_transactions_count


class Blockchain:
    def __init__(self, root_content, root_hash, fork_allowed_distance=3, pow_zeros=5):
        self._min_len = 1
        self._max_len = 1
        self._history_len = fork_allowed_distance
        self._leader_hash = root_hash
        self._lock = Lock()
        self._pow_zeros = pow_zeros

        zero_block = ChainBlock(None, None, None, None, 0, 0)
        self._hash_to_block = {None: zero_block}
        self._local_transactions_pool = []
        self._prev_pool = defaultdict(list)
        self._last_local_block_num = 0
        self._pool_branch_len_to_hashes = defaultdict(list)
        self._pool_branch_len_to_hashes[1].append(ChainTransactionHashes(root_hash, None))
        self._temp_hash_to_content = {root_hash: root_content}

        self._doubtful_pool = dict()

    def try_add_transaction(self, content, content_hash, parent_hash):
        current_pool, prev_pool = self._pool_branch_len_to_hashes.items(), \
                                  self._prev_pool.items()
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
            if parent_hash != accepted_hash:
                continue
            hashes = ChainTransactionHashes(content_hash, parent_hash)
            with self._lock:
                new_len = branch_len + 1
                if new_len > self._max_len:
                    self._max_len = branch_len + 1
                    self._leader_hash = content_hash
                    if self._max_len - self._min_len > self._history_len:
                        del self._pool_branch_len_to_hashes[self._min_len]
                        self._min_len = min(
                            self._pool_branch_len_to_hashes.keys())
                self._pool_branch_len_to_hashes[new_len].append(hashes)
                self._temp_hash_to_content[content_hash] = content
                return True
        return False

    def try_form_block(self):
        with self._lock:
            block_pool = self._pool_branch_len_to_hashes
            self._prev_pool = self._pool_branch_len_to_hashes
            self._pool_branch_len_to_hashes = defaultdict(list)
        if len(block_pool) == 0:
            return
        branch_max_len = block_pool[max(block_pool.keys())]

        if len(branch_max_len) > 0:
            block_num = max(self._last_local_block_num,
                            max(self._doubtful_pool.keys())) + 1
            self._doubtful_pool[block_num] = block_pool
            return

        # TODO deal with doubtful_pool
        block_hashes, prev_transaction_hash = \
            self._get_step_transactions_chain(block_pool, branch_max_len)
        block_merkle_tree = MerkelTree(block_hashes)
        pow_hash, nonce, parent_hash = self.pow_block(
            block_merkle_tree.tree_top.value, prev_transaction_hash)
        self.add_block_to_chain(pow_hash, nonce, block_merkle_tree, parent_hash)

    def pow_block(self, merkle_root_hash, first_transaction_parent):
        while True:
            nonce = Random.get_random_bytes(8).hex()
            prev_block_hash = None # TODO get previous block hash
            pow = (merkle_root_hash + prev_block_hash + nonce).encode('ascii')
            hexed_hash = SHA256.new(data=pow).hexdigest()
            if hexed_hash.startswith('0' * self._pow_zeros):
                return hexed_hash, nonce, prev_block_hash

    def add_block_to_chain(self, block_pow_hash, nonce, block_merkle_tree,
                           prev_block_hash, block_transactions_count):
        parent_block = self._hash_to_block[prev_block_hash]
        block = ChainBlock(block_pow_hash, nonce, block_merkle_tree, prev_block_hash)
        block.branch_blocks_count = parent_block.branch_blocks_count + 1
        block.branch_transactions_count = \
            parent_block.branch_transactions_count + block_transactions_count
        self._hash_to_block[block_pow_hash] = block

    def _get_step_transactions_chain(self,
                                     len_to_hashes: defaultdict,
                                     tail_len: int):
        last_transaction = len_to_hashes[tail_len][0]
        block_parent_transaction_hash = last_transaction.parent_hash
        reversed_list = [last_transaction.hash]
        tail_len -= 1
        while True:
            try:
                for prev_transaction in len_to_hashes[tail_len]:
                    if prev_transaction.hash == last_transaction.parent_hash:
                        last_transaction = prev_transaction
                        reversed_list.append(last_transaction.hash)
                        block_parent_transaction_hash = \
                            last_transaction.parent_hash
            except KeyError:
                break
        answer = reversed_list.reverse()
        return answer, block_parent_transaction_hash

    def get_leader_transaction(self):
        with self._lock:
            return self._leader_hash

    def tree_to_json(self):
        return json.dumps(self._branch_len_to_hashes, cls=VoteEncoder)

    @staticmethod
    def tree_from_json(json_chain):
        return json.loads(json_chain)

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


class MessageHandler:
    def __init__(self, gossip_node: GossipNode):
        self.gossip_node = gossip_node

    def handle_chain_request(self, address):
        # TODO send blockchain:
        # 1) serialize blockchain (.serialize_chain -> bytes, .deserialize_chain) - S
        # 2) send probably large amount of data -> TCP?
        response = self.gossip_node.message_builder.build_message(VoteType.response_chain_ask,
                                                                  signer=self.gossip_node.signer,
                                                                  name=self.gossip_node.name,
                                                                  prev_hash=self.gossip_node.blockchain.get_leader(),
                                                                  blockchain=self.gossip_node.blockchain.tree_to_json())

        with self.gossip_node.node_lock:
            self.gossip_node.node.sendto(json.dumps(response).encode('ascii'), address)

    def handle_chain_response(self, response: Dict[str, Any]):
        other_chain_tree = Blockchain.tree_from_json(response['blockchain'])
        self.gossip_node.blockchain.merge_with_tree(other_chain_tree)

    def handle_enter_request_to_transmit(self, address, message_dict: Dict[str, Any]):
        # so now we only get enter_request if we don't have the node in susceptible, we do not spread this type of msg

        # adding node to voting_process and candidates_keys
        # not adding node to susceptible yet so we don't spread enter_vote messages to it
        self.gossip_node.susceptible_nodes.append(address)
        self.gossip_node.request_voting_process[address] = set()
        self.gossip_node.candidates_keys[address] = message_dict['public_key']

        self.handle_vote_spreading(address, message_dict['name'])

    def handle_vote_spreading(self, address, try_enter_name: str):
        # asking user to vote
        vote = input("New user {} is requesting enter permission. Do you grant permission(Yes/No)?"
                     "Message in any format other than 'Yes' will be taken as No."
                     .format(try_enter_name))

        # add ourself if the vote is Yes
        if vote == "Yes":
            self.gossip_node.request_voting_process[address].add(self.gossip_node.name)

        # building message to spread voting
        message = self.gossip_node.message_builder.build_message(VoteType.enter_vote,
                                                                 signer=self.gossip_node.signer,
                                                                 name=self.gossip_node.name,
                                                                 prev_hash=self.gossip_node.blockchain.get_leader(),
                                                                 try_enter_address=address[0] + ':' + str(address[1]),
                                                                 try_enter_name=try_enter_name,
                                                                 enter_vote=vote == "Yes")

        # transmiting message to all susceptible nodes
        vote_thread = Thread(target=self.gossip_node.input_message, args=(message,))
        vote_thread.start()

    def handle_enter_vote_to_transmit(self, address, message_dict: Dict[str, Any]):
        # we already know about this node and voted for it
        if address in self.gossip_node.request_voting_process.keys():
            # adding received vote if it wasn't added already (that's why set)
            self.gossip_node.request_voting_process[address].add(message_dict['name'])

            # checking if there is enough votes for applying node to be trusted
            if len(self.gossip_node.request_voting_process[address]) == 2:
                self.gossip_node.other_public_keys[address] = self.gossip_node.candidates_keys.pop(address)

        else:
            # adding our vote plus the vote we received and spread our vote
            self.gossip_node.request_voting_process[address] = {message_dict['name']}
            self.handle_vote_spreading(address, message_dict['try_enter_name'])


class GossipNode:

    """
    difficulty_level == amount of zeros in the beginning of hash that brove your work
    voting_progress == current state of election
    """

    difficulty_level = 2
    key_difficulty_level = 1
    voting_progress = {}
    request_voting_process = {}
    candidates_keys = {}
    step_period = 4

    def __init__(self, host, port, connected_nodes, name):
        self.node = socket.socket(type=socket.SOCK_DGRAM)
        self.node_lock = Lock()
        self.hostname = host
        self.port = port
        self.name = name
        self.node.bind((self.hostname, self.port))
        while True:
            self.private_key = RSA.generate(2048)
            self.public_key = self.private_key.publickey().export_key().decode(
                encoding='latin1')
            key_hash = get_hash(self.public_key).hexdigest()
            if key_hash.startswith('0' * self.key_difficulty_level):
                break
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey().export_key().decode(
            encoding='latin1')
        self.signer = PKCS115_SigScheme(self.private_key)
        self.message_handler = MessageHandler(self)
        self.message_builder = MessageBuilder()

        self.susceptible_nodes = connected_nodes
        # clients that you are connected to and who already received message
        self.infected_neighbours = []

        self.ntp_client = ntplib.NTPClient()

        self.other_public_keys = dict()
        self.hashes_lock = Lock()
        self.prev_message_time_to_hashes = dict()
        self.current_block = []
        self.processed_block = []

        if len(self.susceptible_nodes) == 0:

            init_message = self.message_builder.build_message(VoteType.init_message,
                                                              signer=self.signer,
                                                              name=self.name)

            self.blockchain = Blockchain(init_message['hash'])
        else:
            Thread(target=self._enter_network).start()

        self._get_move()

        print(f'{self.port} created successfully')
        self.start_threads()

    def _enter_network(self):
        while self.blockchain is not None:
            time.sleep(1)
        message = self.message_builder.build_message(VoteType.ask_for_chain,
                                                     signer=self.signer,
                                                     name=self.name,
                                                     public_key=self.public_key,
                                                     prev_hash=self.blockchain.get_leader())

        self.input_message(message)

    def _get_move(self):
        self.node.connect(('127.0.0.1', 12345))

        self.node.sendall(b'hello')
        message, address = self.node.recvfrom(2048)
        data = json.loads(message.decode('ascii'))
        self.move_number = data['move_number']
        self.move_time_left_sec = data['move_time_left_sec']
        print(f'move number = {self.move_number}; move time left = {self.move_time_left_sec}')

    def monitor_moves(self):
        while True:
            while self.move_time_left_sec:
                time.sleep(1)
                self.move_time_left_sec -= 1

            self.move_number += 1
            self.move_time_left_sec += 4
            self.processed_block = self.current_block
            self.current_block = []
            Thread(target=self._add_new_block).start()

    def _add_new_block(self):
        block_to_add = []
        for message in self.processed_block:
            copied_message = copy.deepcopy(message)
            block_to_add.append(copied_message)

        if not self.blockchain.try_add_block(block_to_add):
            return

    def input_message(self, message):
        infected_nodes = []
        healthy_nodes = self.susceptible_nodes.copy()
        # current_time = get_time()

        # while (self.step_start is not None and
        #        current_time - self.step_start > GossipNode.step_period):
        #     time.sleep(100)
        #     current_time = get_time()

        self.current_block.append(message)

        self.transmit_message(json.dumps(message).encode('ascii'),
                              infected_nodes,
                              healthy_nodes)
        print(f'You successfully voted for {message["type"]}, {message["content"]}')

    def send_blockchain_requests(self):
        req_message = self.message_builder.build_message(VoteType.ask_for_chain,
                                                         signer=self.signer,
                                                         name=self.name,
                                                         prev_hash=self.blockchain.get_leader(),
                                                         public_key=self.public_key).body

        self.input_message(req_message)

    def read_message_exists_answer(self, response):
        converted_dict = json.loads(response.decode('ascii'))
        if self._check_message(converted_dict):
            return set(converted_dict['extra'])
        return set()

    def ask_connected_for_messages(self, suspicious):
        message = self.message_builder.build_message(VoteType.are_hashes_valid_request,
                                                     signer=self.signer,
                                                     name=self.name,
                                                     prev_hash=self.blockchain.get_leader(),
                                                     what_is_it=suspicious)

        temp_socket = socket.socket(type=socket.SOCK_DGRAM)
        temp_socket.bind((self.hostname, 12345))
        connected_nodes = self.susceptible_nodes.copy()
        for node in connected_nodes:
            temp_socket.sendto(json.dumps(message).encode('ascii'), node)
        threads = []
        for i in range(len(connected_nodes)):
            temp_socket.settimeout(1)
            response = temp_socket.recv(1024)
            t = ThreadWithReturn(self.read_message_exists_answer)
            t.run(response)
            threads.append(t)
        [t.join() for t in threads]
        return set.intersection(t.value for t in threads)

    def response_message_exists(self, messages_list, host, port):
        to_check = set(messages_list)
        local = set(self.prev_step_hashes)
        answer = list(to_check.intersection(local))
        message = self.message_builder.build_message(VoteType.are_hashes_valid_response,
                                                     signer=self.signer,
                                                     name=self.name,
                                                     prev_hash=self.blockchain.get_leader(),
                                                     what_is_it=answer)

        with self.node_lock:
            self.node.sendto(json.dumps(message).encode('ascii'), (host, port))

    def _get_pub_key(self, message: Dict[str, Any], address):
        if message['type'] in [VoteType.enter_request, VoteType.ask_for_chain]:
            # what is happening here?
            pub_key = message['public_key']
            key_hash = get_hash(pub_key).hexdigest()
            if key_hash.startswith('0' * self.key_difficulty_level):
                return None
            return pub_key.encode(encoding='latin1')
        else:
            try:
                return self.other_public_keys.get(address)
            except KeyError:
                return None

    def _common_checks(self, message, pub_key):
        copy_to_check = message.copy()
        message_hash = copy_to_check.pop('hash')
        if self._is_already_received(message['start_time'], message_hash):
            return False
        message_signature = copy_to_check.pop('signature').encode(
            encoding='latin1')
        re_hash = get_hash(copy_to_check)
        if message_hash != re_hash.hexdigest():
            return False

        verifier = PKCS115_SigScheme(RSA.importKey(pub_key))
        try:
            verifier.verify(re_hash, message_signature)
        except ValueError:
            return False
        return True

    def _is_already_received(self, message_time, message_hash):
        time_hashes = self.prev_message_time_to_hashes.get(message_time)
        if time_hashes is not None and message_hash in time_hashes:
            return True
        return False

    # method checks if received message should be send to other connected clients
    def _check_message(self, message: Dict[str, Any], address: (str, int)) -> bool:
        # if received message is our
        if message['name'] == self.name:
            return False

        # if we do not trust sending node
        pub_key = self._get_pub_key(message, address)
        if pub_key is None:
            return False

        if not self._common_checks(message, pub_key):
            return False

        return True

    def deal_with_received_message(self, message: dict, address: (str, int)):
        mes_dict = json.loads(message.decode('ascii'))
        if not self._check_message(mes_dict, address):
            return
        #to edit
        if not self.blockchain.try_add_block(message['hash'], message['prev_hash']):
            return

        if mes_dict['type'] == VoteType.ask_for_chain:
            self.message_handler.handle_chain_request(address)
            return
        if mes_dict['type'] == VoteType.response_chain_ask:
            self.message_handler.handle_chain_response(mes_dict)
            return
        if mes_dict['type'] == VoteType.enter_request:
            self.message_handler.handle_enter_request_to_transmit(address, mes_dict)
            return
        if mes_dict['type'] == VoteType.enter_vote:
            self.message_handler.handle_enter_vote_to_transmit(address, message)

        # creating  copies so initial arrays stay the same for other messages
        infected_nodes = []
        healthy_nodes = self.susceptible_nodes.copy()
        try:
            healthy_nodes.remove(address)
        except ValueError:
            pass

        infected_nodes.append(address)
        time.sleep(2)

        print("\nMessage is: '{0}'.\nReceived at [{1}] fro m [{2}]\n"
              .format(json.dumps(mes_dict), time.ctime(time.time()), address))

        self.current_block.append(message)
        # send message to other connected clients
        self.transmit_message(json.dumps(message).encode('ascii'), infected_nodes, healthy_nodes)

    # method that receives a message and send it to other connected clients
    def receive_message(self):
        while True:
            message_to_forward, address = self.node.recvfrom(2048)
            Thread(target=self.deal_with_received_message,
                   args=(message_to_forward, address)).start()

    # method that sends messages to other connected clients
    def transmit_message(self, message: bytes, infected_nodes: list, healthy_nodes: list):
        while healthy_nodes:
            selected_node = random.choice(healthy_nodes)
            host = selected_node[0]
            port = selected_node[1]

            with self.node_lock:
                self.node.sendto(message, (host, port))

            healthy_nodes.remove((host, port))
            infected_nodes.append((host, port))

            time.sleep(2)

        # self.susceptible_nodes = self.infected_nodes

    def start_threads(self):
        Thread(target=self.receive_message).start()
        # New method if we really want this:
        #Thread(target=self.send_blockchain_requests).start()
        Thread(target=self.monitor_moves).start()
        # TODO think about step number updating
        #Thread(target=self._refresh_step_start).start()
