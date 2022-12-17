from __future__ import annotations

import copy
import random
import socket
from threading import Thread, Lock
import time
import ntplib
from collections import defaultdict
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

            init_message = MessageBuilder(VoteType.init_message, signer=self.signer, name=self.name).body
            self.blockchain = Chain(init_message['hash'])
            #self.step_start = math.ceil(get_time())
            #self.prev_step_hashes = []
            #self.step_counter = 0
        else:
            #self.step_start = None
            #self.prev_step_hashes = None
            #self.step_counter = None
            Thread(target=self._enter_network).start()

        self._get_move()

        print(f'{self.port} created successfully')
        self.start_threads()

    def _enter_network(self):
        while self.blockchain is not None:
            time.sleep(1)
        message = self.message_builder.build_message(VoteType.enter_request,
                                                     signer=self.signer,
                                                     name=self.name,
                                                     public_key=self.public_key,
                                                     connecting_nodes=self.susceptible_nodes,
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

    # def _refresh_step_start(self):
    #     while self.step_start is None:
    #         pass
    #     step_end = self.step_start + GossipNode.step_period
    #     while True:
    #         if get_time() > step_end:
    #             #self.step_hashes_lock.acquire()
    #             self.step_start += GossipNode.step_period
    #             #self._send_prev_hashes()
    #             self.step_counter += 1
    #             #self.step_hashes_lock.release()
    #             step_end += GossipNode.step_period

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

    # method that changes election state after receiving a message
    def update_voting(self, message: dict, address: (str, int)):
        if not message['vote'] in self.voting_progress:
            self.voting_progress[message['vote']] = set()

        self.voting_progress[message['vote']].add(address)
        leading_candidate = max(self.voting_progress, key=self.voting_progress.get)
        if len(self.voting_progress[leading_candidate]) >= 3:
            print(f'{leading_candidate} won the elections')

    def send_blockchain_requests(self):
        while True:
            req_message = self.message_builder.build_message(VoteType.ask_for_chain,
                                         signer=self.signer,
                                         name=self.name,
                                         prev_hash=self.blockchain.get_leader(),
                                         public_key=self.public_key).body

            self.input_message(req_message)
            time.sleep()

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

    def _get_pub_key(self, message, address):
        if message['type'] in [VoteType.enter_request, VoteType.ask_for_chain]:
            pub_key = message['content']
            key_hash = get_hash(pub_key).hexdigest()
            if key_hash.startswith('0' * self.key_difficulty_level):
                return None
            return pub_key.encode(encoding='latin1')
        else:
            try:
                return self.other_public_keys.get(address)
            except:
                return None
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
    def _check_message(self, message: dict, address: (str, int)) -> bool:
        if address[0] == self.port and address[1] == self.hostname:
            self.update_voting(message, address)
            return False

        if 'type' not in message.keys():
            return False

        pub_key = self._get_pub_key(message, address)
        if pub_key is None:
            return False

        if not self._common_checks(message, pub_key):
            return False

        if message['type'] == VoteType.enter_request:
            return True
        elif message['type'] == VoteType.are_hashes_valid_request:
            self.response_message_exists(message['extra'],
                                         message['host'], message['port'])
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
            self.handle_chain_request(address)
        if mes_dict['type'] == VoteType.response_chain_ask:
            self.handle_chain_response(mes_dict)
            return
        if mes_dict['type'] == VoteType.enter_request:
            if not self.handle_enter_request_to_transmit(address, mes_dict):
                return
        if mes_dict['type'] == VoteType.enter_vote:
            if not self.handle_enter_vote_to_transmit(address):
                return

        # creating  copies so initial arrays stay the same for other messages
        infected_nodes = []
        healthy_nodes = self.susceptible_nodes.copy()
        try:
            healthy_nodes.remove(address)
        except ValueError:
            pass

        infected_nodes.append(address)
        # updating election progress
        self.update_voting(mes_dict)
        time.sleep(2)

        print("\nMessage is: '{0}'.\nReceived at [{1}] fro m [{2}]\n"
              .format(json.dumps(mes_dict), time.ctime(time.time()), address))

        self.current_block.append(message)
        # send message to other connected clients
        self.transmit_message(json.dumps(message).encode('ascii'), infected_nodes, healthy_nodes)

    def handle_chain_request(self, address):
        response = self.message_builder.build_message(VoteType.response_chain_ask,
                                                      signer=self.signer,
                                                      name=self.name,
                                                      prev_hash=self.blockchain.get_leader(),
                                                      blockchain=self.blockchain.tree_to_json())

        with self.node_lock:
            self.node.sendto(json.dumps(response).encode('ascii'), address)

    def handle_chain_response(self, response):
        other_chain_tree = Chain.tree_from_json(response['content'])
        self.blockchain.merge_with_tree(other_chain_tree)

    def handle_enter_request_to_transmit(self, address, message_dict):
        my_addr = (self.hostname, self.port)
        newbie_connections = [tuple(i) for i in message_dict['connecting_nodes']]
        if my_addr in newbie_connections and address not in self.susceptible_nodes:
            self.susceptible_nodes.append(address)
            if address not in self.request_voting_process.keys():
                self.request_voting_process[address] = 1
                self.candidates_keys[address] = message_dict['content']

                vote = input("New user {} is requesting enter permission. Do you grant permission(Yes/No)?"
                             "Message in any format other than 'Yes' will be taken as No."
                             .format(message_dict['name']))

                message = self.message_builder.build_message(VoteType.response_chain_ask,
                                                             signer=self.signer,
                                                             name=self.name,
                                                             prev_hash=self.blockchain.get_leader(),
                                                             try_enter_address=address[0] + ':' + str(address[1]),
                                                             try_enter_name=message_dict['name'],
                                                             enter_vote=vote == "Yes")

                vote_thread = Thread(target=self.input_message,
                                     args=(message,))
                vote_thread.start()
                return True
        return False

    def handle_enter_vote_to_transmit(self, address):
        if address in self.request_voting_process.keys():
            if self.request_voting_process[address] < 2:
                self.request_voting_process[address] += 1
            else:
                self.other_public_keys[address] = \
                    self.candidates_keys.pop(address)
                # send chain story to new node
                # randomly add it to susceptible_nodes
            return True
        return False

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
        Thread(target=self.send_blockchain_requests).start()
        Thread(target=self.monitor_moves).start()
        #Thread(target=self._refresh_step_start).start()


if __name__ == '__main__':
    port = 5000
    # ports for the nodes connected to this node
    connected_nodes = []
    node = GossipNode('127.0.0.1', port, connected_nodes, "first")
