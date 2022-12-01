from __future__ import annotations

import copy
import random
import socket
from threading import Thread, Lock
import time
import ntplib
import datetime
from collections import defaultdict
from Cryptodome import Random
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature.pkcs1_15 import PKCS115_SigScheme
import json
from json import JSONEncoder
from enum import Enum
from MerkelTree import MerkelTree


class VoteType(int, Enum):
    enter_request = 1
    enter_vote = 2
    process_vote = 3
    are_hashes_valid_request = 4
    are_hashes_valid_response = 5
    old_message = 6
    init_message = 7
    ask_for_chain = 8
    response_chain_ask = 9


class VoteEncoder(JSONEncoder):
    def default(self, object):
        return object.__dict__


class ThreadWithReturn(Thread):
    def __init__(self, function):
        Thread.__init__(self)
        self.function = function
        self.value = None

    def run(self, *args):
        self.value = self.function(*args)


class ChainBlock:
    def __init__(self, node_hash, parent_hash, merkel_tree):
        self.hash = node_hash
        self.parent_hash = parent_hash
        self.merkel_tree = merkel_tree


class Chain:
    def __init__(self, root_hash, fork_allowed_distance=3):
        self._min_len = 1
        self._max_len = 1
        self._history_len = fork_allowed_distance
        self._leader_hash = root_hash
        self._lock = Lock()
        init_block = ChainBlock(root_hash, None, None)
        self._branch_len_to_hashes = defaultdict(list)
        self._branch_len_to_hashes[1].append(init_block)

    def try_add_block(self, node_data: [str] = None):
        if node_data is None or len(node_data) == 0:
            return False
        cur_merkel_tree = MerkelTree(node_data)
        new_node_hash = cur_merkel_tree.tree_top.value
        new_parent_hash = self.get_leader()
        new_block = ChainBlock(new_node_hash, new_parent_hash, cur_merkel_tree)
        for branch_len, blocks in self._branch_len_to_hashes.items():
            for head_block in blocks:
                if new_block.parent_hash != head_block.hash:
                    continue
                with self._lock:
                    new_len = branch_len + 1
                    if new_len > self._max_len:
                        self._max_len = branch_len + 1
                        self._leader_hash = new_block.hash
                        if self._max_len - self._min_len > self._history_len:
                            del self._branch_len_to_hashes[self._min_len]
                            self._min_len = min(self._branch_len_to_hashes.keys())
                    self._branch_len_to_hashes[new_len].append(new_block)
                    return True
        return False

    def get_leader(self):
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
            key_hash = self._hash(self.public_key).hexdigest()
            if key_hash.startswith('0' * self.key_difficulty_level):
                break
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey().export_key().decode(
            encoding='latin1')
        self.signer = PKCS115_SigScheme(self.private_key)

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
            init_message = self._create_message(VoteType.init_message, None)
            self.blockchain = Chain(init_message['hash'])
            #self.step_start = math.ceil(self._get_time())
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
        message = self._create_message(
            VoteType.enter_request,
            self.public_key,
            connecting_nodes=self.susceptible_nodes)
        self.input_message(message)

    def _get_proof_of_work_hash(self, message, first_message=False):
        while True:
            message['nonce'] = Random.get_random_bytes(8).hex()
            #to edit
            if not first_message:
                message['prev_hash'] = self.blockchain.get_leader()
            c_hash = self._hash(message)
            hexed = c_hash.hexdigest()
            print(hexed, message['nonce'])
            if hexed.startswith('0' * self.difficulty_level):
                print('found hash:', hexed, 'for nonce:', message['nonce'])
                return c_hash

    @staticmethod
    def _hash(content):
        return SHA256.new(data=json.dumps(content).encode())

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

    def _create_message(self, message_type, message_content, **kwargs):
        message = {
            'type': message_type,
            'content': message_content,
            'name': self.name,
            'start_time': self._get_time()
        }
        message.update(kwargs)
        is_first_message = message_content is None
        hash = self._get_proof_of_work_hash(message, first_message=is_first_message)
        message['hash'] = hash.hexdigest()
        message['signature'] = self.signer.sign(hash).decode(encoding='latin1')
        return message

    def _get_time(self):
        while True:
            try:
                #time = self.ntp_client.request('pool.ntp.org').tx_time
                return datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            except ntplib.NTPException:
                pass

    # def _refresh_step_start(self):
    #     while self.step_start is None:
    #         pass
    #     step_end = self.step_start + GossipNode.step_period
    #     while True:
    #         if self._get_time() > step_end:
    #             #self.step_hashes_lock.acquire()
    #             self.step_start += GossipNode.step_period
    #             #self._send_prev_hashes()
    #             self.step_counter += 1
    #             #self.step_hashes_lock.release()
    #             step_end += GossipNode.step_period

    def input_message(self, message):
        infected_nodes = []
        healthy_nodes = self.susceptible_nodes.copy()
        current_time = self._get_time()

        # while (self.step_start is not None and
        #        current_time - self.step_start > GossipNode.step_period):
        #     time.sleep(100)
        #     current_time = self._get_time()

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
            req_message = self._create_message(
                VoteType.ask_for_chain,
                self.public_key)
            self.input_message(req_message)
            time.sleep()

    def read_message_exists_answer(self, response):
        converted_dict = json.loads(response.decode('ascii'))
        if self._check_message(converted_dict):
            return set(converted_dict['extra'])
        return set()

    def ask_connected_for_messages(self, suspicious):
        message = \
            self._create_message(VoteType.are_hashes_valid_request, suspicious)
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
        message = self._create_message(VoteType.are_hashes_valid_response, answer)
        with self.node_lock:
            self.node.sendto(json.dumps(message).encode('ascii'), (host, port))

    def _get_pub_key(self, message, adress):
        if message['type'] in [VoteType.enter_request, VoteType.ask_for_chain]:
            pub_key = message['content']
            key_hash = self._hash(pub_key).hexdigest()
            if key_hash.startswith('0' * self.key_difficulty_level):
                return None
            return pub_key.encode(encoding='latin1')
        else:
            try:
                return self.other_public_keys.get(adress)
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
        re_hash = self._hash(copy_to_check)
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
        response = self._create_message(
            VoteType.response_chain_ask,
            self.blockchain.tree_to_json())
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

                message = self._create_message(
                    VoteType.enter_vote,
                    '',
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