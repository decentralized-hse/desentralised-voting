from __future__ import annotations

from datetime import datetime
import random
import socket
from threading import Thread, Lock, Event
from collections import defaultdict
import time
from typing import List, Dict, Any, Optional
import math

from Cryptodome.PublicKey import RSA
from Cryptodome.Signature.pkcs1_15 import PKCS115_SigScheme
import json
from MessageBuilder import VoteType, MessageBuilder
from Utils import get_hash
from Blockchain import Blockchain, ChainBlock, PeriodType
from enum import Enum
from GossipNodeHelperClasses import ThreadWithReturn


class GossipNode:
    class NodeState(int, Enum):
        not_inited = 1
        before_voting = 2
        voting = 3
        finished = 4

    """
    difficulty_level == amount of zeros in the beginning of hash that brove your work
    voting_process == current state of election
    """

    difficulty_level = 2
    key_difficulty_level = 1
    voting_process: Dict[str, set] = {}
    request_voting_process: Dict[(str, int), set] = {}
    candidates_keys = {}
    step_period_seconds = 4

    def __init__(self, host, port, connected_nodes: List[(str, int)], name,
                 enter_end_time=None, voting_end_time=None, candidates=None):
        print('Connect to:', connected_nodes)
        print('Node initialization started')
        self.node = socket.socket(type=socket.SOCK_DGRAM)
        self.node_lock = Lock()
        self.hostname = host
        self.port = port
        self.name = name
        self.node.bind((self.hostname, self.port))
        self.state = self.NodeState.not_inited
        self.blockchain: Optional[Blockchain] = None
        self.current_period: PeriodType = PeriodType.Default

        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey().export_key().decode(
            encoding='latin1')
        print('Keys generated for', name)
        self.signer = PKCS115_SigScheme(self.private_key)
        self.message_handler = MessageHandler(self)
        self.message_builder = MessageBuilder()
        self.input_messages = []

        self.susceptible_nodes: List[(str, int)] = connected_nodes
        # clients that you are connected to and who already received message
        self.address_port_to_public_key: Dict[str, ] = dict()
        self.prev_message_time_to_hashes = dict()

        # Why did we use threads here?
        self._init_chain(enter_end_time, voting_end_time, candidates)
        self.zero_step_start = self.blockchain.init_block.content['zero_step']
        self._next_deadline = self.blockchain.init_block.content['enter_end_time']
        for option in self.blockchain.init_block.voting_period_options:
            self.voting_process[option] = set()
        self.move_number = -1
        self.start_threads()
        print(f'Node on {self.hostname}:{self.port} created successfully')
        print(f'Enter period lasts until {self.blockchain.init_block.enter_period_end}')
        print(f'Vote period until {self.blockchain.init_block.vote_period_end}')

    def __enter__(self):
        return self

    def _init_chain(self, enter_end_time, voting_end_time, candidates):
        if len(self.susceptible_nodes) == 0:
            str_address = f'{self.hostname}:{self.port}'
            init_message = self.message_builder.build_message(VoteType.init_message,
                                                              signer=self.signer,
                                                              name=self.name,
                                                              org_addr=str_address,
                                                              org_pub_key=self.public_key,
                                                              zero_step=time.time(),
                                                              enter_end_time=enter_end_time,
                                                              voting_end_time=voting_end_time,
                                                              candidates=candidates)
            self.blockchain = Blockchain(init_message, init_message['hash'])
        else:
            while True:
                tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_sock.bind((self.hostname, 1024))
                tcp_sock.listen(1)

                self.blockchain = Blockchain()

                message = self.message_builder.build_message(
                    VoteType.ask_for_chain,
                    signer=self.signer,
                    name=self.name,
                    public_key=self.public_key,
                    tcp_host=self.hostname,
                    tcp_port=1024
                )
                nodes = self.susceptible_nodes.copy()
                for node in nodes:
                    bin_message = json.dumps(message).encode('ascii')
                    self.node.sendto(bin_message, (node[0], node[1]))
                for i in range(len(nodes)):
                    conn, address = tcp_sock.accept()
                    try:
                        while True:
                            data = conn.recv(4096)
                            block = self.blockchain.deserialize_block(data)
                            self.blockchain.try_add_block(block)
                    except:
                        pass
                    finally:
                        conn.close()
                try:
                    self.blockchain.init_block
                except AttributeError:
                    print('No init block')
                    continue
                tcp_sock.close()
                break
            org_addr = self.blockchain.init_block.org_addr
            org_key = self.blockchain.init_block.org_pub_key.encode(encoding='latin1')
            self.address_port_to_public_key[org_addr] = org_key
            print('Start filling counters')
            self._update_period()
            self.fill_counters_from_chain()
            print('Counters filled')
            self.send_enter_request()

    def send_enter_request(self):
        message = self.message_builder.build_message(
            VoteType.enter_request,
            signer=self.signer,
            name=self.name,
            try_enter_address=f'{self.hostname}:{self.port}',
            public_key=self.public_key)
        Thread(target=self.input_message, args=(message,)).start()

    def _next_state(self):
        if self.state == self.NodeState.voting:
            self.state = self.NodeState.finished
        if self.state == self.NodeState.before_voting:
            self.state = self.NodeState.voting
            self._next_deadline = \
                self.blockchain.init_block.content['voting_end_time']
        if self.state == self.NodeState.not_inited:
            self.state = self.NodeState.before_voting
            self._next_deadline = \
                self.blockchain.init_block.content['enter_end_time']

    def _get_move(self) -> int:
        return int((time.time() - self.zero_step_start) / self.step_period_seconds)

    def fill_counters_from_chain(self):
        for block_content in self.blockchain.get_actual_chain_forwards():
            for message in block_content.values():
                if message['type'] == VoteType.enter_request:
                    self._checks_for_fill_counters(message)
                    self.message_handler.handle_enter_request_to_transmit(
                        message, False)
                    return

                if message['type'] == VoteType.enter_vote:
                    self._checks_for_fill_counters(message)
                    self.message_handler.handle_enter_vote_to_transmit(message)

    def _checks_for_fill_counters(self, message):
        splited = message['try_enter_address'].split(':')
        address = (splited[0], int(splited[1]))
        return self._check_message(message, address)

    def send_chain_block_immediately(self, block: ChainBlock):
        json_block = self.blockchain.block_to_json(block)
        message = self.message_builder.build_message(
            VoteType.block,
            signer=self.signer,
            name=self.name,
            block=json_block
        )
        infected_nodes = []
        healthy_nodes = self.susceptible_nodes.copy()
        self.transmit_message(json.dumps(message).encode('ascii'),
                              infected_nodes,
                              healthy_nodes)

    def start_forming_block(self, move_number):
        stop_event = Event()
        thread = ThreadWithReturn(self.blockchain.try_form_block)
        thread.run(move_number, stop_event)
        while True:
            time.sleep(5)
            if (thread.value is not None) or \
                    (move_number in self.blockchain._step_to_blocks_info):
                if thread.value:
                    print('formed a block')
                    self.send_chain_block_immediately(thread.value)
                stop_event.set()
                break

    def update_jobs(self):
        btrd = Thread(target=self.start_forming_block, args=[self.move_number])
        btrd.start()
        self.move_number += 1
        transmitting = Thread(target=self.transmit_all_formed_messages)
        transmitting.start()
        print('step', self.move_number, time.time())
        transmitting.join()
        btrd.join()

    def move_updater_loop(self):
        period = self.step_period_seconds
        start = self.blockchain.init_block.start_timestamp
        while True:
            time_diff = time.time() - self.zero_step_start
            self.move_number = math.trunc(time_diff / period) + 1
            start_time = start + self.move_number * period
            time.sleep(start_time - time.time())
            for i in range(10):
                Thread(target=self.update_jobs).start()
                time.sleep(self.step_period_seconds)
            Thread(target=self.update_jobs).start()

    def set_period(self, period_type: PeriodType):
        self.current_period = period_type

    def period_updater_loop(self):
        while True:
            self._update_period()
            if self.current_period == PeriodType.End:
                break

    def _update_period(self):
        if datetime.now().timestamp() > self.blockchain.init_block.vote_period_end:
            self.set_period(PeriodType.End)
            print(f'Elections are over\n{self.set_period(PeriodType.End)} won')
        elif datetime.now().timestamp() > self.blockchain.init_block.enter_period_end:
            self.set_period(PeriodType.Vote)
        else:
            self.set_period(PeriodType.Enter)

    def timer_launcher(self):
        Thread(target=self.move_updater_loop).start()
        Thread(target=self.period_updater_loop).start()

    def _track_message_in_chain(self, message, block_step: int):
        time.sleep(self.step_period_seconds * 3)
        if not self.blockchain.try_find_transaction_hash_from(block_step,
                                                              message['hash']):
            self.input_messages.append([message, [], self.susceptible_nodes.copy()])

    def transmit_all_formed_messages(self):
        self.input_messages, to_transmit = [], self.input_messages
        for message_info in to_transmit:
            message, infected_nodes, healthy_nodes = message_info
            self.blockchain.add_transaction(message,
                                            message['hash'],
                                            message['start_time'])

            self.transmit_message(json.dumps(message).encode('ascii'),
                                  infected_nodes,
                                  healthy_nodes)
            if message['type'] in [VoteType.enter_request, VoteType.enter_vote]:
                Thread(target=self._track_message_in_chain,
                       args=[message, self.move_number])

    def input_message(self, mes_dict: dict):
        infected_nodes = []
        healthy_nodes = self.susceptible_nodes.copy()
        self.input_messages.append([mes_dict,
                                    infected_nodes,
                                    healthy_nodes])
        print('Prepared a message')

        # print(f'You successfully voted for {message["type"]}, {message["content"]}')

    def _get_pub_key(self, message: Dict[str, Any], address: (str, int)):
        if message['type'] in [VoteType.enter_request, VoteType.ask_for_chain]:
            return message['public_key'].encode(encoding='latin1')
        return self.address_port_to_public_key.get(address[0] + ':' + str(address[1]), None)

    def _hash_checks(self, message, pub_key):
        copy_to_check = message.copy()
        message_hash = copy_to_check.pop('hash')

        if self._is_already_received(message['start_time'], message_hash):
            print('Already recv')
            return False

        message_signature = copy_to_check.pop('signature').encode(
            encoding='latin1')
        re_hash = get_hash(copy_to_check)
        if message_hash != re_hash.hexdigest():
            print('wrong hash')
            return False

        verifier = PKCS115_SigScheme(RSA.importKey(pub_key))
        try:
            verifier.verify(re_hash, message_signature)
        except ValueError:
            print('wrong signature')
            return False

        self.prev_message_time_to_hashes[message['start_time']] = message_hash
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
            print('Our own message')
            return False

        if message['type'] not in self.current_period.value:
            print('Wrong period:', message['type'], 'for', self.current_period.value)
            return False

        # if we do not trust sending node
        pub_key = self._get_pub_key(message, address)
        if pub_key is None:
            print('No public key')
            return False

        if not self._hash_checks(message, pub_key):
            return False

        return True

    def deal_with_received_message(self, mes_dict: dict, address: (str, int)):
        print(f'Received a message from {mes_dict["name"]} ( address is {address[0]}:{address[1]}), type is {VoteType(mes_dict["type"]).name}')
        if not self._check_message(mes_dict, address):
            return
        print('Checks OK')

        if mes_dict['type'] == VoteType.ask_for_chain:
            self.message_handler.handle_chain_request(mes_dict['tcp_host'], mes_dict['tcp_port'])
            return

        if mes_dict['type'] != VoteType.block:
            self.blockchain.add_transaction(mes_dict, mes_dict['hash'], mes_dict['start_time'])

        if mes_dict['type'] == VoteType.enter_request:
            self.message_handler.handle_enter_request_to_transmit(mes_dict)
            return

        if mes_dict['type'] == VoteType.process_vote:
            self.message_handler.handle_process_vote(mes_dict)
            return

        if mes_dict['type'] == VoteType.enter_vote:
            self.message_handler.handle_enter_vote_to_transmit(mes_dict)

        if mes_dict['type'] == VoteType.block.value:
            self.message_handler.handle_block(mes_dict['block'])

        # creating  copies so initial arrays stay the same for other messages

        infected_nodes = []
        healthy_nodes = self.susceptible_nodes.copy()
        try:
            healthy_nodes.remove(address)
        except ValueError:
            pass
        infected_nodes.append(address)
        # send message to other connected clients
        self.transmit_message(json.dumps(mes_dict).encode('ascii'),
                              infected_nodes, healthy_nodes)

    # method that receives a message and send it to other connected clients
    def receive_message(self):
        while True:
            if self.state == self.NodeState.finished:
                return
            try:
                message_to_forward, address = self.node.recvfrom(4096)
                mes_dict = json.loads(message_to_forward.decode('ascii'))
                Thread(target=self.deal_with_received_message,
                       args=(mes_dict, address)).start()
            except BaseException as e:
                print(e)

    # method that sends messages to other connected clients
    def transmit_message(self,
                         message: bytes,
                         infected_nodes: list,
                         healthy_nodes: List[(str, int)]):
        while healthy_nodes:
            selected_node = random.choice(healthy_nodes)

            with self.node_lock:
                self.node.sendto(message, selected_node)

            healthy_nodes.remove(selected_node)
            infected_nodes.append(selected_node)

    def _inform_user_about_period_changing(self):
        period = self.current_period
        while True:
            if period != self.current_period:
                period = self.current_period
                print(f"Voting period has changed. Current period is '{period.name}'")
                if self.current_period == PeriodType.Vote:
                    Thread(target=self.message_handler.handle_process_vote_spreading).start()
                if self.current_period == PeriodType.End or PeriodType.Default:
                    print(self.current_period)
                    print(self._get_final_results())

    def _get_final_results(self):
        voters_names = [self.blockchain.init_block.content['name']]
        voter_candidates = defaultdict(set)
        voting = {x: 0 for x in self.voting_process.keys()}
        for block_content in self.blockchain.get_actual_chain_forwards():
            for message in block_content.values():
                if message['type'] == VoteType.enter_vote and message['enter_vote']:
                    candidate_votes = voter_candidates[message['try_enter_name']]
                    candidate_votes.add(message['name'])
                    if len(voters_names) < 2 or len(candidate_votes) >= 2:
                        voters_names.append(message['try_enter_name'])
                        voter_candidates.pop(message['try_enter_name'])
                if message['type'] == VoteType.process_vote:
                    if message['name'] in voters_names:
                        voters_names.remove(message['name'])
                        voting[message['process_vote_option']] += 1
        max_votes = max(voting.values())
        return [k for k, v in voting.items() if v == max_votes]

    def update_received_messages(self):
        while self.current_period != PeriodType.End:
            new_hashes = []
            for block in self.blockchain.get_actual_chain_backwards():
                for message_hash, message in block.items():
                    new_hashes[message['start_time']] = message_hash
            self.prev_message_time_to_hashes = new_hashes

    def start_threads(self):
        Thread(target=self.timer_launcher).start()
        Thread(target=self.receive_message).start()
        Thread(target=self.update_received_messages).start()
        Thread(target=self._inform_user_about_period_changing).start()

    def __exit__(self, exc_type, exc_value, traceback):
        self.state = self.NodeState.finished
        self.node.close()


from MsgHandler import MessageHandler
