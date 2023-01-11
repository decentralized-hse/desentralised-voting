from __future__ import annotations

from datetime import datetime
import random
import socket
from threading import Thread, Lock, Event
import time
from typing import List, Dict, Any, Optional
import math

from Cryptodome.PublicKey import RSA
from Cryptodome.Signature.pkcs1_15 import PKCS115_SigScheme
import json
from desentralised_voting.VoteTypesComponents.MessageBuilder import VoteType, MessageBuilder
from desentralised_voting.Utils import get_hash
from desentralised_voting.BlockchainComponents.Blockchain import Blockchain, ChainBlock, PeriodType
from enum import Enum
from .GossipNodeHelperClasses import ThreadWithReturn


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
    voting_process = {}
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
        self.move_number = -1
        self.start_threads()
        print(f'Node on {self.hostname}:{self.port} created successfully')
        print(f'Enter period lasts until {self.blockchain.init_block.enter_period_end}')
        print(f'Vote period until {self.blockchain.init_block.vote_period_end}')

    def __enter__(self):
        return self

    def _init_chain(self, enter_end_time, voting_end_time, candidates):
        if len(self.susceptible_nodes) == 0:
            init_message = self.message_builder.build_message(VoteType.init_message,
                                                              signer=self.signer,
                                                              name=self.name,
                                                              zero_step=time.time(),
                                                              enter_end_time=enter_end_time,
                                                              voting_end_time=voting_end_time,
                                                              candidates=candidates)
            self.blockchain = Blockchain(init_message, init_message['hash'])
        else:
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.bind((self.hostname, 1025))
            tcp_sock.listen(1)

            self.blockchain = Blockchain()

            message = self.message_builder.build_message(
                VoteType.ask_for_chain,
                signer=self.signer,
                name=self.name,
                public_key=self.public_key,
                tcp_host=self.hostname,
                tcp_port=1025
            )
            nodes = self.susceptible_nodes.copy()
            for node in nodes:
                bin_message = json.dumps(message).encode('ascii')
                self.node.sendto(bin_message, (node[0], node[1]))
            for i in range(len(nodes)):
                conn, address = tcp_sock.accept()
                try:
                    while True:
                        data = conn.recv(2048)
                        block = self.blockchain.deserialize_block(data)
                        self.blockchain.try_add_block(block)
                except:
                    pass
                finally:
                    conn.close()
            self.send_enter_request()

    def send_enter_request(self):
        message = self.message_builder.build_message(
            VoteType.enter_request,
            signer=self.signer,
            name=self.name,
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
        for block_content in self.blockchain.get_actual_chain_backwards():
            for message in block_content.values():
                self.deal_with_received_message(message, None, True)

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
                    self.send_chain_block_immediately(thread.value)
                stop_event.set()
                break

    def update_jobs(self):
        self.move_number += 1
        print('step', self.move_number, time.time())
        btrd = Thread(target=self.start_forming_block, args=[self.move_number])
        btrd.start()
        transmitting = Thread(target=self.transmit_all_formed_messages)
        transmitting.start()
        transmitting.join()
        btrd.join()

    def move_updater_loop(self):
        time_diff = time.time() - self.zero_step_start
        self.move_number = math.trunc(time_diff / self.step_period_seconds) + 1
        start_time = time.time() + self.move_number * self.step_period_seconds
        time.sleep(start_time - time.time())
        while True:
            Thread(target=self.update_jobs).start()
            time.sleep(self.step_period_seconds)

    def set_period(self, period_type: PeriodType):
        self.current_period = period_type

    def period_updater_loop(self):
        start_time = [self.blockchain.init_block.voting_start_time,
                      self.blockchain.init_block.enter_period_end]
        end_time = [self.blockchain.init_block.enter_period_end,
                    self.blockchain.init_block.vote_period_end]
        period_type = [PeriodType.Enter, PeriodType.Vote]

        for i in range(2):
            time_start = datetime.strptime(start_time[i], '%H:%M')
            while datetime.now().hour != time_start.hour or datetime.now().minute != time_start.minute:
                time.sleep(1)
            self.set_period(period_type[i])
            time_end = datetime.strptime(end_time[i], '%H:%M')
            while datetime.now().hour != time_end.hour or datetime.now().minute != time_end.minute:
                time.sleep(1)
            self.set_period(PeriodType.Default)

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

    def read_message_exists_answer(self, response):
        converted_dict = json.loads(response.decode('ascii'))
        if self._check_message(converted_dict):
            return set(converted_dict['extra'])
        return set()

    def _get_pub_key(self, message: Dict[str, Any], address: (str, int)):
        if message['type'] in [VoteType.enter_request, VoteType.ask_for_chain]:
            return message['public_key'].encode(encoding='latin1')
        return self.address_port_to_public_key.get(address[0] + ':' + str(address[1]), None)

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
            return False

        if self.current_period == PeriodType.Vote and message['type'] == VoteType.enter_request:
            return False

        if self.current_period == PeriodType.Enter and message['type'] == VoteType.enter_vote:
            return False

        # if we do not trust sending node
        pub_key = self._get_pub_key(message, address)
        if pub_key is None:
            return False

        if not self._common_checks(message, pub_key):
            return False

        return True

    def deal_with_received_message(self,
                                   mes_dict: dict,
                                   address: (str, int),
                                   from_chain: bool = False):
        print(f'Received a message from {address[0]}:{address[1]}')
        if not from_chain and not self._check_message(mes_dict, address):
            return

        if mes_dict['type'] == VoteType.ask_for_chain:
            self.message_handler.handle_chain_request(mes_dict['tcp_host'], mes_dict['tcp_port'])
            return

        if mes_dict['type'] == VoteType.process_vote:
            self.message_handler.handle_process_vote(mes_dict)
            return

        # TODO think if we reduce content
        if not from_chain and mes_dict['type'] != VoteType.block:
            self.blockchain.add_transaction(mes_dict, mes_dict['hash'], mes_dict['start_time'])
        if mes_dict['type'] == VoteType.enter_request:
            self.message_handler.handle_enter_request_to_transmit(address, mes_dict, not from_chain)
            return
        if mes_dict['type'] == VoteType.enter_vote:
            if from_chain:
                if mes_dict['try_enter_name'] not in self.request_voting_process.keys():
                    self.request_voting_process[mes_dict['try_enter_name']] = set()
            self.message_handler.handle_enter_vote_to_transmit(
                mes_dict['try_enter_name'], mes_dict['try_enter_address'], mes_dict)
        if mes_dict['type'] == VoteType.block.value:
            self.message_handler.handle_block(mes_dict['block'])

        # creating  copies so initial arrays stay the same for other messages

        if not from_chain:
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
            except BaseException as e:
                continue
            mes_dict = json.loads(message_to_forward.decode('ascii'))
            Thread(target=self.deal_with_received_message,
                   args=(mes_dict, address)).start()

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
            # TODO W H Y timesleep???
            # time.sleep(2)

    def _inform_user_about_period_changing(self):
        period = self.current_period
        while True:
            if period != self.current_period:
                period = self.current_period
                print(f"Voting period has changed. Current period is '{period.name}'"
                      f"This means you can now only send and receive messages of types: {period.value}")

    def start_threads(self):
        Thread(target=self.receive_message).start()
        Thread(target=self.timer_launcher).start()
        Thread(target=self._inform_user_about_period_changing).start()

    def __exit__(self, exc_type, exc_value, traceback):
        self.state = self.NodeState.finished
        self.node.close()


from .MsgHandler import MessageHandler
