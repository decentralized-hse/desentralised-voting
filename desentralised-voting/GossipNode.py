from __future__ import annotations

from datetime import datetime
import random
import socket
from threading import Thread, Lock, Event
import time
from typing import List, Dict, Any, Optional
import math

from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
import json
from VoteTypes import VoteType, MessageBuilder
from Utils import get_hash
from Blockchain import Blockchain, ChainBlock, PeriodType
from enum import Enum
import schedule


class ThreadWithReturn(Thread):
    def __init__(self, function):
        Thread.__init__(self)
        self.function = function
        self.value = None

    def run(self, *args):
        self.value = self.function(*args)


class MessageHandler:
    def __init__(self, gossip_node: GossipNode):
        self.gossip_node = gossip_node

    def handle_chain_request(self, tcp_host, tcp_port):
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_socket.bind((self.gossip_node.hostname, 1000))
        temp_socket.connect((tcp_host, tcp_port))
        for data in self.gossip_node.blockchain.serialize_chain_blocks():
            temp_socket.sendall(data)
        temp_socket.close()

    def handle_enter_request_to_transmit(self, address: (str, int), message_dict: Dict[str, Any], ask_vote: bool):
        # so now we only get enter_request if we don't have the node in susceptible, we do not spread this type of msg

        # adding node to voting_process and candidates_keys
        # not adding node to susceptible yet so we don't spread enter_vote messages to it
        self.gossip_node.susceptible_nodes.append(address)
        if message_dict['name'] not in self.gossip_node.request_voting_process.keys():
            self.gossip_node.request_voting_process[message_dict['name']] = set()
        self.gossip_node.candidates_keys[message_dict['name']] = message_dict['public_key']

        if ask_vote:
            self.handle_vote_spreading(address, message_dict['name'])

    def handle_vote_spreading(self, address, try_enter_name: str):
        # asking user to vote
        vote = input("New user {} is requesting enter permission. Do you grant permission(Yes/No)?"
                     "Message in any format other than 'Yes' will be taken as No."
                     .format(try_enter_name))

        # add ourself if the vote is Yes
        if vote == "Yes":
            self.gossip_node.request_voting_process[try_enter_name].add(self.gossip_node.name)

        # building message to spread voting
        message = self.gossip_node.message_builder.build_message(VoteType.enter_vote,
                                                                 signer=self.gossip_node.signer,
                                                                 name=self.gossip_node.name,
                                                                 try_enter_address=address[0] + ':' + str(address[1]),
                                                                 try_enter_name=try_enter_name,
                                                                 enter_vote=vote == "Yes")

        # transmitting message to all susceptible nodes
        vote_thread = Thread(target=self.gossip_node.input_message, args=(message,))
        vote_thread.start()

    def handle_enter_vote_to_transmit(self, key, address, message_dict: Dict[str, Any]):
        # we already know about this node and voted for it
        if key in self.gossip_node.request_voting_process.keys():
            # adding received vote if it wasn't added already (that's why set)
            self.gossip_node.request_voting_process[key].add(message_dict['name'])

            # checking if there is enough votes for applying node to be trusted
            if len(self.gossip_node.request_voting_process[key]) == 2:
                self.gossip_node.other_public_keys[address] = self.gossip_node.candidates_keys.pop(address)

        else:
            # adding our vote plus the vote we received and spread our vote
            self.gossip_node.request_voting_process[key] = {message_dict['try_enter_name']}
            self.handle_vote_spreading(address, message_dict['try_enter_name'])

    def handle_block(self, block_bytes):
        block = self.gossip_node.blockchain.deserialize_block(block_bytes)
        self.gossip_node.blockchain.try_add_block(block)


class GossipNode:
    class NodeState(int, Enum):
        not_inited = 1
        before_voting = 2
        voting = 3
        finished = 4

    """
    difficulty_level == amount of zeros in the beginning of hash that brove your work
    voting_progress == current state of election
    """

    difficulty_level = 2
    key_difficulty_level = 1
    voting_progress = {}
    request_voting_process: Dict[(str, int), set] = {}
    candidates_keys = {}
    step_period_seconds = 4

    def __init__(self, host, port, connected_nodes: List[(str, int)], name,
                 enter_end_time=None, voting_end_time=None, candidates=None):
        self.node = socket.socket(type=socket.SOCK_DGRAM)
        self.node_lock = Lock()
        self.hostname = host
        self.port = port
        self.name = name
        self.node.bind((self.hostname, self.port))
        self.state = self.NodeState.not_inited
        self.blockchain: Optional[Blockchain] = None

        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey().export_key().decode(
            encoding='latin1')
        self.signer = PKCS115_SigScheme(self.private_key)
        self.message_handler = MessageHandler(self)
        self.message_builder = MessageBuilder()
        self.input_messages = []

        self.susceptible_nodes: List[(str, int)] = connected_nodes
        # clients that you are connected to and who already received message
        self.other_public_keys = dict()
        self.prev_message_time_to_hashes = dict()

        # Why did we use threads here?
        self._init_chain(enter_end_time, voting_end_time, candidates)
        self.zero_step_start = self.blockchain.init_block.content['zero_step']
        self._next_deadline = self.blockchain.init_block.content['enter_end_time']
        self.move_number = -1
        print(f'{self.port} created successfully')
        self.start_threads()

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
            tcp_sock.bind((self.hostname, 1000))
            tcp_sock.listen(1)

            self.blockchain = Blockchain()

            message = self.message_builder.build_message(
                VoteType.ask_for_chain,
                signer=self.signer,
                name=self.name,
                public_key=self.public_key,
                tcp_host=self.hostname,
                tcp_port=1000
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
        bytes_block = self.blockchain.serialize_block(block)
        message = self.message_builder.build_message(
            VoteType.block,
            signer=self.signer,
            name=self.name,
            block=bytes_block
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
                thread.join()
                return

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
        time_diff = time.time() - self.zero_step_start
        self.move_number = math.trunc(time_diff / self.step_period_seconds) + 1
        start_time = time.time() + self.move_number * self.step_period_seconds
        time.sleep(start_time - time.time())
        while True:
            Thread(target=self.update_jobs).start()
            time.sleep(self.step_period_seconds)

    def set_period(self, period_type: PeriodType):
        self.blockchain.init_block.current_period = period_type

    def period_updater_loop(self):
        start_time = [self.blockchain.init_block.enter_period[0],
                      self.blockchain.init_block.vote_period[0]]
        end_time = [self.blockchain.init_block.enter_period[1],
                    self.blockchain.init_block.vote_period[1]]
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

    def transmit_all_formed_messages(self):
        for message_info in self.input_messages:
            message, infected_nodes, healthy_nodes = message_info
            self.blockchain.add_transaction(message,
                                            message['hash'],
                                            message['start_time'])

            self.transmit_message(json.dumps(message).encode('ascii'),
                                  infected_nodes,
                                  healthy_nodes)

    def input_message(self, message):
        infected_nodes = []
        healthy_nodes = self.susceptible_nodes.copy()
        self.input_messages.append([message,
                                    infected_nodes,
                                    healthy_nodes])

        print(f'You successfully voted for {message["type"]}, {message["content"]}')

    def read_message_exists_answer(self, response):
        converted_dict = json.loads(response.decode('ascii'))
        if self._check_message(converted_dict):
            return set(converted_dict['extra'])
        return set()

    def _get_pub_key(self, message: Dict[str, Any], address):
        if message['type'] in [VoteType.enter_request, VoteType.ask_for_chain]:
            return message['public_key'].encode(encoding='latin1')
        return self.other_public_keys.get(address, None) #here was try except

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

        if self.blockchain.init_block.current_period == PeriodType.Vote and message['type'] == VoteType.enter_request:
            return False

        if self.blockchain.init_block.current_period == PeriodType.Enter and message['type'] == VoteType.enter_vote:
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
        if not from_chain and not self._check_message(mes_dict, address):
            return

        if mes_dict['type'] == VoteType.ask_for_chain:
            self.message_handler.handle_chain_request(mes_dict['tcp_host'], mes_dict['tcp_port'])
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
        if mes_dict['type'] == VoteType.block:
            self.message_handler.handle_block()

        # creating  copies so initial arrays stay the same for other messages

        if not from_chain:
            infected_nodes = []
            healthy_nodes = self.susceptible_nodes.copy()
            try:
                healthy_nodes.remove(address)
            except ValueError:
                pass
            infected_nodes.append(address)
            # TODO W H Y is timesleep here?
            # time.sleep(2)
            # send message to other connected clients
            self.transmit_message(json.dumps(mes_dict).encode('ascii'),
                                  infected_nodes, healthy_nodes)

    # method that receives a message and send it to other connected clients
    def receive_message(self):
        while True:
            if self.state == self.NodeState.finished:
                return
            try:
                message_to_forward, address = self.node.recvfrom(2048)
            except:
                continue
            mes_dict = json.loads(message_to_forward.decode('ascii'))
            Thread(target=self.deal_with_received_message,
                   args=(mes_dict, address)).start()

    # method that sends messages to other connected clients
    def transmit_message(self, message: bytes, infected_nodes: list, healthy_nodes: List[(str, int)]):
        while healthy_nodes:
            selected_node = random.choice(healthy_nodes)

            with self.node_lock:
                self.node.sendto(message, selected_node)

            healthy_nodes.remove(selected_node)
            infected_nodes.append(selected_node)

            time.sleep(2)

        # self.susceptible_nodes = self.infected_nodes

    def _inform_user_about_period_changing(self):
        period = self.blockchain.init_block.current_period
        while True:
            if period != self.blockchain.init_block.current_period:
                period = self.blockchain.init_block.current_period
                print(f"Voting period has changed. Current period is '{period.name}'"
                      f"This means you can now only send and receive messages of types: {period.value}")

    def start_threads(self):
        Thread(target=self.receive_message).start()
        Thread(target=self.timer_launcher).start()
        Thread(target=self._inform_user_about_period_changing).start()

    def __exit__(self, exc_type, exc_value, traceback):
        self.state = self.NodeState.finished
        self.node.close()
