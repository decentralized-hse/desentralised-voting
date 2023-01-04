from __future__ import annotations

import random
import socket
from threading import Thread, Lock, Timer
import time
from typing import Dict, Any, Optional

import ntplib
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature.pkcs1_15 import PKCS115_SigScheme
import json
from VoteTypes import VoteType, MessageBuilder
from Utils import get_hash
from Blockchain import Blockchain, PeriodType


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

    # def handle_chain_response(self, response: Dict[str, Any]):
    #     other_chain_tree = Blockchain.tree_from_json(response['blockchain'])
    #     self.gossip_node.blockchain.merge_with_tree(other_chain_tree)

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

    def __init__(self, host, port, connected_nodes, name,
                 enter_end_time=None, voting_end_time=None, candidates=None):
        self.node = socket.socket(type=socket.SOCK_DGRAM)
        self.node_lock = Lock()
        self.hostname = host
        self.port = port
        self.name = name
        self.node.bind((self.hostname, self.port))
        self.blockchain: Optional[Blockchain] = None

        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey().export_key().decode(
            encoding='latin1')
        self.signer = PKCS115_SigScheme(self.private_key)
        self.message_handler = MessageHandler(self)
        self.message_builder = MessageBuilder()

        self.susceptible_nodes = connected_nodes
        # clients that you are connected to and who already received message
        self.ntp_client = ntplib.NTPClient()
        self.other_public_keys = dict()
        self.prev_message_time_to_hashes = dict()

        # Why did we use threads here?
        self._init_chain(enter_end_time, voting_end_time, candidates)
        self.zero_step_start = self.blockchain.init_block.content['zero_step']
        self.move_number = -1
        print(f'{self.port} created successfully')
        self.start_threads()

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

    def _get_move(self) -> int:
        return int((time.time() - self.zero_step_start) / self.step_period)
        # self.node.connect(('127.0.0.1', 12345))
        # self.node.sendall(b'hello')
        # message, address = self.node.recvfrom(2048)
        # data = json.loads(message.decode('ascii'))
        # self.move_number = data['move_number']
        # self.move_time_left_sec = data['move_time_left_sec']
        # print(f'move number = {self.move_number}; move time left = {self.move_time_left_sec}')

    def move_updater_loop(self):
        self.move_number += 1
        Timer(self.step_period, self.move_updater_loop).start()

    def timer_launcher(self):
        time_diff = time.time() - self.zero_step_start
        self.move_number = time_diff / self.step_period
        start_time = time.time() + (self.move_number + 1) * self.step_period
        time.sleep(start_time - time.time())
        self.move_updater_loop()

    def monitor_moves(self):
        while True:
            while self.move_time_left_sec:
                time.sleep(1)
                self.move_time_left_sec -= 1

            self.move_number += 1
            self.move_time_left_sec += 4
            Thread(target=lambda: self.blockchain.try_form_block(
                self.move_number)).start()

    def input_message(self, message):
        infected_nodes = []
        healthy_nodes = self.susceptible_nodes.copy()
        self.blockchain.add_transaction(message,
                                        message['hash'],
                                        message['start_time'])

        self.transmit_message(json.dumps(message).encode('ascii'),
                              infected_nodes,
                              healthy_nodes)
        print(f'You successfully voted for {message["type"]}, {message["content"]}')

    # def send_blockchain_requests(self):
    #     req_message = self.message_builder.build_message(VoteType.ask_for_chain,
    #                                                      signer=self.signer,
    #                                                      name=self.name,
    #                                                      public_key=self.public_key).body
    #
    #     self.input_message(req_message)

    def read_message_exists_answer(self, response):
        converted_dict = json.loads(response.decode('ascii'))
        if self._check_message(converted_dict):
            return set(converted_dict['extra'])
        return set()

    def ask_connected_for_messages(self, suspicious):
        message = self.message_builder.build_message(VoteType.are_hashes_valid_request,
                                                     signer=self.signer,
                                                     name=self.name,
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

    def deal_with_received_message(self, message: dict, address: (str, int)):
        mes_dict = json.loads(message.decode('ascii'))
        if not self._check_message(mes_dict, address):
            return
        #to edit
        # if not self.blockchain.try_add_block(mes_dict['hash'], mes_dict['prev_hash']):
        #     return

        if mes_dict['type'] == VoteType.ask_for_chain:
            self.message_handler.handle_chain_request(mes_dict['tcp_host'], mes_dict['tcp_port'])
            return

        # TODO think if we reduce content
        self.blockchain.add_transaction(mes_dict, mes_dict['hash'], mes_dict['start_time'])
        # return
        # if mes_dict['type'] == VoteType.response_chain_ask:
        #     self.message_handler.handle_chain_response(mes_dict)
        #     return
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

        print("\nMessage is: '{0}'.\nReceived at [{1}] from [{2}]\n"
              .format(json.dumps(mes_dict), time.ctime(time.time()), address))

        self.blockchain.add_transaction(message, )
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

    def _inform_user_about_period_changing(self):
        period = self.blockchain.init_block.current_period
        while True:
            if period != self.blockchain.init_block.current_period:
                period = self.blockchain.init_block.current_period
                print(f"Voting period has changed. Current period is '{period.name}'"
                      f"This means you can now only send and receive messages of types: {period.value}")


    def start_threads(self):
        Thread(target=self.receive_message).start()
        # New method if we really want this:
        #Thread(target=self.send_blockchain_requests).start()
        Thread(target=self.timer_launcher).start()
        Thread(target=self._inform_user_about_period_changing).start()
        # TODO think about step number updating
        #Thread(target=self._refresh_step_start).start()
