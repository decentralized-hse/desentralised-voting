from __future__ import annotations

import socket
import time
from threading import Thread
from typing import Dict, Any
import json
from MessageBuilder import VoteType


class MessageHandler:
    def __init__(self, gossip_node: GossipNode):
        self.gossip_node = gossip_node
        #self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def handle_chain_request(self, tcp_host, tcp_port):
        while True:
            try:
                temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_socket.bind((self.gossip_node.hostname, 1025))
                temp_socket.connect((tcp_host, tcp_port))
                for data in self.gossip_node.blockchain.serialize_chain_blocks():
                    temp_socket.sendall(data)
                print('closing')
                temp_socket.close()
                print('closed')
                break
            except OSError:
                print('used')
                time.sleep(1)

    def handle_enter_request_to_transmit(self, message_dict: Dict[str, Any], ask_vote: bool):
        # so now we only get enter_request if we don't have the node in susceptible, we do not spread this type of msg

        # adding node to voting_process and candidates_keys
        # not adding node to susceptible yet so we don't spread enter_vote messages to it
        print(message_dict)
        key_addr = message_dict['try_enter_address']
        address = (key_addr.split(':')[0], int(key_addr.split(':')[1]))
        self.gossip_node.susceptible_nodes.append(address)
        if message_dict['name'] not in self.gossip_node.request_voting_process.keys():
            self.gossip_node.request_voting_process[message_dict['name']] = set()

        self.gossip_node.candidates_keys[key_addr] = message_dict['public_key']
        print(f'Saved {key_addr} public key')

        if ask_vote:
            self.handle_vote_spreading(address, message_dict['name'])

    def handle_vote_spreading(self, address, try_enter_name: str):
        # asking user to vote
        enter_address = f'{address[0]}:{address[1]}'
        vote = input("New user {} is requesting enter permission. Do you grant permission(Yes/No)?"
                     "Message in any format other than 'Yes' will be taken as No."
                     .format(try_enter_name))

        # add ourself if the vote is Yes
        if vote == "Yes":
            # self.gossip_node.request_voting_process[try_enter_name].add(self.gossip_node.name)
            self._add_vote(try_enter_name, self.gossip_node.name, enter_address)

        # building message to spread voting
        message = self.gossip_node.message_builder.build_message(VoteType.enter_vote,
                                                                 signer=self.gossip_node.signer,
                                                                 name=self.gossip_node.name,
                                                                 try_enter_address=enter_address,
                                                                 try_enter_name=try_enter_name,
                                                                 enter_vote=vote == "Yes")

        # transmitting message to all susceptible nodes
        Thread(target=self.gossip_node.input_message, args=(message,)).start()

    def handle_enter_vote_to_transmit(self, message_dict: Dict[str, Any]):
        # we already know about this node and voted for it
        key = message_dict['try_enter_name']
        address = message_dict['try_enter_address']
        if key in self.gossip_node.request_voting_process.keys():
            # adding received vote if it wasn't added already (that's why set)
            self._add_vote(key, message_dict['name'], address)
        else:
            # adding our vote plus the vote we received and spread our vote
            if key == self.gossip_node.name:
                return
            self.gossip_node.request_voting_process[key] = {message_dict['name']}
            self.handle_vote_spreading(address, message_dict['try_enter_name'])

    def _add_vote(self, candidate_name, voter_name, candidate_address):
        self.gossip_node.request_voting_process[candidate_name].add(voter_name)

        votes_for_request = len(self.gossip_node.request_voting_process[candidate_name])
        voters = len(self.gossip_node.address_port_to_public_key)
        print('votes_for_request', votes_for_request)
        print('voters', voters)
        if votes_for_request >= 2 or voters < 2:
            try:
                self.gossip_node.address_port_to_public_key[candidate_address] = \
                    self.gossip_node.candidates_keys.pop(candidate_address)
                print('Added', candidate_name, candidate_address)
                print(f'Voters: {", ".join(self.gossip_node.address_port_to_public_key.keys())}')
            except KeyError as e:
                print(e)
            print(f'Candidates: {", ".join(self.gossip_node.candidates_keys)}')

    def handle_block(self, block_json):
        block = self.gossip_node.blockchain.deserialize_block_from_json(block_json)
        self.gossip_node.blockchain.try_add_block(block)

    def handle_process_vote(self, message_dict: Dict[str, Any]):
        vote = message_dict['process_vote_option']
        if vote in self.gossip_node.voting_process:
            self.gossip_node.voting_process[vote].add(message_dict['name'])
            Thread(target=self.gossip_node.transmit_message, args=(json.dumps(message_dict).encode('ascii'),
                                                                   [],
                                                                   self.gossip_node.susceptible_nodes.copy())).start()
        else:
            print('This fucker tries to falsify our honest, '
                  'decent and most trusted elections')

    def handle_process_vote_spreading(self):
        vote_options = self.gossip_node.blockchain.init_block.voting_period_options
        # asking user to vote
        vote = None
        while vote not in vote_options:
            vote = input(f"New election has begun. Vote! Or don't, it doesn't really matter these days\n"
                         f"Candidates are: {', '.join(vote_options)}\n"
                         "Type the exact name of a candidate you want to vote for. All other messages "
                         "including candidates names with typos will not be considered.").strip()

        # add our vote
        self.gossip_node.voting_process[vote].add(self.gossip_node.name)

        # building message to spread voting
        message = self.gossip_node.message_builder.build_message(VoteType.process_vote,
                                                                 signer=self.gossip_node.signer,
                                                                 name=self.gossip_node.name,
                                                                 process_vote_option=vote)
        # transmitting message to all susceptible nodes
        Thread(target=self.gossip_node.input_message, args=(message,)).start()


from GossipNode import GossipNode
