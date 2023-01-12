from __future__ import annotations

import socket
from threading import Thread
from typing import Dict, Any
import json
from MessageBuilder import VoteType


class MessageHandler:
    def __init__(self, gossip_node: GossipNode):
        self.gossip_node = gossip_node

    def handle_chain_request(self, tcp_host, tcp_port):
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_socket.bind((self.gossip_node.hostname, 1025))
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
        key_addr = address[0] + ':' + str(address[1])
        self.gossip_node.candidates_keys[key_addr] = message_dict['public_key']

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

    def handle_enter_vote_to_transmit(self, key, address: str, message_dict: Dict[str, Any]):
        # we already know about this node and voted for it
        if key in self.gossip_node.request_voting_process.keys():
            # adding received vote if it wasn't added already (that's why set)
            self.gossip_node.request_voting_process[key].add(message_dict['name'])

            # checking if there is enough votes for applying node to be trusted
            if len(self.gossip_node.request_voting_process[key]) == 2:
                self.gossip_node.address_port_to_public_key[address] = self.gossip_node.candidates_keys.pop(address)

        else:
            # adding our vote plus the vote we received and spread our vote
            self.gossip_node.request_voting_process[key] = {message_dict['name']}
            self.handle_vote_spreading(address, message_dict['try_enter_name'])
        Thread(target=self.gossip_node.transmit_message, args=(json.dumps(message_dict).encode('ascii'),
                                                               [],
                                                               self.gossip_node.susceptible_nodes.copy())).start()

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
            print('This fucker tries to falsify our honest, decent and most trusted votes')

    def handle_process_vote_spreading(self):
        vote_options = self.gossip_node.blockchain.init_block.voting_period_options
        # asking user to vote
        vote = None
        while vote not in vote_options:
            vote = input(f"New election has begun. Vote! Or don't, it doesn't really matter these days"
                         f"Candidates are: {vote_options}"
                         "Type the exact name of a candidate you want to vote for. All other messages "
                         "including candidates names with typos will not be considered.")

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
