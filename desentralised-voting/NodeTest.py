import time
from threading import Event
from unittest import TestCase
from GossipNode import GossipNode
from VoteTypes import VoteType


class NodeTest(TestCase):
    def test_getting_chain_with_one_block(self):
        with GossipNode('127.0.0.1', 5000, [], 'first', 0, 0, []) as node1:
            with GossipNode('127.0.0.2', 5000, [('127.0.0.1', 5000)], 'second') as node2:
                self.assertEqual(node1.blockchain.init_block.hash,
                                 node2.blockchain.init_block.hash)

    def test_getting_chain_with_several_blocks(self):
        with GossipNode('127.0.0.1', 5000, [], 'first', 0, 0, []) as node1:
            node1.blockchain.add_transaction('content', 'hash', time.time())
            node1.blockchain.try_form_block(1)
            node1.blockchain.add_transaction('content2', 'hash2', time.time())
            node1.blockchain.try_form_block(2)
            with GossipNode('127.0.0.2', 5000, [('127.0.0.1', 5000)], 'second') as node2:
                self.assertListEqual(node1.blockchain._block_hashes_list,
                                     node2.blockchain._block_hashes_list)

    def test_getting_info_from_chain(self):
        with GossipNode('127.0.0.1', 5000, [], 'first', 0, 0, []) as node1:
            enter_msg = node1.message_builder.build_message(
                VoteType.enter_request,
                signer=node1.signer,
                name='firsta',
                public_key=node1.public_key)
            node1.blockchain.add_transaction(enter_msg, enter_msg['hash'], 1)
            enter_msg = node1.message_builder.build_message(
                VoteType.enter_request,
                signer=node1.signer,
                name='firstb',
                public_key=node1.public_key)
            node1.blockchain.add_transaction(enter_msg, enter_msg['hash'], 1)
            node1.blockchain.try_form_block(1)

            vote_message = node1.message_builder.build_message(
                VoteType.enter_vote,
                signer=node1.signer,
                name=node1.name,
                try_enter_address='127.0.0.1:5000',
                try_enter_name='firsta',
                enter_vote=True)
            node1.blockchain.add_transaction(vote_message,
                                             vote_message['hash'],
                                             time.time())
            node1.blockchain.try_form_block(2)
            node1.fill_counters_from_chain()

            self.assertEqual(len(node1.request_voting_process), 2)
            self.assertEqual(len(node1.request_voting_process['firsta']), 1)
            self.assertEqual(len(node1.request_voting_process['firstb']), 0)

    def test_message_tracking(self):
        with GossipNode('127.0.0.1', 5000, [], 'first', 0, 0, []) as node1:
            node1.blockchain.add_transaction('content', 'hash', time.time())
            node1.blockchain.try_form_block(1, Event())
            msg = node1.message_builder.build_message(
                VoteType.enter_request,
                signer=node1.signer,
                name=node1.name,
                public_key=node1.public_key)
            print('track sleep')
            node1._track_message_in_chain(msg, 1)
            print('resent message, wait 2 steps for block forming')
            time.sleep(node1.step_period_seconds * 4)
            f = node1.blockchain.try_find_transaction_hash_from(1, msg['hash'])
            self.assertTrue(f)
