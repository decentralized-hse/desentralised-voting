from unittest import TestCase
from GossipNode import GossipNode


class NodeTest(TestCase):
    def test_getting_chain_with_one_block(self):
        node1 = GossipNode('127.0.0.1', 5000, [], 'first', 0, 0, ['1', '2'])
        node2 = GossipNode('127.0.0.2', 5000, [['127.0.0.1', 5000]], 'second')
        self.assertEqual(node1.blockchain.init_block.hash,
                         node2.blockchain.init_block.hash)
