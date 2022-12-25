from unittest import TestCase
from MerkelTree import MerkelTree
from Blockchain import Blockchain, ChainBlock


class TestBlockchain(TestCase):
    def test_add(self):
        try:
            bc = Blockchain('root_content', 'root_hash')
            bc.add_transaction('new_content', 'root_hash', 1)
            bc.try_form_block(step=1)
            bc.add_transaction('block_2_content', 'block_2_hash', 2)
            bc.try_form_block(step=2)
            serialized = bc.serialize_chain_blocks()

            new_chain = Blockchain()
            for one in serialized:
                block = bc.deserialize_block(one)
                new_chain.try_add_block(block, skip_checks=True)
        except:
            self.fail()

    def test_getting_longest_chain_contents(self):
        bc = Blockchain('root_content', 'root_hash')
        block02 = self.crete_block_on(bc.init_block, '02', 'content02', 2)
        block01 = self.crete_block_on(bc.init_block, '01', 'content01', 1)
        block12 = self.crete_block_on(block01, '12', 'content12', 2)
        for block in [block02,  block01, block12]:
            bc.try_add_block(block, skip_checks=True)
        contents = [c for c in bc.get_actual_chain_backwards()]
        expected = ['content12', 'content01', 'root_content']
        self.assertListEqual(contents, expected)

    def crete_block_on(self, parent, block_hash, content, step) -> ChainBlock:
        return ChainBlock(block_hash,
                          'nonce',
                          parent.hash,
                          MerkelTree([dict()]),
                          content,
                          step,
                          parent.blocks_count + 1)
