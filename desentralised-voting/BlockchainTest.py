from unittest import TestCase
from Blockchain import Blockchain


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
