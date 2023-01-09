from threading import Event, Thread
from unittest import TestCase
from MerkelTree import MerkelTree
from Blockchain import Blockchain, ChainBlock


class TestBlockchain(TestCase):
    def test_add(self):
        try:
            bc = Blockchain('root_content', 'root_hash')
            bc.add_transaction('new_content', 'block_1_hash', 1)
            bc.try_form_block(step=1, stopper=Event())
            bc.add_transaction('block_2_content', 'block_2_hash', 2)
            bc.try_form_block(step=2, stopper=Event())
            serialized = bc.serialize_chain_blocks()

            new_chain = Blockchain()
            for one in serialized:
                block = bc.deserialize_block(one)
                new_chain.try_add_block(block, skip_checks=True)
        except BaseException as e:
            self.fail()

    def test_getting_longest_chain_contents(self):
        bc = Blockchain('root_content', 'root_hash')
        block02 = self.crete_block_on(bc.init_block, '02', 'content02', 2)
        block01 = self.crete_block_on(bc.init_block, '01', 'content01', 1)
        block12 = self.crete_block_on(block01, '12', 'content12', 2)
        for block in [block02,  block01, block12]:
            bc.try_add_block(block, skip_checks=True)
        contents = [c for c in bc.get_actual_chain_backwards()]
        expected = ['content12', 'content01']
        self.assertListEqual(contents, expected)

    def test_interrupting_block_forming(self):
        bc = Blockchain('root_content', 'root_hash', pow_zeros=4)
        print('init block created')
        bc.add_transaction('new_content', 'block_1_hash', 1)
        stop_event = Event()
        thread = Thread(target=bc.try_form_block, args=[1, stop_event])
        thread.start()
        stop_event.set()
        thread.join()
        self.assertEqual(len(bc._hash_to_block), 1)

    def test_finding_transaction_hash(self):
        bc = Blockchain('root_content', 'root_hash')
        bc.add_transaction('new_content', 'block_1_hash', 1)
        bc.try_form_block(step=1, stopper=Event())
        bc.add_transaction('block_2_content', 'block_2_hash', 2)
        bc.try_form_block(step=2, stopper=Event())
        self.assertFalse(bc.try_find_transaction_hash_from(2, 'block_1_hash'))
        self.assertTrue(bc.try_find_transaction_hash_from(1, 'block_1_hash'))

    def crete_block_on(self, parent, block_hash, content, step) -> ChainBlock:
        return ChainBlock(block_hash,
                          'nonce',
                          parent.hash,
                          MerkelTree([dict()]),
                          content,
                          step,
                          parent.blocks_count + 1)
