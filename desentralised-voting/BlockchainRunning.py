from Blockchain import Blockchain

if __name__ == '__main__':
    bc = Blockchain('root_content', 'root_hash')
    bc.try_add_transaction('new_content', 'new_hash', 'root_hash')
    bc.try_form_block()
    bc.try_add_transaction('block_2_content', 'block_2_hash', 'new_hash')
    bc.try_form_block()
    s = bc.serialize_chain_blocks()
    for one in s:
        block = bc.deserialize_block(one)
        print(one)
