from typing import Dict, Any, Optional
from MerkelTree import MerkelTree


class ChainBlock:
    def __init__(self,
                 node_hash: str,
                 nonce: str,
                 parent_hash: Optional[str],
                 merkel_tree: MerkelTree,
                 content: Dict[str, Any],
                 step: int,
                 branch_blocks_count: int):
        self.hash = node_hash
        self.nonce = nonce
        self.parent_hash = parent_hash
        self.merkel_tree = merkel_tree
        self.content = content
        self.step = step
        self.blocks_count = branch_blocks_count
