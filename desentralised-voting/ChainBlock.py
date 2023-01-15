from typing import Dict, Any, Optional
from MerkelTree import MerkelTree


class ChainBlock:
    def __init__(self,
                 node_hash: str,
                 parent_hash: Optional[str],
                 merkel_tree: MerkelTree,
                 content: Dict[str, Any],
                 key: str,
                 step: int):
        self.hash = node_hash
        self.parent_hash = parent_hash
        self.merkel_tree = merkel_tree
        self.content = content
        self.public_key = key
        self.step = step
