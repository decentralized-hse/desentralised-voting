import math
from Cryptodome.Hash import SHA256
from MerkelTreeNode import MerkelTreeNode


class MerkelTree:
    def __init__(self, node_data: [dict]):
        self.tree_top = self.build_merkle_tree(node_data)

    @staticmethod
    def calculate_hash(data: str) -> str:
        bytes_data = bytearray(data, "utf-8")
        h = SHA256.new()
        h.update(bytes_data)
        return h.hexdigest()

    @staticmethod
    def compute_tree_depth(number_of_leaves: int) -> int:
        return math.ceil(math.log2(number_of_leaves))

    def build_merkle_tree(self, node_data: [dict]) -> MerkelTreeNode:
        self.fill_set(node_data)
        old_set_of_nodes = [MerkelTreeNode(self.calculate_hash(str(data))) for data in node_data]
        tree_depth = self.compute_tree_depth(len(old_set_of_nodes))

        for i in range(0, tree_depth):
            num_nodes = 2 ** (tree_depth - i)
            new_set_of_nodes = []
            for j in range(0, num_nodes, 2):
                child_node_0 = old_set_of_nodes[j]
                child_node_1 = old_set_of_nodes[j + 1]
                new_node = MerkelTreeNode(
                    value=self.calculate_hash(f"{child_node_0.value}{child_node_1.value}"),
                    left_child=child_node_0,
                    right_child=child_node_1
                )
                new_set_of_nodes.append(new_node)
            old_set_of_nodes = new_set_of_nodes
        return old_set_of_nodes[0]

    @staticmethod
    def is_power_of_2(number_of_leaves: int) -> bool:
        return math.log2(number_of_leaves).is_integer()

    def fill_set(self, list_of_nodes):
        current_number_of_leaves = len(list_of_nodes)
        if self.is_power_of_2(current_number_of_leaves):
            return list_of_nodes
        total_number_of_leaves = 2 ** self.compute_tree_depth(current_number_of_leaves)
        if current_number_of_leaves % 2 == 0:
            for i in range(current_number_of_leaves, total_number_of_leaves, 2):
                list_of_nodes = list_of_nodes + [list_of_nodes[-2], list_of_nodes[-1]]
        else:
            for i in range(current_number_of_leaves, total_number_of_leaves):
                list_of_nodes.append(list_of_nodes[-1])
        return list_of_nodes

    def __getitem__(self, item: str):
        return self.__dict__[item]
