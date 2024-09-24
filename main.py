"""
Description:
This Python file executes the program for regular Nodes
and Delegate node (if promoted).

"""
from models.Node import Node
from utility.node.delegate_utils import get_delegate_node


if __name__ == '__main__':
    # Start regular Node
    node = Node()
    node.start()

    # Promotion to Delegate Node [Polymorphism]
    if node.is_promoted:
        delegate = get_delegate_node(old_node=node)
        delegate.start()
