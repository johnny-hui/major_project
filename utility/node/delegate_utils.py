"""
Description:
This Python file provides utility functions for the DelegateNode class.

"""
from models.DelegateNode import DelegateNode
from utility.general.utils import perform_cleanup


def promotion_preparation(node: object):
    """
    Prepares existing Node data for transfer to Delegate
    Node (due to promotion).

    @param node:
        A reference to the Node object to be promoted

    @return: attributes
        A list of tuples containing the class attribute name
        and its value prior to promotion
    """
    attributes = [(attribute, value) for attribute, value in vars(node).items()]
    return attributes


def get_delegate_node(old_node: object):
    """
    A factory method to create a DelegateNode from a
    promoted regular Node.

    @param old_node:
        An instance of the promoted regular Node

    @return: DelegateNode
        A DelegateNode instance
    """
    original_attributes = promotion_preparation(node=old_node)
    perform_cleanup(old_node)
    return DelegateNode(original_data=original_attributes)
