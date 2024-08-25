"""
Description:
This Python file executes the program.

"""
from models.Node import Node
import sys
import select

if __name__ == '__main__':
    node = Node()
    node.start()