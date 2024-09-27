"""
Description:
This Python file executes the program as an AdminNode.

@author Johnny Hui (A00973103)
@contact <jhui34@my.bcit.ca>

"""
from models.AdminNode import AdminNode

if __name__ == '__main__':
    node = AdminNode()
    node.start()
