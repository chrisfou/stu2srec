#!/usr/bin/env python
# title           :stu2srec_nodes.py
# description     :
# author          :christian FOURNIER
# date            :19/09/2017
# version         :
# usage           :python stu2srec_nodes.py
# notes           :
# python_version  :3.6.2
# =============================================================================

from collections import Sequence


class NodeBytes:
    def __init__(self,
                 p_bytes=b'',
                 p_str_info=""):
        self.m_bytes = p_bytes
        self.m_str_info = p_str_info


class NodesBytes(Sequence):
    def __init__(self):
        self.m_list = []

    def append(self,
               p_node=NodeBytes()):
        self.m_list.append(p_node)

    def insert(self,
               p_int_index=0,
               p_node=NodeBytes()):
        self.m_list.insert(p_int_index, p_node)

    def multiply(self, p_int_val=1):
        self.m_list = p_int_val * self.m_list

    def concat_all_bytes(self):
        l_bytes_result = b''
        for i_node in self.m_list:
            if type(i_node.m_bytes) == bytes:
                l_bytes_result += i_node.m_bytes
        return l_bytes_result

    def nb_bytes(self):
        l_int_result = 0
        for i_node in self.m_list:
            l_int_result += len(i_node.m_bytes)
        return l_int_result

    def __getitem__(self,
                    index):
        return self.m_list[index]

    def __add__(self, other):
        l_nodes = NodesBytes()
        l_nodes.m_list.extend(self.m_list)
        l_nodes.m_list.extend(other.m_list)
        return l_nodes

    def __len__(self):
        return len(self.m_list)

    def __repr__(self):
        return "toto"


if __name__ == "__main__":

    import struct

    l_nodes_1 = NodesBytes()
    l_node_1 = NodeBytes(p_bytes=struct.pack("<bb", 2, 3),
                         p_str_info="node_1")
    l_nodes_1.append(p_node=l_node_1)
    l_nodes_1.append(p_node=l_node_1)

    l_nodes_2 = NodesBytes()
    l_node_2 = NodeBytes(p_bytes=struct.pack("<bbbb", 2, 3, 4, 5),
                         p_str_info="node_2")
    l_nodes_2.append(p_node=l_node_2)
    l_node_2 = NodeBytes(p_bytes="rerer",
                         p_str_info="node_2")
    l_nodes_2.append(p_node=l_node_2)
    l_node_2 = NodeBytes(p_bytes=788,
                         p_str_info="node_2")
    l_nodes_2.append(p_node=l_node_2)

    l_nodes_3 = l_nodes_1 + l_nodes_2

    for i, j in enumerate(l_nodes_3):
        print(i, j, type(j.m_void_data))

    l_nodes_3.multiply(p_int_val=10)

    for i, j in enumerate(l_nodes_3):
        print(i, j, type(j.m_void_data))

    for i, j in enumerate(l_nodes_3):
        print(i, j, type(j.m_void_data))
