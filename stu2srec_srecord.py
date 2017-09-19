#!/usr/bin/env python
# title           :stu2srec_srecord.py
# description     :
# author          :christian FOURNIER
# date            :19/09/2017
# version         :
# usage           :
# notes           :
# python_version  :3.6.2
# =============================================================================

import sys
import struct

C_SREC_LENGTH = 0x10


def srecord_gen(p_bytes_msg=b'',
                p_int_base_addr=0,
                p_file_output=sys.stdout):
    l_int_run = 1
    l_int_addr = 0
    l_int_offset = 0
    l_int_pos = 0
    l_bytes_data = b''

    if len(p_bytes_msg) == 0:
        l_int_run = 0

    while l_int_run == 1:

        l_bytes_data = b''

        l_int_offset = l_int_pos

        if l_int_pos + C_SREC_LENGTH > len(p_bytes_msg):
            l_bytes_data = p_bytes_msg[l_int_pos:]
            l_int_pos = len(p_bytes_msg)
        else:
            l_bytes_data = p_bytes_msg[l_int_pos:l_int_pos + C_SREC_LENGTH]
            l_int_pos += C_SREC_LENGTH

        l_int_addr = p_int_base_addr + l_int_offset

        l_bytes_data = struct.pack(">I", l_int_addr) + l_bytes_data

        l_bytes_data = struct.pack(">B", len(l_bytes_data) + 1) + l_bytes_data

        l_bytes_data = l_bytes_data + struct.pack(">B", ~sum(l_bytes_data) & 0xFF)

        p_file_output.write("S3" + "".join(["%02X" % v for v in l_bytes_data]) + "\n")
        # print("S3" + "".join(["%02X" % v for v in l_bytes_data]), file=p_file_output)

        if len(p_bytes_msg) == l_int_pos:
            print("S70500000000FA", file=p_file_output)
            l_int_run = 0
