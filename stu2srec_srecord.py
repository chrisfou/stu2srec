import sys
import struct

C_SREC_LENGTH = 0x10


def srecord_gen(p_bytes_msg=b'',
                p_int_base_addr=0,
                p_file_output=sys.stdout):
    l_run = 1
    l_addr = 0
    l_offset = 0
    l_pos = 0
    l_data = b''

    if len(p_bytes_msg) == 0:
        l_run = 0

    while l_run == 1:

        l_data = b''

        l_offset = l_pos

        if l_pos + C_SREC_LENGTH > len(p_bytes_msg):
            l_data = p_bytes_msg[l_pos:]
            l_pos = len(p_bytes_msg)
        else:
            l_data = p_bytes_msg[l_pos:l_pos + C_SREC_LENGTH]
            l_pos += C_SREC_LENGTH

        l_addr = p_int_base_addr + l_offset

        l_data = struct.pack(">I", l_addr) + l_data

        l_data = struct.pack(">B", len(l_data) + 1) + l_data

        l_data = l_data + struct.pack(">B", ~sum(l_data) & 0xFF)

        print("S3" + "".join(["%02X" % v for v in l_data]), file=p_file_output)

        if len(p_bytes_msg) == l_pos:
            print("S70500000000FA", file=p_file_output)
            l_run = 0
