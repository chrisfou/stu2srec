import sys
import struct

srec_length = 0x10


def srecord_gen(data=b'', baseaddr=0, file=sys.stdout):
    run = 1
    l_addr = 0
    offset = 0
    pos = 0
    l_data = b''

    if len(data) == 0:
        run = 0

    while run == 1:

        l_data = b''

        offset = pos

        if pos + srec_length > len(data):
            l_data = data[pos:]
            pos = len(data)
        else:
            l_data = data[pos:pos + srec_length]
            pos += srec_length

        l_addr = baseaddr + offset

        l_data = struct.pack(">I", l_addr) + l_data

        l_data = struct.pack(">B", len(l_data) + 1) + l_data

        l_data = l_data + struct.pack(">B", ~sum(l_data) & 0xFF)

        print("S3" + "".join(["%02X" % v for v in l_data]), file=file)

        if len(data) == pos:
            print("S70500000000FA", file=file)
            run = 0
