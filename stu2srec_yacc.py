#!/usr/bin/env python
# title           :stu2srec_yacc.py
# description     :
# author          :christian FOURNIER
# date            :19/09/2017
# version         :
# usage           :
# notes           :
# python_version  :3.6.2
# =============================================================================

from stu2srec_lex import *

from stu2srec_srecord import srecord_gen
from stu2srec_des import cbc_mac_compute, CypherOp, C_INT_DES_ENCRYPT
from stu2srec_sacem import sacem

import struct
import zlib  # crc32
import ply.yacc as yacc

from stu2srec_error import StopException
from stu2srec_nodes import *

#
type_id = None

# Parsing rules
precedence = (
    ('left', 'OR', 'XOR', 'AND', 'LSH', 'RSH'),
    ('left', '+', '-'),
    ('left', '*'),
    ('left', ','),
    ('right', 'UMINUS'),
)


def p_statement_list(p):
    ''' statement_list : statement ';'
                       | statement_list statement ';' '''
    pass


def p_statement_name_equal_expression(p):
    ''' statement : ID '=' expression '''
    # | ID_NUMBER '=' expression
    # | ID_FLOAT '=' expression 
    # | ID_LIST '=' expression '''
    g_map_nodes[p[1]] = p[3]
    pass


def p_statement_name_equal_array(p):
    ''' statement : ID '=' array '''
    # | ID_NUMBER '=' array
    # | ID_FLOAT '=' array 
    # | ID_LIST '=' array '''
    l_nodes = p[3]
    l_nodes.insert(p_int_index=0,
                   p_node=NodeBytes(p_str_info=p[1]))
    g_map_nodes[p[1]] = l_nodes
    pass


def p_statement_expression(p):
    ''' statement : expression '''
    print(p[1])
    pass


def p_statement_array(p):
    ''' statement : array '''
    print(p[1])
    pass


def p_array_float32_list(p):
    ''' array : FLOAT32 set_type_float32 '[' list ']' '''
    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=p[4],
                                 p_str_info=""))

    pass


def p_array_ub_list(p):
    ''' array : UBYTE set_type_ubyte '[' list ']' '''
    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=p[4],
                                 p_str_info=""))
    pass


def p_array_uw_list(p):
    ''' array : UWORD set_type_uword '[' list ']' '''
    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=p[4],
                                 p_str_info=""))
    pass


def p_array_ul_list(p):
    ''' array : ULONG set_type_ulong '[' list ']' '''
    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=p[4],
                                 p_str_info=""))
    pass


def p_array_sb_list(p):
    ''' array : SBYTE set_type_sbyte '[' list ']' '''
    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=p[4],
                                 p_str_info=""))
    pass


def p_array_sw_list(p):
    ''' array : SWORD set_type_sword '[' list ']' '''
    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=p[4],
                                 p_str_info=""))
    pass


def p_array_sl_list(p):
    ''' array : SLONG set_type_slong '[' list ']' '''
    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=p[4],
                                 p_str_info=""))
    pass


def p_array_plus(p):
    ''' array : array '+' array '''
    try:
        p[0] = p[1] + p[3]
    except TypeError as err:
        raise StopException(
            p_str_msg="line {} : {}".format(p.lineno(2), str(err)))
    pass


def p_array_multiply(p):
    ''' array : expression '*' array '''
    try:
        # p[0] = p[1] * p[3]
        p[0] = p[3]
        p[0].multiply(p_int_val=p[1])

    except TypeError as err:
        raise StopException(
            p_str_msg="line {} : {}".format(p.lineno(2), str(err)))
    pass


def p_array_idlist(p):
    ''' array : ID_LIST '''
    p[0] = g_map_nodes[p[1]]
    pass


def p_array_string(p):
    ''' array : TEXT '['  STRING ']' '''
    p.set_lineno(0, p.lineno(1))
    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=bytes(p[3], 'utf-8'),
                                 p_str_info="TEXT[{}]".format(p[3])))
    pass


def p_array_sacem(p):
    ''' array : SACEM '[' ID PARAM array ',' ID PARAM array ']' '''
    if p[3] != "msg":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(3), p[3]))
    if p[7] != "svl":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(7), p[7]))

    l_bytes_svl = p[9].concat_all_bytes()
    l_bytes_msg = p[5].concat_all_bytes()

    if len(l_bytes_svl) != 8:
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter size error ! ( {} bytes instead of 8 )".format(
                p.lineno(7), p[7],
                len(l_bytes_svl)))

    l_bytes_result = sacem(p_bytes_msg=l_bytes_msg,
                           p_bytes_svl=l_bytes_svl)

    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=l_bytes_result,
                                 p_str_info="SACEM(p_msg=0x{}, p_svl=0x{})".format(
                                     l_bytes_msg.hex(), l_bytes_svl.hex())))
    pass


def p_array_cbc_mac(p):
    ''' array : CBCMAC '[' ID PARAM array ',' ID PARAM array ']' '''
    if p[3] != "msg":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(3), p[3]))
    if p[7] != "keys_123":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(7), p[7]))

    l_bytes_msg = p[5].concat_all_bytes()
    l_bytes_keys123 = p[9].concat_all_bytes()

    if len(l_bytes_keys123) != 3 * 8:
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter size error ! ( {} bytes instead of 24 ) ".format(
                p.lineno(7), p[7],
                len(l_bytes_keys123)))

    l_bytes_result = cbc_mac_compute(p_bytes_msg=l_bytes_msg,
                                     p_bytes_key_1=l_bytes_keys123[
                                                   0 * 8:1 * 8],
                                     p_bytes_key_2=l_bytes_keys123[
                                                   1 * 8:2 * 8],
                                     p_bytes_key_3=l_bytes_keys123[
                                                   2 * 8:3 * 8])

    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=l_bytes_result,
                                 p_str_info="CBCMAC(p_msg=0x{}, p_keys=0x{})".format(
                                     l_bytes_msg.hex(),
                                     l_bytes_keys123.hex())))
    pass


def p_array_ecb_encrypt(p):
    ''' array : ECB_ENCRYPT '[' ID PARAM array ',' ID PARAM array ']' '''
    if p[3] != "msg":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(3), p[3]))
    if p[7] != "key":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(7), p[7]))

    l_bytes_msg = p[5].concat_all_bytes()
    l_bytes_key = p[9].concat_all_bytes()

    if len(l_bytes_key) != 8:
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter size error ! ( {} bytes instead of 8 ) ".format(
                p.lineno(7),
                p[7],
                len(l_bytes_key)))

    l_cyphero = CypherOp(p_bytes_key=l_bytes_key,
                         p_int_encrypt=C_INT_DES_ENCRYPT)

    l_bytes_result = l_cyphero.ecb_compute(p_bytes_msg=l_bytes_msg)

    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=l_bytes_result,
                                 p_str_info="ECB_ENCRYPT(p_msg=0x{}, p_key=0x{})".format(
                                     l_bytes_msg.hex(), l_bytes_key.hex())))
    pass


def p_array_cbc_encrypt(p):
    ''' array : CBC_ENCRYPT '[' ID PARAM array ',' ID PARAM array ',' ID PARAM array ']' '''
    if p[3] != "msg":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(3), p[3]))
    if p[7] != "key":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(7), p[7]))
    if p[11] != "iv":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(11), p[11]))

    l_bytes_msg = p[5].concat_all_bytes()
    l_bytes_key = p[9].concat_all_bytes()
    l_bytes_iv = p[13].concat_all_bytes()

    if len(l_bytes_key) != 8:
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter size error ! ( {} bytes instead of 8 ) ".format(
                p.lineno(7),
                p[7],
                len(l_bytes_key)))

    if len(l_bytes_iv) != 8:
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter size error ! ( {} bytes instead of 8 ) ".format(
                p.lineno(7),
                p[11],
                len(l_bytes_iv)))

    l_cypherop = CypherOp(p_bytes_key=l_bytes_key,
                          p_int_encrypt=C_INT_DES_ENCRYPT)

    l_bytes_result = l_cypherop.cbc_compute(p_bytes_msg=l_bytes_msg,
                                            p_bytes_iv=l_bytes_iv)

    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=l_bytes_result,
                                 p_str_info="CBC_ENCRYPT(p_msg=0x{}, p_key=0x{}, p_iv=0x{})".format(
                                     l_bytes_msg.hex(),
                                     l_bytes_key.hex(),
                                     l_bytes_iv.hex())))

    pass


def p_array_crc32(p):
    ''' array : CRC32 '[' ID PARAM array ']' '''
    if p[3] != "msg":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(3), p[3]))

    l_bytes_msg = p[5].concat_all_bytes()

    l_bytes_result = struct.pack(">I",
                                 zlib.crc32(bytes(l_bytes_msg)) & 0xFFFFFFFF)

    p[0] = NodesBytes()
    p[0].append(p_node=NodeBytes(p_bytes=l_bytes_result,
                                 p_str_info="CRC32(p_msg=0x{})".format(
                                     l_bytes_msg.hex())))
    pass


def p_array_hex(p):
    ''' array : HEX '[' STRING ']' '''
    l_str_text = p[3]
    if len(p[3]) % 2 != 0:
        l_str_text = "0" + l_str_text
    try:
        l_bytes_result = bytes.fromhex(l_str_text)
        p[0] = NodesBytes()
        p[0].append(p_node=NodeBytes(p_bytes=l_bytes_result,
                                     p_str_info="HEX[{}]".format(p[3])))
    except:
        raise StopException(
            p_str_msg="line {} : string \'{}\', not hexadecimal".format(
                p.lineno(3), l_str_text))

    pass


def p_array_left_fill(p):
    ''' array : LEFT_FILL '[' ID PARAM array ',' ID PARAM array ',' ID PARAM array ']' '''
    if p[3] != "msg":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(3), p[3]))

    if p[7] != "pattern":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(7), p[7]))

    if p[11] != "size":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(11), p[11]))

    l_int_new_msg_size = int(p[13].concat_all_bytes().hex(), 16)
    l_int_pattern_size = p[9].nb_bytes()

    if l_int_pattern_size != 1:
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter size error {} bytes instead of 1 ! ".format(
                p.lineno(9), p[7], l_int_pattern_size))

    l_bytes_pattern_value = p[9].concat_all_bytes()
    l_int_msg_size = int(p[5].nb_bytes())

    l_int_nb_bytes_to_fill = l_int_new_msg_size - l_int_msg_size

    if l_int_nb_bytes_to_fill < 0:
        raise StopException(
            p_str_msg="line {} : LEFT_FILL not possible. The message size is over the requested size! ".format(
                p.lineno(1)))

    l_node_fill = NodeBytes(
        p_str_info="left fill of {0:#x} bytes with pattern {1:#x}".format(
            l_int_nb_bytes_to_fill,
            int(l_bytes_pattern_value.hex(), 16)),
        p_bytes=l_bytes_pattern_value * l_int_nb_bytes_to_fill)

    p[0] = p[5]
    p[0].insert(p_int_index=0, p_node=l_node_fill)

    pass


def p_array_right_fill(p):
    ''' array : RIGHT_FILL '[' ID PARAM array ',' ID PARAM array ',' ID PARAM array ']' '''
    if p[3] != "msg":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(3), p[3]))

    if p[7] != "pattern":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(7), p[7]))

    if p[11] != "size":
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter not valid ! ".format(
                p.lineno(11), p[11]))

    l_int_new_msg_size = int(p[13].concat_all_bytes().hex(), 16)
    l_int_pattern_size = p[9].nb_bytes()

    if l_int_pattern_size != 1:
        raise StopException(
            p_str_msg="line {} : \'{}\': parameter size error {} bytes instead of 1 ! ".format(
                p.lineno(9), p[7], l_int_pattern_size))

    l_bytes_pattern_value = p[9].concat_all_bytes()
    l_int_msg_size = int(p[5].nb_bytes())

    l_int_nb_bytes_to_fill = l_int_new_msg_size - l_int_msg_size

    if l_int_nb_bytes_to_fill < 0:
        raise StopException(
            p_str_msg="line {} : RIGTH_FILL not possible. The message size is over the requested size! ".format(
                p.lineno(1)))

    l_node_fill = NodeBytes(
        p_str_info="right fill of {0:#x} bytes with pattern {1:#x}".format(
            l_int_nb_bytes_to_fill,
            int(l_bytes_pattern_value.hex(), 16)),
        p_bytes=l_bytes_pattern_value * l_int_nb_bytes_to_fill)

    p[0] = p[5]
    p[0].append(p_node=l_node_fill)

    pass


def p_list(p):
    ''' list : list ',' list '''
    p[0] = p[1] + p[3]
    pass


def p_list_expression(p):
    ''' list : expression '''
    try:
        if type_id == "UB":
            p[0] = struct.pack(">B", p[1])
        elif type_id == "SB":
            p[0] = struct.pack(">b", p[1])
        elif type_id == "UW":
            p[0] = struct.pack(">H", p[1])
        elif type_id == "SW":
            p[0] = struct.pack(">h", p[1])
        elif type_id == "UL":
            p[0] = struct.pack(">I", p[1])
        elif type_id == "SL":
            p[0] = struct.pack(">i", p[1])
        elif type_id == "F32":
            p[0] = struct.pack(">f", p[1])

        else:
            raise StopException(
                p_str_msg="line {} : Array format not defined".format(
                    p.lineno(1)))

    except struct.error as err:
        raise StopException(
            p_str_msg="line {} : value \'{}\', ".format(p.lineno(1),
                                                        p[1]) + str(err))

    pass


def p_expression_plus(p):
    ''' expression : expression '+' expression '''
    p[0] = p[1] + p[3]
    pass


def p_expression_minus(p):
    ''' expression : expression '-' expression '''
    p[0] = p[1] - p[3]
    pass


def p_expression_multiply(p):
    ''' expression : expression '*' expression '''
    p[0] = p[1] * p[3]
    pass


def p_expression_uminus(p):
    ''' expression : '-' expression %prec UMINUS '''
    p[0] = -p[2]
    p.set_lineno(0, p.lineno(2))
    pass


def p_expression_lsh(p):
    ''' expression : expression LSH expression '''
    try:
        p[0] = p[1] << p[3]
    except TypeError as err:
        raise StopException(
            p_str_msg="line {} : {}".format(p.lineno(2), str(err)))
    pass


def p_expression_rsh(p):
    ''' expression : expression RSH expression '''
    try:
        p[0] = p[1] >> p[3]
    except TypeError as err:
        raise StopException(
            p_str_msg="line {} : {}".format(p.lineno(2), str(err)))
    pass


def p_expression_and(p):
    ''' expression : expression AND expression '''
    try:
        p[0] = p[1] & p[3]
    except TypeError as err:
        raise StopException(
            p_str_msg="line {} : {}".format(p.lineno(2), str(err)))
    pass


def p_expression_or(p):
    ''' expression : expression OR expression '''
    try:
        p[0] = p[1] | p[3]
    except TypeError as err:
        raise StopException(
            p_str_msg="line {} : {}".format(p.lineno(2), str(err)))
    pass


def p_expression_xor(p):
    ''' expression : expression XOR expression '''
    try:
        p[0] = p[1] ^ p[3]
    except TypeError as err:
        raise StopException(
            p_str_msg="line {} : {}".format(p.lineno(2), str(err)))
    pass


def p_expression_paren(p):
    ''' expression : '(' expression ')' '''
    p[0] = p[2]
    p.set_lineno(0, p.lineno(2))
    pass


def p_expression_number(p):
    ''' expression : NUMBER '''
    p[0] = p[1]
    p.set_lineno(0, p.lineno(1))
    pass


def p_expression_idnumber(p):
    ''' expression : ID_NUMBER '''
    p[0] = g_map_nodes[p[1]]
    p.set_lineno(0, p.lineno(1))
    pass


def p_expression_float(p):
    ''' expression : FLOAT'''
    p[0] = p[1]
    p.set_lineno(0, p.lineno(1))
    pass


def p_expression_idfloat(p):
    ''' expression : ID_FLOAT'''
    p[0] = g_map_nodes[p[1]]
    p.set_lineno(0, p.lineno(1))
    pass


def p_expression_size(p):
    ''' expression : SIZE '(' array ')' '''
    p[0] = p[3].nb_bytes()
    p.set_lineno(0, p.lineno(1))
    pass


def p_expression_bytsum(p):
    ''' expression : BYTSUM '(' array ')' '''
    l_int_sum = sum(p[3].concat_all_bytes())
    p[0] = l_int_sum
    p.set_lineno(0, p.lineno(1))
    pass


def p_error(p):
    if p:
        raise StopException(
            p_str_msg="line {} : Syntax error at \'{}\'".format(p.lineno,
                                                                p.value))
    else:
        raise StopException(p_str_msg="Syntax error at EOF")


def p_set_type_ubyte(p):
    ''' set_type_ubyte :'''
    global type_id
    type_id = "UB"


def p_set_type_uword(p):
    ''' set_type_uword :'''
    global type_id
    type_id = "UW"


def p_set_type_ulong(p):
    ''' set_type_ulong :'''
    global type_id
    type_id = "UL"


def p_set_type_sbyte(p):
    ''' set_type_sbyte :'''
    global type_id
    type_id = "SB"


def p_set_type_sword(p):
    ''' set_type_sword :'''
    global type_id
    type_id = "SW"


def p_set_type_slong(p):
    ''' set_type_slong :'''

    global type_id
    type_id = "SL"


def p_set_type_float32(p):
    ''' set_type_float32 :'''
    global type_id
    type_id = "F32"


# Set up a logging object
import logging

if __name__ == '__main__':

    logging.basicConfig(level=logging.DEBUG,
                        filename="stu2srec_log.txt",
                        filemode="w",
                        format="%(filename)10s:%(lineno)4d:%(message)s")

    log = logging.getLogger()

    lex.lex()  # debug=True,debuglog=log)
    yacc.yacc()  # debug=True,debuglog=log)

    while 1:
        try:
            s = input('stu2srec > ')
        except EOFError:
            break
        if not s: continue
        yacc.parse(s, debug=log)
