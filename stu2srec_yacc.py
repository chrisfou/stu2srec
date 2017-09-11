from stu2srec_lex import *

from stu2srec_sacem import sacem
from stu2srec_srecord import srecord_gen

import struct 
import zlib #crc32
import ply.yacc as yacc

from stu2srec_error import StopException

# 
type_id = None

# Parsing rules
precedence = (
    ('left','OR','XOR','AND','LSH','RSH'),
    ('left','+','-'),
    ('left','*'),
    ('left',','),
    ('right','UMINUS'),
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
    #print("p_statement_name_equal_expression")
    names[p[1]] = p[3]
    pass

def p_statement_name_equal_array(p):
    ''' statement : ID '=' array '''
    # | ID_NUMBER '=' array
    # | ID_FLOAT '=' array 
    # | ID_LIST '=' array '''
    #print("p_statement_name_equal_array")
    names[p[1]] = p[3]
    pass

def p_statement_expression(p):
    ''' statement : expression '''
    #print("p_statement_expression")
    print(p[1])
    pass

def p_statement_array(p):
    ''' statement : array '''
    #print("p_statement_array")
    print(p[1])
    pass

def p_array_float32_list(p):
    ''' array : FLOAT32 set_type_float32 '[' list ']' '''
    #print("p_array_float32_list")
    p[0]=p[4]
    pass

def p_array_ub_list(p):
    ''' array : UBYTE set_type_ubyte '[' list ']' '''
    #print("p_array_ub_list")
    p[0]=p[4]
    pass
    
def p_array_uw_list(p):
    ''' array : UWORD set_type_uword '[' list ']' '''
    #print("p_array_uw_list")
    p[0]=p[4]
    pass

def p_array_ul_list(p):
    ''' array : ULONG set_type_ulong '[' list ']' '''
    #print("p_array_ul_list")
    p[0]=p[4]
    pass

def p_array_sb_list(p):
    ''' array : SBYTE set_type_sbyte '[' list ']' '''
    #print("p_array_sb_list")
    p[0]=p[4]
    pass
    
def p_array_sw_list(p):
    ''' array : SWORD set_type_sword '[' list ']' '''
    #print("p_array_sw_list")
    p[0]=p[4]
    pass

def p_array_sl_list(p):
    ''' array : SLONG set_type_slong '[' list ']' '''
    #print("p_array_sl_list")
    p[0]=p[4]
    pass

def p_array_plus(p):
    ''' array : array '+' array '''
    #print("p_array_plus")
    try:
        p[0]=p[1]+p[3]
    except TypeError as err:
        raise StopException\
            (message = "line {} : {}".format(p.lineno(2), str(err)))
    pass

def p_array_multiply(p):
    ''' array : expression '*' array '''
    #print("p_array_multiply")
    try:
        p[0]=p[1]*p[3]
    except TypeError as err:
        raise StopException\
            (message = "line {} : {}".format(p.lineno(2), str(err)))

    pass

def p_array_idlist(p):
    ''' array : ID_LIST '''
    #print("p_array_idlist")
    p[0] = names[p[1]]
    pass

def p_array_text(p):
    ''' array : TEXT '''
    #print("p_array_text")
    p[0]=b''
    p.set_lineno(0,p.lineno(1))
    p[0]=bytes(p[1], 'utf-8')

def p_array_sacem(p):
    ''' array : SACEM '[' ID PARAM array ',' ID PARAM array ']' '''
    #print("p_array_sacem")
    if p[3]!="data":
        raise StopException \
            (message = 
             "line {} : \'{}\': parameter not valid! ".format \
                 (p.lineno(3), p[3]))

    if p[7]!="svl":
        raise StopException \
            (message = 
             "line {} : \'{}\': parameter not valid! ".format \
                 (p.lineno(7), p[7]))
    
    p[0]=sacem(data=p[5], svl=p[9])
    pass

def p_array_crc32(p):
    ''' array : CRC32 '[' ID PARAM array ']' '''
    #print("p_array_crc32")

    if p[3]!="data":
        raise StopException \
            (message = 
             "line {} : \'{}\': parameter not valid! ".format \
                 (p.lineno(3), p[3]))

    p[0]=struct.pack(">I", zlib.crc32(bytes(p[5])) & 0xFFFFFFFF)
    pass

def p_array_hex(p):
    ''' array : HEX '[' ID PARAM TEXT ']' '''
    #print("p_array_hex")

    if p[3]!="string":
        raise StopException \
            (message = 
             "line {} : \'{}\': parameter not valid! ".format \
                 (p.lineno(3), p[3]))
    text=p[5]
    if len(p[5]) % 2 != 0:
        text="0"+text

    try:
        p[0] = bytes.fromhex(text)
    except:
        raise StopException\
            (message = 
             "line {} : string \'{}\', not hexadecimal".format\
                 (p.lineno(5), text))

    pass

def p_list(p):
    ''' list : list ',' list '''
    #print("p_list")
    p[0] = p[1] + p[3]
    pass

def p_list_expression(p):
    ''' list : expression '''
    #print("p_list_expression")

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
            raise StopException\
                (message="line {} : Array format not defined".format\
                     (p.lineno(1)))

    except struct.error as err:
        raise StopException\
            (message = "line {} : value \'{}\', ".format\
                 (p.lineno(1), p[1]) + str(err))

    pass
	
def p_expression_plus(p):
    ''' expression : expression '+' expression '''
    #print("p_expression_plus")
    p[0]=p[1] + p[3]
    pass

def p_expression_minus(p):
    ''' expression : expression '-' expression '''
    #print("p_expression_minus")
    p[0]=p[1] - p[3]    
    pass
    
def p_expression_multiply(p):
    ''' expression : expression '*' expression '''
    #print("p_expression_multiply")
    p[0]=p[1] * p[3]    
    pass

def p_expression_uminus(p):
    ''' expression : '-' expression %prec UMINUS '''
    #print("p_expression_uminus")
    p[0]=-p[2]
    p.set_lineno(0,p.lineno(2))
    pass

def p_expression_lsh(p):
    ''' expression : expression LSH expression '''
    #print("p_expression_lsh")
    try:
        p[0]=p[1] << p[3]
    except TypeError as err:
        raise StopException\
            (message = "line {} : {}".format(p.lineno(2), str(err)))
    pass

def p_expression_rsh(p):
    ''' expression : expression RSH expression '''
    #print("p_expression_rsh")
    try:
        p[0]=p[1] >> p[3]
    except TypeError as err:
        raise StopException\
            (message = "line {} : {}".format(p.lineno(2), str(err)))
    pass

def p_expression_and(p):
    ''' expression : expression AND expression '''
    #print("p_expression_and")
    try:
        p[0]=p[1] & p[3]
    except TypeError as err:
        raise StopException\
            (message = "line {} : {}".format(p.lineno(2), str(err)))
    pass

def p_expression_or(p):
    ''' expression : expression OR expression '''
    #print("p_expression_or")
    try:
        p[0]=p[1] | p[3]
    except TypeError as err:
        raise StopException\
            (message = "line {} : {}".format(p.lineno(2), str(err)))
    pass

def p_expression_xor(p):
    ''' expression : expression XOR expression '''
    #print("p_expression_xor")
    try:
        p[0]=p[1] ^ p[3]
    except TypeError as err:
        raise StopException\
            (message = "line {} : {}".format(p.lineno(2), str(err)))
    pass

def p_expression_paren(p):
    ''' expression : '(' expression ')' '''
    #print("p_expression_paren")
    p[0]=p[2]
    p.set_lineno(0,p.lineno(2))
    pass

def p_expression_number(p):
    ''' expression : NUMBER '''
    #print("p_expression_number")
    p[0] = p[1]
    p.set_lineno(0,p.lineno(1))
    pass

def p_expression_idnumber(p):
    ''' expression : ID_NUMBER '''
    #print("p_expression_idnumber")
    p[0] = names[p[1]]
    p.set_lineno(0,p.lineno(1))
    pass

def p_expression_float(p):
    ''' expression : FLOAT'''
    #print("p_expression_float")
    p[0] = p[1]
    p.set_lineno(0,p.lineno(1))
    pass

def p_expression_idfloat(p):
    ''' expression : ID_FLOAT'''
    #print("p_expression_idfloat")
    p[0] = names[p[1]]
    p.set_lineno(0,p.lineno(1))
    pass

def p_expression_size(p):
    ''' expression : SIZE '(' array ')' '''
    #print("p_expression_size")
    
    p[0]=len(p[3])
    p.set_lineno(0,p.lineno(1))
    pass

def p_expression_bytsum(p):
    ''' expression : BYTSUM '(' array ')' '''
    #print("p_expression_bytsum")

    p[0]=sum(p[3])
    p.set_lineno(0,p.lineno(1))
    pass

def p_error(p):
    if p:
        raise StopException\
            (message = "line {} : Syntax error at \'{}\'".format\
                 (p.lineno, p.value))
        # print("Syntax error at '%s'" % p.value)
    else:
        raise StopException(message = "Syntax error at EOF")
        #print("Syntax error at EOF")

def p_set_type_ubyte(p):
    ''' set_type_ubyte :'''
    #print("p_set_type_ubyte")
    global type_id
    type_id="UB"

def p_set_type_uword(p):
    ''' set_type_uword :'''
    #print("p_set_type_uword")
    global type_id
    type_id="UW"

def p_set_type_ulong(p):
    ''' set_type_ulong :'''
    #print("p_set_type_ulong")
    global type_id
    type_id="UL"
    
def p_set_type_sbyte(p):
    ''' set_type_sbyte :'''
    #print("p_set_type_sbyte")
    global type_id
    type_id="SB"

def p_set_type_sword(p):
    ''' set_type_sword :'''
    #print("p_set_type_sword")
    global type_id
    type_id="SW"

def p_set_type_slong(p):
    ''' set_type_slong :'''
    #print("p_set_type_slong")
    global type_id
    type_id="SL"
    
def p_set_type_float32(p):
    ''' set_type_float32 :'''
    #print("p_set_type_float32")
    global type_id
    type_id="F32"

# Set up a logging object
import logging

if __name__ == '__main__':

    logging.basicConfig(level    = logging.DEBUG,
                        filename = "stu2srec_log.txt",
                        filemode = "w",
                        format   = "%(filename)10s:%(lineno)4d:%(message)s")

    log = logging.getLogger()

    lex.lex()#debug=True,debuglog=log)
    yacc.yacc()#debug=True,debuglog=log)

    while 1:
        try:
            s = input('stu2srec > ')
        except EOFError:
            break
        if not s: continue
        yacc.parse(s, debug=log)