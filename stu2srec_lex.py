from stu2srec_error import StopException

import ply.lex as lex
import re

# dictionary of names
names = {}

reserved = {'SIZE': 'SIZE',
            'BYTSUM': 'BYTSUM',
            'SACEM': 'SACEM',
            'CRC32': 'CRC32',
            'HEX': 'HEX',
            'TEXT':'TEXT',
            'CBCMAC': 'CBCMAC',
            'F32': 'FLOAT32',
            'UB': 'UBYTE',
            'UW': 'UWORD',
            'UL': 'ULONG',
            'SB': 'SBYTE',
            'SW': 'SWORD',
            'SL': 'SLONG'}

tokens = ['NUMBER',
          'LSH',
          'RSH',
          'AND',
          'OR',
          'XOR',
          'STRING',
          'FLOAT',
          'ID_FLOAT',
          'ID_NUMBER',
          'ID_LIST',
          'ID',
          'PARAM'] + list(reserved.values())

literals = ['=', ',', '[', ']', '+', '-', '*', ';', '(', ')']

# tokens
t_LSH = r'<<'
t_RSH = r'>>'
t_AND = r'&'
t_OR = r'\|'
t_XOR = r'\^'


def t_FLOAT(t):
    r'[0-9]+\.[0-9]+'
    t.value = float(t.value)
    return t


def t_HEXA(t):
    r'0x([0-9a-fA-F]){1,8}'
    t.value = int(t.value, 16)
    t.type = 'NUMBER'
    return t


def t_NUMBER(t):
    r'\d+'
    t.value = int(t.value)
    return t


def t_PARAM(t):
    r'=>'
    return t


# Ignored characters
t_ignore = " \t"


def t_newline(t):
    r'\n+'
    t.lexer.lineno += t.value.count("\n")


def t_ID(t):
    r'[a-zA-Z_][a-zA-Z0-9_]*'
    t.type = reserved.get(t.value, 'ID')
    if t.type == 'ID':
        if t.value in list(names.keys()):
            if type(names[t.value]) == int:
                t.type = 'ID_NUMBER'
            elif type(names[t.value]) == bytes:
                t.type = 'ID_LIST'
            elif type(names[t.value]) == float:
                t.type = 'ID_FLOAT'
                # else:
                #     pass
    return t


def t_COMMENT(t):
    r'(\#|//).*'
    pass  # no return value. Token discarded


def t_STRING(t):
    r'\"[^"]*\"'
    if len(t.value) > 2:
        t.value = t.value[1:-1]
    else:
        pass
    return t


def t_error(t):
    raise StopException(p_msg="Illegal character {}".format(t.value[0]))
    # print("Illegal character '%s'" % t.value[0])
    # t.lexer.skip(1)


if __name__ == '__main__':

    # build the lexer
    lexer = lex.lex(debug=1)

    # read the stu file
    data = open('cap.stu').read()

    print(data)

    # Give the lexer some input
    lexer.input(data)

    for tok in lexer:
        print(tok)
