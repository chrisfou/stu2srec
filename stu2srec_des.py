#!/usr/bin/env python
# title           :stu2srec_des.py
# description     :Encryption/Decryption funtionalites base on the DES.
# author          :christian FOURNIER
# date            :19/09/2017
# version         :
# usage           :python stu2srec_des.py
# notes           :
# python_version  :3.6.2
# =============================================================================

import struct


class DESException(Exception):
    def __init__(self, p_str_msg):
        self.m_str_msg = p_str_msg

    def __str__(self):
        return repr(self.m_str_msg)


C_IP_POS_TABLE = [58, 50, 42, 34, 26, 18, 10, 2,
                  60, 52, 44, 36, 28, 20, 12, 4,
                  62, 54, 46, 38, 30, 22, 14, 6,
                  64, 56, 48, 40, 32, 24, 16, 8,
                  57, 49, 41, 33, 25, 17, 9, 1,
                  59, 51, 43, 35, 27, 19, 11, 3,
                  61, 53, 45, 37, 29, 21, 13, 5,
                  63, 55, 47, 39, 31, 23, 15, 7]

C_IP_NEG_TABLE = [40, 8, 48, 16, 56, 24, 64, 32,
                  39, 7, 47, 15, 55, 23, 63, 31,
                  38, 6, 46, 14, 54, 22, 62, 30,
                  37, 5, 45, 13, 53, 21, 61, 29,
                  36, 4, 44, 12, 52, 20, 60, 28,
                  35, 3, 43, 11, 51, 19, 59, 27,
                  34, 2, 42, 10, 50, 18, 58, 26,
                  33, 1, 41, 9, 49, 17, 57, 25]

C_PC_1_TABLE = [57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4]

C_PC_2_TABLE = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32]

C_E_BIT_SELECTION_TABLE = [32, 1, 2, 3, 4, 5,
                           4, 5, 6, 7, 8, 9,
                           8, 9, 10, 11, 12, 13,
                           12, 13, 14, 15, 16, 17,
                           16, 17, 18, 19, 20, 21,
                           20, 21, 22, 23, 24, 25,
                           24, 25, 26, 27, 28, 29,
                           28, 29, 30, 31, 32, 1]

C_P = [16, 7, 20, 21,
       29, 12, 28, 17,
       1, 15, 23, 26,
       5, 18, 31, 10,
       2, 8, 24, 14,
       32, 27, 3, 9,
       19, 13, 30, 6,
       22, 11, 4, 25]

C_SUBKEYS_LEFT_SHIFTS = [0, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

C_S_TABLES = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

C_INT_DES_DECRYPT = 0
C_INT_DES_ENCRYPT = 1


def bits_permutate(p_bytes_input=b'',
                   p_list_permut=[]):
    # Sanity parameter check
    if type(p_list_permut) != list:
        raise DESException \
            (p_str_msg="Permutation p_list_permut parameter type error !")

    l_int_nb_bits = len(p_list_permut)

    if type(p_bytes_input) != bytes:
        raise DESException \
            (p_str_msg="Permutation p_bytes_input parameter type error !")

    if len(p_bytes_input) * 8 < max(p_list_permut):
        raise DESException \
            (p_str_msg="Permutation not possible !")

    if min(p_list_permut) <= 0:
        raise DESException \
            (p_str_msg="Permutation not possible !")

    l_str_input_bits = (bin(int.from_bytes(bytes=p_bytes_input,
                                           byteorder="big"))[2:])

    l_str_input_bits = l_str_input_bits.rjust(8 * len(p_bytes_input), '0')

    l_str_output_bits = ''.join(l_str_input_bits[i - 1] for i in p_list_permut)

    return int(l_str_output_bits, 2).to_bytes(length=int(l_int_nb_bits / 8),
                                              byteorder="big")


def subkeys_create(p_bytes_key=b''):
    # Sanity parameter check
    if type(p_bytes_key) != bytes:
        raise DESException \
            (p_str_msg="Subkey_Create p_bytes_key parameter type error !")

    if len(p_bytes_key) != 8:
        raise DESException \
            (p_str_msg="Subkey_Create p_bytes_key size error !")

    l_bytes_key_p = bits_permutate(p_bytes_input=p_bytes_key,
                                   p_list_permut=C_PC_1_TABLE)

    l_str_cd_0 = bin(int.from_bytes(l_bytes_key_p, "big"))[2:]

    l_str_cd_0 = l_str_cd_0.rjust(56, "0")

    l_str_cd = [[l_str_cd_0[0:28], l_str_cd_0[28:56]]]

    for i in range(1, 16 + 1):
        l_lf = C_SUBKEYS_LEFT_SHIFTS[i]
        l_str_cd.append(
            [l_str_cd[i - 1][0][l_lf:28] + l_str_cd[i - 1][0][0:l_lf],
             l_str_cd[i - 1][1][l_lf:28] + l_str_cd[i - 1][1][0:l_lf]])

    l_list_k = []
    for i in range(1, 16 + 1):
        l_list_k.append(bits_permutate
                        (p_bytes_input=int(l_str_cd[i][0] + l_str_cd[i][1],
                                           2).to_bytes(length=7,
                                                       byteorder="big"),
                         p_list_permut=C_PC_2_TABLE))

    return l_list_k


def calculate(p_bytes_k=b'',
              p_bytes_r=b''):
    # sanity parameter check
    if type(p_bytes_k) != bytes:
        raise DESException \
            (p_str_msg="calculate p_bytes_k parameter type error !")

    if type(p_bytes_r) != bytes:
        raise DESException \
            (p_str_msg="calculate p_bytes_r parameter type error !")

    if len(p_bytes_k) != 6:
        raise DESException \
            (p_str_msg="calculate p_bytes_k parameter size error !")

    if len(p_bytes_r) != 4:
        raise DESException \
            (p_str_msg="calculate p_bytes_r parameter size error !")

    # E Permutation
    l_bytes_e = bits_permutate(p_bytes_input=p_bytes_r,
                               p_list_permut=C_E_BIT_SELECTION_TABLE)

    # k xor E(r)
    l_bytes_result = int.from_bytes(p_bytes_k, "big") \
                     ^ int.from_bytes(l_bytes_e, "big")

    # Sboxes translation
    l_str_bin_result = bin(l_bytes_result)[2:]
    l_str_bin_result = l_str_bin_result.rjust(48, '0')
    l_str_bin_boxed_result = ''

    for i in range(0, 8):
        l_int_s_box_i = int(l_str_bin_result[6 * i]
                            + l_str_bin_result[6 * i + 5], 2)

        l_int_s_box_j = int(l_str_bin_result[6 * i + 1: 6 * (i + 1) - 1], 2)
        l_str_s_box_out = bin(C_S_TABLES[i][l_int_s_box_i][l_int_s_box_j])[2:]
        l_str_bin_boxed_result += l_str_s_box_out.rjust(4, '0')

        # P Permuation
        l_bytes_result = bits_permutate \
            (p_bytes_input=int(l_str_bin_boxed_result, 2).to_bytes(4, "big"),
             p_list_permut=C_P)

    return l_bytes_result


class DES:
    def __init__(self,
                 p_bytes_key=b'',
                 p_int_encrypt=C_INT_DES_ENCRYPT):

        # Sanity parameter check
        if type(p_bytes_key) != bytes:
            raise DESException \
                (p_str_msg="DES init p_bytes_key parameter type error !")

        if len(p_bytes_key) != 8:
            raise DESException \
                (p_str_msg="DES init p_bytes_key parameter size error !")

        if type(p_int_encrypt) != int:
            raise DESException \
                (p_str_msg="DES init p_int_encrypt parameter type error !")

        if (p_int_encrypt != C_INT_DES_ENCRYPT) \
                and (p_int_encrypt != C_INT_DES_DECRYPT):
            raise DESException \
                (p_str_msg="DES init p_int_encrypt parameter value error !")

        if p_int_encrypt == C_INT_DES_ENCRYPT:
            self.subkeys = subkeys_create(p_bytes_key=p_bytes_key)
        else:
            # Only subkeys need to be reversed for decrypting.
            self.subkeys = subkeys_create(p_bytes_key=p_bytes_key)[::-1]

    def compute(self,
                p_bytes_data=b''):

        # Sanity parameter check
        if type(p_bytes_data) != bytes:
            raise DESException \
                (p_str_msg="DES compute p_bytes_data parameter type error !")

        if len(p_bytes_data) != 8:
            raise DESException \
                (p_str_msg="DES compute p_bytes_data parameter size error !")

        l_bytes_result = b''

        # IP + permutation
        l_bytes_ip = bits_permutate(p_bytes_input=p_bytes_data,
                                    p_list_permut=C_IP_POS_TABLE)

        l_bytes_lr = [[l_bytes_ip[0:4], l_bytes_ip[4:8]]]

        for i in range(1, 16 + 1):
            l_int_ri \
                = int.from_bytes(l_bytes_lr[i - 1][0], "big") \
                  ^ int.from_bytes(calculate(p_bytes_k=self.subkeys[i - 1],
                                             p_bytes_r=l_bytes_lr[i - 1][1]),
                                   "big")
            l_bytes_lr.append([l_bytes_lr[i - 1][1],
                               l_int_ri.to_bytes(4, "big")])

        l_bytes_rl_16 = l_bytes_lr[16][1] + l_bytes_lr[16][0]

        # IP - permutation
        l_bytes_result += bits_permutate(p_bytes_input=l_bytes_rl_16,
                                         p_list_permut=C_IP_NEG_TABLE)

        return l_bytes_result


class CypherOp(DES):
    def __init__(self,
                 p_bytes_key=b'',
                 p_int_encrypt=C_INT_DES_ENCRYPT):
        # Sanity parameter check
        if type(p_bytes_key) != bytes:
            raise DESException(
                p_str_msg="CypherOp.__init__ p_bytes_key parameter type error !")
        if len(p_bytes_key) != 8:
            raise DESException(
                p_str_msg="CypherOP.__init__ p_bytes_key parameter size error !")

        # DES Configuration
        DES.__init__(self,
                     p_bytes_key=p_bytes_key,
                     p_int_encrypt=p_int_encrypt)

        # Encrypt parameter is stored for cbc encryption/decryption algorithms
        self.m_int_encrypt = p_int_encrypt

    def ecb_compute(self,
                    p_bytes_msg=b''):
        # Sanity parameter check
        if type(p_bytes_msg) != bytes:
            raise DESException(
                p_str_msg="CypherOp.ecb p_bytes_msg parameter type error ! ")

        # The message is 0 filled to be lenght modulo 8 bytes
        l_tuple_divmod = divmod(len(p_bytes_msg), 8)
        l_bytes_msg = p_bytes_msg
        l_int_nb_block = l_tuple_divmod[0]
        if l_tuple_divmod[1] != 0:
            l_bytes_msg = l_bytes_msg + (8 - l_tuple_divmod[1]) * struct.pack(
                ">b", 0)
            l_int_nb_block = l_int_nb_block + 1

        # for ecb every 8 bytes blocks are DES encrypted/decripted in row.
        l_bytes_result = b''
        for id_block in range(0, l_int_nb_block):
            l_bytes_result += DES.compute(self, p_bytes_data=l_bytes_msg[
                                                             id_block * 8: (
                                                                           id_block + 1) * 8])

        return l_bytes_result

    def cbc_compute(self,
                    p_bytes_msg=b'',
                    p_bytes_iv=b''):
        # Sanity parameter check
        if type(p_bytes_msg) != bytes:
            raise DESException(
                p_str_msg="CypherOp.cbc p_bytes_msg parameter type error !")
        if type(p_bytes_iv) != bytes:
            raise DESException(
                p_str_msg="CypherOp.cbc p_bytes_iv parameter type error !")
        if len(p_bytes_iv) != 8:
            raise DESException(
                p_str_msg="CypherOp.cbc p_bytes_iv parameter size error !")

        # The message is 0 filled to be to modulo 8 bytes lenght.
        l_tuple_divmod = divmod(len(p_bytes_msg), 8)
        l_bytes_msg = p_bytes_msg
        l_int_nb_block = l_tuple_divmod[0]
        if l_tuple_divmod[1] != 0:
            l_bytes_msg = l_bytes_msg + (8 - l_tuple_divmod[1]) * struct.pack(
                ">b", 0)
            l_int_nb_block = l_int_nb_block + 1

        # CBC computation.
        l_bytes_result = b''
        l_int_des_in = 0
        l_bytes_des_out = b''
        if self.m_int_encrypt == C_INT_DES_ENCRYPT:
            # For CBC encryption every 8 bytes blocks are xored with the previous DES encrypted/decrypted block before
            # to be DES encrypted.
            # At start, the first block is xored with the p_bytes_iv vector.
            l_bytes_des_out = p_bytes_iv
            for id_block in range(0, l_int_nb_block):
                l_int_des_in = int(
                    l_bytes_msg[id_block * 8: (id_block + 1) * 8].hex(),
                    16) ^ int(l_bytes_des_out.hex(),
                              16)
                l_bytes_des_out = DES.compute(self,
                                              p_bytes_data=l_int_des_in.to_bytes(
                                                  8, "big"))
                l_bytes_result += l_bytes_des_out
        else:
            # For CBC decryption every 8 bytes blocks are DES decrypted first. The result is xored then with the
            # previous encrypted 8 bytes blocks.
            # for every DES decryption, the result must be xored with the previous encrypted 8 bytes blocks.
            # At start, the first DES decrypted output must be xored with p_bytes_iv vector.
            l_bytes_des_pre = p_bytes_iv
            for id_block in range(0, l_int_nb_block):
                l_int_des_in = l_bytes_msg[id_block * 8: (id_block + 1) * 8]
                l_bytes_des_out = DES.compute(self, p_bytes_data=l_int_des_in)
                l_int_des_out_xor_pre \
                    = int(l_bytes_des_out.hex(), 16) ^ int(
                    l_bytes_des_pre.hex(), 16)
                l_bytes_result += l_int_des_out_xor_pre.to_bytes(8, 'big')
                l_bytes_des_pre = l_int_des_in

        return l_bytes_result


def cbc_mac_compute(p_bytes_msg='b',
                    p_bytes_key_1=b'',
                    p_bytes_key_2=b'',
                    p_bytes_key_3=b''):
    # Sanity parameter check
    if type(p_bytes_msg) != bytes:
        raise DESException(
            p_str_msg="cbc_mac_computer p_bytes_msg parameter type error !")
    if type(p_bytes_key_1) != bytes:
        raise DESException(
            p_str_msg="cbc_mac_compute p_bytes_key_1 parameter type error !")
    if type(p_bytes_key_2) != bytes:
        raise DESException(
            p_str_msg="cbc_mac_compute p_bytes_key_2 parameter type error !")
    if type(p_bytes_key_3) != bytes:
        raise DESException(
            p_str_msg="cbc_mac_compute p_bytes_key_3 parameter type error !")
    if len(p_bytes_key_1) != 8:
        raise DESException(
            p_str_msg="cbc_mac_compute p_bytes_key_1 size error !")
    if len(p_bytes_key_2) != 8:
        raise DESException(
            p_str_msg="cbc_mac_compute p_bytes_key_2 size error !")
    if len(p_bytes_key_3) != 8:
        raise DESException(
            p_str_msg="cbc_mac_compute p_bytes_key_3 size error !")

    l_cypherop_k1 = CypherOp(p_bytes_key=p_bytes_key_1,
                             p_int_encrypt=C_INT_DES_ENCRYPT)

    l_des_k2 = DES(p_bytes_key=p_bytes_key_2,
                   p_int_encrypt=C_INT_DES_DECRYPT)

    l_des_k3 = DES(p_bytes_key=p_bytes_key_3,
                   p_int_encrypt=C_INT_DES_ENCRYPT)

    # CBC Initial Vector is null for the CBC-MAC computation.
    l_bytes_iv = 8 * bytes.fromhex("00")

    # Cbc computation on p_bytes_msg with key 1.
    # Only the last 8 bytes of the encrypted message are usefull.
    l_bytes_cbc_k1_encryption_result \
        = l_cypherop_k1.cbc_compute(p_bytes_msg=p_bytes_msg,
                                    p_bytes_iv=l_bytes_iv)[-8::]

    # The previous result is DES decrypted with the key 2.
    l_bytes_des_k2_decryption_result \
        = l_des_k2.compute(p_bytes_data=l_bytes_cbc_k1_encryption_result)

    # The previous result is DES encrypted with the key 3.
    l_bytes_des_k3_encryption_result \
        = l_des_k3.compute(p_bytes_data=l_bytes_des_k2_decryption_result)

    return l_bytes_des_k3_encryption_result


if __name__ == "__main__":

    # ----------------------------------------------------------------------
    # TEST 1

    # bits_permutate test with _IP_POS_Table
    l_bytes_input_value_ref = int(
        '0000000100100011010001010110011110001001101010111100110111101111',
        2).to_bytes(8,
                    "big")
    l_bytes_output_value_ref = int(
        '1100110000000000110011001111111111110000101010101111000010101010',
        2).to_bytes(8,
                    "big")

    l_bytes_output_value = bits_permutate(
        p_bytes_input=l_bytes_input_value_ref,
        p_list_permut=C_IP_POS_TABLE)

    if l_bytes_output_value != l_bytes_output_value_ref:
        print("TEST 1 KO !!")
    else:
        print("TEST 1 OK ..")

    # ----------------------------------------------------------------------
    # TEST 2

    # bits_permutate test with _PC_1_Table
    l_bytes_input_value_ref = int(
        '0001001100110100010101110111100110011011101111001101111111110001',
        2).to_bytes(8,
                    "big")
    l_bytes_output_value_ref = int(
        '11110000110011001010101011110101010101100110011110001111',
        2).to_bytes(7, "big")

    l_bytes_output_value = bits_permutate(
        p_bytes_input=l_bytes_input_value_ref,
        p_list_permut=C_PC_1_TABLE)

    if l_bytes_output_value != l_bytes_output_value_ref:
        print("TEST 2 KO !!")
    else:
        print("TEST 2 OK ..")

    # ----------------------------------------------------------------------
    # TEST 3

    # bits_permutate test with _PC_2_Table
    l_bytes_input_value_ref = int(
        '11100001100110010101010111111010101011001100111100011110',
        2).to_bytes(7, "big")
    l_bytes_output_value_ref = int(
        '000110110000001011101111111111000111000001110010', 2).to_bytes(6,
                                                                        "big")

    l_bytes_output_value = bits_permutate(
        p_bytes_input=l_bytes_input_value_ref,
        p_list_permut=C_PC_2_TABLE)

    if l_bytes_output_value != l_bytes_output_value_ref:
        print("TEST 3 KO !!")
    else:
        print("TEST 3 OK ..")

    # ----------------------------------------------------------------------
    # TEST 4

    # subkeys_create

    l_key_input_ref = int(
        '0001001100110100010101110111100110011011101111001101111111110001',
        2).to_bytes(8, "big")

    l_subkeys_output_ref = [
        int('000110110000001011101111111111000111000001110010', 2).to_bytes(6,
                                                                            "big"),
        int('011110011010111011011001110110111100100111100101', 2).to_bytes(6,
                                                                            "big"),
        int('010101011111110010001010010000101100111110011001', 2).to_bytes(6,
                                                                            "big"),
        int('011100101010110111010110110110110011010100011101', 2).to_bytes(6,
                                                                            "big"),
        int('011111001110110000000111111010110101001110101000', 2).to_bytes(6,
                                                                            "big"),
        int('011000111010010100111110010100000111101100101111', 2).to_bytes(6,
                                                                            "big"),
        int('111011001000010010110111111101100001100010111100', 2).to_bytes(6,
                                                                            "big"),
        int('111101111000101000111010110000010011101111111011', 2).to_bytes(6,
                                                                            "big"),
        int('111000001101101111101011111011011110011110000001', 2).to_bytes(6,
                                                                            "big"),
        int('101100011111001101000111101110100100011001001111', 2).to_bytes(6,
                                                                            "big"),
        int('001000010101111111010011110111101101001110000110', 2).to_bytes(6,
                                                                            "big"),
        int('011101010111000111110101100101000110011111101001', 2).to_bytes(6,
                                                                            "big"),
        int('100101111100010111010001111110101011101001000001', 2).to_bytes(6,
                                                                            "big"),
        int('010111110100001110110111111100101110011100111010', 2).to_bytes(6,
                                                                            "big"),
        int('101111111001000110001101001111010011111100001010', 2).to_bytes(6,
                                                                            "big"),
        int('110010110011110110001011000011100001011111110101', 2).to_bytes(6,
                                                                            "big")]

    l_subkeys_output = subkeys_create(p_bytes_key=l_key_input_ref)

    if l_subkeys_output != l_subkeys_output_ref:
        print("TEST 4 KO !!")
    else:
        print("TEST 4 OK ..")

    # ----------------------------------------------------------------------
    # TEST 5

    # bits_permutate test with C_E_BIT_SELECTION_TABLE
    l_bytes_input_value_ref = int('11110000101010101111000010101010',
                                  2).to_bytes(4, "big")
    l_bytes_output_value_ref = int(
        '011110100001010101010101011110100001010101010101', 2).to_bytes(6,
                                                                        "big")

    l_bytes_output_value = bits_permutate(
        p_bytes_input=l_bytes_input_value_ref,
        p_list_permut=C_E_BIT_SELECTION_TABLE)

    if l_bytes_output_value != l_bytes_output_value_ref:
        print("TEST 5 KO !!")
    else:
        print("TEST 5 OK ..")

    # ----------------------------------------------------------------------
    # TEST 6

    # calculate test

    l_bytes_k_input_ref = int(
        '000110110000001011101111111111000111000001110010', 2).to_bytes(6,
                                                                        "big")
    l_bytes_r_input_ref = int('11110000101010101111000010101010', 2).to_bytes(
        4, "big")
    l_bytes_f_output_ref = int('00100011010010101010100110111011', 2).to_bytes(
        4, "big")

    l_bytes_f_output = calculate(p_bytes_k=l_bytes_k_input_ref,
                                 p_bytes_r=l_bytes_r_input_ref)

    if l_bytes_f_output_ref != l_bytes_f_output:
        print("TEST 6 KO !!")
    else:
        print("TEST 6 OK ..")

    # ----------------------------------------------------------------------
    # TEST 7

    # ECB computation test on string

    l_msg_test = "Your lips are smoother than vaseline\r\n" + 2 * chr(0)

    l_cypher_op_encrypt = CypherOp(
        p_bytes_key=int("0x0E329232EA6D0D73", 16).to_bytes(8, "big"),
        p_int_encrypt=C_INT_DES_ENCRYPT)

    l_cypher_op_decrypt = CypherOp(
        p_bytes_key=int("0x0E329232EA6D0D73", 16).to_bytes(8, "big"),
        p_int_encrypt=C_INT_DES_DECRYPT)

    l_encrypted_msg_ref = "C0999FDDE378D7ED727DA00BCA5A84EE47F269A4D6438190D9D52F78F5358499828AC9B453E0E653"

    l_encrypted_msg = l_cypher_op_encrypt.ecb_compute(
        p_bytes_msg=l_msg_test.encode('utf-8'))

    # print("uncrypted l_msg_test : ", l_msg_test)
    # print("encrypted l_msg_test : ", l_encrypted_msg.hex())

    l_decrypted_msg = l_cypher_op_decrypt.ecb_compute(
        p_bytes_msg=l_encrypted_msg)

    if (l_decrypted_msg.decode('utf-8') != l_msg_test) and (
        l_encrypted_msg.hex().upper() != l_encrypted_msg_ref):
        print("TEST 7 KO !!")
    else:
        print("TEST 7 OK ..")

    # print("decrypted l_msg_test : " , l_decrypted_msg.decode('utf-8'))

    # ----------------------------------------------------------------------
    # TEST 8

    # ECB computation test on string

    l_msg_test = "je suis ne a Digne les Bains le 26121971"  # .ljust(80, '.')

    l_cypher_op_encrypt = CypherOp(
        p_bytes_key=int("0x0E329232EA6D0D73", 16).to_bytes(8, "big"),
        p_int_encrypt=C_INT_DES_ENCRYPT)

    l_cypher_op_decrypt = CypherOp(
        p_bytes_key=int("0x0E329232EA6D0D73", 16).to_bytes(8, "big"),
        p_int_encrypt=C_INT_DES_DECRYPT)

    l_encrypted_msg_ref = "C0999FDDE378D7ED727DA00BCA5A84EE47F269A4D6438190D9D52F78F5358499828AC9B453E0E653"

    l_encrypted_msg = l_cypher_op_encrypt.ecb_compute(
        p_bytes_msg=l_msg_test.encode('utf-8'))

    # print("uncrypted l_msg_test : ", l_msg_test)
    # print("encrypted l_msg_test : ", l_encrypted_msg.hex())

    l_decrypted_msg = l_cypher_op_decrypt.ecb_compute(
        p_bytes_msg=l_encrypted_msg)

    if (l_decrypted_msg.decode('utf-8') != l_msg_test) and (
        l_encrypted_msg.hex().upper() != l_encrypted_msg_ref):
        print("TEST 8 KO !!")
    else:
        print("TEST 8 OK ..")

    # print("decrypted l_msg_test : " , l_decrypted_msg.decode('utf-8'))

    # ----------------------------------------------------------------------
    # TEST 9

    # CBC computation test on string

    l_msg_test = "je suis ne a Digne les Bains le 26121971A".ljust(80, '.')

    l_cypher_op_encrypt = CypherOp(
        p_bytes_key=int("0x0E329232EA6D0D73", 16).to_bytes(8, "big"),
        p_int_encrypt=C_INT_DES_ENCRYPT)

    l_cypher_op_decrypt = CypherOp(
        p_bytes_key=int("0x0E329232EA6D0D73", 16).to_bytes(8, "big"),
        p_int_encrypt=C_INT_DES_DECRYPT)

    l_encrypted_msg_ref = "C0999FDDE378D7ED727DA00BCA5A84EE47F269A4D6438190D9D52F78F5358499828AC9B453E0E653"

    l_bytes_iv = int(0).to_bytes(8, 'big')
    # print(l_msg_test.encode('utf-8').hex())
    l_encrypted_msg = l_cypher_op_encrypt.cbc_compute(
        p_bytes_msg=l_msg_test.encode('utf-8'),
        p_bytes_iv=l_bytes_iv)

    # print("uncrypted l_msg_test : ", l_msg_test)
    # print("encrypted l_msg_test : ", l_encrypted_msg.hex())

    l_decrypted_msg = l_cypher_op_decrypt.cbc_compute(
        p_bytes_msg=l_encrypted_msg,
        p_bytes_iv=l_bytes_iv)
    # print(l_decrypted_msg.hex())

    if (l_decrypted_msg.decode('utf-8') != l_msg_test) and (
        l_encrypted_msg.hex().upper() != l_encrypted_msg_ref):
        print("TEST 9 KO !!")
    else:
        print("TEST 9 OK ..")

    # print("decrypted l_msg_test : " , l_decrypted_msg.decode('utf-8'))

    # -----------------------------------------------------------------
    # TEST 10

    # CBC-MAC test. (based on the subset-37 Annexe E CBC-MAC Calculation example )

    l_msg_test = bytes.fromhex("000102030405060708090A0B0C0D0E0F1011121314")
    l_desk1 = bytes.fromhex("01020407080B0D0E")
    l_desk2 = bytes.fromhex("10131516191A1C1F")
    l_desk3 = bytes.fromhex("20232526292A2C2F")
    l_cbcmac_ref = bytes.fromhex("361D431ED396C175")

    CbcMacResult = cbc_mac_compute(p_bytes_msg=l_msg_test,
                                   p_bytes_key_1=l_desk1,
                                   p_bytes_key_2=l_desk2,
                                   p_bytes_key_3=l_desk3)

    if l_cbcmac_ref != CbcMacResult:
        print("TEST 10 KO !!")
    else:
        print("TEST 10 OK ..")
