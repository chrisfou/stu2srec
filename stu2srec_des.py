import struct


class DESException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return repr(self.message)


_IP_POS_TABLE = [58, 50, 42, 34, 26, 18, 10, 2,
                 60, 52, 44, 36, 28, 20, 12, 4,
                 62, 54, 46, 38, 30, 22, 14, 6,
                 64, 56, 48, 40, 32, 24, 16, 8,
                 57, 49, 41, 33, 25, 17, 9, 1,
                 59, 51, 43, 35, 27, 19, 11, 3,
                 61, 53, 45, 37, 29, 21, 13, 5,
                 63, 55, 47, 39, 31, 23, 15, 7]

_IP_NEG_TABLE = [40, 8, 48, 16, 56, 24, 64, 32,
                 39, 7, 47, 15, 55, 23, 63, 31,
                 38, 6, 46, 14, 54, 22, 62, 30,
                 37, 5, 45, 13, 53, 21, 61, 29,
                 36, 4, 44, 12, 52, 20, 60, 28,
                 35, 3, 43, 11, 51, 19, 59, 27,
                 34, 2, 42, 10, 50, 18, 58, 26,
                 33, 1, 41, 9, 49, 17, 57, 25]

_PC_1_TABLE = [57, 49, 41, 33, 25, 17, 9,
               1, 58, 50, 42, 34, 26, 18,
               10, 2, 59, 51, 43, 35, 27,
               19, 11, 3, 60, 52, 44, 36,
               63, 55, 47, 39, 31, 23, 15,
               7, 62, 54, 46, 38, 30, 22,
               14, 6, 61, 53, 45, 37, 29,
               21, 13, 5, 28, 20, 12, 4]

_PC_2_TABLE = [14, 17, 11, 24, 1, 5,
               3, 28, 15, 6, 21, 10,
               23, 19, 12, 4, 26, 8,
               16, 7, 27, 20, 13, 2,
               41, 52, 31, 37, 47, 55,
               30, 40, 51, 45, 33, 48,
               44, 49, 39, 56, 34, 53,
               46, 42, 50, 36, 29, 32]

_E_BIT_SELECTION_TABLE = [32, 1, 2, 3, 4, 5,
                          4, 5, 6, 7, 8, 9,
                          8, 9, 10, 11, 12, 13,
                          12, 13, 14, 15, 16, 17,
                          16, 17, 18, 19, 20, 21,
                          20, 21, 22, 23, 24, 25,
                          24, 25, 26, 27, 28, 29,
                          28, 29, 30, 31, 32, 1]

_P = [16, 7, 20, 21,
      29, 12, 28, 17,
      1, 15, 23, 26,
      5, 18, 31, 10,
      2, 8, 24, 14,
      32, 27, 3, 9,
      19, 13, 30, 6,
      22, 11, 4, 25]

_SUBKEYS_LEFT_SHIFTS = [0, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

_S_TABLES = [
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

DES_DECRYPT = 0
DES_ENCRYPT = 1


def bits_permutate(input=b'', table=[]):
    # Sanity parameter check
    if type(table) != list:
        raise DESException \
            (message="Permutation table parameter type error !")

    l_nb_bits = len(table)

    if type(input) != bytes:
        raise DESException \
            (message="Permutation input parameter type error !")

    if len(input) * 8 < max(table):
        raise DESException \
            (message="Permutation not possible !")

    if min(table) <= 0:
        raise DESException \
            (message="Permutation not possible !")

    l_input_bits = (bin(int.from_bytes(bytes=input,
                                       byteorder="big"))[2:])

    l_input_bits = l_input_bits.rjust(8 * len(input), '0')

    l_output_nb_bits = ''.join(l_input_bits[i - 1] for i in table)

    return int(l_output_nb_bits, 2).to_bytes(length=int(l_nb_bits / 8),
                                             byteorder="big")


def subkeys_create(key=b''):
    # Sanity parameter check
    if type(key) != bytes:
        raise DESException \
            (message="Subkey_Create key parameter type error !")

    if len(key) != 8:
        raise DESException \
            (message="Subkey_Create key size error !")

    l_key_p = bits_permutate(input=key,
                             table=_PC_1_TABLE)

    l_cd_0 = bin(int.from_bytes(l_key_p, "big"))[2:]

    l_cd_0_filled = (56 - len(l_cd_0)) * "0" + l_cd_0

    l_cd = [[l_cd_0_filled[0:28], l_cd_0_filled[28:56]]]

    for i in range(1, 16 + 1):
        l_lf = _SUBKEYS_LEFT_SHIFTS[i]
        l_cd.append([l_cd[i - 1][0][l_lf:28] + l_cd[i - 1][0][0:l_lf],
                     l_cd[i - 1][1][l_lf:28] + l_cd[i - 1][1][0:l_lf]])

    l__k = []
    for i in range(1, 16 + 1):
        l__k.append(bits_permutate
                    (input=int(l_cd[i][0] + l_cd[i][1], 2).to_bytes(length=7,
                                                                    byteorder="big"),
                     table=_PC_2_TABLE))

    return l__k


def f_calculate(k=b'', r=b''):
    # sanity parameter check
    if type(k) != bytes:
        raise DESException \
            (message="f_calculate k parameter type error !")

    if type(r) != bytes:
        raise DESException \
            (message="f_calculate r parameter type error !")

    if len(k) != 6:
        raise DESException \
            (message="f_calculate k parameter size error !")

    if len(r) != 4:
        raise DESException \
            (message="f_calculate r parameter size error !")

    # E Permutation
    l_e = bits_permutate(input=r,
                         table=_E_BIT_SELECTION_TABLE)

    # k xor E(r)
    l_result = int.from_bytes(k, "big") ^ int.from_bytes(l_e, "big")

    # Sboxes translation
    l_bin_result = bin(l_result)[2:]
    l_bin_result = l_bin_result.rjust(48, '0')
    l_bin_boxed_result = ''

    for i in range(0, 8):
        l_s_box_i = int(l_bin_result[6 * i] + l_bin_result[6 * i + 5], 2)
        l_s_box_j = int(l_bin_result[6 * i + 1: 6 * (i + 1) - 1], 2)
        l_s_box_out = bin(_S_TABLES[i][l_s_box_i][l_s_box_j])[2:]
        l_bin_boxed_result += l_s_box_out.rjust(4, '0')

        # P Permuation
        l_result = bits_permutate \
            (input=int(l_bin_boxed_result, 2).to_bytes(4, "big"),
             table=_P)

    return l_result


class DES:
    def __init__(self, key=b'', encrypt=DES_ENCRYPT):

        # Sanity parameter check
        if type(key) != bytes:
            raise DESException \
                (message="DES init key parameter type error !")

        if len(key) != 8:
            raise DESException \
                (message="DES init key parameter size error !")

        if type(encrypt) != int:
            raise DESException \
                (message="DES init encrypt parameter type error !")

        if (encrypt != DES_ENCRYPT) and (encrypt != DES_DECRYPT):
            raise DESException \
                (message="DES init encrypt parameter value error !")

        if encrypt == DES_ENCRYPT:
            self.subkeys = subkeys_create(key=key)
        else:
            # Only subkeys need to be reversed for decrypting.
            self.subkeys = subkeys_create(key=key)[::-1]

    def compute(self, data=b''):

        # Sanity parameter check
        if type(data) != bytes:
            raise DESException \
                (message="DES compute msg parameter type error !")

        if len(data) != 8:
            raise DESException \
                (message="DES compute msg parameter size error !")

        l_result = b''

        # IP + permutation
        l_ip = bits_permutate(input=data,
                              table=_IP_POS_TABLE)

        l_lr = [[l_ip[0:4], l_ip[4:8]]]

        for i in range(1, 16 + 1):
            l_ri = int.from_bytes(l_lr[i - 1][0], "big") \
                   ^ int.from_bytes(f_calculate(k=self.subkeys[i - 1],
                                                r=l_lr[i - 1][1]),
                                    "big")
            l_lr.append([l_lr[i - 1][1], l_ri.to_bytes(4, "big")])

        l_rl_16 = l_lr[16][1] + l_lr[16][0]

        # IP - permutation
        l_result += bits_permutate(input=l_rl_16,
                                   table=_IP_NEG_TABLE)

        return l_result


class CypherOp(DES):
    def __init__(self, key=b'', encrypt=DES_ENCRYPT):
        # Sanity paramter check
        if type(key) != bytes:
            raise DESException(message="CypherOp.__init__ key paramter type error !")
        if len(key) != 8:
            raise DESException(message="CypherOP.__init__ key paramter size error !")

        # DES Configuration
        DES.__init__(self, key=key, encrypt=encrypt)

        # Encrypt parameter is stored for cbc encryption/decryption algorithms
        self.encrypt = encrypt

    def ecb_compute(self, msg=b''):
        # Sanity parameter check
        if type(msg) != bytes:
            raise DESException(message="CypherOp.ecb msg parameter type error ! ")

        # The message is 0 filled to be lenght modulo 8 bytes
        l_divmod = divmod(len(msg), 8)
        l_msg = msg + (8 - l_divmod[1]) * struct.pack(">b", 0)

        # for ecb every 8 bytes blocks are DES encrypted/decripted in row.
        l_result = b''
        for id_block in range(0, l_divmod[0]):
            l_result += DES.compute(self, data=l_msg[id_block * 8: (id_block + 1) * 8])

        return l_result

    def cbc_compute(self, msg=b'', iv=b''):
        # Sanity parameter check
        if type(msg) != bytes:
            raise DESException(message="CypherOp.cbc msg parameter type error !")
        if type(iv) != bytes:
            raise DESException(message="CypherOp.cbc iv parameter type error !")
        if len(iv) != 8:
            raise DESException(message="CypherOp.cbc iv parameter size error !")

        # The message is 0 filled to be to modulo 8 bytes lenght.
        l_divmod = divmod(len(msg), 8)
        l_msg = msg + (8 - l_divmod[1]) * struct.pack(">b", 0)

        # CBC computation.
        l_result = b''
        l_des_in = b''
        l_des_out = 'b'
        if self.encrypt == DES_ENCRYPT:
            # For CBC encryption every 8 bytes blocks are xored with the previous DES encrypted/decrypted block before
            # the be DES  encrypted.
            # At start, the first block is xored with the iv vector.
            l_des_out = iv
            for id_block in range(0, l_divmod[0]):
                l_des_in = int(l_msg[id_block * 8: (id_block + 1) * 8].hex(), 16) ^ int(l_des_out.hex(), 16)
                l_des_out = DES.compute(self, data=l_des_in.to_bytes(8, "big"))
                l_result += l_des_out
        else:
            # For CBC decryption every 8 bytes blocks are DES decrypted first. The result is xored then with the
            # previous encrypted 8 bytes blocks.
            # for every DES decryption, the result must be xored witht the previous encrypted 8 bytes blocks.
            # At start, the first DES decrypted output must be xored with iv vector.
            l_des_pre = iv
            for id_block in range(0, l_divmod[0]):
                l_des_in = l_msg[id_block * 8: (id_block + 1) * 8]
                l_des_out = DES.compute(self, data=l_des_in)
                l_des_out_xor_pre = int(l_des_out.hex(), 16) ^ int(l_des_pre.hex(), 16)
                l_result += l_des_out_xor_pre.to_bytes(8, 'big')
                l_des_pre = l_des_in

        return l_result


if __name__ == "__main__":

    # ----------------------------------------------------------------------
    # TEST 1

    # bits_permutate test with _IP_POS_Table
    bytes_input_value_ref = int('0000000100100011010001010110011110001001101010111100110111101111', 2).to_bytes(8,
                                                                                                                "big")
    bytes_output_value_ref = int('1100110000000000110011001111111111110000101010101111000010101010', 2).to_bytes(8,
                                                                                                                 "big")

    bytes_output_value = bits_permutate(input=bytes_input_value_ref,
                                        table=_IP_POS_TABLE)

    if bytes_output_value != bytes_output_value_ref:
        print("TEST 1 KO !!")
    else:
        print("TEST 1 OK ..")

    # ----------------------------------------------------------------------
    # TEST 2

    # bits_permutate test with _PC_1_Table
    bytes_input_value_ref = int('0001001100110100010101110111100110011011101111001101111111110001', 2).to_bytes(8,
                                                                                                                "big")
    bytes_output_value_ref = int('11110000110011001010101011110101010101100110011110001111', 2).to_bytes(7, "big")

    bytes_output_value = bits_permutate(input=bytes_input_value_ref,
                                        table=_PC_1_TABLE)

    if bytes_output_value != bytes_output_value_ref:
        print("TEST 2 KO !!")
    else:
        print("TEST 2 OK ..")

    # ----------------------------------------------------------------------
    # TEST 3

    # bits_permutate test with _PC_2_Table
    bytes_input_value_ref = int('11100001100110010101010111111010101011001100111100011110', 2).to_bytes(7, "big")
    bytes_output_value_ref = int('000110110000001011101111111111000111000001110010', 2).to_bytes(6, "big")

    bytes_output_value = bits_permutate(input=bytes_input_value_ref,
                                        table=_PC_2_TABLE)

    if bytes_output_value != bytes_output_value_ref:
        print("TEST 3 KO !!")
    else:
        print("TEST 3 OK ..")

    # ----------------------------------------------------------------------
    # TEST 4

    # subkeys_create

    key_input_ref = int('0001001100110100010101110111100110011011101111001101111111110001', 2).to_bytes(8, "big")

    subkeys_output_ref = [int('000110110000001011101111111111000111000001110010', 2).to_bytes(6, "big"),
                          int('011110011010111011011001110110111100100111100101', 2).to_bytes(6, "big"),
                          int('010101011111110010001010010000101100111110011001', 2).to_bytes(6, "big"),
                          int('011100101010110111010110110110110011010100011101', 2).to_bytes(6, "big"),
                          int('011111001110110000000111111010110101001110101000', 2).to_bytes(6, "big"),
                          int('011000111010010100111110010100000111101100101111', 2).to_bytes(6, "big"),
                          int('111011001000010010110111111101100001100010111100', 2).to_bytes(6, "big"),
                          int('111101111000101000111010110000010011101111111011', 2).to_bytes(6, "big"),
                          int('111000001101101111101011111011011110011110000001', 2).to_bytes(6, "big"),
                          int('101100011111001101000111101110100100011001001111', 2).to_bytes(6, "big"),
                          int('001000010101111111010011110111101101001110000110', 2).to_bytes(6, "big"),
                          int('011101010111000111110101100101000110011111101001', 2).to_bytes(6, "big"),
                          int('100101111100010111010001111110101011101001000001', 2).to_bytes(6, "big"),
                          int('010111110100001110110111111100101110011100111010', 2).to_bytes(6, "big"),
                          int('101111111001000110001101001111010011111100001010', 2).to_bytes(6, "big"),
                          int('110010110011110110001011000011100001011111110101', 2).to_bytes(6, "big")]

    subkeys_output = subkeys_create(key=key_input_ref)

    if subkeys_output != subkeys_output_ref:
        print("TEST 4 KO !!")
    else:
        print("TEST 4 OK ..")

    # ----------------------------------------------------------------------
    # TEST 5

    # bits_permutate test with _E_BIT_SELECTION_TABLE
    bytes_input_value_ref = int('11110000101010101111000010101010', 2).to_bytes(4, "big")
    bytes_output_value_ref = int('011110100001010101010101011110100001010101010101', 2).to_bytes(6, "big")

    bytes_output_value = bits_permutate(input=bytes_input_value_ref,
                                        table=_E_BIT_SELECTION_TABLE)

    if bytes_output_value != bytes_output_value_ref:
        print("TEST 5 KO !!")
    else:
        print("TEST 5 OK ..")

    # ----------------------------------------------------------------------
    # TEST 6

    # f_calculate test

    bytes_k_input_ref = int('000110110000001011101111111111000111000001110010', 2).to_bytes(6, "big")
    bytes_r_input_ref = int('11110000101010101111000010101010', 2).to_bytes(4, "big");
    bytes_f_output_ref = int('00100011010010101010100110111011', 2).to_bytes(4, "big")

    bytes_f_output = f_calculate(k=bytes_k_input_ref,
                                 r=bytes_r_input_ref)

    if bytes_f_output_ref != bytes_f_output:
        print("TEST 6 KO !!")
    else:
        print("TEST 6 OK ..")

    # ----------------------------------------------------------------------
    # TEST 7

    # ECB computation test on string

    msg = "Your lips are smoother than vaseline\r\n" + 2 * chr(0)

    CypherOpEncrypt = CypherOp(key=int("0x0E329232EA6D0D73", 16).to_bytes(8, "big"),
                               encrypt=DES_ENCRYPT)

    CypherOpDecrypt = CypherOp(key=int("0x0E329232EA6D0D73", 16).to_bytes(8, "big"),
                               encrypt=DES_DECRYPT)

    encrypted_msg_ref = "C0999FDDE378D7ED727DA00BCA5A84EE47F269A4D6438190D9D52F78F5358499828AC9B453E0E653"

    encrypted_msg = CypherOpEncrypt.ecb_compute(msg=msg.encode('utf-8'))

    # print("uncrypted msg : ", msg)
    # print("encrypted msg : ", encrypted_msg.hex())

    decrypted_msg = CypherOpDecrypt.ecb_compute(msg=encrypted_msg)

    if (decrypted_msg.decode('utf-8') != msg) and (encrypted_msg.hex().upper() != encrypted_msg_ref):
        print("TEST 7 KO !!")
    else:
        print("TEST 7 OK ..")

    # print("decrypted msg : " , decrypted_msg.decode('utf-8'))

    # ----------------------------------------------------------------------
    # TEST 8

    # ECB computation test on string

    msg = "je suis ne a Digne les Bains le 26121971".ljust(80, '.')

    CypherOpEncrypt = CypherOp(key=int("0x0E329232EA6D0D73", 16).to_bytes(8, "big"),
                               encrypt=DES_ENCRYPT)

    CypherOpDecrypt = CypherOp(key=int("0x0E329232EA6D0D73", 16).to_bytes(8, "big"),
                               encrypt=DES_DECRYPT)

    encrypted_msg_ref = "C0999FDDE378D7ED727DA00BCA5A84EE47F269A4D6438190D9D52F78F5358499828AC9B453E0E653"

    encrypted_msg = CypherOpEncrypt.ecb_compute(msg=msg.encode('utf-8'))

    # print("uncrypted msg : ", msg)
    # print("encrypted msg : ", encrypted_msg.hex())

    decrypted_msg = CypherOpDecrypt.ecb_compute(msg=encrypted_msg)

    if (decrypted_msg.decode('utf-8') != msg) and (encrypted_msg.hex().upper() != encrypted_msg_ref):
        print("TEST 8 KO !!")
    else:
        print("TEST 8 OK ..")

    # print("decrypted msg : " , decrypted_msg.decode('utf-8'))

    # -----------------------------------------------------------------
    # TEST 9

    # CBC computation test on string

    msg = bytes.fromhex("124536987AAAFFF0000000000000000000000AAABF000000")

    CypherOpEncrypt = CypherOp(key=int("0x0123456789ABCDEF", 16).to_bytes(8, "big"),
                               encrypt=DES_ENCRYPT)

    CypherOpDecrypt = CypherOp(key=int("0x0123456789ABCDEF", 16).to_bytes(8, "big"),
                               encrypt=DES_DECRYPT)

    iv = int("0x0123456789ABCDEF", 16).to_bytes(8, "big")

    encrypted_msg = CypherOpEncrypt.cbc_compute(msg=msg, iv=iv)

    print("uncrypted msg : ", msg.hex())
    print("encrypted msg : ", encrypted_msg.hex())

    decrypted_msg = CypherOpDecrypt.cbc_compute(msg=encrypted_msg, iv=iv)

    print("decrypted msg : ", decrypted_msg.hex())
