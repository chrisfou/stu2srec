import struct


class T_SacemException(Exception):
    def __init__(self, p_str_msg):
        self.m_str_msg = p_str_msg

    def __str__(self):
        return repr(self.m_str_msg)


C_TAB_CLE = (12970357, 12239417)

C_TAB_RK_TETA = (
    (
        11864353, 9521837, 11185447, 2498713, 1157036, 12884998, 12735449,
        10377554, 1514093, 2708362, 4506482, 5693826, 4307756, 1167344,
        2341246, 11050558, 5242791, 6924383, 11628556, 5452666, 1209530,
        1332755, 11636795, 241399, 9754171, 1085261, 7648941, 3513262,
        10923155, 11110607, 7418961, 4712882, 8214253, 3124944, 6388509,
        7272542, 5948117, 8349264, 8228542, 1585196, 4479462, 3102860,
        1300446, 3720142, 12212735, 10106026, 7976907, 10620882, 12239523,
        537717, 8087828, 5350003, 12272246, 7230635, 8105667, 1462510,
        11411150, 4511260, 10681536, 5703595, 2468990, 9469449, 4253335,
        10175948, 4372693, 12642823, 3457939, 2735147, 10267100, 2804238,
        11468926, 3788034, 9220310, 9482688, 11080596, 8687668, 6350566,
        5858612, 12098489, 9446541, 11438339, 3939686, 5455974, 7534767,
        11099882, 8574661, 4378446, 3375989, 7242428, 10372252, 6408876,
        361350, 12943228, 5281602, 383957, 8934988, 4461553, 10142225,
        5648355, 6849354, 9494430, 1561443, 1536452, 12090244, 6404591,
        9863037, 3110564, 1649405, 4635196, 6759480, 5029554, 9857188,
        10029496, 5611484, 5712949, 2640149, 458757, 9521626, 8456896,
        7635530, 2207111, 4673441, 4210456, 11259115, 11068155, 10028280,
        1812106, 4396740, 4942042, 3172583, 11474115, 9910579, 6634458,
        6710388, 886602, 2329157, 8029787, 6887867, 3772198, 7782430,
        11925196, 10040283, 7593432, 11853024, 5633088, 12031859, 6014318,
        11827715, 6788160, 12551177, 4293544, 7022247, 12088120, 3096098,
        12641213, 11099210, 5109704, 6722994, 12498567, 3280971, 187528,
        1409699, 12778483, 4168150, 2847550, 7194771, 6467709, 11708499,
        9415518, 4169192, 770061, 3096099, 11855023, 3452475, 5289140,
        1536886, 8113066, 8132993, 9916119, 9181810, 4984450, 9214910,
        631592, 5832908, 12510043, 8333003, 3692130, 11300829, 5000991,
        1143834, 2909421, 3672031, 2068456, 10967663, 418916, 8705261,
        1310458, 5392561, 4148929, 3739635, 5002682, 7643315, 3726465,
        8780096, 321160, 1159319, 7922494, 369609, 4978518, 3565470,
        3725183, 4987830, 10815895, 4588793, 2719809, 6417310, 10457674,
        8995242, 1113057, 9763246, 107361, 4938766, 10600337, 3448251,
        5744308, 5156596, 2456108, 7320212, 12602547, 7404942, 1507042,
        7791613, 3860918, 11585576, 8118881, 2003807, 6535890, 2003233,
        3846455, 7248457, 4613047, 892339, 5641363, 4458466, 11653996,
        5069560, 10655773, 618931, 11520679, 4106873, 6306282, 9058384,
        10030673, 1161201, 6933612, 6310609),
    (
        11439861, 3110631, 2168229, 5518612, 607540, 12218270, 7077232,
        5330275, 9959217, 1950113, 1070020, 6682206, 6848397, 6007385,
        5383288, 2918468, 1940158, 11531609, 841995, 12151384, 3848043,
        10011374, 2900532, 2719299, 10037286, 3614647, 8999795, 10682854,
        5814829, 5278060, 7033740, 10765289, 8014406, 2056870, 6816477,
        755664, 8117541, 4326237, 4421860, 8759018, 3538507, 11403832,
        9451808, 1971824, 2225254, 4262245, 6890505, 7887704, 8866915,
        3789939, 4068272, 4113844, 2824776, 51481, 10006491, 5018576,
        1002962, 8147170, 4999669, 5013110, 10279395, 8847750, 8721608,
        2525465, 4819123, 6603947, 12219409, 2392252, 10643436, 3529686,
        8991249, 5817402, 1733165, 5163394, 6718097, 2138677, 3668800,
        8703438, 9263881, 9669310, 1971949, 11124382, 8509643, 9172214,
        7521386, 10505477, 10650631, 1218403, 849911, 1050255, 8064195,
        11844797, 3104111, 8472902, 4773415, 7904382, 11252773, 4348297,
        4377980, 10266650, 2803327, 6973963, 1452185, 7408962, 5502660,
        9860445, 2645924, 240792, 7233089, 3733065, 5402014, 10892878,
        4820049, 3106714, 5105491, 9307788, 10769297, 4799551, 10759672,
        4974047, 1934868, 634292, 5662520, 9098605, 3684167, 8229012,
        10218668, 10233542, 5210540, 3317567, 5751341, 3384786, 8502719,
        31391, 5385931, 3867508, 6854545, 7293444, 9938005, 483185,
        2722918, 3705094, 8009842, 2798316, 2623014, 3415570, 3769868,
        8535691, 9874962, 5302396, 11479407, 11864767, 7014735, 8483928,
        7991655, 11068080, 11595491, 1802381, 5857951, 5813688, 11583130,
        2925520, 5310557, 9987342, 9228942, 2060044, 6011217, 10102766,
        7501325, 6872446, 10387044, 1920253, 3925728, 4508346, 9630056,
        1473013, 1708328, 2649511, 7590623, 6428506, 3214050, 6933739,
        3374211, 7136694, 540380, 10631905, 5483410, 10209437, 9475150,
        3800699, 2448976, 8422274, 1445308, 9153692, 5649634, 7115774,
        7328652, 7715255, 11850899, 4933989, 4023011, 10506674, 7940709,
        8306526, 8599748, 3711060, 9851087, 6847911, 8027911, 4437943,
        3544971, 1504011, 7217102, 4619294, 10796427, 10271633, 5356702,
        9640335, 10063435, 8178769, 1008661, 5960924, 4676758, 8873398,
        2978097, 8745752, 3387351, 11438184, 2980809, 2759355, 9569233,
        7186623, 7076760, 8249588, 579285, 90538, 10971871, 4607440,
        5127512, 4137412, 5174736, 10989874, 10752369, 9094271, 1706518,
        100921, 8754115, 9618034, 9497488, 11113232, 7821647, 7278356,
        4719382, 8910675, 1572371, 3663410)
)


def sacem(p_bytes_msg=b'',
          p_bytes_svl=b''):
    l_int_result = 2 * [0]

    if len(p_bytes_msg) % 4 != 0:
        raise T_SacemException(p_str_msg="size of p_bytes_msg : {}, not modulo 32bits".format(len(p_bytes_msg)))

    if len(p_bytes_msg) > 4 * 256:
        raise T_SacemException(p_str_msg="size of m_str_msg : {} > 1024 bytes".format(len(p_bytes_msg)))

    if len(p_bytes_msg) == 0:
        raise T_SacemException(p_str_msg="m_str_msg is length null")

    if len(p_bytes_svl) != 8:
        raise T_SacemException(p_str_msg="p_bytes_svl cannot be converted into a 2x32bits array")

    l_tuple_svl = struct.unpack(">II", p_bytes_svl)

    for i in range(0, 2):
        for j in range(0, len(p_bytes_msg) >> 2):
            l_tuple_data = struct.unpack(">I", p_bytes_msg[4 * j: 4 * j + 4])[0]
            l_int_result[i] += C_TAB_RK_TETA[i][j] * l_tuple_data
        l_int_result[i] = (l_int_result[i] + l_tuple_svl[i]) % C_TAB_CLE[i]

    return struct.pack(">II", l_int_result[0], l_int_result[1])


if __name__ == "__main__":
    print(sacem(p_bytes_msg=struct.pack("bbbb", 1, 2, 3, 4),
                p_bytes_svl=struct.pack(">II", 1, 2)))
