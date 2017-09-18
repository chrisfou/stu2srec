from stu2srec_lex import *
from stu2srec_yacc import *
from stu2srec_version import c_str_version

import getopt
import logging
import os
import sys


def print_usage():
    print("Usage")

    print("-v            : version ")
    print("-h,--help     : help ")
    print("-i,--inputf   : input file name (STU format)")
    print("-i,--outputf  : output file name (S19 format)")
    print("-m,--mapf     : map file name")
    print("-x,--baseaddr : data location memory address")
    print("")
    print(" NOTA : The tutorial.stu file located into the installation path gives more details about STU format")


def print_version():
    print("Version : " + c_str_version)


def parse_stu_file(p_str_input_file_name=""):

    # An error is raised if the input file is not an existing file.
    if not os.path.isfile(p_str_input_file_name):
        raise StopException(p_str_msg="input file arg : \'{}\' , is not a file".format(p_str_input_file_name))

    # The contains of the input file is read.
    l_str_input = open(p_str_input_file_name).read()

    logging.basicConfig(level=logging.DEBUG,
                        filename="stu2srec.log",
                        filemode="w",
                        format="%(filename)10s:%(lineno)4d:%(message)s")

    log = logging.getLogger()

    lex.lex()  # ,debug=True,debuglog=log)
    yacc.yacc(outputdir=".")  # ,debug=True,debuglog=log)

    yacc.parse(l_str_input, debug=log)


def compute_abs_file(p_str_output_file_name="",
                     p_int_base_addr=0):
    # If the output file name is void then the srecord data
    # is sent to the stdout.
    if p_str_output_file_name == "":
        l_file_output = sys.stdout
    else:
        l_file_output = open(p_str_output_file_name,
                             mode='w',
                             newline='')

    if 'main' in names.keys():

        # The list referenced as "main" is parsed to get the whole bytes arrays
        # and join them into a single "bytes" variable.
        l_bytes_msg = b''
        for x in names['main']:
            l_bytes_msg += x.m_bytes_data

        # The SRecord file is generated by taking into account
        # the base addresse.
        srecord_gen(p_bytes_msg=l_bytes_msg,
                    p_int_base_addr=p_int_base_addr,
                    p_file_output=l_file_output)

        l_file_output.close()

    else:
        raise StopException(p_str_msg="No \'main\' defined into the stu file")


def compute_map_file(p_str_map_file_name="",
                     p_int_base_addr=0):
    # If the map file name is void then the map is not recorded
    if p_str_map_file_name == "":
        l_file_map = None
    else:
        l_file_map = open(p_str_map_file_name,
                          mode='w',
                          newline='')

    if 'main' in names.keys():

        # If the map file is asked to be generated then then the datas and the informations
        # inside the liste referenced as "main" are written into the map file.
        if l_file_map is not None:
            l_int_addr = p_int_base_addr
            print("-----------+" + "-" * 64, file=l_file_map)
            print("  Addr     |  Definition ", file=l_file_map)
            print("-----------+" + "-" * 64, file=l_file_map)

            for x in names['main']:
                if x.m_str_info != "":
                    print("{0:#010x} | {1}".format(l_int_addr, x.m_str_info), file=l_file_map)
                if x.m_bytes_data != b'':
                    print("{0:#010x} | 0x{1}".format(l_int_addr, x.m_bytes_data.hex()), file=l_file_map)
                    print("-----------+" + "-" * 64, file=l_file_map)
                    l_int_addr += len(x.m_bytes_data)

            l_file_map.close()

    else:
        raise StopException(p_str_msg="No \'main\' defined into the stu file")


def main():
    l_int_base_addr = 0
    l_str_input_file_name = ""
    l_str_output_file_name = ""
    l_str_map_file_name = ""

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "vhi:o:x:m:",
                                   ["version", "help", "inputf=", "ouputf=", "baseaddr=", "mapf="])

    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        print_usage()
        sys.exit(2)

    for l_opt, l_arg in opts:

        if l_opt in ("-v", "--version"):
            print_version()
            sys.exit()

        if l_opt in ("-h", "--help"):
            print_usage()
            sys.exit()

        elif l_opt in ("-i", "--inputf"):
            l_str_input_file_name = l_arg

        elif l_opt in ("-o", "--ouputf"):
            l_str_output_file_name = l_arg

        elif l_opt in ("-m", "--mapf"):
            l_str_map_file_name = l_arg

        elif l_opt in ("-x", "--baseaddr"):
            try:
                l_int_base_addr = int(eval(l_arg))
            except:
                raise StopException(p_str_msg="baseaddr arg : \'{}\', is not an integer".format(l_arg))

            if l_int_base_addr < 0:
                raise StopException(
                    p_str_msg="baseaddr arg : \'{}\', is not a positive integer".format(l_int_base_addr))

    # The STU file is parsed.
    # The result is stored into the global LEX "names" map.
    parse_stu_file(p_str_input_file_name=l_str_input_file_name)

    # The item designed as "main" in the global LEX "names" map
    # variable is used to generated the SRECORD file.
    compute_abs_file(p_str_output_file_name=l_str_output_file_name,
                     p_int_base_addr=l_int_base_addr)

    # The item designed as "main" into the global LEX "names" map
    # variable is use to generate the mapping file.
    compute_map_file(p_str_map_file_name=l_str_map_file_name,
                     p_int_base_addr=l_int_base_addr)


if __name__ == '__main__':

    try:
        main()

    except StopException as err:
        print(err)
        sys.exit(2)
