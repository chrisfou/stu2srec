#!/usr/bin/env python
# title           :stu2srec_main.py
# description     :
# author          :christian FOURNIER
# date            :19/09/2017
# version         :
# usage           :
# notes           :
# python_version  :3.6.2
# =============================================================================

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
    print("-o,--outputf  : output file name (S19 format)")
    print("-m,--mapf     : map file name")
    print("-x,--baseaddr : data location memory address")
    print("-d,--debug    : generate debugging informations")

    print("")
    print(
        " NOTA : The tutorial.stu file located into the installation path gives more details about STU format")


def print_version():
    print("Version : " + c_str_version)


def parse_stu_file(p_str_input_file_name="",
                   p_bool_debug_info_flag=False):
    # The contains of the input file is read.
    l_str_input = open(p_str_input_file_name).read()

    # Debug infos generated only if asked.
    if p_bool_debug_info_flag is True:
        logging.basicConfig(level=logging.DEBUG,
                            filename="stu2srec.log",
                            filemode="w",
                            format="%(filename)10s:%(lineno)4d:%(message)s")
        l_debug_log = logging.getLogger()
    else:
        l_debug_log = None

    lex.lex()  # ,debug=True,debuglog=log)

    # The 'outputdir' option is defined for cx_freeze compatibility compatibility.
    yacc.yacc(outputdir=".")  # ,debug=True, debuglog=log)

    yacc.parse(l_str_input, debug=l_debug_log)


def compute_abs_file(p_str_output_file_name="",
                     p_int_base_addr=0):
    # If the output file name is void then the srecord data
    # is sent to the stdout.
    l_boot_is_not_stdout_file = False

    if p_str_output_file_name == "":
        l_file_output = sys.stdout
    else:
        l_file_output = open(p_str_output_file_name,
                             mode='w',
                             newline='')
        l_boot_is_not_stdout_file = True

    if 'main' in g_map_nodes.keys():

        # The list referenced as "main" is parsed to get the whole bytes arrays
        # and join them into a single "bytes" variable.
        l_bytes_msg = g_map_nodes['main'].concat_all_bytes()

        # The SRecord file is generated by taking into account
        # the base address.
        srecord_gen(p_bytes_msg=l_bytes_msg,
                    p_int_base_addr=p_int_base_addr,
                    p_file_output=l_file_output)

        if l_boot_is_not_stdout_file is True:
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

    if 'main' in g_map_nodes.keys():

        # If the map file is asked to be generated then then the datas and the informations
        # inside the liste referenced as "main" are written into the map file.
        if l_file_map is not None:
            l_int_addr = p_int_base_addr
            l_file_map.write("-----------+" + "-" * 64 + "\n")
            l_file_map.write("  Addr     |  Definition   \n")
            l_file_map.write("-----------+" + "-" * 64 + "\n")

            # print(g_map_nodes['main'])
            for i_node in g_map_nodes['main']:
                if i_node.m_str_info != "":
                    l_file_map.write("{0:#010x} | {1} \n".format(l_int_addr,
                                                                 i_node.m_str_info))
                if i_node.m_bytes != b'':
                    l_int_bytes_len = len(i_node.m_bytes)
                    l_int_addr_offset = 0
                    while l_int_bytes_len > 0:
                        if l_int_bytes_len > 4 * 4:
                            l_file_map.write(
                                "{0:#010x} | 0x{1} 0x{2} 0x{3} 0x{4} \n".format
                                (l_int_addr + l_int_addr_offset,
                                 i_node.m_bytes[l_int_addr_offset + 0 * 4:l_int_addr_offset + 1 * 4].hex(),
                                 i_node.m_bytes[l_int_addr_offset + 1 * 4:l_int_addr_offset + 2 * 4].hex(),
                                 i_node.m_bytes[l_int_addr_offset + 2 * 4:l_int_addr_offset + 3 * 4].hex(),
                                 i_node.m_bytes[l_int_addr_offset + 3 * 4:l_int_addr_offset + 4 * 4].hex()))
                            l_int_addr_offset += 4 * 4
                            l_int_bytes_len -= 4 * 4

                        elif l_int_bytes_len > 3 * 4:
                            l_file_map.write(
                                "{0:#010x} | 0x{1} 0x{2} 0x{3} 0x{4} \n".format
                                (l_int_addr + l_int_addr_offset,
                                 i_node.m_bytes[l_int_addr_offset + 0 * 4:l_int_addr_offset + 1 * 4].hex(),
                                 i_node.m_bytes[l_int_addr_offset + 1 * 4:l_int_addr_offset + 2 * 4].hex(),
                                 i_node.m_bytes[l_int_addr_offset + 2 * 4:l_int_addr_offset + 3 * 4].hex(),
                                 i_node.m_bytes[l_int_addr_offset + 3 * 4:].hex()))
                            l_int_addr_offset += l_int_bytes_len
                            l_int_bytes_len -= l_int_bytes_len

                        elif l_int_bytes_len > 2 * 4:
                            l_file_map.write(
                                "{0:#010x} | 0x{1} 0x{2} 0x{3}  \n".format
                                (l_int_addr + l_int_addr_offset,
                                 i_node.m_bytes[l_int_addr_offset + 0 * 4:l_int_addr_offset + 1 * 4].hex(),
                                 i_node.m_bytes[l_int_addr_offset + 1 * 4:l_int_addr_offset + 2 * 4].hex(),
                                 i_node.m_bytes[l_int_addr_offset + 2 * 4:].hex()))
                            l_int_addr_offset += l_int_bytes_len
                            l_int_bytes_len -= l_int_bytes_len

                        elif l_int_bytes_len > 1 * 4:
                            l_file_map.write(
                                "{0:#010x} | 0x{1} 0x{2}   \n".format
                                (l_int_addr + l_int_addr_offset,
                                 i_node.m_bytes[l_int_addr_offset + 0 * 4:l_int_addr_offset + 1 * 4].hex(),
                                 i_node.m_bytes[l_int_addr_offset + 1 * 4:].hex()))
                            l_int_addr_offset += l_int_bytes_len
                            l_int_bytes_len -= l_int_bytes_len
                        else:
                            l_file_map.write("{0:#010x} | 0x{1}   \n".format
                                             (l_int_addr + l_int_addr_offset,
                                              i_node.m_bytes[l_int_addr_offset + 0 * 4:].hex()))
                            l_int_addr_offset += l_int_bytes_len
                            l_int_bytes_len -= l_int_bytes_len

                    l_file_map.write("-----------+" + "-" * 64 + "\n")
                    l_int_addr += len(i_node.m_bytes)
            l_file_map.close()

    else:
        raise StopException(p_str_msg="No \'main\' defined into the stu file")


def main():
    l_int_base_addr = 0
    l_str_input_file_name = ""
    l_str_output_file_name = ""
    l_str_map_file_name = ""
    l_bool_debug_info_flag = None

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "vhi:o:x:m:d",
                                   ["version", "help", "inputf=", "ouputf=",
                                    "baseaddr=", "mapf="])

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

        elif l_opt in ("-d", "--debug"):
            l_bool_debug_info_flag = True

        elif l_opt in ("-x", "--baseaddr"):
            try:
                l_int_base_addr = int(eval(l_arg))
            except:
                raise StopException(
                    p_str_msg="baseaddr arg \'{}\' is not an integer !".format(
                        l_arg))

            if l_int_base_addr < 0:
                raise StopException(
                    p_str_msg="baseaddr arg \'{}\' is not a positive value !".format(
                        l_int_base_addr))

    # Check the parameters
    # An error is raised if the input file is not an existing file.
    if not os.path.isfile(l_str_input_file_name):
        print_usage()
        sys.exit(2)

    # The STU file is parsed.
    # The result is stored into the global LEX "g_map_nodes" map.
    parse_stu_file(p_str_input_file_name=l_str_input_file_name,
                   p_bool_debug_info_flag=l_bool_debug_info_flag)

    # The item designed as "main" in the global LEX "g_map_nodes" map
    # variable is used to generated the SRECORD file.
    compute_abs_file(p_str_output_file_name=l_str_output_file_name,
                     p_int_base_addr=l_int_base_addr)

    # The item designed as "main" into the global LEX "g_map_nodes" map
    # variable is use to generate the mapping file.
    compute_map_file(p_str_map_file_name=l_str_map_file_name,
                     p_int_base_addr=l_int_base_addr)


if __name__ == '__main__':

    try:
        main()

    except StopException as err:
        print(err)
        sys.exit(2)
