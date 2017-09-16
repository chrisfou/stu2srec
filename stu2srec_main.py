from stu2srec_lex import *
from stu2srec_yacc import *
from stu2srec_version import c_version

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
    print("-x,--baseaddr : data location memory address")
    print("")
    print(" NOTA : The tutorial.stu file located into the installation path gives more details about STU format")


def print_version():
    print("Version : " + c_version)


def compute_stu_file(InputFileName="", OutputFileName=sys.stdout, BaseAddr=0):
    logging.basicConfig(level=logging.DEBUG,
                        filename="stu2srec.log",
                        filemode="w",
                        format="%(filename)10s:%(lineno)4d:%(message)s")

    log = logging.getLogger()

    lex.lex()  # debug=True,debuglog=log)
    yacc.yacc(outputdir=".")  # debug=True,debuglog=log)

    s = open(InputFileName).read()

    yacc.parse(s, debug=log)

    if 'main' in names.keys():
        srecord_gen(p_data=names['main'],
                    p_base_addr=BaseAddr,
                    p_file=OutputFileName)
    else:
        raise StopException(p_msg="No \'main\' defined into file \'{}\'".format(InputFileName))


def main():
    baseaddr = 0
    inputf = None
    outputf = None

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "vhi:o:x:",
                                   ["version", "help", "inputf=", "ouputf=", "baseaddr="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        print_usage()
        sys.exit(2)

    for o, a in opts:

        if o in ("-v", "--version"):
            print_version()
            sys.exit()

        if o in ("-h", "--help"):
            print_usage()
            sys.exit()

        elif o in ("-i", "--inputf"):
            inputf = a
            if not os.path.isfile(a):
                raise StopException(p_msg="input file arg : \'{}\' , is not a file".format(a))

        elif o in ("-o", "--ouputf"):

            if os.path.isfile(a):
                raise StopException(p_msg="output file arg : \'{}\', already exists".format(a))

            try:
                outputf = open(a, mode='w', newline='')
            except:
                raise StopException(p_msg="output file arg : \'{}\', is not a file".format(a))

        elif o in ("-x", "--baseaddr"):
            try:
                baseaddr = int(eval(a))
            except:
                raise StopException(p_msg="baseaddr arg : \'{}\', is not an integer".format(a))

            if baseaddr < 0:
                raise StopException(p_msg="baseaddr arg : \'{}\', is not a positive integer".format(baseaddr))

    if inputf == None:
        raise StopException(p_msg="input file arg not defined")

    if outputf == None:
        outputf = sys.stdout

    compute_stu_file(InputFileName=inputf, OutputFileName=outputf, BaseAddr=baseaddr)


if __name__ == '__main__':

    try:
        #main()
        compute_stu_file(InputFileName="tutorial.stu", OutputFileName=sys.stdout)
        # print("Test gc_odo.stu")
        # compute_stu_file(InputFileName="gc_odo.stu", OutputFileName=sys.stdout)
        # print("Test mtor_ferriby.stu")
        # compute_stu_file(InputFileName="mtor_ferriby.stu", OutputFileName=sys.stdout)
    except StopException as err:
        print(err)
        sys.exit(2)
