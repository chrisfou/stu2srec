#!/usr/bin/env python
# title           :stu2srec_error.py
# description     :
# author          :christian FOURNIER
# date            :19/09/2017
# version         :
# usage           :python stu2srec_des.py
# notes           :
# python_version  :3.6.2
# =============================================================================


class StopException(Exception):
    def __init__(self, p_str_msg):
        self.m_str_msg = p_str_msg

    def __str__(self):
        return repr(self.m_str_msg)
