class StopException(Exception):

    def __init__(self, p_str_msg):
        self.m_str_msg = p_str_msg

    def __str__(self):
        return repr(self.m_str_msg)
