class StopException(Exception):

    def __init__(self, p_msg):
        self.m_msg = p_msg

    def __str__(self):
        return repr(self.m_msg)
