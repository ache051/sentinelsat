# -*- coding: utf-8 -*-

class SentinelAPIError(Exception):
    """Invalid responses from DataHub.

    Attributes
    ----------
    msg: str
        The error message.
    response: requests.Response
        The response from the server as a `requests.Response` object.
    """

    def __init__(self, msg=None, response=None):
        self.msg = msg
        self.response = response

    def __str__(self):
        return 'HTTP status {0} {1}: {2}'.format(
            self.response.status_code, self.response.reason,
            ('\n' if '\n' in self.msg else '') + self.msg)

class SentinelAPILTAError(SentinelAPIError):
    """ Error when retrieving a product from the Long Term Archive

    Attributes
    ----------
    msg: str
        The error message.
    response: requests.Response
        The response from the server as a `requests.Response` object.
    """

    def __init__(self, msg=None, response=None):
        self.msg = msg
        self.response = response


class InvalidChecksumError(Exception):
    """MD5 checksum of a local file does not match the one from the server.
    """
    pass
