"""
Infrastructure Agent: Cache manager exceptions
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""


class ClientApiError(Exception):
    """An error has been detected in the client request"""

    def __init__(self, message: str, details=None):
        super(ClientApiError, self).__init__(message)
        self.details = details


class ServerApiError(Exception):
    """The server has encountered an error"""

    def __init__(self, message: str, details=None):
        super(ServerApiError, self).__init__(message)
        self.details = details


class UnicodeKeyError(Exception):
    pass


class CacheItemSizeError(Exception):
    pass


class CacheTTLError(Exception):
    pass


class InvalidCharacterError(Exception):
    pass
