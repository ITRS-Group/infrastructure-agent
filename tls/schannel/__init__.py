"""
Schannel TLS package (Windows LocalMachine store).

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from tls.schannel.errors import SchannelError
from tls.schannel.server import SchannelTlsServer
from tls.schannel.socket_adapter import SchannelSocket
from tls.schannel.store import acquire_server_credential

__all__ = [
    'SchannelError',
    'SchannelSocket',
    'SchannelTlsServer',
    'acquire_server_credential',
]
