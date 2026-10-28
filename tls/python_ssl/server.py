"""
Python stdlib ssl TLS server for NRPE.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent.ssl_helper import get_ssl_context

if TYPE_CHECKING:
    from agent.config import TLSConfig
    from agent.objects import Platform


class PythonSslTlsServer:
    """TLS server using Python ssl.SSLContext (PEM / self-signed)."""

    backend = 'python_ssl'

    def __init__(self, tls_config: 'TLSConfig', handshake_timeout: float, _platform: 'Platform'):
        self._tls_config = tls_config
        self._handshake_timeout = handshake_timeout
        self.context = get_ssl_context(tls_config, 'server')

    def wrap_accepted(self, conn):
        conn.settimeout(self._handshake_timeout)
        return self.context.wrap_socket(conn, server_side=True)
