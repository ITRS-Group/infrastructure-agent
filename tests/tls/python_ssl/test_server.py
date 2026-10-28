"""
Unit tests for Python ssl TLS server adapter.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from agent.config import TLSConfig
from agent.objects import Platform
from tls.python_ssl.server import PythonSslTlsServer


def test_python_ssl_server_wrap_accepted(mocker):
    ctx = mocker.Mock()
    mocker.patch('tls.python_ssl.server.get_ssl_context', return_value=ctx)
    platform = Platform(system='Linux', architecture='x86_64', windows_version=())
    server = PythonSslTlsServer(TLSConfig(), 2.0, platform)
    conn = mocker.Mock()
    server.wrap_accepted(conn)
    conn.settimeout.assert_called_with(2.0)
    ctx.wrap_socket.assert_called_once_with(conn, server_side=True)
