"""
Unit tests for SchannelTlsServer wiring (mocked acquire).

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

import pytest

from agent.config import TLSConfig
from tls.schannel.server import SchannelTlsServer


@pytest.fixture(autouse=True)
def _set_startup_log(mocker):
    mocker.patch('agent.config.startup_log', return_value=lambda *args, **kwargs: print(*args, kwargs))


def test_schannel_server_passes_mutual_auth_flag(mocker):
    mock_acquire = mocker.patch('tls.schannel.server.acquire_server_credential', return_value=object())
    mock_wrap = mocker.patch('tls.schannel.server.SchannelSocket.wrap_accepted')
    mock_pool = mocker.patch('tls.schannel.server.configure_thread_pool')
    tls = TLSConfig(connector='schannel', schannel_cert_thumbprint='AABBCCDD', check_client_cert=True)
    server = SchannelTlsServer(tls, handshake_timeout=3.0, max_active_connections=15)
    mock_pool.assert_called_once_with(15)
    mock_acquire.assert_called_once_with(
        thumbprint='AABBCCDD',
        store_name='MY',
        cert_name=None,
    )
    # context_options are not passed — Windows Schannel / OS policy owns protocols.
    assert 'context_options' not in mock_acquire.call_args.kwargs
    conn = mocker.Mock()
    server.wrap_accepted(conn)
    mock_wrap.assert_called_once()
    assert mock_wrap.call_args.kwargs['check_client_cert'] is True


def test_schannel_server_cert_name(mocker):
    mock_acquire = mocker.patch('tls.schannel.server.acquire_server_credential', return_value=object())
    mocker.patch('tls.schannel.server.configure_thread_pool')
    tls = TLSConfig(
        connector='schannel',
        schannel_cert_name='host.example.com',
        schannel_cert_store='MY',
        check_client_cert=False,
    )
    SchannelTlsServer(tls, handshake_timeout=5.0, max_active_connections=15)
    assert mock_acquire.call_args.kwargs['cert_name'] == 'host.example.com'
    assert mock_acquire.call_args.kwargs['thumbprint'] is None


def test_schannel_server_close_releases_credential(mocker):
    cred = object()
    mocker.patch('tls.schannel.server.acquire_server_credential', return_value=cred)
    mocker.patch('tls.schannel.server.configure_thread_pool')
    shutdown = mocker.patch('tls.schannel.server.shutdown_thread_pool')
    release = mocker.patch('tls.schannel.server.release_server_credential')
    tls = TLSConfig(connector='schannel', schannel_cert_thumbprint='AABBCCDD')
    server = SchannelTlsServer(tls, handshake_timeout=3.0, max_active_connections=4)

    server.close()
    server.close()

    shutdown.assert_called()
    release.assert_called_once_with(cred)
    assert server._cred is None


def test_schannel_server_close_releases_credential_when_pool_shutdown_fails(mocker):
    cred = object()
    mocker.patch('tls.schannel.server.acquire_server_credential', return_value=cred)
    mocker.patch('tls.schannel.server.configure_thread_pool')
    mocker.patch('tls.schannel.server.shutdown_thread_pool', side_effect=RuntimeError('pool'))
    release = mocker.patch('tls.schannel.server.release_server_credential')
    tls = TLSConfig(connector='schannel', schannel_cert_thumbprint='AABBCCDD')
    server = SchannelTlsServer(tls, handshake_timeout=3.0, max_active_connections=4)

    with pytest.raises(RuntimeError, match='pool'):
        server.close()

    release.assert_called_once_with(cred)
    assert server._cred is None
