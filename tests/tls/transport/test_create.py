"""
Unit tests for tls.transport factories.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

import pytest

from agent.config import TLSConfig
from agent.objects import Platform
from tls.transport import create_tls_server


@pytest.fixture
def platform_linux():
    return Platform(system='Linux', architecture='x86_64', windows_version=())


@pytest.fixture
def platform_win():
    return Platform(
        system='Windows',
        architecture='x86_64',
        windows_version=('10', '10.0.17763', 'SP0', 'Multiprocessor Free'),
    )


def test_create_tls_server_python(platform_linux, mocker):
    mock_cls = mocker.patch('tls.python_ssl.server.PythonSslTlsServer')
    mock_cls.return_value.backend = 'python_ssl'
    tls = TLSConfig()
    transport = create_tls_server(tls, 3.0, platform_linux, max_active_connections=15)
    mock_cls.assert_called_once()
    assert transport is mock_cls.return_value


def test_create_tls_server_logs_redacted_pkcs11_uri(platform_linux, mocker, caplog):
    import logging

    mock_cls = mocker.patch('tls.python_ssl.server.PythonSslTlsServer')
    mock_cls.return_value.backend = 'python_ssl'
    with caplog.at_level(logging.DEBUG, logger='tls'):
        create_tls_server(
            TLSConfig(
                connector='pkcs11',
                pkcs11_module='/m.so',
                pkcs11_key_uri='pkcs11:object=key?pin-value=1234&pin-source=file:/tmp/pin',
                pkcs11_cert_uri='pkcs11:object=cert?pin-value=abcd',
                pkcs11_key_pin='not-logged',
            ),
            3.0,
            platform_linux,
            max_active_connections=15,
        )
    assert '1234' not in caplog.text
    assert 'abcd' not in caplog.text
    assert '/tmp/pin' not in caplog.text
    assert 'not-logged' not in caplog.text
    assert 'pin-value=***' in caplog.text
    assert 'pin-source=***' in caplog.text
    assert 'object=key' in caplog.text
    assert 'object=cert' in caplog.text


def test_create_tls_server_pkcs11_identity_uses_python_ssl(platform_linux, mocker):
    mock_cls = mocker.patch('tls.python_ssl.server.PythonSslTlsServer')
    mock_cls.return_value.backend = 'python_ssl'
    transport = create_tls_server(
        TLSConfig(
            connector='pkcs11',
            pkcs11_module='/m.so',
            pkcs11_key_uri='pkcs11:x',
            pkcs11_cert_uri='pkcs11:cert',
            pkcs11_key_pin='1',
        ),
        3.0,
        platform_linux,
        max_active_connections=15,
    )
    mock_cls.assert_called_once()
    assert transport is mock_cls.return_value


def test_create_tls_server_schannel(platform_win, mocker, caplog):
    import logging

    mock_cls = mocker.patch('tls.schannel.server.SchannelTlsServer')
    mock_cls.return_value.backend = 'schannel'
    with caplog.at_level(logging.DEBUG, logger='tls'):
        transport = create_tls_server(
            TLSConfig(connector='schannel', schannel_cert_thumbprint='AABB'),
            3.0,
            platform_win,
            max_active_connections=15,
        )
    mock_cls.assert_called_once()
    assert mock_cls.call_args.args[2] == 15
    assert transport is mock_cls.return_value
    assert 'schannel_cert_thumbprint=AABB' in caplog.text
    assert 'constructing TLS backend=schannel' in caplog.text
