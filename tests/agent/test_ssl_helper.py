"""
Infrastructure Agent: Unit tests for logger
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

import ctypes
import errno
import os
import socket
import ssl
import subprocess
import sys
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from mock import call

import agent.pkcs11
import agent.ssl_helper
from agent.config import TLSConfig


@pytest.fixture(autouse=True)
def _set_startup_log(mocker):
    mocker.patch('agent.config.startup_log', return_value=lambda *args, **kwargs: print(*args, kwargs))


def _pkcs11_tls(**overrides) -> TLSConfig:
    values = dict(
        connector='pkcs11',
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key',
        pkcs11_cert_uri='pkcs11:object=cert',
    )
    values.update(overrides)
    return TLSConfig(**values)


def _mock_pkcs11_system_policy(mocker):
    mocker.patch('agent.pkcs11.load_pkcs11_into_context')
    mocker.patch(
        'agent.ssl_helper.get_system_cipher_lists',
        return_value=('ECDH+AESGCM:!aNULL', ''),
    )
    mocker.patch(
        'agent.ssl_helper.get_system_tls_versions',
        return_value=(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    )


@contextmanager
def _file_check(filename):
    """Side effect based on filename"""
    if filename.startswith('notfound'):
        raise OSError(errno.ENOENT, filename)
    if filename.startswith('noaccess'):
        raise OSError(errno.EPERM, filename)
    yield 42


def _path_check(pathname):
    """Side effect based on pathname"""
    with _file_check(pathname):
        pass
    return []


@pytest.mark.parametrize(
    'tls_config, client_mode, logall, certerr, exception, logexp', [
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', False, False, None, []), False, False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Loading system default CA certificates'],
            id="default_CA_server_mode"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', False, False, None, []), True, False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Loading system default CA certificates'],
            id="default_CA_client_mode"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', False, True, None, []), True, False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Loading system default CA certificates'],
            id="default_CA_client_mode_check_server_cert"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', False, False, None, []), True, False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Loading system default CA certificates'],
            id="default_CA"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'key', False, False, None, []), False, False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_file"),
        pytest.param(
            TLSConfig('notfound', None, 'cert', 'key', False, False, None, []), False,
            False, None, agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_file_not_found"),
        pytest.param(
            TLSConfig('noaccess', None, 'cert', 'key', False, False, None, []), False,
            False, None, agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_file_no_access"),
        pytest.param(
            TLSConfig(None, 'ca', 'cert', 'key', False, False, None, []), False, False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_path"),
        pytest.param(
            TLSConfig(None, 'notfound', 'cert', 'key', False, False, None, []), False,
            False, None, agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_path_not_found"),
        pytest.param(
            TLSConfig(None, 'noaccess', 'cert', 'key', False, False, None, []), False,
            False, None, agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_path_no_access"),
        pytest.param(
            TLSConfig('ca', None, 'cert', None, False, False, None, []), False, False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Using configured TLS cert_file'],
            id="cert"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'key', False, False, None, []), False, False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Using configured TLS cert_file and key_file'],
            id="cert_with_key"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'notfound', False, False, None, []), False, False, None,
            agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured TLS cert_file and key_file'],
            id="cert_with_key_not_found"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'noaccess', False, False, None, []), False, False, None,
            agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured TLS cert_file and key_file'],
            id="cert_with_key_no_access"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'key', False, False, None, []), False, True, None, None,
            ['foo: Logging all TLS messages'],
            id="log_all_true"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'key', False, False, None, []), False,
            True, ssl.SSLError, agent.ssl_helper.AgentSSLError,
            ["foo: TLS key missing or does not match the certificate"],
            id="cert_error"),
        pytest.param(
            TLSConfig('ca', None, None, 'key', False, False, None, []), False,
            False, None, agent.ssl_helper.AgentSSLError,
            ["foo: TLS identity is not configured"],
            id="no_cert"),
        pytest.param(
            TLSConfig('ca', None, None, None, False, False, None, []), False,
            False, None, agent.ssl_helper.AgentSSLError,
            ["foo: TLS identity is not configured"],
            id="ca_no_cert_no_key"),
        pytest.param(
            TLSConfig(None, None, None, None, False, False, None, []), False, False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Using configured TLS cert_file and key_file'],
            id="ca_no_cert_no_key_no_cert"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', True, False, None, []), False, False, None, None,
            ['foo: Check client certificate'],
            id="check_client_certificate"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', False, False, 'cipher', []), False, False, None, None,
            ['foo: Using configured TLS ciphers'],
            id="ciphers"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', True, False, 'cipher', []), False, False, None, None,
            ['foo: Using configured TLS ciphers', 'foo: Check client certificate'],
            id="ciphers_check_client"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', False, False, None, ['ALL']), False, False, None, None,
            ["foo: Setting Context property 'ssl.OP_ALL'"],
            id="option"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', False, False, None, ['foo']), False, False, None, AttributeError,
            ["Invalid foo tls_context_option 'foo' in config"],
            id="bad_option"),
        pytest.param(
            TLSConfig('ca', None, None, None, False, False, None, []), True, False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="client_mode_no_cert"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'key', True, False, 'cipher', ['ALL']), False, True, None, None,
            [
                'foo: Using OpenSSL',
                'foo: Using configured CA Certificate',
                'foo: Using configured TLS cert_file and key_file',
                'foo: Check client certificate',
                'foo: Using configured TLS ciphers',
                "foo: Setting Context property 'ssl.OP_ALL'",
                'foo: Logging all TLS messages',
            ],
            id="option"),
    ])
def test_ssl_helper_get_ssl_context(tls_config, client_mode, logall, certerr, exception, logexp, mocker, caplog):
    tls_config.log_all_messages = logall
    mock_context = mocker.Mock()
    mock_context.load_cert_chain.side_effect = certerr
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch('agent.ssl_helper.create_self_signed_cert', return_value=('key', 'cert'))
    if not exception:
        agent.ssl_helper.get_ssl_context(tls_config, 'foo', client_mode=client_mode)
    else:
        with pytest.raises(exception):
            agent.ssl_helper.get_ssl_context(tls_config, 'foo', client_mode=client_mode)
    for text in logexp:
        assert text in caplog.text


def test_ssl_helper_system_ca_does_not_open_path(mocker, caplog, monkeypatch):
    tls_config = _pkcs11_tls()
    _mock_pkcs11_system_policy(mocker)
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mock_open = mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.os.path.isfile',
        side_effect=lambda path: path == '/etc/pki/tls/cert.pem',
    )
    mocker.patch('agent.ssl_helper.os.path.isdir', return_value=False)
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.load_verify_locations.assert_called_once_with('/etc/pki/tls/cert.pem', None)
    mock_context.load_default_certs.assert_not_called()
    opened = [call.args[0] for call in mock_open.call_args_list]
    assert 'system' not in opened
    assert 'foo: Loading system default CA certificates' in caplog.text


def test_ssl_helper_system_ca_uses_ssl_cert_env(mocker, monkeypatch):
    tls_config = _pkcs11_tls()
    _mock_pkcs11_system_policy(mocker)
    monkeypatch.setenv('SSL_CERT_FILE', 'env-ca.pem')
    monkeypatch.setenv('SSL_CERT_DIR', 'env-ca-dir')
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    isfile = mocker.patch('agent.ssl_helper.os.path.isfile')
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.load_verify_locations.assert_called_once_with('env-ca.pem', 'env-ca-dir')
    isfile.assert_not_called()


def test_ssl_helper_system_ca_ignores_configured_ca_path(mocker, monkeypatch):
    tls_config = _pkcs11_tls(ca_path='extra-ca-dir')
    _mock_pkcs11_system_policy(mocker)
    assert tls_config.ca_path is None
    monkeypatch.setenv('SSL_CERT_FILE', 'env-ca.pem')
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)

    agent.ssl_helper.get_ssl_context(tls_config, 'foo')

    mock_context.load_verify_locations.assert_called_once_with('env-ca.pem', None)


def test_ssl_helper_system_ca_ignores_freeze_ssl_cert_file(mocker, monkeypatch, tmp_path):
    tls_config = _pkcs11_tls()
    _mock_pkcs11_system_policy(mocker)
    agent_root = tmp_path / 'infrastructure-agent'
    freeze_share = agent_root / 'bin' / 'share'
    freeze_share.mkdir(parents=True)
    freeze_bundle = freeze_share / 'certs.pem'
    freeze_bundle.write_text('freeze-ca\n')
    freeze_dir = freeze_share / 'certs'
    freeze_dir.mkdir()
    host_bundle = tmp_path / 'host-ca.pem'
    host_bundle.write_text('host-ca\n')
    monkeypatch.setenv('SSL_CERT_FILE', str(freeze_bundle))
    monkeypatch.setenv('SSL_CERT_DIR', str(freeze_dir))
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.check_file_access')
    mocker.patch('agent.ssl_helper.get_agent_root', return_value=agent_root)
    monkeypatch.setattr(agent.ssl_helper.sys, 'frozen', True, raising=False)
    mocker.patch('agent.ssl_helper.HOST_CA_BUNDLE_FILES', (str(host_bundle),))
    mocker.patch('agent.ssl_helper.HOST_CA_BUNDLE_DIRS', ())
    mocker.patch('agent.ssl_helper.HOST_CA_ANCHOR_DIRS', ())
    mocker.patch(
        'agent.ssl_helper.os.path.isfile',
        side_effect=lambda path: path in (str(host_bundle), 'cert', 'key'),
    )
    mocker.patch('agent.ssl_helper.os.path.isdir', return_value=False)
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.load_verify_locations.assert_called_once_with(str(host_bundle), None)


def test_ssl_helper_system_ca_freeze_ssl_cert_resolve_error(mocker, monkeypatch):
    monkeypatch.setattr(agent.ssl_helper.sys, 'frozen', True, raising=False)
    mocker.patch('agent.ssl_helper.get_agent_root', side_effect=OSError('boom'))
    assert agent.ssl_helper._path_is_inside_agent_install('/etc/ssl/certs') is False


def test_ssl_helper_system_ca_uses_ssl_cert_file_only(mocker, monkeypatch):
    tls_config = _pkcs11_tls()
    _mock_pkcs11_system_policy(mocker)
    monkeypatch.setenv('SSL_CERT_FILE', 'env-ca.pem')
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.load_verify_locations.assert_called_once_with('env-ca.pem', None)


def test_ssl_helper_system_ca_uses_ssl_cert_dir_only(mocker, monkeypatch):
    tls_config = _pkcs11_tls()
    _mock_pkcs11_system_policy(mocker)
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    monkeypatch.setenv('SSL_CERT_DIR', 'env-ca-dir')
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.load_verify_locations.assert_called_once_with(None, 'env-ca-dir')


def test_ssl_helper_system_ca_ssl_cert_env_error(mocker, monkeypatch):
    tls_config = _pkcs11_tls()
    _mock_pkcs11_system_policy(mocker)
    monkeypatch.setenv('SSL_CERT_FILE', 'noaccess-ca.pem')
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='foo: '):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')


def test_ssl_helper_system_ca_wraps_unexpected_error(mocker):
    tls_config = _pkcs11_tls()
    _mock_pkcs11_system_policy(mocker)
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.load_system_ca_certs', side_effect=RuntimeError('boom'))
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='foo: boom'):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')


def test_ssl_helper_system_ca_loads_trust_anchors(mocker, monkeypatch, tmp_path):
    tls_config = _pkcs11_tls()
    _mock_pkcs11_system_policy(mocker)
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    bundle = tmp_path / 'bundle.pem'
    bundle.write_text('bundle\n')
    anchors = tmp_path / 'anchors'
    anchors.mkdir()
    (anchors / 'lab-mtls-ca.pem').write_text('anchor\n')
    (anchors / 'ignore.txt').write_text('nope\n')
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.check_file_access')
    mocker.patch('agent.ssl_helper.HOST_CA_BUNDLE_FILES', (str(bundle),))
    mocker.patch('agent.ssl_helper.HOST_CA_BUNDLE_DIRS', ())
    mocker.patch('agent.ssl_helper.HOST_CA_ANCHOR_DIRS', (str(anchors),))
    mocker.patch(
        'agent.ssl_helper.os.path.isfile',
        side_effect=lambda path: path in (str(bundle), str(anchors / 'lab-mtls-ca.pem'), 'cert', 'key'),
    )
    mocker.patch(
        'agent.ssl_helper.os.path.isdir',
        side_effect=lambda path: path == str(anchors),
    )
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    assert mock_context.load_verify_locations.call_args_list == [
        mocker.call(str(bundle), None),
        mocker.call(str(anchors / 'lab-mtls-ca.pem')),
    ]


def test_ssl_helper_system_ca_missing_host_store(mocker, monkeypatch):
    tls_config = _pkcs11_tls()
    _mock_pkcs11_system_policy(mocker)
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.path.isfile', return_value=False)
    mocker.patch('agent.ssl_helper.os.path.isdir', return_value=False)
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='could not find a host CA trust store'):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.load_default_certs.assert_not_called()


def test_ssl_helper_system_ca_uses_host_bundle_dir(mocker, monkeypatch):
    tls_config = _pkcs11_tls()
    _mock_pkcs11_system_policy(mocker)
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.HOST_CA_ANCHOR_DIRS', ())
    mocker.patch('agent.ssl_helper.HOST_CA_BUNDLE_FILES', ())
    mocker.patch('agent.ssl_helper.HOST_CA_BUNDLE_DIRS', ('/etc/ssl/certs',))
    mocker.patch('agent.ssl_helper.os.path.isfile', side_effect=lambda path: path in ('cert', 'key'))
    mocker.patch('agent.ssl_helper.os.path.isdir', side_effect=lambda path: path == '/etc/ssl/certs')
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.load_verify_locations.assert_called_once_with(None, '/etc/ssl/certs')


def test_ssl_helper_system_ca_skips_unusable_anchors(mocker, monkeypatch, tmp_path):
    tls_config = _pkcs11_tls()
    _mock_pkcs11_system_policy(mocker)
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    bundle = tmp_path / 'bundle.pem'
    bundle.write_text('bundle\n')
    blocked = tmp_path / 'blocked'
    blocked.mkdir()
    usable = tmp_path / 'usable'
    usable.mkdir()
    empty = usable / 'empty.pem'
    empty.write_text('')
    bad = usable / 'bad.pem'
    bad.write_text('bad\n')
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.HOST_CA_BUNDLE_FILES', (str(bundle),))
    mocker.patch('agent.ssl_helper.HOST_CA_BUNDLE_DIRS', ())
    mocker.patch('agent.ssl_helper.HOST_CA_ANCHOR_DIRS', (str(blocked), str(usable)))

    def isfile(path):
        return path in (str(bundle), str(empty), str(bad), 'cert', 'key')

    def listdir(path):
        if path == str(blocked):
            raise OSError('denied')
        if path == str(usable):
            return ['empty.pem', 'not-a-file.pem', 'bad.pem']
        return []

    def check_access(path):
        if path == str(bad):
            raise OSError('denied')

    mocker.patch('agent.ssl_helper.os.path.isfile', side_effect=isfile)
    mocker.patch('agent.ssl_helper.os.path.isdir', side_effect=lambda path: path in (str(blocked), str(usable)))
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=listdir)
    mocker.patch('agent.ssl_helper.check_file_access', side_effect=check_access)
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.load_verify_locations.assert_called_once_with(str(bundle), None)


def test_ssl_helper_system_ca_counts_as_configured(mocker):
    tls_config = TLSConfig(None, None, None, None, False, False, None, [])
    tls_config.ca_cert = 'system'
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    create_self_signed = mocker.patch(
        'agent.ssl_helper.create_self_signed_cert', return_value=('key', 'cert')
    )
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='TLS identity is not configured'):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    create_self_signed.assert_not_called()
    mock_context.load_verify_locations.assert_not_called()


def test_ssl_helper_system_ca_also_loads_mutated_ca_path(mocker, monkeypatch):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.ca_cert = 'system'
    tls_config.ca_path = 'extra-ca-dir'
    monkeypatch.setenv('SSL_CERT_FILE', 'env-ca.pem')
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)

    agent.ssl_helper.get_ssl_context(tls_config, 'foo')

    assert mock_context.load_verify_locations.call_args_list == [
        call('env-ca.pem', None),
        call(None, 'extra-ca-dir'),
    ]


def test_ssl_helper_cipher_suite_system_applies_host_ciphers(mocker, caplog):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.cipher_suite = 'system'
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.get_system_cipher_lists',
        return_value=('ECDH+AESGCM:!aNULL', 'TLS_AES_256_GCM_SHA384'),
    )
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.set_ciphers.assert_called_once_with('ECDH+AESGCM:!aNULL')
    mock_context.set_ciphersuites.assert_called_once_with('TLS_AES_256_GCM_SHA384')
    assert 'foo: Using host OpenSSL TLS ciphers' in caplog.text
    assert "foo: Host TLS 1.3 ciphersuites 'TLS_AES_256_GCM_SHA384'" in caplog.text


def test_ssl_helper_cipher_suite_system_skips_empty_tls13(mocker):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.cipher_suite = 'system'
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.get_system_cipher_lists',
        return_value=('ECDH+AESGCM:!aNULL', ''),
    )
    apply_tls13 = mocker.patch('agent.ssl_helper._apply_tls13_ciphersuites')
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.set_ciphers.assert_called_once_with('ECDH+AESGCM:!aNULL')
    apply_tls13.assert_not_called()
    mock_context.set_ciphersuites.assert_not_called()


def test_ssl_helper_cipher_suite_system_skips_empty_tls12(mocker, caplog):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.cipher_suite = 'system'
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.get_system_cipher_lists',
        return_value=('', 'TLS_AES_256_GCM_SHA384'),
    )
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.set_ciphers.assert_not_called()
    mock_context.set_ciphersuites.assert_called_once_with('TLS_AES_256_GCM_SHA384')
    assert mock_context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert "foo: Host TLS 1.3 ciphersuites 'TLS_AES_256_GCM_SHA384'" in caplog.text
    assert 'Host TLS 1.2 cipher string' not in caplog.text
    assert 'No host TLS 1.2 ciphers; requiring TLS 1.3' in caplog.text


def test_ssl_helper_cipher_suite_system_applies_tls13_via_openssl(mocker, caplog):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.cipher_suite = 'system'
    mock_context = mocker.MagicMock(spec=[
        'options', 'verify_mode', 'check_hostname', 'load_default_certs',
        'load_cert_chain', 'set_ciphers',
    ])
    mock_context.options = 0
    openssl = mocker.Mock()
    openssl.ssl.SSL_CTX_set_ciphersuites.return_value = 1
    openssl.errors.return_value = ''
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.get_system_cipher_lists',
        return_value=('ECDH+AESGCM:!aNULL', 'TLS_AES_256_GCM_SHA384'),
    )
    mocker.patch('agent.ssl_helper.OpenSSLLibraries', return_value=openssl)
    mocker.patch('agent.ssl_helper.get_ssl_ctx_pointer', return_value=4321)
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.set_ciphers.assert_called_once_with('ECDH+AESGCM:!aNULL')
    openssl.ssl.SSL_CTX_set_ciphersuites.assert_called_once_with(
        4321, b'TLS_AES_256_GCM_SHA384'
    )
    assert "foo: Host TLS 1.3 ciphersuites 'TLS_AES_256_GCM_SHA384'" in caplog.text


def test_ssl_helper_apply_tls13_ciphersuites_openssl_failure(mocker):
    mock_context = mocker.MagicMock(spec=['options'])
    openssl = mocker.Mock()
    openssl.ssl.SSL_CTX_set_ciphersuites.return_value = 0
    openssl.errors.return_value = 'no ciphersuite match'
    mocker.patch('agent.ssl_helper.OpenSSLLibraries', return_value=openssl)
    mocker.patch('agent.ssl_helper.get_ssl_ctx_pointer', return_value=4321)
    with pytest.raises(
        agent.ssl_helper.AgentSSLError,
        match='apply host TLS 1.3 ciphersuites: no ciphersuite match',
    ):
        agent.ssl_helper._apply_tls13_ciphersuites(
            mock_context, 'TLS_AES_256_GCM_SHA384'
        )


def test_ssl_helper_apply_tls13_ciphersuites_live_context():
    if sys.platform == 'win32':
        pytest.skip('freeze OpenSSL attach is Linux-only')
    if sys.implementation.name != 'cpython':
        pytest.skip('CPython only')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    suites = 'TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256'
    try:
        agent.ssl_helper._apply_tls13_ciphersuites(context, suites)
    except agent.ssl_helper.AgentSSLError as ex:
        pytest.skip(str(ex))
    names = [cipher['name'] for cipher in context.get_ciphers() if cipher['protocol'] == 'TLSv1.3']
    assert names == suites.split(':')
    assert 'TLS_CHACHA20_POLY1305_SHA256' not in names


def test_ssl_helper_cipher_suite_system_propagates_agent_error(mocker):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.cipher_suite = 'system'
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.get_system_cipher_lists',
        side_effect=agent.ssl_helper.AgentSSLError('openssl not found'),
    )
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='openssl not found'):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.set_ciphers.assert_not_called()


def test_ssl_helper_cipher_suite_system_wraps_set_ciphers_failure(mocker):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.cipher_suite = 'system'
    mock_context = mocker.Mock()
    mock_context.options = 0
    mock_context.set_ciphers.side_effect = ssl.SSLError('no cipher match')
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.get_system_cipher_lists',
        return_value=('ECDH+AESGCM:!aNULL', 'TLS_AES_256_GCM_SHA384'),
    )
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='failed to apply host TLS ciphers'):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')


def test_ssl_helper_cipher_suite_system_empty_tls12_clamps_host_min_to_tls13(mocker):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.cipher_suite = 'system'
    tls_config.context_options = 'system'
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.get_system_cipher_lists',
        return_value=('', 'TLS_AES_256_GCM_SHA384'),
    )
    mocker.patch(
        'agent.ssl_helper.get_system_tls_versions',
        return_value=(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    )
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    mock_context.set_ciphers.assert_not_called()
    assert mock_context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert mock_context.maximum_version == ssl.TLSVersion.TLSv1_3


def test_ssl_helper_cipher_suite_system_empty_tls12_fails_without_tls13(mocker):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.cipher_suite = 'system'
    tls_config.context_options = 'system'
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.get_system_cipher_lists',
        return_value=('', 'TLS_AES_256_GCM_SHA384'),
    )
    mocker.patch(
        'agent.ssl_helper.get_system_tls_versions',
        return_value=(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    )
    with pytest.raises(
        agent.ssl_helper.AgentSSLError,
        match='host TLS 1.2 cipher list is empty and TLS 1.3 is not enabled',
    ):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')


def test_ssl_helper_context_options_system_applies_host_versions(mocker, caplog):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.context_options = 'system'
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.get_system_tls_versions',
        return_value=(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    )
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    assert mock_context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert mock_context.maximum_version == ssl.TLSVersion.TLSv1_3
    assert 'foo: Using host TLS protocol versions' in caplog.text
    assert 'foo: Host TLS versions TLSv1_2-TLSv1_3' in caplog.text


def test_ssl_helper_context_options_system_propagates_agent_error(mocker):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.context_options = 'system'
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.get_system_tls_versions',
        side_effect=agent.ssl_helper.AgentSSLError('could not determine host TLS versions'),
    )
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='could not determine host TLS versions'):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')


def test_ssl_helper_context_options_system_wraps_apply_failure(mocker):
    tls_config = TLSConfig(None, None, 'cert', 'key', False, False, None, [])
    tls_config.context_options = 'system'
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch(
        'agent.ssl_helper.get_system_tls_versions',
        side_effect=RuntimeError('boom'),
    )
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='failed to apply host TLS versions'):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')


def test_get_system_tls_versions_from_crypto_policy(tmp_path, mocker):
    policy = tmp_path / 'opensslcnf.config'
    policy.write_text('MinProtocol = TLSv1.2\nMaxProtocol = TLSv1.3\n')
    mocker.patch('agent.ssl_helper.HOST_CRYPTO_POLICY_OPENSSLCNF', policy)
    mocker.patch('agent.ssl_helper.subprocess.run', side_effect=AssertionError('openssl should not run'))
    assert agent.ssl_helper.get_system_tls_versions() == (
        ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3,
    )


def test_parse_crypto_policy_repeated_protocol_ignores_dtls_values():
    text = (
        'MinProtocol = TLSv1.2\n'
        'MinProtocol = DTLSv1.2\n'
        'MaxProtocol = TLSv1.3\n'
        'MaxProtocol = DTLSv1.2\n'
    )
    assert agent.ssl_helper._parse_crypto_policy_opensslcnf(text) == (
        ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3,
    )


def test_parse_crypto_policy_dtls_only_returns_none():
    assert agent.ssl_helper._parse_crypto_policy_opensslcnf(
        'MinProtocol = DTLSv1.2\nMaxProtocol = DTLSv1.2\n'
    ) is None


def test_parse_crypto_policy_prefixed_keys_ignore_dtls():
    text = (
        'TLS.MinProtocol = TLSv1.2\n'
        'TLS.MaxProtocol = TLSv1.3\n'
        'DTLS.MinProtocol = DTLSv1.2\n'
        'DTLS.MaxProtocol = DTLSv1.2\n'
    )
    assert agent.ssl_helper._parse_crypto_policy_opensslcnf(text) == (
        ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3,
    )


def test_parse_crypto_policy_min_only_defaults_max():
    assert agent.ssl_helper._parse_crypto_policy_opensslcnf('MinProtocol = TLSv1.2\n') == (
        ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3,
    )


def test_parse_crypto_policy_empty():
    assert agent.ssl_helper._parse_crypto_policy_opensslcnf('# comment\nCipherString = DEFAULT\n') is None


def test_parse_crypto_policy_unknown_protocol():
    with pytest.raises(agent.ssl_helper.AgentSSLError, match="unsupported host TLS protocol 'TLSv1.4'"):
        agent.ssl_helper._parse_crypto_policy_opensslcnf('MinProtocol = TLSv1.4\n')


def test_parse_crypto_policy_min_greater_than_max():
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='is greater than MaxProtocol'):
        agent.ssl_helper._parse_crypto_policy_opensslcnf(
            'MinProtocol = TLSv1.3\nMaxProtocol = TLSv1.2\n'
        )


def test_get_system_tls_versions_falls_back_to_openssl(tmp_path, mocker):
    mocker.patch('agent.ssl_helper.HOST_CRYPTO_POLICY_OPENSSLCNF', tmp_path / 'missing')

    def run(cmd, **_kwargs):
        if '-tls1_3' in cmd:
            return _openssl_completed(_OPENSSL_TLS13_STDOUT)
        if '-tls1_2' in cmd:
            return _openssl_completed(_OPENSSL_TLS12_STDOUT)
        return _openssl_completed('', returncode=1, stderr='no ciphers')

    mocker.patch('agent.ssl_helper.subprocess.run', side_effect=run)
    assert agent.ssl_helper.get_system_tls_versions() == (
        ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3,
    )


def test_get_system_tls_versions_unreadable_policy_falls_back(mocker, caplog):
    policy = mocker.Mock()
    policy.read_text.side_effect = OSError('denied')
    mocker.patch('agent.ssl_helper.HOST_CRYPTO_POLICY_OPENSSLCNF', policy)

    def run(cmd, **_kwargs):
        if '-tls1_2' in cmd or '-tls1_3' in cmd:
            return _openssl_completed(_OPENSSL_TLS12_STDOUT if '-tls1_2' in cmd else _OPENSSL_TLS13_STDOUT)
        return _openssl_completed('', returncode=1)

    mocker.patch('agent.ssl_helper.subprocess.run', side_effect=run)
    versions = agent.ssl_helper.get_system_tls_versions()
    assert versions == (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)
    assert 'Host crypto-policies OpenSSL backend unreadable' in caplog.text


def test_get_system_tls_versions_missing_sources(tmp_path, mocker):
    mocker.patch('agent.ssl_helper.HOST_CRYPTO_POLICY_OPENSSLCNF', tmp_path / 'missing')
    mocker.patch(
        'agent.ssl_helper.subprocess.run',
        return_value=_openssl_completed('', returncode=0),
    )
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='could not determine host TLS versions'):
        agent.ssl_helper.get_system_tls_versions()


def _openssl_completed(stdout='', returncode=0, stderr=''):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


_OPENSSL_TLS12_STDOUT = 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256\n'
_OPENSSL_TLS13_STDOUT = (
    'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256\n'
)


def test_get_system_cipher_lists_from_openssl(mocker):
    def run(cmd, **_kwargs):
        assert cmd[0] == '/usr/bin/openssl'
        if '-tls1_3' in cmd:
            return _openssl_completed(_OPENSSL_TLS13_STDOUT)
        return _openssl_completed(_OPENSSL_TLS12_STDOUT)

    mocker.patch('agent.ssl_helper.subprocess.run', side_effect=run)
    tls12, tls13 = agent.ssl_helper.get_system_cipher_lists()
    assert tls12 == (
        'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256'
        ':!aNULL:!MD5:!DSS:!RC4:!3DES'
    )
    assert tls13 == 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256'


def test_get_system_cipher_lists_falls_back_without_policy(mocker):
    def run(cmd, **_kwargs):
        if '-policy' in cmd:
            return _openssl_completed('ciphers: Unknown option: -policy\n', returncode=1)
        if '-tls1_3' in cmd:
            return _openssl_completed(_OPENSSL_TLS13_STDOUT)
        return _openssl_completed(_OPENSSL_TLS12_STDOUT)

    mocker.patch('agent.ssl_helper.subprocess.run', side_effect=run)
    tls12, tls13 = agent.ssl_helper.get_system_cipher_lists()
    assert tls12.startswith('ECDHE-RSA-AES256-GCM-SHA384:')
    assert 'TLS_AES_256_GCM_SHA384' in tls13


def test_get_system_cipher_lists_missing_openssl(mocker):
    mocker.patch('agent.ssl_helper.subprocess.run', side_effect=FileNotFoundError('openssl'))
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='/usr/bin/openssl not found'):
        agent.ssl_helper.get_system_cipher_lists()


def test_get_system_cipher_lists_retries_after_timeout(mocker):
    calls = []

    def run(cmd, **_kwargs):
        calls.append(cmd)
        if '-policy' in cmd:
            raise subprocess.TimeoutExpired(cmd, agent.ssl_helper.OPENSSL_CIPHERS_TIMEOUT)
        if '-tls1_3' in cmd:
            return _openssl_completed(_OPENSSL_TLS13_STDOUT)
        return _openssl_completed(_OPENSSL_TLS12_STDOUT)

    mocker.patch('agent.ssl_helper.subprocess.run', side_effect=run)
    tls12, tls13 = agent.ssl_helper.get_system_cipher_lists()
    assert tls12.startswith('ECDHE-RSA-AES256-GCM-SHA384:')
    assert tls13.startswith('TLS_AES_256_GCM_SHA384')
    assert any('-policy' in cmd for cmd in calls)


def test_get_system_cipher_lists_oserror_every_attempt(mocker, caplog):
    mocker.patch('agent.ssl_helper.subprocess.run', side_effect=OSError('exec format error'))
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='could not determine host TLS cipher list'):
        agent.ssl_helper.get_system_cipher_lists()
    assert 'Host openssl cipher query failed' in caplog.text


@pytest.mark.parametrize(
    'stdout, expected', [
        pytest.param('', [], id="empty"),
        pytest.param('\n   \n', [], id="blank_lines"),
        pytest.param('ECDHE-RSA-AES256-GCM-SHA384\n', ['ECDHE-RSA-AES256-GCM-SHA384'], id="bare_name"),
        pytest.param(
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 - ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2\n',
            ['ECDHE-RSA-AES256-GCM-SHA384'],
            id="stdname_line",
        ),
        pytest.param('some free text line\n', [], id="spaced_text_ignored"),
    ]
)
def test_parse_openssl_cipher_output(stdout, expected):
    assert agent.ssl_helper._parse_openssl_cipher_output(stdout) == expected


def test_system_tls12_cipher_string_keeps_chacha_and_exclusions():
    assert agent.ssl_helper._system_tls12_cipher_string(
        ['ECDHE-RSA-CHACHA20-POLY1305']
    ) == 'ECDHE-RSA-CHACHA20-POLY1305:!aNULL:!MD5:!DSS:!RC4:!3DES'


def test_system_tls12_cipher_string_skips_tls13_names():
    assert agent.ssl_helper._system_tls12_cipher_string(['TLS_AES_256_GCM_SHA384']) == ''


def test_get_system_cipher_lists_empty_output(mocker):
    mocker.patch(
        'agent.ssl_helper.subprocess.run',
        return_value=_openssl_completed('', returncode=0),
    )
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='could not determine host TLS cipher list'):
        agent.ssl_helper.get_system_cipher_lists()


def test_get_system_cipher_lists_tls13_only(mocker):
    def run(cmd, **_kwargs):
        if '-tls1_3' in cmd:
            return _openssl_completed(_OPENSSL_TLS13_STDOUT)
        return _openssl_completed('', returncode=0)

    mocker.patch('agent.ssl_helper.subprocess.run', side_effect=run)
    tls12, tls13 = agent.ssl_helper.get_system_cipher_lists()
    assert tls12 == ''
    assert tls13 == 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256'


def test_ssl_helper_ssl_debug_message_callback(mocker, caplog):
    mock_version = mocker.Mock()
    mock_content = mocker.Mock()
    mock_message = mocker.Mock()
    mock_version.name = 'ver'
    mock_content.name = 'cnt'
    mock_message.name = 'msg'
    agent.ssl_helper.ssl_debug_message_callback(
        None, 'dir', mock_version, mock_content, mock_message, None)
    assert '| tls message dir   | ver     | msg                  | cnt                 \n' in caplog.text


def _make_self_signed_key_cert():
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private_key = rsa.generate_private_key(65537, 2048, backend=default_backend())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test.pem')])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(private_key, hashes.SHA256(), backend=default_backend())
    )
    return private_key, cert


def _write_pem_identity(tmp_path, passphrase='secret'):
    from cryptography.hazmat.primitives import serialization

    private_key, cert = _make_self_signed_key_cert()
    key_path = tmp_path / 'key.pem'
    cert_path = tmp_path / 'cert.pem'
    encryption_algorithm = serialization.NoEncryption()
    if passphrase is not None:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def test_ssl_helper_get_ssl_context_encrypted_pem_key(tmp_path, mocker, caplog):
    cert_path, key_path = _write_pem_identity(tmp_path, passphrase='secret')
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)

    tls_config = TLSConfig(
        cert_file=str(cert_path),
        key_file=str(key_path),
        key_passphrase='secret',
        check_client_cert=False,
    )
    agent.ssl_helper.get_ssl_context(tls_config, 'foo')

    mock_context.load_cert_chain.assert_called_once_with(
        str(cert_path), str(key_path), password='secret'
    )
    assert 'foo: Using configured TLS cert_file and key_file' in caplog.text


def test_ssl_helper_get_ssl_context_encrypted_pem_key_loads(tmp_path):
    cert_path, key_path = _write_pem_identity(tmp_path, passphrase='secret')
    tls_config = TLSConfig(
        cert_file=str(cert_path),
        key_file=str(key_path),
        key_passphrase='secret',
        check_client_cert=False,
    )
    context = agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    assert isinstance(context, ssl.SSLContext)


def test_ssl_helper_get_ssl_context_encrypted_pem_key_bad_passphrase(tmp_path):
    cert_path, key_path = _write_pem_identity(tmp_path, passphrase='secret')
    tls_config = TLSConfig(
        cert_file=str(cert_path),
        key_file=str(key_path),
        key_passphrase='wrong',
        check_client_cert=False,
    )
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='TLS key missing or does not match'):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')


@pytest.mark.parametrize('key_passphrase', [None, ''], ids=['omitted', 'empty'])
def test_ssl_helper_get_ssl_context_encrypted_pem_key_missing_passphrase(tmp_path, key_passphrase):
    cert_path, key_path = _write_pem_identity(tmp_path, passphrase='secret')
    tls_config = TLSConfig(
        cert_file=str(cert_path),
        key_file=str(key_path),
        key_passphrase=key_passphrase,
        check_client_cert=False,
    )
    with pytest.raises(
        agent.ssl_helper.AgentSSLError,
        match='encrypted TLS private key requires key_passphrase',
    ):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')


def test_ssl_helper_get_ssl_context_unencrypted_pem_key_without_passphrase(tmp_path):
    cert_path, key_path = _write_pem_identity(tmp_path, passphrase=None)
    tls_config = TLSConfig(
        cert_file=str(cert_path),
        key_file=str(key_path),
        check_client_cert=False,
    )
    context = agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    assert isinstance(context, ssl.SSLContext)


def test_ssl_helper_create_self_signed_cert(tmp_path):
    output_dir = tmp_path / 'var'
    key_file, cert_file = agent.ssl_helper.create_self_signed_cert('server', output_dir)
    assert output_dir.is_dir()
    assert (os.stat(key_file).st_mode & 0o777) == 0o600
    assert (os.stat(cert_file).st_mode & 0o777) == 0o644


def test_ssl_helper_create_self_signed_cert_exists(tmp_path):
    config_name = 'server'
    base_name = f'{socket.gethostname()}-{config_name}'

    output_path = tmp_path / 'var'
    output_path.mkdir(parents=True)
    orig_key_path = (output_path / base_name).with_suffix('.key')
    orig_cert_path = (output_path / base_name).with_suffix('.crt')
    orig_key_path.touch()
    orig_cert_path.touch()
    key_file, cert_file = agent.ssl_helper.create_self_signed_cert(config_name, output_path)
    assert key_file == orig_key_path
    assert cert_file == orig_cert_path
    assert os.path.getsize(key_file) == 0
    assert os.path.getsize(cert_file) == 0


def test_ssl_helper_ephemeral_pin_writes_tempfile(tmp_path, mocker):
    mocker.patch('agent.pkcs11.get_agent_root', return_value=tmp_path)
    pin_files = agent.pkcs11._EphemeralPinFiles()
    var_dir = tmp_path / 'var'
    try:
        path = pin_files.write('agent-pkcs11-pin', b'test-pin')
        assert path.startswith(str(var_dir))
        assert os.path.isfile(path)
        assert oct(os.stat(path).st_mode & 0o777) == '0o600'
        assert open(path, 'rb').read() == b'test-pin'
    finally:
        pin_files.close()
    assert not os.path.exists(path)


def test_ssl_helper_get_ssl_context_pkcs11(mocker, caplog):
    tls_config = _pkcs11_tls(check_client_cert=False)
    mock_context = mocker.Mock()
    mock_context.options = 0
    mock_load = mocker.patch('agent.pkcs11.load_pkcs11_into_context')
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.load_system_ca_certs')
    mocker.patch(
        'agent.ssl_helper.get_system_cipher_lists',
        return_value=('ECDH+AESGCM:!aNULL', ''),
    )
    mocker.patch(
        'agent.ssl_helper.get_system_tls_versions',
        return_value=(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    )

    result = agent.ssl_helper.get_ssl_context(tls_config, 'foo')

    assert result == mock_context
    mock_load.assert_called_once_with(mock_context, tls_config)
    mock_context.load_cert_chain.assert_not_called()
    assert 'foo: Using configured TLS PKCS#11 identity' in caplog.text


def test_ssl_helper_load_pkcs11_windows(mocker):
    tls_config = TLSConfig(
        cert_file='cert.pem',
        connector='pkcs11',
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key',
    )
    mocker.patch('agent.pkcs11.sys.platform', 'win32')
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='only supported on Linux'):
        agent.pkcs11.load_pkcs11_into_context(mocker.Mock(), tls_config)


def test_ssl_helper_pkcs11_runtime_rejects_untested_python(mocker):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    mocker.patch('agent.pkcs11.sys.version_info', (3, 13, 0))
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='CPython 3.14'):
        agent.pkcs11.require_pkcs11_runtime(context)


def test_ssl_helper_pkcs11_runtime_rejects_free_threaded(mocker):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    mocker.patch('agent.pkcs11.sys._is_gil_enabled', lambda: False)
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='free-threaded'):
        agent.pkcs11.require_pkcs11_runtime(context)


@pytest.mark.parametrize('error, expected', [
    pytest.param(agent.ssl_helper.AgentSSLError('engine unavailable'), 'engine unavailable', id="agent_error"),
    pytest.param(ValueError('token missing'), 'foo: token missing', id="other_error"),
])
def test_ssl_helper_get_ssl_context_pkcs11_errors(error, expected, mocker):
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.pkcs11.load_pkcs11_into_context', side_effect=error)
    mocker.patch('agent.ssl_helper.load_system_ca_certs')
    mocker.patch(
        'agent.ssl_helper.get_system_cipher_lists',
        return_value=('ECDH+AESGCM:!aNULL', ''),
    )
    mocker.patch(
        'agent.ssl_helper.get_system_tls_versions',
        return_value=(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    )

    tls_config = _pkcs11_tls(check_client_cert=False)
    with pytest.raises(agent.ssl_helper.AgentSSLError, match=expected):
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')


@pytest.mark.parametrize('mapped', [(None, None), (None, '/lib/libssl.so.3'), ('/lib/libcrypto.so.3', None)])
def test_ssl_helper_openssl_libraries_not_found(mapped, mocker):
    mocker.patch('agent.ssl_helper._packaged_openssl_libraries', return_value=mapped)
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='Packaged OpenSSL libraries could not be found'):
        agent.ssl_helper.OpenSSLLibraries()


def _install_packaged_openssl(lib_dir, *, hashed=True, major=3):
    lib_dir.mkdir(parents=True, exist_ok=True)
    suffix = f'-ed7c3029.so.{major}' if hashed else f'.so.{major}'
    crypto = lib_dir / f'libcrypto{suffix}'
    ssl_lib = lib_dir / f'libssl{suffix}'
    crypto.write_bytes(b'')
    ssl_lib.write_bytes(b'')
    return crypto, ssl_lib


def _patch_packaged_openssl_layout(mocker, executable, agent_root, *, frozen=True, base_prefix=None):
    mocker.patch('agent.ssl_helper.sys.executable', executable)
    mocker.patch('agent.ssl_helper.get_agent_root', return_value=agent_root)
    mocker.patch('agent.ssl_helper.ssl.OPENSSL_VERSION_INFO', (3, 5, 0, 8, 0))
    mocker.patch('agent.ssl_helper.sys.frozen', frozen, create=True)
    if base_prefix is not None:
        mocker.patch('agent.ssl_helper.sys.base_prefix', base_prefix)
    # Path selection tests treat every candidate as already mapped. Attach
    # fallback is covered by tests that replace this stub.
    mocker.patch(
        'agent.ssl_helper.OpenSSLLibraries._load_mapped_library',
        return_value=mocker.Mock(),
    )


def test_packaged_openssl_libraries_from_executable_lib(tmp_path, mocker):
    crypto, ssl_lib = _install_packaged_openssl(tmp_path / 'bin' / 'lib')
    _patch_packaged_openssl_layout(
        mocker, str(tmp_path / 'bin' / 'infrastructure-agent'), tmp_path,
    )
    assert agent.ssl_helper._packaged_openssl_libraries() == (str(crypto), str(ssl_lib))


def test_packaged_openssl_libraries_from_agent_root(tmp_path, mocker):
    crypto, ssl_lib = _install_packaged_openssl(tmp_path / 'bin' / 'lib')
    _patch_packaged_openssl_layout(
        mocker, str(tmp_path / 'elsewhere' / 'python'), tmp_path,
    )
    assert agent.ssl_helper._packaged_openssl_libraries() == (str(crypto), str(ssl_lib))


def test_packaged_openssl_libraries_prefers_hashed_soname(tmp_path, mocker):
    lib = tmp_path / 'bin' / 'lib'
    hashed, _ = _install_packaged_openssl(lib)
    plain, _ = _install_packaged_openssl(lib, hashed=False)
    _patch_packaged_openssl_layout(
        mocker, str(tmp_path / 'bin' / 'infrastructure-agent'), tmp_path,
    )
    crypto_path, ssl_path = agent.ssl_helper._packaged_openssl_libraries()
    assert crypto_path == str(hashed)
    assert ssl_path.endswith('libssl-ed7c3029.so.3')
    assert crypto_path != str(plain)


def test_packaged_openssl_libraries_ignores_wrong_major(tmp_path, mocker):
    _install_packaged_openssl(tmp_path / 'bin' / 'lib', hashed=False, major=1)
    _patch_packaged_openssl_layout(
        mocker, str(tmp_path / 'bin' / 'infrastructure-agent'), tmp_path,
    )
    assert agent.ssl_helper._packaged_openssl_libraries() == (None, None)


def test_packaged_openssl_libraries_missing(tmp_path, mocker):
    _patch_packaged_openssl_layout(
        mocker, str(tmp_path / 'bin' / 'infrastructure-agent'), tmp_path,
    )
    assert agent.ssl_helper._packaged_openssl_libraries() == (None, None)


def test_packaged_openssl_lib_dirs_source_without_prefix(tmp_path, mocker):
    _patch_packaged_openssl_layout(
        mocker,
        str(tmp_path / 'venv' / 'bin' / 'python'),
        tmp_path / 'src',
        frozen=False,
        base_prefix='',
    )
    directories = agent.ssl_helper._packaged_openssl_lib_dirs()
    assert directories == (
        str(tmp_path / 'venv' / 'bin' / 'lib'),
        str(tmp_path / 'src' / 'bin' / 'lib'),
        str(tmp_path / 'src' / 'lib'),
    )


def test_packaged_openssl_libraries_from_interpreter_prefix(tmp_path, mocker):
    crypto, ssl_lib = _install_packaged_openssl(tmp_path / 'python' / 'lib', hashed=False)
    _patch_packaged_openssl_layout(
        mocker,
        str(tmp_path / 'venv' / 'bin' / 'python'),
        tmp_path / 'src',
        frozen=False,
        base_prefix=str(tmp_path / 'python'),
    )
    assert agent.ssl_helper._packaged_openssl_libraries() == (str(crypto), str(ssl_lib))


def test_packaged_openssl_libraries_prefix_does_not_override_freeze(tmp_path, mocker):
    freeze_crypto, freeze_ssl = _install_packaged_openssl(tmp_path / 'bin' / 'lib')
    _install_packaged_openssl(tmp_path / 'python' / 'lib', hashed=False)
    _patch_packaged_openssl_layout(
        mocker,
        str(tmp_path / 'elsewhere' / 'python'),
        tmp_path,
        frozen=False,
        base_prefix=str(tmp_path / 'python'),
    )
    assert agent.ssl_helper._packaged_openssl_libraries() == (str(freeze_crypto), str(freeze_ssl))


def test_packaged_openssl_libraries_frozen_ignores_interpreter_prefix(tmp_path, mocker):
    _install_packaged_openssl(tmp_path / 'python' / 'lib', hashed=False)
    _patch_packaged_openssl_layout(
        mocker,
        str(tmp_path / 'bin' / 'infrastructure-agent'),
        tmp_path,
        frozen=True,
        base_prefix=str(tmp_path / 'python'),
    )
    assert agent.ssl_helper._packaged_openssl_libraries() == (None, None)


def test_packaged_openssl_libraries_skip_directory_missing_one_library(tmp_path, mocker):
    partial = tmp_path / 'bin' / 'lib'
    partial.mkdir(parents=True)
    (partial / 'libcrypto.so.3').write_bytes(b'')
    crypto, ssl_lib = _install_packaged_openssl(tmp_path / 'lib', hashed=False)
    _patch_packaged_openssl_layout(
        mocker, str(tmp_path / 'bin' / 'infrastructure-agent'), tmp_path,
    )
    assert agent.ssl_helper._packaged_openssl_libraries() == (str(crypto), str(ssl_lib))


def test_packaged_openssl_libraries_uses_loaded_soname_when_hash_is_not_mapped(tmp_path, mocker):
    lib = tmp_path / 'bin' / 'lib'
    _install_packaged_openssl(lib)
    plain_crypto, plain_ssl = _install_packaged_openssl(lib, hashed=False)
    _patch_packaged_openssl_layout(
        mocker, str(tmp_path / 'bin' / 'infrastructure-agent'), tmp_path,
    )

    def load(name):
        if '-ed7c3029.' in name:
            raise agent.ssl_helper.AgentSSLError(
                f"OpenSSL library '{name}' is not already loaded by this process"
            )
        return mocker.Mock()

    mocker.patch('agent.ssl_helper.OpenSSLLibraries._load_mapped_library', side_effect=load)
    assert agent.ssl_helper._packaged_openssl_libraries() == (str(plain_crypto), str(plain_ssl))


def test_packaged_openssl_libraries_none_when_present_files_are_not_mapped(tmp_path, mocker):
    _install_packaged_openssl(tmp_path / 'bin' / 'lib', hashed=False)
    _patch_packaged_openssl_layout(
        mocker, str(tmp_path / 'bin' / 'infrastructure-agent'), tmp_path,
    )
    mocker.patch(
        'agent.ssl_helper.OpenSSLLibraries._load_mapped_library',
        side_effect=agent.ssl_helper.AgentSSLError(
            "OpenSSL library 'libcrypto.so.3' is not already loaded by this process"
        ),
    )
    assert agent.ssl_helper._packaged_openssl_libraries() == (None, None)


def test_mapped_library_uses_realpath(tmp_path, mocker):
    real = tmp_path / 'libcrypto-4a5569f9.so.3'
    real.write_bytes(b'')
    link = tmp_path / 'libcrypto.so.3'
    link.symlink_to(real.name)

    def load(name):
        if name == str(real):
            return mocker.Mock()
        raise agent.ssl_helper.AgentSSLError(
            f"OpenSSL library '{name}' is not already loaded by this process"
        )

    mocker.patch('agent.ssl_helper.OpenSSLLibraries._load_mapped_library', side_effect=load)
    assert agent.ssl_helper._mapped_library([link]) == str(real)


def test_mapped_library_reraises_when_noload_is_unavailable(tmp_path, mocker):
    lib = tmp_path / 'libcrypto.so.3'
    lib.write_bytes(b'')
    mocker.patch(
        'agent.ssl_helper.OpenSSLLibraries._load_mapped_library',
        side_effect=agent.ssl_helper.AgentSSLError(
            "OpenSSL cannot be attached without RTLD_NOLOAD"
        ),
    )
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='RTLD_NOLOAD'):
        agent.ssl_helper._mapped_library([lib])


def test_packaged_openssl_libraries_from_interpreter_lib64(tmp_path, mocker):
    crypto, ssl_lib = _install_packaged_openssl(tmp_path / 'python' / 'lib64', hashed=False)
    _patch_packaged_openssl_layout(
        mocker,
        str(tmp_path / 'venv' / 'bin' / 'python'),
        tmp_path / 'src',
        frozen=False,
        base_prefix=str(tmp_path / 'python'),
    )
    assert agent.ssl_helper._packaged_openssl_libraries() == (str(crypto), str(ssl_lib))


def test_ssl_helper_load_mapped_library(mocker):
    library = mocker.Mock()
    mocker.patch.object(agent.ssl_helper.os, 'RTLD_NOLOAD', 4, create=True)
    mock_cdll = mocker.patch('agent.ssl_helper.ctypes.CDLL', return_value=library)

    assert agent.ssl_helper.OpenSSLLibraries._load_mapped_library('libtest.so') is library
    mock_cdll.assert_called_once()
    assert mock_cdll.call_args[1]['mode'] & 4


def test_ssl_helper_load_mapped_library_requires_already_loaded(mocker):
    mocker.patch.object(agent.ssl_helper.os, 'RTLD_NOLOAD', 4, create=True)
    mocker.patch('agent.ssl_helper.ctypes.CDLL', side_effect=OSError('not mapped'))
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='not already loaded'):
        agent.ssl_helper.OpenSSLLibraries._load_mapped_library('libtest.so')


def test_ssl_helper_load_mapped_library_requires_noload(mocker):
    mocker.patch.object(agent.ssl_helper.os, 'RTLD_NOLOAD', 0, create=True)
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='RTLD_NOLOAD'):
        agent.ssl_helper.OpenSSLLibraries._load_mapped_library('libtest.so')


def test_ssl_helper_load_mapped_library_requires_rtld_now(mocker):
    mocker.patch.object(agent.ssl_helper.os, 'RTLD_NOLOAD', 4, create=True)
    mocker.patch.object(agent.ssl_helper.os, 'RTLD_NOW', 0, create=True)
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='RTLD_NOW'):
        agent.ssl_helper.OpenSSLLibraries._load_mapped_library('libtest.so')


def test_ssl_helper_openssl_libraries_declare_required_api(mocker):
    mocker.patch(
        'agent.ssl_helper._packaged_openssl_libraries',
        return_value=('/lib/libcrypto-hash.so.3', '/lib/libssl-hash.so.3'),
    )
    crypto = mocker.Mock()
    ssl_library = mocker.Mock()
    mock_cdll = mocker.patch('agent.ssl_helper.ctypes.CDLL', side_effect=[crypto, ssl_library])

    openssl = agent.ssl_helper.OpenSSLLibraries()

    assert openssl.crypto is crypto
    assert openssl.ssl is ssl_library
    assert mock_cdll.call_args_list[0][0][0] == '/lib/libcrypto-hash.so.3'
    assert mock_cdll.call_args_list[1][0][0] == '/lib/libssl-hash.so.3'

    assert openssl.crypto is crypto
    assert openssl.ssl is ssl_library
    assert crypto.OSSL_PROVIDER_load.argtypes == [ctypes.c_void_p, ctypes.c_char_p]
    assert crypto.OSSL_PROVIDER_load.restype == ctypes.c_void_p
    assert ssl_library.SSL_CTX_use_PrivateKey.restype == ctypes.c_int
    assert ssl_library.SSL_CTX_set_ciphersuites.argtypes == [ctypes.c_void_p, ctypes.c_char_p]
    assert ssl_library.SSL_CTX_set_ciphersuites.restype == ctypes.c_int


def test_ssl_helper_declare_missing_openssl_api(mocker):
    with pytest.raises(agent.ssl_helper.AgentSSLError, match="required PKCS#11 API 'OSSL_PROVIDER_load'"):
        agent.ssl_helper.OpenSSLLibraries._declare(mocker.Mock(spec=[]), 'OSSL_PROVIDER_load', [], None)


def test_ssl_helper_openssl_errors_drains_queue(mocker):
    openssl = object.__new__(agent.ssl_helper.OpenSSLLibraries)
    openssl.crypto = mocker.Mock()
    openssl.crypto.ERR_get_error.side_effect = [1, 2, 0]

    def error_string(code, buffer, _size):
        buffer.value = f'error {code}'.encode('utf-8')

    openssl.crypto.ERR_error_string_n.side_effect = error_string

    assert openssl.errors() == 'error 1; error 2'


def test_redact_pkcs11_secrets_query_and_legacy_path():
    redact = agent.ssl_helper.redact_pkcs11_secrets
    assert redact('pkcs11:object=key?pin-value=1234&pin-source=file:/tmp/pin') == (
        'pkcs11:object=key?pin-value=***&pin-source=***'
    )
    assert redact('pkcs11:object=key?pin-value=1234&module-name=softhsm') == (
        'pkcs11:object=key?pin-value=***&module-name=softhsm'
    )
    assert redact('pkcs11:object=key?pin-source=file:/tmp/a;b&module-name=softhsm') == (
        'pkcs11:object=key?pin-source=***&module-name=softhsm'
    )
    assert redact('pkcs11:object=key;pin-value=1234;type=private') == (
        'pkcs11:object=key;pin-value=***;type=private'
    )
    assert redact('pkcs11:object=key?pin-value=1234;pin-source=file:/tmp/pin') == (
        'pkcs11:object=key?pin-value=***'
    )
    assert redact('pin-source=file:/tmp/pin extra') == 'pin-source=*** extra'
    assert redact("uri 'pkcs11:object=key?pin-value=1234'") == (
        "uri 'pkcs11:object=key?pin-value=***'"
    )


def test_ssl_helper_openssl_errors_redacts_pin_material(mocker):
    openssl = object.__new__(agent.ssl_helper.OpenSSLLibraries)
    openssl.crypto = mocker.Mock()
    openssl.crypto.ERR_get_error.side_effect = [1, 0]

    def error_string(_code, buffer, _size):
        buffer.value = b"uri 'pkcs11:object=key?pin-value=1234&pin-source=file:/tmp/pin'"

    openssl.crypto.ERR_error_string_n.side_effect = error_string
    details = openssl.errors()
    assert '1234' not in details
    assert '/tmp/pin' not in details
    assert 'pin-value=***' in details
    assert 'pin-source=***' in details


def test_ssl_helper_pkcs11_provider_handle_close(mocker):
    openssl = mocker.Mock()
    handle = agent.pkcs11._PKCS11ProviderHandle(openssl, 111)

    handle.close()
    handle.close()  # second call is a no-op once the provider has been released

    openssl.crypto.OSSL_PROVIDER_unload.assert_called_once_with(111)
    assert handle.provider is None


def test_ssl_helper_pkcs11_runtime_rejects_other_implementations(mocker):
    mocker.patch.object(agent.pkcs11.sys, 'implementation', SimpleNamespace(name='pypy'))
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='requires CPython'):
        agent.pkcs11.require_pkcs11_runtime(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))


def test_ssl_helper_pkcs11_runtime_requires_ssl_module(mocker):
    mocker.patch.object(agent.pkcs11.sys, 'version_info', agent.pkcs11.PKCS11_REQUIRED_PYTHON + (0,))
    mocker.patch.dict(sys.modules, {'_ssl': None})
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='requires the _ssl module'):
        agent.pkcs11.require_pkcs11_runtime(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))


def test_ssl_helper_pkcs11_runtime_requires_stdlib_context(mocker):
    mocker.patch.object(agent.pkcs11.sys, 'version_info', agent.pkcs11.PKCS11_REQUIRED_PYTHON + (0,))
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='requires a stdlib SSLContext'):
        agent.pkcs11.require_pkcs11_runtime(mocker.Mock())


def test_ssl_helper_pkcs11_runtime_accepts_validated_runtime(mocker):
    mocker.patch.object(agent.pkcs11.sys, 'version_info', agent.pkcs11.PKCS11_REQUIRED_PYTHON + (0,))
    agent.pkcs11.require_pkcs11_runtime(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))


def test_ssl_helper_get_ssl_ctx_pointer(mocker):
    mock_void_p = mocker.Mock()
    mock_void_p.from_address.return_value = mocker.Mock(value=4321)
    mocker.patch.object(agent.ssl_helper.ctypes, 'c_void_p', mock_void_p)
    context = mocker.Mock()
    context.options = 6
    openssl = mocker.Mock()
    openssl.ssl.SSL_CTX_get_options.side_effect = lambda _ctx: context.options

    assert agent.ssl_helper.get_ssl_ctx_pointer(context, openssl) == 4321
    assert context.options == 6


def test_ssl_helper_get_ssl_ctx_pointer_clears_existing_probe(mocker):
    mock_void_p = mocker.Mock()
    mock_void_p.from_address.return_value = mocker.Mock(value=4321)
    mocker.patch.object(agent.ssl_helper.ctypes, 'c_void_p', mock_void_p)
    probe = ssl.OP_CIPHER_SERVER_PREFERENCE
    context = mocker.Mock()
    context.options = probe | 6
    openssl = mocker.Mock()
    openssl.ssl.SSL_CTX_get_options.side_effect = lambda _ctx: context.options

    assert agent.ssl_helper.get_ssl_ctx_pointer(context, openssl) == 4321
    assert context.options == probe | 6


def test_ssl_helper_get_ssl_ctx_pointer_probe_mismatch(mocker):
    mock_void_p = mocker.Mock()
    mock_void_p.from_address.return_value = mocker.Mock(value=4321)
    mocker.patch.object(agent.ssl_helper.ctypes, 'c_void_p', mock_void_p)
    context = mocker.Mock()
    context.options = 6
    openssl = mocker.Mock()
    openssl.ssl.SSL_CTX_get_options.side_effect = [6, 6]

    with pytest.raises(agent.ssl_helper.AgentSSLError, match='Could not verify the OpenSSL SSL_CTX pointer'):
        agent.ssl_helper.get_ssl_ctx_pointer(context, openssl)


def test_ssl_helper_get_ssl_ctx_pointer_unavailable(mocker):
    mock_void_p = mocker.Mock()
    mock_void_p.from_address.return_value = mocker.Mock(value=None)
    mocker.patch.object(agent.ssl_helper.ctypes, 'c_void_p', mock_void_p)

    with pytest.raises(agent.ssl_helper.AgentSSLError, match='Could not access the OpenSSL SSL_CTX'):
        agent.ssl_helper.get_ssl_ctx_pointer(mocker.Mock(), mocker.Mock())


def test_ssl_helper_get_ssl_ctx_pointer_option_mismatch(mocker):
    mock_void_p = mocker.Mock()
    mock_void_p.from_address.return_value = mocker.Mock(value=4321)
    mocker.patch.object(agent.ssl_helper.ctypes, 'c_void_p', mock_void_p)
    openssl = mocker.Mock()
    openssl.ssl.SSL_CTX_get_options.return_value = 7
    context = mocker.Mock()
    context.options = 0

    with pytest.raises(agent.ssl_helper.AgentSSLError, match='Could not verify the OpenSSL SSL_CTX pointer'):
        agent.ssl_helper.get_ssl_ctx_pointer(context, openssl)


def test_ssl_helper_get_ssl_ctx_pointer_live_context():
    """Sanity-check the CPython 3.14 SSL_CTX layout against a real context."""
    if sys.implementation.name != 'cpython':
        pytest.skip('CPython only')
    if sys.version_info[:2] != agent.pkcs11.PKCS11_REQUIRED_PYTHON:
        pytest.skip('PKCS#11 SSL_CTX layout is only validated on CPython 3.14')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        openssl = agent.ssl_helper.OpenSSLLibraries()
    except agent.ssl_helper.AgentSSLError as ex:
        pytest.skip(str(ex))
    original = int(context.options)
    ssl_ctx = agent.ssl_helper.get_ssl_ctx_pointer(context, openssl)
    assert ssl_ctx
    assert int(context.options) == original
    assert int(openssl.ssl.SSL_CTX_get_options(ssl_ctx)) == original


@pytest.mark.parametrize('details, expected', [
    pytest.param('', 'OpenSSL failed to load the key', id="no_details"),
    pytest.param('bad token', 'OpenSSL failed to load the key: bad token', id="with_details"),
])
def test_ssl_helper_openssl_check_raises(details, expected, mocker):
    openssl = mocker.Mock()
    openssl.errors.return_value = details
    with pytest.raises(agent.ssl_helper.AgentSSLError, match=expected):
        agent.ssl_helper.openssl_check(0, openssl, 'load the key')


@pytest.fixture
def pkcs11_openssl(mocker):
    """Stub the OpenSSL provider/store calls made by load_pkcs11_into_context()."""
    mocker.patch('agent.pkcs11.require_pkcs11_runtime')
    mocker.patch('agent.ssl_helper.check_file_access')
    mocker.patch('agent.ssl_helper.get_ssl_ctx_pointer', return_value=4321)
    mocker.patch('agent.pkcs11._pkcs11_provider_modules_dir', return_value='/modules')
    mocker.patch.dict(agent.ssl_helper.os.environ, {}, clear=False)

    openssl = mocker.Mock()
    openssl.errors.return_value = ''
    openssl.crypto.OSSL_PROVIDER_load.return_value = 111
    openssl.crypto.OSSL_STORE_open.return_value = 555
    openssl.crypto.OSSL_STORE_eof.return_value = 0
    openssl.crypto.OSSL_STORE_error.return_value = 0
    openssl.crypto.OSSL_STORE_close.return_value = 1
    openssl.crypto.OSSL_STORE_load.return_value = 666
    openssl.crypto.OSSL_STORE_INFO_get_type.return_value = agent.pkcs11.OSSL_STORE_INFO_PKEY
    openssl.crypto.OSSL_STORE_INFO_get1_PKEY.return_value = 222
    openssl.crypto.OSSL_STORE_INFO_get1_CERT.return_value = 333
    openssl.ssl.SSL_CTX_use_certificate_chain_file.return_value = 1
    openssl.ssl.SSL_CTX_use_certificate.return_value = 1
    openssl.ssl.SSL_CTX_use_PrivateKey.return_value = 1
    openssl.ssl.SSL_CTX_check_private_key.return_value = 1
    mocker.patch('agent.ssl_helper.OpenSSLLibraries', return_value=openssl)

    keepalives = agent.pkcs11._PKCS11_PROVIDER_KEEPALIVES
    original = list(keepalives)
    yield openssl
    keepalives[:] = original


def test_ssl_helper_load_pkcs11_without_pin(pkcs11_openssl, mocker):
    tls_config = TLSConfig(
        cert_file='cert.pem',
        connector='pkcs11',
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key',
    )
    context = mocker.Mock()

    agent.pkcs11.load_pkcs11_into_context(context, tls_config)

    assert agent.ssl_helper.os.environ.get('OPENSSL_MODULES') != '/modules'
    assert 'PKCS11_PROVIDER_MODULE' not in agent.ssl_helper.os.environ
    pkcs11_openssl.crypto.OSSL_PROVIDER_load.assert_called_once_with(
        None, b'/modules/pkcs11.so'
    )
    pkcs11_openssl.crypto.OSSL_STORE_open.assert_called_once_with(
        b'pkcs11:object=key', None, None, None, None
    )
    handle = agent.pkcs11._PKCS11_PROVIDER_KEEPALIVES[-1]
    assert handle is context._pkcs11_provider_handle
    assert handle.pin_files is not None
    pkcs11_openssl.crypto.EVP_PKEY_free.assert_called_once_with(222)


def test_ssl_helper_load_pkcs11_restores_existing_module_env(pkcs11_openssl, mocker):
    mocker.patch.dict(
        agent.ssl_helper.os.environ,
        {'PKCS11_PROVIDER_MODULE': '/previous/module.so'},
    )
    tls_config = TLSConfig(
        cert_file='cert.pem',
        connector='pkcs11',
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key',
    )

    agent.pkcs11.load_pkcs11_into_context(mocker.Mock(), tls_config)

    assert agent.ssl_helper.os.environ['PKCS11_PROVIDER_MODULE'] == '/previous/module.so'


def test_ssl_helper_load_pkcs11_key_attach_failure_releases_provider(pkcs11_openssl, mocker):
    pkcs11_openssl.ssl.SSL_CTX_use_PrivateKey.return_value = 0
    tls_config = TLSConfig(
        cert_file='cert.pem',
        connector='pkcs11',
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key',
        pkcs11_key_pin='1234',
    )

    with pytest.raises(agent.ssl_helper.AgentSSLError, match='attach the PKCS#11 private key'):
        agent.pkcs11.load_pkcs11_into_context(mocker.Mock(), tls_config)

    pkcs11_openssl.crypto.OSSL_STORE_open.assert_called_once()
    opened = pkcs11_openssl.crypto.OSSL_STORE_open.call_args[0][0].decode('utf-8')
    assert 'pin-value=' not in opened
    assert opened.startswith('pkcs11:object=key?pin-source=file:')
    pkcs11_openssl.crypto.OSSL_PROVIDER_unload.assert_called_once_with(111)
    pkcs11_openssl.crypto.EVP_PKEY_free.assert_called_once_with(222)
    crypto_calls = [name for name, *_ in pkcs11_openssl.crypto.method_calls]
    assert crypto_calls.index('EVP_PKEY_free') < crypto_calls.index('OSSL_PROVIDER_unload')
    assert 'PKCS11_PROVIDER_MODULE' not in agent.ssl_helper.os.environ


def test_ssl_helper_load_pkcs11_key_load_failure(pkcs11_openssl, mocker):
    pkcs11_openssl.crypto.OSSL_STORE_open.return_value = 0
    tls_config = TLSConfig(
        cert_file='cert.pem',
        connector='pkcs11',
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key',
    )

    with pytest.raises(agent.ssl_helper.AgentSSLError, match='load the PKCS#11 private key'):
        agent.pkcs11.load_pkcs11_into_context(mocker.Mock(), tls_config)

    pkcs11_openssl.crypto.OSSL_PROVIDER_unload.assert_called_once_with(111)
    pkcs11_openssl.crypto.EVP_PKEY_free.assert_not_called()


def test_ssl_helper_pkcs11_uri_with_pin_source():
    pin_files = agent.pkcs11._EphemeralPinFiles()
    try:
        assert agent.pkcs11._pkcs11_uri_for_store(
            'pkcs11:object=key', None, pin_files
        ) == 'pkcs11:object=key'
        with_pin = agent.pkcs11._pkcs11_uri_for_store(
            'pkcs11:object=key', '1234', pin_files
        )
        assert 'pin-value=' not in with_pin
        assert with_pin.startswith('pkcs11:object=key?pin-source=file:')
        assert agent.pkcs11._pkcs11_uri_for_store(
            'pkcs11:object=key;pin-value=9999', '1234', pin_files
        ) == 'pkcs11:object=key;pin-value=9999'
        ends_with_colon = agent.pkcs11._pkcs11_uri_for_store(
            'pkcs11:', '1234', pin_files
        )
        assert ends_with_colon.startswith('pkcs11:?pin-source=file:')
        with_query = agent.pkcs11._pkcs11_uri_for_store(
            'pkcs11:object=key?module-name=softhsm', '1234', pin_files
        )
        assert with_query.startswith(
            'pkcs11:object=key?module-name=softhsm&pin-source=file:'
        )
        empty_query = agent.pkcs11._pkcs11_uri_for_store(
            'pkcs11:object=key?', '1234', pin_files
        )
        assert empty_query.startswith('pkcs11:object=key?pin-source=file:')
        assert agent.pkcs11._pkcs11_uri_for_store(
            'pkcs11:object=key;pin-source=/tmp/pin', '1234', pin_files
        ) == 'pkcs11:object=key;pin-source=/tmp/pin'
        assert agent.pkcs11._pkcs11_uri_for_store(
            'pkcs11:object=key?pin-source=/tmp/pin', '1234', pin_files
        ) == 'pkcs11:object=key?pin-source=/tmp/pin'
        not_an_attr = agent.pkcs11._pkcs11_uri_for_store(
            'pkcs11:object=my-pin-value=secret', '1234', pin_files
        )
        assert not_an_attr.startswith('pkcs11:object=my-pin-value=secret?pin-source=file:')
        assert agent.ssl_helper.redact_pkcs11_secrets('') == ''
    finally:
        pin_files.close()


def test_ssl_helper_pkcs11_provider_modules_dir(tmp_path, mocker):
    provider_dir = tmp_path / 'lib' / 'ossl-modules'
    provider_dir.mkdir(parents=True)
    (provider_dir / 'pkcs11.so').write_bytes(b'\0')
    mocker.patch('agent.ssl_helper.sys.executable', str(tmp_path / 'python'))
    mocker.patch('agent.ssl_helper.get_agent_root', return_value=tmp_path)
    mocker.patch('agent.ssl_helper.sys.frozen', True, create=True)
    mocker.patch(
        'agent.pkcs11.os.path.isfile',
        side_effect=lambda path: path == str(provider_dir / 'pkcs11.so'),
    )
    assert agent.pkcs11._pkcs11_provider_modules_dir() == str(provider_dir)


def test_pkcs11_provider_modules_dir_from_interpreter_prefix(tmp_path, mocker):
    provider_dir = tmp_path / 'python' / 'lib' / 'ossl-modules'
    provider_dir.mkdir(parents=True)
    (provider_dir / 'pkcs11.so').write_bytes(b'\0')
    mocker.patch('agent.ssl_helper.sys.executable', str(tmp_path / 'venv' / 'bin' / 'python'))
    mocker.patch('agent.ssl_helper.get_agent_root', return_value=tmp_path / 'src')
    mocker.patch('agent.ssl_helper.sys.frozen', False, create=True)
    mocker.patch('agent.ssl_helper.sys.base_prefix', str(tmp_path / 'python'))
    assert agent.pkcs11._pkcs11_provider_modules_dir() == str(provider_dir)


def test_pkcs11_provider_modules_dir_frozen_ignores_interpreter_prefix(tmp_path, mocker):
    provider_dir = tmp_path / 'python' / 'lib' / 'ossl-modules'
    provider_dir.mkdir(parents=True)
    (provider_dir / 'pkcs11.so').write_bytes(b'\0')
    mocker.patch('agent.ssl_helper.sys.executable', str(tmp_path / 'bin' / 'infrastructure-agent'))
    mocker.patch('agent.ssl_helper.get_agent_root', return_value=tmp_path)
    mocker.patch('agent.ssl_helper.sys.frozen', True, create=True)
    mocker.patch('agent.ssl_helper.sys.base_prefix', str(tmp_path / 'python'))
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='pkcs11.so was not found'):
        agent.pkcs11._pkcs11_provider_modules_dir()


def test_ssl_helper_ossl_store_skips_until_matching_object(mocker):
    openssl = mocker.Mock()
    openssl.errors.return_value = ''
    openssl.crypto.OSSL_STORE_open.return_value = 555
    openssl.crypto.OSSL_STORE_eof.return_value = 0
    openssl.crypto.OSSL_STORE_load.side_effect = [10, 20, 30]
    openssl.crypto.OSSL_STORE_INFO_get_type.side_effect = [
        99,
        agent.pkcs11.OSSL_STORE_INFO_PKEY,
        agent.pkcs11.OSSL_STORE_INFO_PKEY,
    ]
    openssl.crypto.OSSL_STORE_INFO_get1_PKEY.side_effect = [0, 222]

    found = agent.pkcs11._ossl_store_load_object(
        openssl, 'pkcs11:object=key', agent.pkcs11.OSSL_STORE_INFO_PKEY,
        'OSSL_STORE_INFO_get1_PKEY', 'load the PKCS#11 private key',
    )

    assert found == 222
    assert openssl.crypto.OSSL_STORE_INFO_free.call_args_list == [call(10), call(20), call(30)]
    openssl.crypto.OSSL_STORE_close.assert_called_once_with(555)


def test_ssl_helper_ossl_store_empty_entry_without_error(mocker):
    openssl = mocker.Mock()
    openssl.errors.return_value = ''
    openssl.crypto.OSSL_STORE_open.return_value = 555
    openssl.crypto.OSSL_STORE_eof.return_value = 0
    openssl.crypto.OSSL_STORE_load.return_value = None
    openssl.crypto.OSSL_STORE_error.return_value = 0
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='load the PKCS#11 private key'):
        agent.pkcs11._ossl_store_load_object(
            openssl, 'pkcs11:object=key', agent.pkcs11.OSSL_STORE_INFO_PKEY,
            'OSSL_STORE_INFO_get1_PKEY', 'load the PKCS#11 private key',
        )
    openssl.crypto.OSSL_STORE_close.assert_called_once_with(555)


def test_ssl_helper_ossl_store_empty_entry_with_error(mocker):
    openssl = mocker.Mock()
    openssl.errors.return_value = 'token error'
    openssl.crypto.OSSL_STORE_open.return_value = 555
    openssl.crypto.OSSL_STORE_eof.return_value = 0
    openssl.crypto.OSSL_STORE_load.return_value = None
    openssl.crypto.OSSL_STORE_error.return_value = 1
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='token error'):
        agent.pkcs11._ossl_store_load_object(
            openssl, 'pkcs11:object=key', agent.pkcs11.OSSL_STORE_INFO_PKEY,
            'OSSL_STORE_INFO_get1_PKEY', 'load the PKCS#11 private key',
        )
    openssl.crypto.OSSL_STORE_close.assert_called_once_with(555)


def test_ssl_helper_ossl_store_eof_before_any_object(mocker):
    openssl = mocker.Mock()
    openssl.errors.return_value = ''
    openssl.crypto.OSSL_STORE_open.return_value = 555
    openssl.crypto.OSSL_STORE_eof.return_value = 1
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='load the PKCS#11 private key'):
        agent.pkcs11._ossl_store_load_object(
            openssl, 'pkcs11:object=key', agent.pkcs11.OSSL_STORE_INFO_PKEY,
            'OSSL_STORE_INFO_get1_PKEY', 'load the PKCS#11 private key',
        )
    openssl.crypto.OSSL_STORE_load.assert_not_called()
    openssl.crypto.OSSL_STORE_close.assert_called_once_with(555)


def test_ssl_helper_load_pkcs11_certificate_from_token(pkcs11_openssl, mocker):
    pkcs11_openssl.crypto.OSSL_STORE_INFO_get_type.side_effect = [
        agent.pkcs11.OSSL_STORE_INFO_PKEY,
        agent.pkcs11.OSSL_STORE_INFO_CERT,
    ]
    tls_config = TLSConfig(
        connector='pkcs11',
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key;type=private',
        pkcs11_cert_uri='pkcs11:object=key;type=cert',
        check_client_cert=False,
    )
    context = mocker.Mock()

    agent.pkcs11.load_pkcs11_into_context(context, tls_config)

    pkcs11_openssl.ssl.SSL_CTX_use_certificate.assert_called_once_with(4321, 333)
    pkcs11_openssl.ssl.SSL_CTX_use_certificate_chain_file.assert_not_called()
    pkcs11_openssl.crypto.X509_free.assert_called_once_with(333)
    assert pkcs11_openssl.crypto.OSSL_STORE_open.call_args_list == [
        call(b'pkcs11:object=key;type=private', None, None, None, None),
        call(b'pkcs11:object=key;type=cert', None, None, None, None),
    ]


def test_ssl_helper_pkcs11_provider_missing(mocker):
    mocker.patch('agent.pkcs11.require_pkcs11_runtime')
    mocker.patch('agent.ssl_helper.check_file_access')
    mocker.patch('agent.pkcs11.os.path.isfile', return_value=False)
    tls_config = TLSConfig(
        cert_file='cert.pem',
        connector='pkcs11',
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key',
    )
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='pkcs11.so was not found'):
        agent.pkcs11.load_pkcs11_into_context(mocker.Mock(), tls_config)


def test_ssl_helper_ephemeral_pin_ignores_close_error_after_failed_write(tmp_path, mocker):
    mocker.patch('agent.pkcs11.get_agent_root', return_value=tmp_path)
    mocker.patch.object(agent.pkcs11.os, 'chmod', side_effect=OSError(errno.EPERM, 'denied'))
    mocker.patch.object(agent.pkcs11.os, 'close', side_effect=OSError(errno.EBADF, 'closed'))
    mocker.patch.object(agent.pkcs11.os, 'unlink', side_effect=OSError(errno.ENOENT, 'gone'))

    pin_files = agent.pkcs11._EphemeralPinFiles()
    with pytest.raises(OSError, match='denied'):
        pin_files.write('agent-pkcs11-pin', b'test-pin')
    assert pin_files._paths == []
    pin_files.close()


def test_ssl_helper_ephemeral_pin_cleans_up_unwritable_temp_file(tmp_path, mocker):
    mocker.patch('agent.pkcs11.get_agent_root', return_value=tmp_path)
    mocker.patch.object(agent.pkcs11.os, 'chmod', side_effect=OSError(errno.EPERM, 'denied'))
    mocker.patch.object(agent.pkcs11.os, 'unlink', side_effect=OSError(errno.ENOENT, 'gone'))

    pin_files = agent.pkcs11._EphemeralPinFiles()
    with pytest.raises(OSError):
        pin_files.write('agent-pkcs11-pin', b'test-pin')
    assert pin_files._paths == []
    pin_files.close()


def test_ssl_helper_ephemeral_pin_close_ignores_cleanup_errors(tmp_path):
    pin_files = agent.pkcs11._EphemeralPinFiles()
    pin_files._paths.append(str(tmp_path / 'already-removed.pin'))

    pin_files.close()

    assert pin_files._paths == []


def test_ssl_helper_close_pin_files_unlinks_without_unloading_provider(tmp_path, mocker):
    mocker.patch('agent.pkcs11.get_agent_root', return_value=tmp_path)
    pin_files = agent.pkcs11._EphemeralPinFiles()
    path = pin_files.write(agent.pkcs11.PIN_FILE_NAME, b'test-pin')
    provider = mocker.Mock()
    handle = agent.pkcs11._PKCS11ProviderHandle(mocker.Mock(), provider, pin_files)
    keepalives = agent.pkcs11._PKCS11_PROVIDER_KEEPALIVES
    keepalives.append(handle)
    try:
        agent.pkcs11.close_pin_files()
        assert not os.path.exists(path)
        assert handle.pin_files is None
        assert handle.provider is provider
        provider_unload = handle.openssl.crypto.OSSL_PROVIDER_unload
        provider_unload.assert_not_called()
        agent.pkcs11.close_pin_files()
    finally:
        keepalives.remove(handle)


def test_ssl_helper_remove_stale_pin_files(tmp_path, mocker):
    var_dir = tmp_path / 'var'
    var_dir.mkdir()
    stale = var_dir / 'agent-pkcs11-pin-stale'
    stale.write_bytes(b'old-pin')
    other = var_dir / 'startup.log'
    other.write_text('keep')
    (var_dir / 'agent-pkcs11-pin-dir').mkdir()
    mocker.patch('agent.pkcs11.get_agent_root', return_value=tmp_path)

    pin_files = agent.pkcs11._EphemeralPinFiles()
    live_path = pin_files.write(agent.pkcs11.PIN_FILE_NAME, b'live-pin')
    handle = agent.pkcs11._PKCS11ProviderHandle(mocker.Mock(), mocker.Mock(), pin_files)
    keepalives = agent.pkcs11._PKCS11_PROVIDER_KEEPALIVES
    keepalives.append(handle)
    try:
        removed = agent.pkcs11.remove_stale_pin_files()
        assert os.path.isfile(live_path)
    finally:
        pin_files.close()
        keepalives.remove(handle)

    assert removed == [str(stale)]
    assert not stale.exists()
    assert other.is_file()
    assert (var_dir / 'agent-pkcs11-pin-dir').is_dir()
    assert not os.path.exists(live_path)


def test_ssl_helper_remove_stale_pin_files_skips_handle_without_files(tmp_path, mocker):
    var_dir = tmp_path / 'var'
    var_dir.mkdir()
    stale = var_dir / 'agent-pkcs11-pin-stale'
    stale.write_bytes(b'old-pin')
    mocker.patch('agent.pkcs11.get_agent_root', return_value=tmp_path)
    handle = agent.pkcs11._PKCS11ProviderHandle(mocker.Mock(), mocker.Mock(), None)
    keepalives = agent.pkcs11._PKCS11_PROVIDER_KEEPALIVES
    keepalives.append(handle)
    try:
        removed = agent.pkcs11.remove_stale_pin_files()
    finally:
        keepalives.remove(handle)

    assert removed == [str(stale)]
    assert not stale.exists()


def test_ssl_helper_remove_stale_pin_files_missing_directory(tmp_path, mocker):
    mocker.patch('agent.pkcs11.get_agent_root', return_value=tmp_path)
    assert agent.pkcs11.remove_stale_pin_files() == []


def test_ssl_helper_remove_stale_pin_files_ignores_unlink_error(tmp_path, mocker, caplog):
    var_dir = tmp_path / 'var'
    var_dir.mkdir()
    stale = var_dir / 'agent-pkcs11-pin-stuck'
    stale.write_bytes(b'old-pin')
    mocker.patch('agent.pkcs11.get_agent_root', return_value=tmp_path)
    mocker.patch('pathlib.Path.unlink', side_effect=OSError(errno.EPERM, 'denied'))

    assert agent.pkcs11.remove_stale_pin_files() == []
    assert stale.is_file()
    assert 'Failed to remove stale PKCS#11 PIN file' in caplog.text


def test_ssl_helper_ephemeral_pin_removed_on_exit(tmp_path, mocker):
    register = mocker.patch('agent.pkcs11.atexit.register')
    mocker.patch('agent.pkcs11.get_agent_root', return_value=tmp_path)
    pin_files = agent.pkcs11._EphemeralPinFiles()
    register.assert_called_once_with(pin_files.close)
    path = pin_files.write('agent-pkcs11-pin', b'test-pin')
    assert os.path.isfile(path)

    pin_files.close()

    assert not os.path.exists(path)


def test_ssl_helper_rejects_schannel_on_windows(mocker):
    mocker.patch('agent.ssl_helper.sys.platform', 'win32')
    tls = TLSConfig(connector='schannel', schannel_cert_name='host.example.com')
    with pytest.raises(agent.ssl_helper.AgentSSLError, match='connector=schannel'):
        agent.ssl_helper.get_ssl_context(tls, 'server')


def test_ssl_helper_skips_ciphers_when_unset(mocker, caplog):
    """Cover get_ssl_context path when cipher_suite is cleared after TLSConfig defaults."""
    tls = TLSConfig(None, None, None, None, False, False, None, [])
    tls.cipher_suite = None
    mock_context = mocker.Mock()
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.create_self_signed_cert', return_value=('key', 'cert'))
    mocker.patch('agent.ssl_helper.check_file_access')
    agent.ssl_helper.get_ssl_context(tls, 'foo')
    mock_context.set_ciphers.assert_not_called()
    assert 'Using configured TLS ciphers' not in caplog.text
