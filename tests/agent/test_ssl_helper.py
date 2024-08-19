"""
Infrastructure Agent: Unit tests for logger
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""
import agent.ssl_helper
import errno
import os.path
import pytest
import socket
import ssl
import subprocess
from agent.config import TLSConfig
from contextlib import contextmanager
from mock import call
from pathlib import Path
from tempfile import TemporaryDirectory


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
    'tls_config, logall, certerr, exception, logexp', [
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', False, None, []), False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Loading system default CA certificates'],
            id="default_CA"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'key', False, None, []), False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_file"),
        pytest.param(
            TLSConfig('notfound', None, 'cert', 'key', False, None, []), False, None, agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_file_not_found"),
        pytest.param(
            TLSConfig('noaccess', None, 'cert', 'key', False, None, []), False, None, agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_file_no_access"),
        pytest.param(
            TLSConfig(None, 'ca', 'cert', 'key', False, None, []), False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_path"),
        pytest.param(
            TLSConfig(None, 'notfound', 'cert', 'key', False, None, []), False, None, agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_path_not_found"),
        pytest.param(
            TLSConfig(None, 'noaccess', 'cert', 'key', False, None, []), False, None, agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured CA Certificate'],
            id="configured_CA_path_no_access"),
        pytest.param(
            TLSConfig('ca', None, 'cert', None, False, None, []), False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Using configured TLS cert_file'],
            id="cert"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'key', False, None, []), False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Using configured TLS cert_file and key_file'],
            id="cert_with_key"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'notfound', False, None, []), False, None, agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured TLS cert_file and key_file'],
            id="cert_with_key_not_found"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'noaccess', False, None, []), False, None, agent.ssl_helper.AgentSSLError,
            ['foo: Using OpenSSL version ', 'foo: Using configured TLS cert_file and key_file'],
            id="cert_with_key_no_access"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'key', False, None, []), True, None, None,
            ['foo: Logging all TLS messages'],
            id="log_all_true"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'key', False, None, []), True, ssl.SSLError, agent.ssl_helper.AgentSSLError,
            ["foo: TLS key missing or does not match the certificate"],
            id="cert_error"),
        pytest.param(
            TLSConfig('ca', None, None, 'key', False, None, []), False, None, agent.ssl_helper.AgentSSLError,
            ["foo: TLS config 'cert_file' not specified"],
            id="no_cert"),
        pytest.param(
            TLSConfig('ca', None, None, None, False, None, []), False, None, agent.ssl_helper.AgentSSLError,
            ["foo: TLS config 'cert_file' not specified"],
            id="ca_no_cert_no_key"),
        pytest.param(
            TLSConfig(None, None, None, None, False, None, []), False, None, None,
            ['foo: Using OpenSSL version ', 'foo: Using configured TLS cert_file and key_file'],
            id="ca_no_cert_no_key_no_cert"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', True, None, []), False, None, None,
            ['foo: Check client certificate'],
            id="check_client_certificate"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', False, 'cipher', []), False, None, None,
            ['foo: Using configured TLS ciphers'],
            id="ciphers"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', True, 'cipher', []), False, None, None,
            ['foo: Using configured TLS ciphers', 'foo: Check client certificate'],
            id="ciphers_check_client"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', False, None, ['ALL']), False, None, None,
            ["foo: Setting Context property 'ssl.OP_ALL'"],
            id="option"),
        pytest.param(
            TLSConfig(None, None, 'cert', 'key', False, None, ['foo']), False, None, AttributeError,
            ["Invalid foo tls_context_option 'foo' in config"],
            id="bad_option"),
        pytest.param(
            TLSConfig('ca', None, 'cert', 'key', True, 'cipher', ['ALL']), True, None, None,
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
def test_ssl_helper_get_ssl_context(tls_config, logall, certerr, exception, logexp, mocker, caplog):
    tls_config.log_all_messages = logall
    mock_context = mocker.Mock()
    mock_context.load_cert_chain.side_effect = certerr
    mock_context.options = 0
    mocker.patch('agent.ssl_helper.ssl.SSLContext', return_value=mock_context)
    mocker.patch('agent.ssl_helper.open', side_effect=_file_check)
    mocker.patch('agent.ssl_helper.os.listdir', side_effect=_path_check)
    mocker.patch('agent.ssl_helper.create_self_signed_cert', return_value=('key', 'cert'))
    if not exception:
        agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    else:
        with pytest.raises(exception):
            agent.ssl_helper.get_ssl_context(tls_config, 'foo')
    for text in logexp:
        assert text in caplog.text


@pytest.mark.parametrize(
    'returncode, stdout, stderr, cafile, capath, logexp, callexp', [
        pytest.param(0, None, None, None, None, [], ['/usr/bin/openssl', 'verify', 'cert'], id="verified"),
        pytest.param(
            0, None, None, 'ca_file', None, [],
            ['/usr/bin/openssl', 'verify', '-CAfile', 'ca_file', 'cert'],
            id="verified_CA_file"),
        pytest.param(
            0, None, None, None, 'ca_path', [],
            ['/usr/bin/openssl', 'verify', '-CApath', 'ca_path', 'cert'],
            id="verified_CA_path"),
        pytest.param(
            0, None, None, 'ca_file', 'ca_path', [],
            ['/usr/bin/openssl', 'verify', '-CAfile', 'ca_file', '-CApath', 'ca_path', 'cert'],
            id="verified_CA_file_and_CA_path"),
        pytest.param(
            2, b'error cert: verification failed\n',
            b'CN = test.system\nerror 18 at 0 depth lookup: self signed certificate\n'
            b'CN = test.system\nerror 10 at 0 depth lookup: certificate has expired\n',
            None, None,
            [
                'error cert: verification failed',
                'self signed certificate',
                'certificate has expired',
            ],
            ['/usr/bin/openssl', 'verify', 'cert'],
            id="errors"),
    ])
def test_ssl_helper_verify_certificate(returncode, stdout, stderr, cafile, capath, logexp, callexp, mocker, caplog):
    mock_verify = mocker.Mock(returncode=returncode, stdout=stdout, stderr=stderr)
    mock_run = mocker.patch('agent.ssl_helper.subprocess.run', return_value=mock_verify)
    agent.ssl_helper.verify_certificate(TLSConfig(cafile, capath, 'cert', None, True, None, []))
    for text in logexp:
        assert text in caplog.text
    assert mock_run.called
    assert mock_run.call_args == call(callexp, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


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


def test_ssl_helper_create_self_signed_cert():
    with TemporaryDirectory() as d:
        output_dir = os.path.join(d, 'var')
        key_file, cert_file = agent.ssl_helper.create_self_signed_cert('server', output_dir)
        assert os.path.isdir(output_dir)
        assert (os.stat(key_file).st_mode & 0o777) == 0o640
        assert (os.stat(cert_file).st_mode & 0o777) == 0o644


def test_ssl_helper_create_self_signed_cert_exists():
    config_name = 'server'
    base_name = f'{socket.gethostname()}-{config_name}'
    with TemporaryDirectory() as d:
        output_path = Path(d) / 'var'
        os.makedirs(output_path)
        orig_key_path = (output_path / base_name).with_suffix('.key')
        orig_cert_path = (output_path / base_name).with_suffix('.crt')
        orig_key_path.touch()
        orig_cert_path.touch()
        key_file, cert_file = agent.ssl_helper.create_self_signed_cert(config_name, output_path)
        assert key_file == orig_key_path
        assert cert_file == orig_cert_path
        assert os.path.getsize(key_file) == 0
        assert os.path.getsize(cert_file) == 0
