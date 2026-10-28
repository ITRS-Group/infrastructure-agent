"""
Unit tests for TLS connector selection / capabilities.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

import logging

import pytest

from agent.config import ConfigurationError, TLSConfig
from agent.objects import Platform
from tls.transport.capabilities import (
    log_selection,
    normalize_connector,
    select_backend,
    yaml_value_set,
)


@pytest.fixture(autouse=True)
def _set_startup_log(mocker):
    mocker.patch('agent.config.startup_log', return_value=lambda *args, **kwargs: print(*args, kwargs))


def _pkcs11(**kwargs):
    values = dict(
        connector='pkcs11',
        pkcs11_module='/m.so',
        pkcs11_key_uri='pkcs11:object=key',
        pkcs11_cert_uri='pkcs11:object=cert',
        pkcs11_key_pin='1',
    )
    values.update(kwargs)
    return TLSConfig(**values)


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


def test_normalize_connector():
    assert normalize_connector('file') == 'file'
    assert normalize_connector('pkcs11') == 'pkcs11'
    assert normalize_connector('schannel') == 'schannel'
    assert normalize_connector(' FILE ') == 'file'


def test_normalize_connector_invalid():
    with pytest.raises(ConfigurationError, match='Invalid TLS connector'):
        normalize_connector('openssl')
    with pytest.raises(ConfigurationError, match='Invalid TLS connector'):
        normalize_connector('python_ssl')


def test_normalize_connector_empty_string():
    assert normalize_connector('   ') is None


def test_select_file_default(platform_linux):
    tls = TLSConfig()
    assert tls.connector == 'file'
    assert tls.backend == 'python_ssl'
    sel = select_backend(tls, platform_linux)
    assert sel.backend == 'python_ssl'
    assert sel.connector == 'file'
    assert not sel.ignored_keys


def test_select_file_with_pem(platform_linux):
    sel = select_backend(TLSConfig(cert_file='/a.crt', key_file='/a.key'), platform_linux)
    assert sel.backend == 'python_ssl'


def test_unset_connector_with_schannel_keys_fails(platform_win):
    with pytest.raises(ConfigurationError, match='require server.tls.connector=schannel'):
        TLSConfig(schannel_cert_name='host.example.com')


def test_pkcs11_connector_uses_python_ssl(platform_linux):
    tls = _pkcs11()
    assert tls.backend == 'python_ssl'
    sel = select_backend(tls, platform_linux)
    assert sel.backend == 'python_ssl'
    assert sel.connector == 'pkcs11'
    assert tls.ca_cert == 'system'
    assert tls.cipher_suite == 'system'
    assert tls.context_options == 'system'
    assert tls.check_client_cert is True
    assert tls.check_server_cert is True


def test_select_explicit_schannel(platform_win):
    tls = TLSConfig(connector='schannel', schannel_cert_name='host.example.com')
    sel = select_backend(tls, platform_win)
    assert sel.backend == 'schannel'
    assert tls.check_client_cert is True


def test_select_explicit_schannel_without_identity_fails(platform_win):
    with pytest.raises(ConfigurationError, match='identity_cert_name'):
        TLSConfig(connector='schannel')


@pytest.mark.parametrize(
    'pem_kwargs',
    [
        {'ca_cert': '/ca.crt'},
        {'ca_path': '/ca/dir'},
        {'cert_file': '/a.crt'},
        {'key_file': '/a.key'},
        {'key_file': '/a.key', 'key_passphrase': 'secret'},
    ],
    ids=['ca_cert', 'ca_path', 'cert_file', 'key_file', 'key_passphrase'],
)
def test_schannel_warns_and_ignores_pem(pem_kwargs, monkeypatch):
    messages = []
    monkeypatch.setattr(
        'agent.config.startup_log',
        lambda message, prefix='[INFO]': messages.append(f'{prefix} {message}'),
    )
    tls = TLSConfig(connector='schannel', schannel_cert_name='host', **pem_kwargs)
    assert tls.schannel_cert_name == 'host'
    assert tls.ca_cert is None
    assert tls.cert_file is None
    assert tls.key_file is None
    assert tls.key_passphrase is None
    assert any(
        line.startswith('[WARNING] Ignoring leftover TLS file options')
        for line in messages
    )


def test_select_explicit_schannel_on_linux_fails(platform_linux):
    with pytest.raises(ConfigurationError, match='only available on Windows'):
        select_backend(
            TLSConfig(connector='schannel', schannel_cert_name='host'),
            platform_linux,
        )


def test_select_explicit_schannel_on_server_2016_fails():
    platform_2016 = Platform(
        system='Windows',
        architecture='x86_64',
        windows_version=('10', '10.0.14393', 'SP0', 'Multiprocessor Free'),
    )
    with pytest.raises(ConfigurationError, match='Windows Server 2019'):
        select_backend(
            TLSConfig(connector='schannel', schannel_cert_name='host'),
            platform_2016,
        )


def test_pkcs11_identity_on_windows_is_python_ssl(platform_win):
    sel = select_backend(_pkcs11(), platform_win)
    assert sel.backend == 'python_ssl'


def test_schannel_ignores_cipher_suite(monkeypatch):
    messages = []
    monkeypatch.setattr(
        'agent.config.startup_log',
        lambda message, prefix='[INFO]': messages.append(f'{prefix} {message}'),
    )
    tls = TLSConfig(
        connector='schannel',
        schannel_cert_name='host',
        cipher_suite='ECDH+AESGCM',
    )
    assert tls.cipher_suite is None
    assert any(
        line.startswith('[WARNING] Ignoring leftover TLS file options') and 'cipher_suite' in line
        for line in messages
    )


def test_pkcs11_ignores_explicit_cipher_suite():
    tls = _pkcs11(cipher_suite='ECDH+AESGCM')
    assert tls.cipher_suite == 'system'


def test_schannel_rejects_pkcs11_identity():
    with pytest.raises(ConfigurationError, match='cannot be combined with pkcs11'):
        TLSConfig(
            connector='schannel',
            schannel_cert_name='host',
            pkcs11_module='/m.so',
            pkcs11_key_uri='pkcs11:x',
        )


def test_select_schannel_both_identities_fails(platform_win):
    with pytest.raises(ConfigurationError, match='only one Schannel identity'):
        TLSConfig(connector='schannel', schannel_cert_name='host', schannel_cert_thumbprint='AABB')


def test_select_file_with_schannel_keys_fails(platform_linux):
    with pytest.raises(ConfigurationError, match='require server.tls.connector=schannel'):
        TLSConfig(schannel_cert_thumbprint='AABB')


def test_select_cert_store_without_schannel_fails(platform_linux):
    with pytest.raises(ConfigurationError, match='identity_cert_store requires'):
        TLSConfig(schannel_cert_store='MY')


def test_select_schannel_ignores_log_all_messages(platform_win):
    tls = TLSConfig(connector='schannel', schannel_cert_name='host', log_all_messages=True)
    sel = select_backend(tls, platform_win)
    assert 'log_all_messages' in sel.ignored_keys
    assert 'check_server_cert' in sel.ignored_keys


def test_log_selection_os_managed_message(platform_win, caplog):
    tls = TLSConfig(connector='schannel', schannel_cert_name='host')
    sel = select_backend(tls, platform_win)
    with caplog.at_level(logging.INFO, logger='tls'):
        log_selection(sel, name='NRPE')
    assert 'OS-managed extras (agent ignores):' in caplog.text
    assert 'connector=schannel' in caplog.text


def test_nonempty_skips_blank_strings():
    from types import SimpleNamespace
    from tls.transport.capabilities import validate_identity_keys
    tls = SimpleNamespace(
        connector='schannel',
        schannel_cert_name='   ',
        schannel_cert_thumbprint=None,
        schannel_cert_store=None,
        pkcs11_module=None,
        pkcs11_key_uri=None,
        pkcs11_key_pin=None,
        pkcs11_cert_uri=None,
        pkcs11_cert_pin=None,
    )
    with pytest.raises(ConfigurationError, match='identity_cert_name'):
        validate_identity_keys(tls)


def test_log_selection_python_ssl_and_context_options(caplog):
    from tls.transport.capabilities import TlsSelection
    py = TlsSelection(
        backend='python_ssl',
        ignored_keys=('log_all_messages',),
        ignored_context_options=(),
        connector='file',
    )
    with caplog.at_level(logging.INFO, logger='tls'):
        log_selection(py)
    assert 'ignoring: log_all_messages' in caplog.text

    sch = TlsSelection(
        backend='schannel',
        ignored_keys=(),
        ignored_context_options=('NO_SSLv3',),
        connector='schannel',
    )
    with caplog.at_level(logging.INFO, logger='tls'):
        log_selection(sch)
    assert 'context_options[NO_SSLv3]' in caplog.text
    assert 'OS-managed extras' in caplog.text


def test_yaml_value_set_nested_and_sequences():
    assert yaml_value_set(None) is False
    assert yaml_value_set('') is False
    assert yaml_value_set('  ') is False
    assert yaml_value_set('x') is True
    assert yaml_value_set({'a': None, 'b': ''}) is False
    assert yaml_value_set({'a': ['', None]}) is False
    assert yaml_value_set({'a': ['token.so']}) is True
    assert yaml_value_set(('pkcs11:object=key',)) is True
    assert yaml_value_set(0) is True
    assert yaml_value_set(False) is True
