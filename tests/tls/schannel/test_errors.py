"""
Unit tests for Schannel errors and portable pieces that run without Windows APIs.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tls.schannel.errors import SchannelError
from tls.schannel.socket_adapter import peercert_dict_from_der


def _make_cert_der(cn='peer.example.com', san_dns='peer.example.com'):
    key = rsa.generate_private_key(65537, 2048, default_backend())
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san_dns)]), critical=False)
    )
    cert = builder.sign(key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.DER)


def test_peercert_dict_from_der_shape():
    der = _make_cert_der()
    d = peercert_dict_from_der(der)
    assert 'subject' in d
    assert any(item[0][0] == 'commonName' for item in d['subject'])
    assert ('DNS', 'peer.example.com') in d['subjectAltName']


def test_schannel_error_carries_winerror():
    err = SchannelError('cannot open store', winerror=5)
    assert isinstance(err, Exception)
    assert err.winerror == 5
    # Must not be ssl.SSLError's default "('msg',)" form — NRPE logs str(ex).
    assert str(err) == 'cannot open store'
    assert 'winerror=5' in repr(err)
    assert repr(SchannelError('plain')) == "SchannelError('plain')"


def teststatus_hex():
    from tls.schannel.errors import status_hex

    assert status_hex(5) == '0x00000005'


def testraise_config_error_with_winerror(caplog):
    import logging

    from tls.schannel.errors import raise_config_error

    # Schannel operator errors log on the TLS logger.
    with caplog.at_level(logging.ERROR, logger='tls'):
        with pytest.raises(SchannelError):
            raise_config_error('store open failed', winerror=5)
    assert 'winerror=0x00000005' in caplog.text


def testraise_store_open_error_access_denied():
    from tls.schannel.errors import ERROR_ACCESS_DENIED, raise_store_open_error

    with pytest.raises(SchannelError, match='cannot open LocalMachine certificate stores'):
        raise_store_open_error('MY', ERROR_ACCESS_DENIED)


def testraise_store_open_error_invalid_store():
    from tls.schannel.errors import raise_store_open_error

    with pytest.raises(SchannelError, match='usually MY'):
        raise_store_open_error('NOPE', 2)


def test_ensure_win32_rejects_non_windows(mocker):
    from tls.schannel import win32 as win32_mod

    win32_mod._win32_loaded = False
    mocker.patch.object(win32_mod.sys, 'platform', 'linux')

    with pytest.raises(SchannelError, match='only available on Windows'):
        win32_mod.ensure_win32()


def testraise_config_error_logs_and_names_keys(caplog):
    import logging

    from tls.schannel.errors import raise_config_error

    with caplog.at_level(logging.ERROR, logger='tls'):
        with pytest.raises(SchannelError, match='server.tls.schannel.identity_cert_thumbprint') as ei:
            raise_config_error(
                'No certificate with server.tls.schannel.identity_cert_thumbprint=AABB in LocalMachine\\MY',
                winerror=None,
            )
    assert ei.value.winerror is None
    assert str(ei.value).startswith('No certificate with server.tls.schannel.identity_cert_thumbprint')
    assert any('server.tls.schannel.identity_cert_thumbprint' in r.message for r in caplog.records)


def test_wrap_accepted_preserves_schannel_error(mocker):
    from tls.schannel.socket_adapter import SchannelSocket

    # wrap_accepted lives in socket_adapter; patch where symbols are used.
    mocker.patch('tls.schannel.session.win32.ensure_win32')
    pool = mocker.Mock()
    pool.spawn.return_value.get.side_effect = SchannelError(
        'No certificate with server.tls.schannel.identity_cert_thumbprint=AABB',
        winerror=None,
    )
    mocker.patch('tls.schannel.socket_adapter._get_thread_pool', return_value=pool)

    conn = mocker.Mock()
    conn.fileno.return_value = 3
    conn.getpeername.return_value = ('1.2.3.4', 1234)
    mocker.patch('tls.schannel.socket_adapter._RawSocket', return_value=mocker.Mock())
    mocker.patch('tls.schannel.socket_adapter.SchannelServerSession')

    with pytest.raises(SchannelError, match='server.tls.schannel.identity_cert_thumbprint') as ei:
        SchannelSocket.wrap_accepted(conn, cred=object(), handshake_timeout=1.0)
    assert 'Schannel handshake failed' not in str(ei.value)


def test_configure_thread_pool_sizes_from_max_active(mocker):
    import tls.schannel.socket_adapter as adapter

    mock_pool_cls = mocker.patch('gevent.threadpool.ThreadPool')
    adapter._thread_pool = None
    adapter._thread_pool_size = None

    adapter.configure_thread_pool(15)
    mock_pool_cls.assert_called_once_with(15)
    assert adapter._thread_pool_size == 15
    assert adapter._get_thread_pool() is mock_pool_cls.return_value

    # Same size: do not recreate.
    mock_pool_cls.reset_mock()
    adapter.configure_thread_pool(15)
    mock_pool_cls.assert_not_called()

    # Different size: recreate.
    adapter.configure_thread_pool(4)
    mock_pool_cls.assert_called_once_with(4)
    assert adapter._thread_pool_size == 4

    # Reset module state for other tests.
    adapter._thread_pool = None
    adapter._thread_pool_size = None


def test_get_thread_pool_requires_configure():
    import tls.schannel.socket_adapter as adapter

    adapter._thread_pool = None
    adapter._thread_pool_size = None
    with pytest.raises(SchannelError, match='not configured'):
        adapter._get_thread_pool()

    adapter._thread_pool = None
    adapter._thread_pool_size = None


def test_shutdown_thread_pool_joins_then_kills(mocker):
    import tls.schannel.socket_adapter as adapter

    pool = mocker.Mock()
    adapter._thread_pool = pool
    adapter._thread_pool_size = 4

    adapter.shutdown_thread_pool()

    pool.join.assert_called_once()
    pool.kill.assert_called_once()
    assert adapter._thread_pool is None
    assert adapter._thread_pool_size is None


def test_shutdown_thread_pool_kills_when_join_fails(mocker):
    import tls.schannel.socket_adapter as adapter

    pool = mocker.Mock()
    pool.join.side_effect = RuntimeError('join failed')
    adapter._thread_pool = pool
    adapter._thread_pool_size = 2

    with pytest.raises(RuntimeError, match='join failed'):
        adapter.shutdown_thread_pool()

    pool.kill.assert_called_once()
    assert adapter._thread_pool is None


def test_shutdown_thread_pool_when_unset():
    import tls.schannel.socket_adapter as adapter

    adapter._thread_pool = None
    adapter._thread_pool_size = None
    adapter.shutdown_thread_pool()
    assert adapter._thread_pool is None


def test_run_on_pool_applies_socket_timeout_in_worker(mocker):
    import tls.schannel.socket_adapter as adapter

    sock = mocker.Mock()
    captured = {}

    async_result = mocker.Mock()
    async_result.get.return_value = b'data'

    def fake_spawn(worker):
        captured['worker'] = worker
        return async_result

    mocker.patch.object(adapter, '_get_thread_pool', return_value=mocker.Mock(spawn=fake_spawn))

    out = adapter._run_on_pool(sock, 0.5, lambda: b'data')
    assert out == b'data'
    captured['worker']()
    sock.setblocking.assert_called_once_with(True)
    sock.settimeout.assert_called_once_with(0.5)
    async_result.get.assert_called_once_with()


def test_run_on_pool_uses_pool_wait_when_no_socket_timeout(mocker):
    import tls.schannel.socket_adapter as adapter

    sock = mocker.Mock()
    async_result = mocker.Mock()
    async_result.get.return_value = None

    mocker.patch.object(
        adapter,
        '_get_thread_pool',
        return_value=mocker.Mock(spawn=lambda worker: async_result),
    )

    adapter._run_on_pool(sock, None, lambda: None, pool_wait=42.0)
    async_result.get.assert_called_once_with(timeout=42.0)


def test_schannel_socket_recv_waits_without_gevent_timeout(mocker):
    import tls.schannel.socket_adapter as adapter

    raw = mocker.Mock()
    session = mocker.Mock()
    session.recv_clear.return_value = b'x'
    sock = adapter.SchannelSocket(raw, session, ('1.2.3.4', 1))
    sock.settimeout(0.1)

    async_result = mocker.Mock()
    async_result.get.return_value = b'x'
    spawn = mocker.Mock(return_value=async_result)
    mocker.patch.object(adapter, '_get_thread_pool', return_value=mocker.Mock(spawn=spawn))

    assert sock.recv(4096) == b'x'
    async_result.get.assert_called_once_with()


def test_name_matches_exact_only(mocker):
    from tls.schannel import store as store_mod

    mocker.patch.object(store_mod.win32, 'CERT_NAME_FRIENDLY_DISPLAY_TYPE', 5)
    mocker.patch.object(store_mod.win32, 'CERT_NAME_SIMPLE_DISPLAY_TYPE', 4)
    mocker.patch.object(
        store_mod,
        '_cert_get_name_string',
        side_effect=lambda ctx, typ: (
            'Host Display' if typ == 5 else 'host.example.com'
        ),
    )
    ctx = object()

    assert store_mod._evaluate_name_match('host.example.com', ctx) == store_mod._MATCH_SIMPLE
    assert store_mod._evaluate_name_match('HOST.EXAMPLE.COM', ctx) == store_mod._MATCH_SIMPLE
    assert store_mod._evaluate_name_match('  host.example.com  ', ctx) == store_mod._MATCH_SIMPLE
    assert store_mod._evaluate_name_match('Host Display', ctx) == store_mod._MATCH_FRIENDLY
    assert store_mod._match_via_label(store_mod._MATCH_SIMPLE) == 'SimpleName'
    assert store_mod._match_via_label(store_mod._MATCH_FRIENDLY) == 'FriendlyName'
    assert store_mod._match_via_label(0) == 'no match'
    # Substring / wildcard-style values must not match.
    assert store_mod._evaluate_name_match('host', ctx) == 0
    assert store_mod._evaluate_name_match('*.example.com', ctx) == 0
    assert store_mod._evaluate_name_match('host*', ctx) == 0
    assert store_mod._evaluate_name_match('', ctx) == 0
    assert store_mod._evaluate_name_match('other.example.com', ctx) == 0


def test_name_matches_friendly_when_distinct_from_simple(mocker):
    from tls.schannel import store as store_mod

    mocker.patch.object(store_mod.win32, 'CERT_NAME_FRIENDLY_DISPLAY_TYPE', 5)
    mocker.patch.object(store_mod.win32, 'CERT_NAME_SIMPLE_DISPLAY_TYPE', 4)
    mocker.patch.object(
        store_mod,
        '_cert_get_name_string',
        side_effect=lambda ctx, typ: (
            'My Server Cert' if typ == 5 else 'cn.example.com'
        ),
    )
    ctx = object()

    assert store_mod._evaluate_name_match('My Server Cert', ctx) == store_mod._MATCH_FRIENDLY
    assert store_mod._evaluate_name_match('My Server', ctx) == 0


def _make_schannel_session(mocker, *, check_client_cert=True):
    import tls.schannel.session as session_mod

    mocker.patch.object(session_mod.win32, 'ensure_win32')
    mocker.patch.object(session_mod.win32, 'CtxtHandle', return_value=mocker.Mock())
    return session_mod.SchannelServerSession(
        mocker.Mock(), mocker.Mock(), check_client_cert=check_client_cert,
    )


def test_getpeercert_reads_cached_peer_der(mocker):
    import tls.schannel.socket_adapter as adapter

    session = mocker.Mock()
    session._peer_der = None
    sock = adapter.SchannelSocket(mocker.Mock(), session, ('1.2.3.4', 1))

    run_pool = mocker.patch.object(adapter, '_run_on_pool')
    assert sock.getpeercert() is None
    run_pool.assert_not_called()


def test_decrypt_more_fails_and_logs_on_renegotiate(mocker, caplog):
    import logging

    import tls.schannel.session as session_mod
    from tls.schannel.errors import SchannelError

    sess = _make_schannel_session(mocker, check_client_cert=False)
    sess.sizes = mocker.Mock()
    sess._buf = bytearray(b'ciphertext')

    mocker.patch.object(
        session_mod.win32, 'create_string_buffer', return_value=mocker.Mock(),
    )
    mocker.patch.object(session_mod.win32, 'SecBuffer', return_value=mocker.Mock())
    mocker.patch.object(session_mod.win32, 'SecBufferDesc', return_value=mocker.Mock())
    mocker.patch.object(session_mod.win32, 'cast', return_value=None)
    mocker.patch.object(session_mod.win32, 'byref', lambda x: x)
    mocker.patch.object(session_mod.win32, 'POINTER', lambda _t: mocker.Mock)
    mocker.patch.object(session_mod.win32, 'SECBUFFER_DATA', 1)
    mocker.patch.object(session_mod.win32, 'SECBUFFER_EMPTY', 0)
    mocker.patch.object(session_mod.win32, 'SECBUFFER_VERSION', 0)
    mocker.patch.object(session_mod.win32, 'SEC_E_INCOMPLETE_MESSAGE', 0x80090318)
    mocker.patch.object(session_mod.win32, 'SEC_I_CONTEXT_EXPIRED', 0x00090317)
    mocker.patch.object(session_mod.win32, 'SEC_I_RENEGOTIATE', 0x00090321)
    mocker.patch.object(session_mod.win32, 'SEC_E_OK', 0)

    mock_secur32 = mocker.Mock()
    mock_secur32.DecryptMessage.return_value = 0x00090321
    mocker.patch.object(session_mod.win32, 'secur32', mock_secur32)

    with caplog.at_level(logging.ERROR, logger='tls'):
        with pytest.raises(SchannelError, match='does not support renegotiation'):
            sess._decrypt_more()
    assert 'renegotiation' in caplog.text
    assert '0x00090321' in caplog.text
