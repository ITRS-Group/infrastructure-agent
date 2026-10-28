"""
Mocked Schannel socket adapter unit tests (Linux-runnable).

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import socket as socket_mod
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tls.schannel.errors import SchannelError
from tls.schannel.socket_adapter import (
    SchannelSocket,
    _get_raw_socket_type,
    _reraise_from_pool,
    peercert_dict_from_der,
)


def _make_cert_der(*, cn='peer.example.com', san_dns=None, san_ip=None):
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
    )
    san_entries = []
    if san_dns:
        san_entries.append(x509.DNSName(san_dns))
    if san_ip:
        san_entries.append(x509.IPAddress(san_ip))
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False,
        )
    cert = builder.sign(key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.DER)


def test_get_raw_socket_type_propagates_get_original_failure(mocker):
    import tls.schannel.socket_adapter as adapter

    fake_monkey = mocker.Mock()
    fake_monkey.get_original.side_effect = RuntimeError('not patched')
    mocker.patch.object(adapter, 'gevent_monkey', fake_monkey)

    with pytest.raises(RuntimeError, match='not patched'):
        _get_raw_socket_type()


def test_get_raw_socket_type_gevent_original(mocker):
    import tls.schannel.socket_adapter as adapter

    raw_cls = type('RawSocket', (), {})
    fake_monkey = mocker.Mock()
    fake_monkey.get_original.return_value = raw_cls
    mocker.patch.object(adapter, 'gevent_monkey', fake_monkey)

    assert _get_raw_socket_type() is raw_cls


def test_reraise_from_pool_direct_schannel_error():
    err = SchannelError('direct')
    with pytest.raises(SchannelError, match='direct'):
        _reraise_from_pool(err)


def test_reraise_from_pool_direct_timeout():
    err = socket_mod.timeout('timed out')
    with pytest.raises(socket_mod.timeout):
        _reraise_from_pool(err)


def test_reraise_from_pool_unwraps_schannel_cause():
    root = SchannelError('inner')
    outer = RuntimeError('outer')
    outer.__cause__ = root
    with pytest.raises(SchannelError, match='inner') as ei:
        _reraise_from_pool(outer)
    assert ei.value.__cause__ is outer


def test_reraise_from_pool_unwraps_timeout_context():
    root = socket_mod.timeout('inner')
    outer = RuntimeError('outer')
    outer.__context__ = root
    with pytest.raises(socket_mod.timeout):
        _reraise_from_pool(outer)


def test_reraise_from_pool_reraises_unknown():
    with pytest.raises(ValueError, match='nope'):
        _reraise_from_pool(ValueError('nope'))


def test_peercert_dict_san_ip():
    der = _make_cert_der(san_ip=ip_address('192.168.1.1'))
    d = peercert_dict_from_der(der)
    assert ('IP Address', '192.168.1.1') in d['subjectAltName']


def test_peercert_dict_skips_non_dns_non_ip_san():
    """SAN entries that are neither DNS nor IP are omitted from the ssl-like dict."""
    key = rsa.generate_private_key(65537, 2048, default_backend())
    now = datetime.now(timezone.utc)
    cn = 'peer.example.com'
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(cn),
                x509.RFC822Name('ops@example.com'),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    d = peercert_dict_from_der(der)
    assert d['subjectAltName'] == (('DNS', cn),)


def test_peercert_dict_no_san_extension():
    der = _make_cert_der(cn='only-cn.example.com')
    d = peercert_dict_from_der(der)
    assert 'subjectAltName' not in d
    assert d['subject']


def test_wrap_accepted_success(mocker):
    import tls.schannel.socket_adapter as adapter

    pool = mocker.Mock()
    pool.spawn.return_value.get.return_value = None
    mocker.patch.object(adapter, '_get_thread_pool', return_value=pool)

    raw_sock = mocker.Mock()
    mocker.patch.object(adapter, '_RawSocket', return_value=raw_sock)

    session = mocker.Mock()
    mocker.patch.object(adapter, 'SchannelServerSession', return_value=session)

    conn = mocker.Mock()
    conn.fileno.return_value = 7
    conn.getpeername.return_value = ('10.0.0.1', 5666)

    wrapped = SchannelSocket.wrap_accepted(conn, cred=object(), handshake_timeout=5.0)

    conn.detach.assert_called_once()
    session.handshake.assert_not_called()
    pool.spawn.assert_called_once()
    assert wrapped.getpeername() == ('10.0.0.1', 5666)
    assert wrapped._session is session


def test_wrap_accepted_detach_oserror_ignored(mocker):
    import tls.schannel.socket_adapter as adapter

    pool = mocker.Mock()
    pool.spawn.return_value.get.return_value = None
    mocker.patch.object(adapter, '_get_thread_pool', return_value=pool)
    mocker.patch.object(adapter, '_RawSocket', return_value=mocker.Mock())
    mocker.patch.object(adapter, 'SchannelServerSession', return_value=mocker.Mock())

    conn = mocker.Mock()
    conn.fileno.return_value = 7
    conn.getpeername.return_value = ('10.0.0.1', 5666)
    conn.detach.side_effect = OSError('no detach')

    SchannelSocket.wrap_accepted(conn, cred=object(), handshake_timeout=1.0)


def test_wrap_accepted_raw_socket_failure_propagates(mocker):
    import tls.schannel.socket_adapter as adapter

    mocker.patch.object(adapter, '_RawSocket', side_effect=OSError('bad fd'))

    conn = mocker.Mock()
    conn.fileno.return_value = 7
    conn.getpeername.return_value = ('10.0.0.1', 5666)

    with pytest.raises(OSError, match='bad fd'):
        SchannelSocket.wrap_accepted(conn, cred=object(), handshake_timeout=1.0)


def test_wrap_accepted_timeout_closes_session(mocker):
    import tls.schannel.socket_adapter as adapter

    pool = mocker.Mock()
    pool.spawn.return_value.get.side_effect = socket_mod.timeout('handshake slow')
    mocker.patch.object(adapter, '_get_thread_pool', return_value=pool)
    mocker.patch.object(adapter, '_RawSocket', return_value=mocker.Mock())

    session = mocker.Mock()
    mocker.patch.object(adapter, 'SchannelServerSession', return_value=session)

    with pytest.raises(socket_mod.timeout):
        SchannelSocket.wrap_accepted(mocker.Mock(), cred=object(), handshake_timeout=0.1)

    session.close.assert_called_once()


def test_wrap_accepted_generic_exception_wraps(mocker):
    import tls.schannel.socket_adapter as adapter

    pool = mocker.Mock()
    pool.spawn.return_value.get.side_effect = RuntimeError('boom')
    mocker.patch.object(adapter, '_get_thread_pool', return_value=pool)
    mocker.patch.object(adapter, '_RawSocket', return_value=mocker.Mock())

    session = mocker.Mock()
    mocker.patch.object(adapter, 'SchannelServerSession', return_value=session)

    with pytest.raises(SchannelError, match='Schannel handshake failed: boom'):
        SchannelSocket.wrap_accepted(mocker.Mock(), cred=object(), handshake_timeout=1.0)

    session.close.assert_called_once()


def test_wrap_accepted_close_failure_ignored(mocker):
    """Handshake failure still surfaces when session.close() also fails."""
    import tls.schannel.socket_adapter as adapter

    pool = mocker.Mock()
    pool.spawn.return_value.get.side_effect = SchannelError('handshake failed')
    mocker.patch.object(adapter, '_get_thread_pool', return_value=pool)
    mocker.patch.object(adapter, '_RawSocket', return_value=mocker.Mock())

    session = mocker.Mock()
    session.close.side_effect = RuntimeError('close failed')
    mocker.patch.object(adapter, 'SchannelServerSession', return_value=session)

    with pytest.raises(SchannelError, match='handshake failed'):
        SchannelSocket.wrap_accepted(mocker.Mock(), cred=object(), handshake_timeout=1.0)


def test_wrap_accepted_unwraps_nested_schannel_error(mocker):
    """Generic pool wrapper with SchannelError cause re-raises the inner error."""
    import tls.schannel.socket_adapter as adapter

    pool = mocker.Mock()
    outer = RuntimeError('pool wrapper')
    outer.__cause__ = SchannelError('inner handshake')
    pool.spawn.return_value.get.side_effect = outer
    mocker.patch.object(adapter, '_get_thread_pool', return_value=pool)
    mocker.patch.object(adapter, '_RawSocket', return_value=mocker.Mock())
    mocker.patch.object(adapter, 'SchannelServerSession', return_value=mocker.Mock())

    with pytest.raises(SchannelError, match='inner handshake') as ei:
        SchannelSocket.wrap_accepted(mocker.Mock(), cred=object(), handshake_timeout=1.0)
    assert ei.value.__cause__ is outer


def test_settimeout_swallows_oserror(mocker):
    import tls.schannel.socket_adapter as adapter

    raw = mocker.Mock()
    raw.settimeout.side_effect = OSError('bad fd')
    sock = adapter.SchannelSocket(raw, mocker.Mock(), ('1.2.3.4', 1))

    sock.settimeout(5.0)
    assert sock._timeout == 5.0


def test_getpeercert_binary_form(mocker):
    import tls.schannel.socket_adapter as adapter

    der = b'cert-der'
    session = mocker.Mock()
    session._peer_der = der
    sock = adapter.SchannelSocket(mocker.Mock(), session, ('1.2.3.4', 1))

    assert sock.getpeercert(binary_form=True) == der


def test_getpeercert_returns_none_when_missing(mocker):
    import tls.schannel.socket_adapter as adapter

    session = mocker.Mock()
    session._peer_der = None
    sock = adapter.SchannelSocket(mocker.Mock(), session, ('1.2.3.4', 1))

    assert sock.getpeercert() is None


def test_recv_pool_errors_surface(mocker):
    import tls.schannel.socket_adapter as adapter

    sock = adapter.SchannelSocket(mocker.Mock(), mocker.Mock(), ('1.2.3.4', 1))

    mocker.patch.object(adapter, '_run_on_pool', side_effect=socket_mod.timeout('recv slow'))
    with pytest.raises(socket_mod.timeout):
        sock.recv(16)

    mocker.patch.object(adapter, '_run_on_pool', side_effect=ValueError('pool wrap'))
    with pytest.raises(ValueError, match='pool wrap'):
        sock.recv(16)


def test_sendall_pool_errors_surface(mocker):
    import tls.schannel.socket_adapter as adapter

    sock = adapter.SchannelSocket(mocker.Mock(), mocker.Mock(), ('1.2.3.4', 1))

    mocker.patch.object(adapter, '_run_on_pool', side_effect=SchannelError('send failed'))
    with pytest.raises(SchannelError, match='send failed'):
        sock.sendall(b'x')

    mocker.patch.object(adapter, '_run_on_pool', side_effect=ValueError('pool wrap'))
    with pytest.raises(ValueError, match='pool wrap'):
        sock.sendall(b'x')


def test_version_and_cipher(mocker):
    import tls.schannel.socket_adapter as adapter

    session = mocker.Mock()
    session._protocol_name = 'TLS 1.2'
    session._cipher_tuple = ('AES128-GCM', 'TLS 1.2', 128)
    sock = adapter.SchannelSocket(mocker.Mock(), session, ('1.2.3.4', 1))

    assert sock.version() == 'TLS 1.2'
    assert sock.cipher() == ('AES128-GCM', 'TLS 1.2', 128)


def test_sendall_coerces_non_bytes(mocker):
    import tls.schannel.socket_adapter as adapter

    session = mocker.Mock()
    mocker.patch.object(adapter, '_run_on_pool', return_value=None)

    sock = adapter.SchannelSocket(mocker.Mock(), session, ('1.2.3.4', 1))
    sock.sendall(bytearray(b'abc'))

    adapter._run_on_pool.assert_called_once()


def test_close_uses_pool(mocker):
    import tls.schannel.socket_adapter as adapter

    session = mocker.Mock()
    mocker.patch.object(adapter, '_run_on_pool', return_value=None)

    sock = adapter.SchannelSocket(mocker.Mock(), session, ('1.2.3.4', 1))
    sock.close()

    adapter._run_on_pool.assert_called_once()


def test_close_falls_back_when_pool_fails(mocker):
    import tls.schannel.socket_adapter as adapter

    session = mocker.Mock()
    mocker.patch.object(adapter, '_run_on_pool', side_effect=RuntimeError('pool dead'))

    sock = adapter.SchannelSocket(mocker.Mock(), session, ('1.2.3.4', 1))
    sock.close()

    session.close.assert_called_once()


def test_close_swallows_when_fallback_also_fails(mocker):
    import tls.schannel.socket_adapter as adapter

    session = mocker.Mock()
    session.close.side_effect = RuntimeError('close dead')
    mocker.patch.object(adapter, '_run_on_pool', side_effect=RuntimeError('pool dead'))

    sock = adapter.SchannelSocket(mocker.Mock(), session, ('1.2.3.4', 1))
    sock.close()  # must not raise

    session.close.assert_called_once()
