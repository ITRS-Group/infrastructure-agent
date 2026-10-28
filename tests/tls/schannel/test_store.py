"""
Linux-runnable unit tests for tls.schannel.store certificate lookup.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tls.schannel.errors import SchannelError


def _make_cert_der(
        cn='server.example.com',
        *,
        not_after=None,
        display_cn=None,
):
    key = rsa.generate_private_key(65537, 2048, default_backend())
    now = datetime.now(timezone.utc)
    subject_cn = display_cn or cn
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(not_after or (now + timedelta(days=30)))
    )
    cert = builder.sign(key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.DER)


def _load_win32_bindings(mocker):
    """Load real ctypes structures with mocked crypt32/secur32/kernel32 DLLs."""
    import tls.schannel.win32 as win32_mod

    win32_mod._win32_loaded = False
    crypt32 = mocker.Mock(name='crypt32')
    secur32 = mocker.Mock(name='secur32')
    kernel32 = mocker.Mock(name='kernel32')

    def fake_windll(name, use_last_error=True):
        return {'crypt32': crypt32, 'secur32': secur32, 'kernel32': kernel32}[name]

    mocker.patch('ctypes.WinDLL', create=True, side_effect=fake_windll)
    mocker.patch.object(win32_mod.sys, 'platform', 'win32')
    win32_mod.ensure_win32()
    return win32_mod, crypt32, secur32, kernel32


def _cert_context_ptr(win32_mod, der: bytes):
    """Build a CERT_CONTEXT pointer backed by real DER bytes in memory."""
    buf = (win32_mod.c_char * len(der)).from_buffer_copy(der)
    ctx = win32_mod.CERT_CONTEXT(
        cbCertEncoded=len(der),
        pbCertEncoded=win32_mod.cast(buf, win32_mod.c_void_p),
    )
    return win32_mod.pointer(ctx), buf


def test_thumbprint_bytes_strips_separators():
    from tls.schannel.store import _thumbprint_bytes

    raw = bytes.fromhex('aabbccddeeff00112233445566778899aabbccdd')
    assert _thumbprint_bytes('AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD') == raw
    assert _thumbprint_bytes('aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd') == raw


def testder_of_reads_encoded_certificate(mocker):
    from tls.schannel import store as store_mod

    win32_mod, *_ = _load_win32_bindings(mocker)
    der = _make_cert_der()
    ctx, _buf = _cert_context_ptr(win32_mod, der)

    assert store_mod.der_of(ctx) == der


def test_cert_get_name_string_from_crypt32(mocker):
    from tls.schannel import store as store_mod
    from tls.schannel import win32 as win32_mod

    _win32, crypt32, *_ = _load_win32_bindings(mocker)
    ctx, _buf = _cert_context_ptr(_win32, _make_cert_der())

    def fake_get_name(_ctx, typ, _flags, _para, buf, size):
        if typ == win32_mod.CERT_NAME_FRIENDLY_DISPLAY_TYPE:
            value = 'web server'
        else:
            value = 'host.example.com'
        needed = len(value) + 1
        if not buf or size == 0:
            return needed
        buf.value = value
        return needed

    crypt32.CertGetNameStringW.side_effect = fake_get_name

    assert store_mod._cert_get_name_string(
        ctx, win32_mod.CERT_NAME_FRIENDLY_DISPLAY_TYPE,
    ) == 'web server'
    assert store_mod._cert_get_name_string(
        ctx, win32_mod.CERT_NAME_SIMPLE_DISPLAY_TYPE,
    ) == 'host.example.com'


def test_cert_get_name_string_empty_when_crypt32_returns_short(mocker):
    from tls.schannel import store as store_mod
    from tls.schannel import win32 as win32_mod

    _win32, crypt32, *_ = _load_win32_bindings(mocker)
    ctx, _buf = _cert_context_ptr(_win32, _make_cert_der())
    crypt32.CertGetNameStringW.return_value = 1

    assert store_mod._cert_get_name_string(
        ctx, win32_mod.CERT_NAME_SIMPLE_DISPLAY_TYPE,
    ) == ''
    crypt32.CertGetNameStringW.assert_called_once_with(
        ctx, win32_mod.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None, 0,
    )


def test_cert_get_name_string_empty_when_second_call_short(mocker):
    from tls.schannel import store as store_mod
    from tls.schannel import win32 as win32_mod

    _win32, crypt32, *_ = _load_win32_bindings(mocker)
    ctx, _buf = _cert_context_ptr(_win32, _make_cert_der())

    def fake_get_name(_ctx, _typ, _flags, _para, buf, size):
        if not buf or size == 0:
            return 8
        return 1

    crypt32.CertGetNameStringW.side_effect = fake_get_name

    assert store_mod._cert_get_name_string(
        ctx, win32_mod.CERT_NAME_SIMPLE_DISPLAY_TYPE,
    ) == ''


def test_cert_get_name_string_sizes_buffer_for_long_names(mocker):
    from tls.schannel import store as store_mod
    from tls.schannel import win32 as win32_mod

    _win32, crypt32, *_ = _load_win32_bindings(mocker)
    ctx, _buf = _cert_context_ptr(_win32, _make_cert_der())
    long_name = 'x' * 400

    def fake_get_name(_ctx, _typ, _flags, _para, buf, size):
        needed = len(long_name) + 1
        if not buf or size == 0:
            return needed
        assert size == needed
        buf.value = long_name
        return needed

    crypt32.CertGetNameStringW.side_effect = fake_get_name

    assert store_mod._cert_get_name_string(
        ctx, win32_mod.CERT_NAME_FRIENDLY_DISPLAY_TYPE,
    ) == long_name
    assert crypt32.CertGetNameStringW.call_count == 2


def test_cert_not_after_uses_utc_attribute(mocker):
    from tls.schannel import store as store_mod

    win32_mod, *_ = _load_win32_bindings(mocker)
    expiry = datetime.now(timezone.utc) + timedelta(days=10)
    der = _make_cert_der(not_after=expiry)
    ctx, _buf = _cert_context_ptr(win32_mod, der)

    got = store_mod._cert_not_after(ctx)
    # cryptography normalises not_after to whole seconds in DER round-trip.
    assert got.replace(microsecond=0) == expiry.replace(microsecond=0)


def _fake_name_string_from_cn(store_mod, win32_mod, crypt32, friendly_by_cn=None):
    """Mock names: override FriendlyName by CN when set; else both equal DER CN."""
    friendly_by_cn = friendly_by_cn or {}

    def fake_get_name(ctx, typ, _flags, _para, buf, size):
        der = store_mod.der_of(ctx)
        cert = x509.load_der_x509_certificate(der)
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = attrs[0].value if attrs else ''
        if typ == win32_mod.CERT_NAME_FRIENDLY_DISPLAY_TYPE:
            value = friendly_by_cn.get(cn, cn)
        else:
            value = cn
        if not value:
            return 1
        needed = len(value) + 1
        if not buf or size == 0:
            return needed
        buf.value = value
        return needed

    crypt32.CertGetNameStringW.side_effect = fake_get_name


def test_find_store_cert_skips_non_matching_thumbprint(mocker):
    from tls.schannel import store as store_mod

    win32_mod, crypt32, _, _kernel32 = _load_win32_bindings(mocker)

    der_match = _make_cert_der()
    der_other = _make_cert_der(cn='other.example.com')
    thumb = hashlib.sha1(der_match).hexdigest()
    ctx_other, _ = _cert_context_ptr(win32_mod, der_other)
    ctx_match, _ = _cert_context_ptr(win32_mod, der_match)
    duplicate = object()

    crypt32.CertOpenStore.return_value = object()
    crypt32.CertEnumCertificatesInStore.side_effect = [ctx_other, ctx_match, None]
    crypt32.CertDuplicateCertificateContext.return_value = duplicate

    assert store_mod.find_store_cert(thumb) is duplicate
    crypt32.CertFreeCertificateContext.assert_called_once_with(ctx_match)


def test_find_store_cert_by_name_skips_non_match_and_ignores_older(mocker):
    from tls.schannel import store as store_mod
    from tls.schannel import win32 as win32_names

    win32_mod, crypt32, _, _kernel32 = _load_win32_bindings(mocker)

    now = datetime.now(timezone.utc)
    der_skip = _make_cert_der(cn='other.example.com')
    der_newer = _make_cert_der(cn='chosen.example.com', not_after=now + timedelta(days=90))
    der_older = _make_cert_der(cn='chosen.example.com', not_after=now + timedelta(days=10))
    ctx_skip, _ = _cert_context_ptr(win32_mod, der_skip)
    ctx_newer, _ = _cert_context_ptr(win32_mod, der_newer)
    ctx_older, _ = _cert_context_ptr(win32_mod, der_older)
    dup_newer = object()

    crypt32.CertOpenStore.return_value = object()
    crypt32.CertEnumCertificatesInStore.side_effect = [ctx_skip, ctx_newer, ctx_older, None]
    crypt32.CertDuplicateCertificateContext.return_value = dup_newer
    _fake_name_string_from_cn(store_mod, win32_names, crypt32)

    found = store_mod.find_store_cert_by_name('chosen.example.com')

    assert found is dup_newer
    crypt32.CertFreeCertificateContext.assert_not_called()
    crypt32.CertOpenStore.assert_called_once_with(
        win32_mod.CERT_STORE_PROV_SYSTEM_W,
        0,
        None,
        win32_mod.CERT_SYSTEM_STORE_LOCAL_MACHINE |
        win32_mod.CERT_STORE_READONLY_FLAG |
        win32_mod.CERT_STORE_OPEN_EXISTING_FLAG,
        'MY',
    )


def test_find_store_cert_by_name_prefers_friendly_name(mocker):
    from tls.schannel import store as store_mod
    from tls.schannel import win32 as win32_names

    win32_mod, crypt32, _, _kernel32 = _load_win32_bindings(mocker)

    now = datetime.now(timezone.utc)
    # Same CN; FriendlyName distinguishes. Older FriendlyName match must still win
    # over a newer simple-display-only match.
    der_friendly = _make_cert_der(
        cn='host.example.com',
        not_after=now + timedelta(days=10),
    )
    der_other = _make_cert_der(
        cn='host.example.com',
        not_after=now + timedelta(days=90),
    )
    ctx_friendly, _ = _cert_context_ptr(win32_mod, der_friendly)
    ctx_other, _ = _cert_context_ptr(win32_mod, der_other)
    dup_friendly = object()

    crypt32.CertOpenStore.return_value = object()
    crypt32.CertEnumCertificatesInStore.side_effect = [ctx_other, ctx_friendly, None]
    crypt32.CertDuplicateCertificateContext.return_value = dup_friendly

    # Same CN: bind FriendlyName by ctx id (enumeration order alone is not enough).
    names = {
        id(ctx_other): ('DC cert', 'host.example.com'),
        id(ctx_friendly): ('web server', 'host.example.com'),
    }

    def fake_get_name(ctx, typ, _flags, _para, buf, size):
        friendly, simple = names[id(ctx)]
        value = friendly if typ == win32_names.CERT_NAME_FRIENDLY_DISPLAY_TYPE else simple
        needed = len(value) + 1
        if not buf or size == 0:
            return needed
        buf.value = value
        return needed

    crypt32.CertGetNameStringW.side_effect = fake_get_name

    found = store_mod.find_store_cert_by_name('web server')
    assert found is dup_friendly


def test_find_store_cert_open_failure(mocker):
    from tls.schannel import store as store_mod

    _win32_mod, crypt32, _, kernel32 = _load_win32_bindings(mocker)

    crypt32.CertOpenStore.return_value = None
    kernel32.GetLastError.return_value = 5

    with pytest.raises(SchannelError, match='cannot open LocalMachine certificate stores'):
        store_mod.find_store_cert('AABBCCDD', store_name='MY')


def test_find_store_cert_not_found(mocker):
    from tls.schannel import store as store_mod

    win32_mod, crypt32, _, _kernel32 = _load_win32_bindings(mocker)

    store_handle = object()
    crypt32.CertOpenStore.return_value = store_handle
    crypt32.CertEnumCertificatesInStore.return_value = None

    with pytest.raises(SchannelError, match='server.tls.schannel.identity_cert_thumbprint'):
        store_mod.find_store_cert('00112233445566778899AABBCCDDEEFF00112233')
    crypt32.CertFreeCertificateContext.assert_not_called()


def test_find_store_cert_success_by_thumbprint(mocker, caplog):
    from tls.schannel import store as store_mod

    win32_mod, crypt32, _, _kernel32 = _load_win32_bindings(mocker)

    der = _make_cert_der()
    thumb = hashlib.sha1(der).hexdigest()
    ctx, _buf = _cert_context_ptr(win32_mod, der)
    duplicate = object()

    store_handle = object()
    crypt32.CertOpenStore.return_value = store_handle
    crypt32.CertEnumCertificatesInStore.side_effect = [ctx, None]
    crypt32.CertDuplicateCertificateContext.return_value = duplicate

    with caplog.at_level(logging.DEBUG, logger='tls'):
        found = store_mod.find_store_cert(thumb, store_name='my')

    assert found is duplicate
    crypt32.CertFreeCertificateContext.assert_called_once_with(ctx)
    crypt32.CertCloseStore.assert_called_once_with(store_handle, 0)
    crypt32.CertOpenStore.assert_called_once_with(
        win32_mod.CERT_STORE_PROV_SYSTEM_W,
        0,
        None,
        win32_mod.CERT_SYSTEM_STORE_LOCAL_MACHINE |
        win32_mod.CERT_STORE_READONLY_FLAG |
        win32_mod.CERT_STORE_OPEN_EXISTING_FLAG,
        'MY',
    )
    assert 'cert_thumbprint' in caplog.text


def test_find_store_cert_by_name_open_failure(mocker):
    from tls.schannel import store as store_mod

    _win32_mod, crypt32, _, kernel32 = _load_win32_bindings(mocker)

    crypt32.CertOpenStore.return_value = None
    kernel32.GetLastError.return_value = 2

    with pytest.raises(SchannelError, match='usually MY'):
        store_mod.find_store_cert_by_name('host.example.com')


def test_find_store_cert_by_name_not_found(mocker):
    from tls.schannel import store as store_mod

    _win32_mod, crypt32, _, _kernel32 = _load_win32_bindings(mocker)

    crypt32.CertOpenStore.return_value = object()
    crypt32.CertEnumCertificatesInStore.return_value = None

    with pytest.raises(SchannelError, match='server.tls.schannel.identity_cert_name'):
        store_mod.find_store_cert_by_name('missing.example.com')


def test_find_store_cert_by_name_picks_latest_not_after(mocker, caplog):
    from tls.schannel import store as store_mod
    from tls.schannel import win32 as win32_names

    win32_mod, crypt32, _, _kernel32 = _load_win32_bindings(mocker)

    now = datetime.now(timezone.utc)
    der_old = _make_cert_der(cn='pick-me.example.com', not_after=now + timedelta(days=5))
    der_new = _make_cert_der(cn='pick-me.example.com', not_after=now + timedelta(days=60))
    ctx_old, _ = _cert_context_ptr(win32_mod, der_old)
    ctx_new, _ = _cert_context_ptr(win32_mod, der_new)
    dup_old = object()
    dup_new = object()

    crypt32.CertOpenStore.return_value = object()
    crypt32.CertEnumCertificatesInStore.side_effect = [ctx_old, ctx_new, None]
    crypt32.CertDuplicateCertificateContext.side_effect = [dup_old, dup_new]
    _fake_name_string_from_cn(store_mod, win32_names, crypt32)

    with caplog.at_level(logging.INFO, logger='tls'):
        found = store_mod.find_store_cert_by_name('pick-me.example.com')

    assert found is dup_new
    crypt32.CertFreeCertificateContext.assert_called_once_with(dup_old)
    assert 'via FriendlyName' in caplog.text
    assert 'NotAfter=' in caplog.text


def test_find_store_cert_by_name_logs_candidates_and_friendly_selection(mocker, caplog):
    from tls.schannel import store as store_mod
    from tls.schannel import win32 as win32_names

    win32_mod, crypt32, _, _kernel32 = _load_win32_bindings(mocker)

    now = datetime.now(timezone.utc)
    der_other = _make_cert_der(
        cn='host.example.com',
        not_after=now + timedelta(days=90),
    )
    der_friendly = _make_cert_der(
        cn='host.example.com',
        not_after=now + timedelta(days=10),
    )
    ctx_other, _ = _cert_context_ptr(win32_mod, der_other)
    ctx_friendly, _ = _cert_context_ptr(win32_mod, der_friendly)
    dup = object()

    crypt32.CertOpenStore.return_value = object()
    crypt32.CertEnumCertificatesInStore.side_effect = [ctx_other, ctx_friendly, None]
    crypt32.CertDuplicateCertificateContext.return_value = dup
    names = {
        id(ctx_other): ('DC cert', 'host.example.com'),
        id(ctx_friendly): ('web server', 'host.example.com'),
    }

    def fake_get_name(ctx, typ, _flags, _para, buf, size):
        friendly, simple = names[id(ctx)]
        value = friendly if typ == win32_names.CERT_NAME_FRIENDLY_DISPLAY_TYPE else simple
        needed = len(value) + 1
        if not buf or size == 0:
            return needed
        buf.value = value
        return needed

    crypt32.CertGetNameStringW.side_effect = fake_get_name

    with caplog.at_level(logging.DEBUG, logger='tls'):
        found = store_mod.find_store_cert_by_name('web server')

    assert found is dup
    assert 'candidate FriendlyName=' in caplog.text
    assert "FriendlyName='DC cert'" in caplog.text
    assert '-> no match' in caplog.text
    assert '-> FriendlyName' in caplog.text
    assert 'via FriendlyName' in caplog.text
    assert "FriendlyName='web server'" in caplog.text


def test_acquire_server_credential_rejects_ambiguous_identity(mocker):
    from tls.schannel import store as store_mod

    mocker.patch.object(store_mod.win32, 'ensure_win32')

    with pytest.raises(SchannelError, match='ambiguous'):
        store_mod.acquire_server_credential(thumbprint='AA', cert_name='host')


def test_acquire_server_credential_requires_identity(mocker):
    from tls.schannel import store as store_mod

    mocker.patch.object(store_mod.win32, 'ensure_win32')

    with pytest.raises(SchannelError, match='requires server.tls.schannel.identity_cert_name'):
        store_mod.acquire_server_credential()


def test_acquire_server_credential_by_name_success(mocker, caplog):
    from tls.schannel import store as store_mod

    win32_mod, _crypt32, secur32, _ = _load_win32_bindings(mocker)

    cert_ctx, _buf = _cert_context_ptr(win32_mod, _make_cert_der(cn='host.example.com'))
    mocker.patch.object(store_mod, 'find_store_cert_by_name', return_value=cert_ctx)
    secur32.AcquireCredentialsHandleW.return_value = win32_mod.SEC_E_OK

    with caplog.at_level(logging.INFO, logger='tls'):
        handle = store_mod.acquire_server_credential(cert_name='host.example.com', store_name='MY')

    assert isinstance(handle, win32_mod.CredHandle)
    assert handle._keep[1] is cert_ctx
    secur32.AcquireCredentialsHandleW.assert_called_once()
    assert 'server credential acquired' in caplog.text


def test_acquire_server_credential_by_thumbprint_success(mocker):
    from tls.schannel import store as store_mod

    win32_mod, _, secur32, _ = _load_win32_bindings(mocker)

    cert_ctx, _buf = _cert_context_ptr(win32_mod, _make_cert_der())
    mocker.patch.object(store_mod, 'find_store_cert', return_value=cert_ctx)
    secur32.AcquireCredentialsHandleW.return_value = win32_mod.SEC_E_OK

    handle = store_mod.acquire_server_credential(thumbprint='aa:bb cc', store_name='MY')
    assert isinstance(handle, win32_mod.CredHandle)


def test_acquire_server_credential_acquire_handle_failure(mocker):
    from tls.schannel import store as store_mod

    win32_mod, crypt32, secur32, _ = _load_win32_bindings(mocker)

    cert_ctx, _buf = _cert_context_ptr(win32_mod, _make_cert_der())
    mocker.patch.object(store_mod, 'find_store_cert', return_value=cert_ctx)
    secur32.AcquireCredentialsHandleW.return_value = 0x8009030D

    with pytest.raises(SchannelError, match='AcquireCredentialsHandle') as ei:
        store_mod.acquire_server_credential(thumbprint='AABB')

    crypt32.CertFreeCertificateContext.assert_called_once_with(cert_ctx)
    assert ei.value.winerror == 0x8009030D


def test_release_server_credential_frees_handle_and_cert(mocker):
    from tls.schannel import store as store_mod

    win32_mod, crypt32, secur32, _ = _load_win32_bindings(mocker)
    cert_ctx, _buf = _cert_context_ptr(win32_mod, _make_cert_der())
    mocker.patch.object(store_mod, 'find_store_cert', return_value=cert_ctx)
    secur32.AcquireCredentialsHandleW.return_value = win32_mod.SEC_E_OK
    secur32.FreeCredentialsHandle.return_value = win32_mod.SEC_E_OK

    handle = store_mod.acquire_server_credential(thumbprint='AABB')
    store_mod.release_server_credential(handle)

    secur32.FreeCredentialsHandle.assert_called_once()
    crypt32.CertFreeCertificateContext.assert_called_once_with(cert_ctx)
    assert handle._released is True
    assert handle._keep is None
    store_mod.release_server_credential(handle)
    secur32.FreeCredentialsHandle.assert_called_once()


def test_release_server_credential_keeps_cert_when_free_handle_fails(mocker):
    from tls.schannel import store as store_mod

    win32_mod, crypt32, secur32, _ = _load_win32_bindings(mocker)
    cert_ctx, _buf = _cert_context_ptr(win32_mod, _make_cert_der())
    mocker.patch.object(store_mod, 'find_store_cert', return_value=cert_ctx)
    secur32.AcquireCredentialsHandleW.return_value = win32_mod.SEC_E_OK
    secur32.FreeCredentialsHandle.return_value = 0x80090301

    handle = store_mod.acquire_server_credential(thumbprint='AABB')
    store_mod.release_server_credential(handle)

    crypt32.CertFreeCertificateContext.assert_not_called()
    assert handle._released is False
    assert handle._keep[1] is cert_ctx


def test_release_server_credential_without_kept_cert(mocker):
    from tls.schannel import store as store_mod

    win32_mod, crypt32, secur32, _ = _load_win32_bindings(mocker)
    secur32.FreeCredentialsHandle.return_value = win32_mod.SEC_E_OK
    handle = win32_mod.CredHandle()
    handle._released = False

    store_mod.release_server_credential(None)
    store_mod.release_server_credential(handle)

    crypt32.CertFreeCertificateContext.assert_not_called()
    assert handle._released is True
    assert handle._keep is None
