"""
Mocked Schannel SSPI contracts (Linux-runnable).

Locks EncryptMessage stream buffer layout and CompleteAuthToken ordering
without loading crypt32/secur32. Live Windows automation is separate.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import pytest

from tls.schannel.errors import SchannelError


class _FakeSecBufferMeta(type):
    def __mul__(cls, n):
        def factory(*items):
            assert len(items) == n
            return list(items)

        return factory


class FakeSecBuffer(metaclass=_FakeSecBufferMeta):
    def __init__(self, cbBuffer=0, BufferType=0, pvBuffer=None):
        self.cbBuffer = cbBuffer
        self.BufferType = BufferType
        self.pvBuffer = pvBuffer


class FakeSecBufferDesc:
    def __init__(self, ulVersion, cBuffers, pBuffers):
        self.ulVersion = ulVersion
        self.cBuffers = cBuffers
        self.pBuffers = pBuffers


class FakeAlertToken:
    def __init__(self, token_type, alert_type, alert_number):
        self.dwTokenType = token_type
        self.dwAlertType = alert_type
        self.dwAlertNumber = alert_number


def _patch_sspi_types(session_mod, mocker):
    """Stand-ins for ctypes SecBuffer / SecBufferDesc used by session I/O."""
    mocker.patch.object(session_mod.win32, 'SecBuffer', FakeSecBuffer)
    mocker.patch.object(session_mod.win32, 'SecBufferDesc', FakeSecBufferDesc)
    mocker.patch.object(session_mod.win32, 'SCHANNEL_ALERT_TOKEN', FakeAlertToken)
    mocker.patch.object(session_mod.win32, 'cast', side_effect=lambda x, _t: x)
    mocker.patch.object(session_mod.win32, 'pointer', side_effect=lambda x: x)
    mocker.patch.object(session_mod.win32, 'byref', side_effect=lambda x: x)
    mocker.patch.object(session_mod.win32, 'POINTER', side_effect=lambda _t: object)
    mocker.patch.object(session_mod.win32, 'c_void_p', object)

    def create_string_buffer(init, size=None):
        buf = mocker.Mock()
        if isinstance(init, (bytes, bytearray)):
            buf.raw = bytes(init)
        else:
            buf.raw = b'\x00' * int(init)
        return buf

    mocker.patch.object(session_mod.win32, 'create_string_buffer', side_effect=create_string_buffer)
    mocker.patch.object(session_mod.win32, 'SECBUFFER_VERSION', 0)
    mocker.patch.object(session_mod.win32, 'SECBUFFER_EMPTY', 0)
    mocker.patch.object(session_mod.win32, 'SECBUFFER_DATA', 1)
    mocker.patch.object(session_mod.win32, 'SECBUFFER_TOKEN', 2)
    mocker.patch.object(session_mod.win32, 'SECBUFFER_EXTRA', 5)
    mocker.patch.object(session_mod.win32, 'SECBUFFER_STREAM_TRAILER', 6)
    mocker.patch.object(session_mod.win32, 'SECBUFFER_STREAM_HEADER', 7)
    mocker.patch.object(session_mod.win32, 'SEC_E_OK', 0)
    mocker.patch.object(session_mod.win32, 'SEC_I_CONTINUE_NEEDED', 0x00090312)
    mocker.patch.object(session_mod.win32, 'SEC_I_COMPLETE_NEEDED', 0x00090313)
    mocker.patch.object(session_mod.win32, 'SEC_I_COMPLETE_AND_CONTINUE', 0x00090314)
    mocker.patch.object(session_mod.win32, 'SEC_E_INCOMPLETE_MESSAGE', 0x80090318)
    mocker.patch.object(session_mod.win32, 'ASC_REQ_MUTUAL_AUTH', 0x00000002)
    mocker.patch.object(session_mod.win32, 'ASC_REQ_BASE', 0x0001811C)
    mocker.patch.object(session_mod.win32, 'ASC_RET_STREAM', 0x00010000)
    mocker.patch.object(session_mod.win32, 'SECURITY_NATIVE_DREP', 0x10)
    mocker.patch.object(session_mod.win32, 'SECPKG_ATTR_STREAM_SIZES', 4)
    mocker.patch.object(session_mod.win32, 'SCHANNEL_ALERT', 2)
    mocker.patch.object(session_mod.win32, 'TLS1_ALERT_FATAL', 2)
    mocker.patch.object(session_mod.win32, 'TLS1_ALERT_CERTIFICATE_UNKNOWN', 46)
    mocker.patch.object(session_mod.win32, 'TLS1_ALERT_UNKNOWN_CA', 48)
    mocker.patch.object(session_mod.win32, 'TLS1_ALERT_BAD_CERTIFICATE', 42)
    mocker.patch.object(session_mod.win32, 'ULONG', lambda v=0: mocker.Mock(value=v))
    mocker.patch.object(session_mod.win32, 'FILETIME', lambda: mocker.Mock())
    mocker.patch.object(session_mod.win32, 'SecPkgContext_StreamSizes', lambda: mocker.Mock())


def grant_stream_attr(session_mod, accept_args) -> None:
    """Simulate Schannel setting ASC_RET_STREAM in pfContextAttr (args[7])."""
    accept_args[7].value |= session_mod.win32.ASC_RET_STREAM


def _make_session(mocker, *, check_client_cert=False):
    import tls.schannel.session as session_mod

    mocker.patch.object(session_mod.win32, 'ensure_win32')
    mocker.patch.object(session_mod.win32, 'CtxtHandle', return_value=mocker.Mock())
    _patch_sspi_types(session_mod, mocker)
    sock = mocker.Mock()
    sess = session_mod.SchannelServerSession(
        sock, mocker.Mock(), check_client_cert=check_client_cert,
    )
    return session_mod, sess, sock


def test_send_clear_encrypt_message_four_buffer_layout(mocker):
    """EncryptMessage must use STREAM_HEADER, DATA, STREAM_TRAILER, EMPTY."""
    session_mod, sess, sock = _make_session(mocker)
    sess.sizes = mocker.Mock(cbHeader=5, cbTrailer=7, cbMaximumMessage=64)
    captured = {}

    class TrackingMeta(_FakeSecBufferMeta):
        def __mul__(cls, n):
            def factory(*items):
                assert len(items) == n
                captured['bufs'] = list(items)
                return captured['bufs']

            return factory

    TrackingSecBuffer = TrackingMeta('TrackingSecBuffer', (FakeSecBuffer,), {})
    mocker.patch.object(session_mod.win32, 'SecBuffer', TrackingSecBuffer)

    def encrypt_message(_ctx, _qop, _desc, _seq):
        bufs = captured['bufs']
        assert [b.BufferType for b in bufs] == [
            session_mod.win32.SECBUFFER_STREAM_HEADER,
            session_mod.win32.SECBUFFER_DATA,
            session_mod.win32.SECBUFFER_STREAM_TRAILER,
            session_mod.win32.SECBUFFER_EMPTY,
        ]
        # Simulate Schannel writing actual sizes into cbBuffer.
        bufs[0].cbBuffer = 3
        bufs[1].cbBuffer = 4
        bufs[2].cbBuffer = 2
        return 0

    secur32 = mocker.Mock()
    secur32.EncryptMessage.side_effect = encrypt_message
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    sess.send_clear(b'abcd')

    secur32.EncryptMessage.assert_called_once()
    sock.sendall.assert_called_once()
    assert sock.sendall.call_args[0][0] == b'\x00\x00\x00' + b'abcd' + b'\x00\x00'


def test_handshake_complete_auth_token_before_free_and_send(mocker):
    """SEC_I_COMPLETE_NEEDED must CompleteAuthToken before FreeContextBuffer/send."""
    session_mod, sess, sock = _make_session(mocker, check_client_cert=False)
    sess._buf = bytearray(b'client-hello')
    order = []

    def accept_security_context(*args):
        grant_stream_attr(session_mod, args)
        order.append('AcceptSecurityContext')
        out_desc = args[6]
        out_buf = out_desc.pBuffers
        out_buf.cbBuffer = 4
        out_buf.pvBuffer = 0xABCD
        return session_mod.win32.SEC_I_COMPLETE_NEEDED

    def complete_auth_token(*_args):
        order.append('CompleteAuthToken')
        return 0

    def free_context_buffer(*_args):
        order.append('FreeContextBuffer')

    def query_context_attributes(*_args):
        order.append('QueryContextAttributesW')
        return 0

    secur32 = mocker.Mock()
    secur32.AcceptSecurityContext.side_effect = accept_security_context
    secur32.CompleteAuthToken.side_effect = complete_auth_token
    secur32.FreeContextBuffer.side_effect = free_context_buffer
    secur32.QueryContextAttributesW.side_effect = query_context_attributes
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(session_mod, '_string_at', return_value=b'out!')
    mocker.patch.object(sess, '_load_connection_info')
    mocker.patch.object(sess, '_load_peer_certificate')

    sess.handshake()

    assert order[:4] == [
        'AcceptSecurityContext',
        'CompleteAuthToken',
        'FreeContextBuffer',
        'QueryContextAttributesW',
    ]
    sock.sendall.assert_called_once_with(b'out!')
    assert sess.have_ctx is True


def test_handshake_always_requests_mutual_auth(mocker):
    """Request client cert always; presence is enforced separately."""
    session_mod, sess, sock = _make_session(mocker, check_client_cert=False)
    sess._buf = bytearray(b'client-hello')
    seen_flags = []

    def accept_security_context(*args):
        grant_stream_attr(session_mod, args)
        seen_flags.append(args[3])
        return session_mod.win32.SEC_E_OK

    secur32 = mocker.Mock()
    secur32.AcceptSecurityContext.side_effect = accept_security_context
    secur32.QueryContextAttributesW.return_value = 0
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(sess, '_load_connection_info')
    mocker.patch.object(sess, '_load_peer_certificate')

    sess.handshake()

    expected = (
        session_mod.win32.ASC_REQ_BASE | session_mod.win32.ASC_REQ_MUTUAL_AUTH
    )
    assert seen_flags == [expected]
    sess._load_peer_certificate.assert_called_once()


def test_handshake_requires_asc_ret_stream(mocker):
    """Handshake must fail when Schannel does not grant ASC_RET_STREAM."""
    session_mod, sess, _sock = _make_session(mocker, check_client_cert=False)
    sess._buf = bytearray(b'client-hello')

    secur32 = mocker.Mock()
    secur32.AcceptSecurityContext.return_value = session_mod.win32.SEC_E_OK
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    with pytest.raises(SchannelError, match='ASC_RET_STREAM'):
        sess.handshake()


def test_handshake_always_loads_peer_certificate(mocker):
    session_mod, sess, _sock = _make_session(mocker, check_client_cert=False)
    sess._buf = bytearray(b'client-hello')

    def accept_security_context(*args):
        grant_stream_attr(session_mod, args)
        return session_mod.win32.SEC_E_OK

    secur32 = mocker.Mock()
    secur32.AcceptSecurityContext.side_effect = accept_security_context
    secur32.QueryContextAttributesW.return_value = 0
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(sess, '_load_connection_info')
    load_peer = mocker.patch.object(sess, '_load_peer_certificate')

    sess.handshake()

    load_peer.assert_called_once()


def test_load_peer_certificate_missing_peer_ok_without_check(mocker):
    session_mod, sess, _sock = _make_session(mocker, check_client_cert=False)
    empty = mocker.Mock()
    empty.__bool__ = lambda self: False
    mocker.patch.object(session_mod.win32, 'POINTER', return_value=lambda: empty)
    mocker.patch.object(session_mod.win32, 'byref', side_effect=lambda x: x)
    mocker.patch.object(session_mod.win32, 'SECPKG_ATTR_REMOTE_CERT_CONTEXT', 0x53)
    mocker.patch.object(session_mod.win32, 'CERT_CONTEXT', object)

    secur32 = mocker.Mock()
    secur32.QueryContextAttributesW.return_value = 0
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    verify = mocker.patch('tls.schannel.session.verify_client_certificate_chain')

    sess._load_peer_certificate()

    assert sess._peer_der is None
    verify.assert_not_called()


def test_load_peer_certificate_missing_peer_raises_when_check(mocker):
    session_mod, sess, _sock = _make_session(mocker, check_client_cert=True)
    empty = mocker.Mock()
    empty.__bool__ = lambda self: False
    mocker.patch.object(session_mod.win32, 'POINTER', return_value=lambda: empty)
    mocker.patch.object(session_mod.win32, 'byref', side_effect=lambda x: x)
    mocker.patch.object(session_mod.win32, 'SECPKG_ATTR_REMOTE_CERT_CONTEXT', 0x53)
    mocker.patch.object(session_mod.win32, 'CERT_CONTEXT', object)

    secur32 = mocker.Mock()
    secur32.QueryContextAttributesW.return_value = 0
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    send_alert = mocker.patch.object(sess, '_send_fatal_alert')

    with pytest.raises(SchannelError, match='no client certificate received'):
        sess._load_peer_certificate()

    send_alert.assert_called_once_with(session_mod.win32.TLS1_ALERT_CERTIFICATE_UNKNOWN)


def test_load_peer_certificate_verifies_when_present_even_if_optional(mocker):
    """CERT_OPTIONAL: presented cert must still pass OS chain policy."""
    session_mod, sess, _sock = _make_session(mocker, check_client_cert=False)
    pctx = mocker.Mock()
    mocker.patch.object(session_mod.win32, 'POINTER', return_value=lambda: pctx)
    mocker.patch.object(session_mod.win32, 'byref', side_effect=lambda x: x)
    mocker.patch.object(session_mod.win32, 'SECPKG_ATTR_REMOTE_CERT_CONTEXT', 0x53)
    mocker.patch.object(session_mod.win32, 'CERT_CONTEXT', object)

    secur32 = mocker.Mock()
    secur32.QueryContextAttributesW.return_value = 0
    crypt32 = mocker.Mock()
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(session_mod.win32, 'crypt32', crypt32)
    verify = mocker.patch(
        'tls.schannel.session.verify_client_certificate_chain',
    )
    mocker.patch('tls.schannel.session.der_of', return_value=b'der-bytes')

    sess._load_peer_certificate()

    verify.assert_called_once_with(pctx)
    assert sess._peer_der == b'der-bytes'
    crypt32.CertFreeCertificateContext.assert_called_once_with(pctx)


def test_load_peer_certificate_trusted_caches_der_and_verifies(mocker):
    session_mod, sess, _sock = _make_session(mocker, check_client_cert=True)
    pctx = mocker.Mock()
    mocker.patch.object(session_mod.win32, 'POINTER', return_value=lambda: pctx)
    mocker.patch.object(session_mod.win32, 'byref', side_effect=lambda x: x)
    mocker.patch.object(session_mod.win32, 'SECPKG_ATTR_REMOTE_CERT_CONTEXT', 0x53)
    mocker.patch.object(session_mod.win32, 'CERT_CONTEXT', object)

    secur32 = mocker.Mock()
    secur32.QueryContextAttributesW.return_value = 0
    crypt32 = mocker.Mock()
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(session_mod.win32, 'crypt32', crypt32)
    verify = mocker.patch(
        'tls.schannel.session.verify_client_certificate_chain',
    )
    mocker.patch('tls.schannel.session.der_of', return_value=b'der-bytes')

    sess._load_peer_certificate()

    verify.assert_called_once_with(pctx)
    assert sess._peer_der == b'der-bytes'
    crypt32.CertFreeCertificateContext.assert_called_once_with(pctx)


def test_load_peer_certificate_policy_failure_sends_mapped_alert(mocker):
    session_mod, sess, _sock = _make_session(mocker, check_client_cert=True)
    pctx = mocker.Mock()
    mocker.patch.object(session_mod.win32, 'POINTER', return_value=lambda: pctx)
    mocker.patch.object(session_mod.win32, 'SECPKG_ATTR_REMOTE_CERT_CONTEXT', 0x53)
    mocker.patch.object(session_mod.win32, 'CERT_CONTEXT', object)

    secur32 = mocker.Mock()
    secur32.QueryContextAttributesW.return_value = 0
    crypt32 = mocker.Mock()
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(session_mod.win32, 'crypt32', crypt32)
    verify = mocker.patch(
        'tls.schannel.session.verify_client_certificate_chain',
        side_effect=SchannelError(
            'untrusted root', winerror=session_mod.win32.CERT_E_UNTRUSTEDROOT,
        ),
    )
    send_alert = mocker.patch.object(sess, '_send_fatal_alert')

    with pytest.raises(SchannelError, match='untrusted root'):
        sess._load_peer_certificate()

    verify.assert_called_once_with(pctx)
    send_alert.assert_called_once_with(session_mod.win32.TLS1_ALERT_UNKNOWN_CA)
    crypt32.CertFreeCertificateContext.assert_called_once_with(pctx)


def test_send_fatal_alert_applies_generates_and_sends_wire_token(mocker):
    session_mod, sess, sock = _make_session(mocker)
    sess.have_ctx = True
    mocker.patch.object(session_mod, 'sizeof', return_value=12)
    mocker.patch.object(session_mod, '_string_at', return_value=b'tls-alert')

    def accept_security_context(*args):
        assert args[2] is None
        out_buf = args[6].pBuffers
        out_buf.cbBuffer = 9
        out_buf.pvBuffer = 0xA11E
        return session_mod.win32.SEC_E_OK

    secur32 = mocker.Mock()
    secur32.ApplyControlToken.return_value = session_mod.win32.SEC_E_OK
    secur32.AcceptSecurityContext.side_effect = accept_security_context
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    sess._send_fatal_alert(session_mod.win32.TLS1_ALERT_UNKNOWN_CA)

    alert_desc = secur32.ApplyControlToken.call_args.args[1]
    alert = alert_desc.pBuffers.pvBuffer
    assert alert.dwTokenType == session_mod.win32.SCHANNEL_ALERT
    assert alert.dwAlertType == session_mod.win32.TLS1_ALERT_FATAL
    assert alert.dwAlertNumber == session_mod.win32.TLS1_ALERT_UNKNOWN_CA
    sock.sendall.assert_called_once_with(b'tls-alert')
    secur32.FreeContextBuffer.assert_called_once_with(0xA11E)


def test_alert_for_policy_error_defaults_when_unknown(mocker):
    session_mod, _sess, _sock = _make_session(mocker)
    assert session_mod._alert_for_policy_error(None) == session_mod.win32.TLS1_ALERT_BAD_CERTIFICATE
    assert session_mod._alert_for_policy_error(0xDEAD) == session_mod.win32.TLS1_ALERT_BAD_CERTIFICATE


def test_send_fatal_alert_skips_without_context(mocker):
    session_mod, sess, sock = _make_session(mocker)
    sess.have_ctx = False
    secur32 = mocker.Mock()
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    sess._send_fatal_alert(session_mod.win32.TLS1_ALERT_UNKNOWN_CA)

    secur32.ApplyControlToken.assert_not_called()
    sock.sendall.assert_not_called()


def test_send_fatal_alert_returns_when_apply_fails(mocker):
    session_mod, sess, sock = _make_session(mocker)
    sess.have_ctx = True
    mocker.patch.object(session_mod, 'sizeof', return_value=12)
    secur32 = mocker.Mock()
    secur32.ApplyControlToken.return_value = 0x80090304
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    sess._send_fatal_alert(session_mod.win32.TLS1_ALERT_UNKNOWN_CA)

    secur32.AcceptSecurityContext.assert_not_called()
    sock.sendall.assert_not_called()


def test_send_fatal_alert_swallows_send_oserror_and_frees(mocker):
    session_mod, sess, sock = _make_session(mocker)
    sess.have_ctx = True
    mocker.patch.object(session_mod, 'sizeof', return_value=12)
    mocker.patch.object(session_mod, '_string_at', return_value=b'tls-alert')
    sock.sendall.side_effect = OSError('broken pipe')

    def accept_security_context(*args):
        out_buf = args[6].pBuffers
        out_buf.cbBuffer = 9
        out_buf.pvBuffer = 0xA11E
        return session_mod.win32.SEC_E_OK

    secur32 = mocker.Mock()
    secur32.ApplyControlToken.return_value = session_mod.win32.SEC_E_OK
    secur32.AcceptSecurityContext.side_effect = accept_security_context
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    sess._send_fatal_alert(session_mod.win32.TLS1_ALERT_UNKNOWN_CA)

    sock.sendall.assert_called_once()
    secur32.FreeContextBuffer.assert_called_once_with(0xA11E)


def test_send_fatal_alert_logs_when_accept_fails_without_token(mocker):
    session_mod, sess, sock = _make_session(mocker)
    sess.have_ctx = True
    mocker.patch.object(session_mod, 'sizeof', return_value=12)
    secur32 = mocker.Mock()
    secur32.ApplyControlToken.return_value = session_mod.win32.SEC_E_OK
    secur32.AcceptSecurityContext.return_value = 0x80090304
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    sess._send_fatal_alert(session_mod.win32.TLS1_ALERT_UNKNOWN_CA)

    sock.sendall.assert_not_called()
    secur32.FreeContextBuffer.assert_not_called()


def test_complete_auth_token_failure_raises(mocker):
    session_mod, sess, _sock = _make_session(mocker)
    sess._buf = bytearray(b'client-hello')

    secur32 = mocker.Mock()
    secur32.AcceptSecurityContext.return_value = session_mod.win32.SEC_I_COMPLETE_NEEDED
    secur32.CompleteAuthToken.return_value = 0x80090300
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    with pytest.raises(SchannelError, match='CompleteAuthToken failed'):
        sess.handshake()
