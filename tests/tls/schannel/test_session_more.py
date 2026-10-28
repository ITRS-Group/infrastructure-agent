"""
Additional mocked Schannel session unit tests (Linux-runnable).

Complements test_session_sspi.py (buffer layout / CompleteAuthToken ordering).

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import pytest

from tls.schannel.errors import SchannelError
from tests.tls.schannel.test_session_sspi import (
    FakeSecBuffer,
    _FakeSecBufferMeta,
    _make_session,
    _patch_sspi_types,
    grant_stream_attr,
)


def test_read_more_extends_buf_and_raises_on_peer_close(mocker):
    session_mod, sess, sock = _make_session(mocker)

    sock.recv.return_value = b'chunk'
    sess._read_more()
    assert sess._buf == bytearray(b'chunk')

    sock.recv.return_value = b''
    with pytest.raises(ConnectionError, match='peer closed'):
        sess._read_more()


def test_handshake_incomplete_message_then_ok(mocker):
    session_mod, sess, sock = _make_session(mocker)
    sess._buf = bytearray(b'partial')
    calls = {'n': 0}

    def accept(*args):
        grant_stream_attr(session_mod, args)
        calls['n'] += 1
        if calls['n'] == 1:
            return session_mod.win32.SEC_E_INCOMPLETE_MESSAGE
        return session_mod.win32.SEC_E_OK

    secur32 = mocker.Mock()
    secur32.AcceptSecurityContext.side_effect = accept
    secur32.QueryContextAttributesW.return_value = 0
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(sess, '_load_connection_info')
    mocker.patch.object(sess, '_load_peer_certificate')
    sock.recv.return_value = b'rest'

    sess.handshake()

    assert calls['n'] == 2
    sock.recv.assert_called_once()
    assert sess.have_ctx is True


def test_handshake_continue_needed_then_ok(mocker):
    session_mod, sess, sock = _make_session(mocker)
    sess._buf = bytearray(b'token1')
    rounds = []

    def accept(*args):
        grant_stream_attr(session_mod, args)
        out_desc = args[6]
        out_buf = out_desc.pBuffers
        if not rounds:
            rounds.append(1)
            out_buf.cbBuffer = 3
            out_buf.pvBuffer = 0x1000
            return session_mod.win32.SEC_I_CONTINUE_NEEDED
        return session_mod.win32.SEC_E_OK

    secur32 = mocker.Mock()
    secur32.AcceptSecurityContext.side_effect = accept
    secur32.QueryContextAttributesW.return_value = 0
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(session_mod, '_string_at', return_value=b'out')
    mocker.patch.object(sess, '_load_connection_info')
    mocker.patch.object(sess, '_load_peer_certificate')
    sess._buf = bytearray(b'token1')
    sock.recv.return_value = b'token2'

    sess.handshake()

    assert secur32.AcceptSecurityContext.call_count == 2
    secur32.FreeContextBuffer.assert_called_once()
    sock.sendall.assert_called_once_with(b'out')


def test_handshake_keeps_extra_input_buffer(mocker):
    session_mod, sess, sock = _make_session(mocker)
    sess._buf = bytearray(b'0123456789')

    def accept(*args):
        grant_stream_attr(session_mod, args)
        in_desc = args[2]
        bufs = in_desc.pBuffers
        bufs[1].BufferType = session_mod.win32.SECBUFFER_EXTRA
        bufs[1].cbBuffer = 4
        return session_mod.win32.SEC_E_OK

    secur32 = mocker.Mock()
    secur32.AcceptSecurityContext.side_effect = accept
    secur32.QueryContextAttributesW.return_value = 0
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(sess, '_load_connection_info')
    mocker.patch.object(sess, '_load_peer_certificate')

    sess.handshake()

    assert sess._buf == bytearray(b'6789')


def test_handshake_accept_failure_raises(mocker):
    session_mod, sess, _sock = _make_session(mocker)
    sess._buf = bytearray(b'bad')

    secur32 = mocker.Mock()
    secur32.AcceptSecurityContext.return_value = 0x80090300
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    with pytest.raises(SchannelError, match='AcceptSecurityContext failed'):
        sess.handshake()


def test_handshake_stream_sizes_query_failure(mocker):
    session_mod, sess, _sock = _make_session(mocker)
    sess._buf = bytearray(b'ok')

    def accept(*args):
        grant_stream_attr(session_mod, args)
        return session_mod.win32.SEC_E_OK

    secur32 = mocker.Mock()
    secur32.AcceptSecurityContext.side_effect = accept
    secur32.QueryContextAttributesW.return_value = 0x80090304
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    with pytest.raises(SchannelError, match='STREAM_SIZES query failed'):
        sess.handshake()


def test_handshake_complete_and_continue_then_ok(mocker):
    session_mod, sess, sock = _make_session(mocker)
    rounds = []

    def accept(*args):
        grant_stream_attr(session_mod, args)
        if not rounds:
            rounds.append(1)
            return session_mod.win32.SEC_I_COMPLETE_AND_CONTINUE
        return session_mod.win32.SEC_E_OK

    secur32 = mocker.Mock()
    secur32.AcceptSecurityContext.side_effect = accept
    secur32.CompleteAuthToken.return_value = 0
    secur32.QueryContextAttributesW.return_value = 0
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(sess, '_load_connection_info')
    mocker.patch.object(sess, '_load_peer_certificate')
    sess._buf = bytearray(b'token1')
    sock.recv.return_value = b'token2'

    sess.handshake()

    secur32.CompleteAuthToken.assert_called_once()
    assert secur32.AcceptSecurityContext.call_count == 2


def test_load_connection_info_success(mocker):
    session_mod, sess, _sock = _make_session(mocker)

    conn_info = mocker.Mock(dwProtocol=0x800, aiCipher=0xC02F, dwCipherStrength=256)
    cipher_info = mocker.Mock(szCipherSuite='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', dwCipherLen=128)

    def query(_ctx, attr, _out):
        if attr == session_mod.win32.SECPKG_ATTR_CONNECTION_INFO:
            _out.dwProtocol = conn_info.dwProtocol
            _out.aiCipher = conn_info.aiCipher
            _out.dwCipherStrength = conn_info.dwCipherStrength
            return session_mod.win32.SEC_E_OK
        if attr == session_mod.win32.SECPKG_ATTR_CIPHER_INFO:
            _out.szCipherSuite = cipher_info.szCipherSuite
            _out.dwCipherLen = cipher_info.dwCipherLen
            return session_mod.win32.SEC_E_OK
        return 0x80090300

    mocker.patch.object(
        session_mod.win32, 'SecPkgContext_ConnectionInfo', return_value=conn_info,
    )
    mocker.patch.object(
        session_mod.win32, 'SecPkgContext_CipherInfo', return_value=cipher_info,
    )
    mocker.patch.object(session_mod.win32, 'SECPKGCONTEXT_CIPHERINFO_V1', 1)
    mocker.patch.object(session_mod.win32, 'PROTOCOL_FLAG_NAMES', {0x800: 'TLS 1.2'})
    secur32 = mocker.Mock()
    secur32.QueryContextAttributesW.side_effect = query
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    sess._load_connection_info()

    assert sess._protocol_name == 'TLS 1.2'
    assert sess._cipher_tuple == ('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS 1.2', 128)


def test_send_clear_encrypt_message_failure(mocker):
    session_mod, sess, _sock = _make_session(mocker)
    sess.sizes = mocker.Mock(cbHeader=5, cbTrailer=7, cbMaximumMessage=64)

    secur32 = mocker.Mock()
    secur32.EncryptMessage.return_value = 0x80090321
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    with pytest.raises(SchannelError, match='EncryptMessage failed'):
        sess.send_clear(b'data')


def test_recv_clear_soft_close_on_peer_disconnect(mocker):
    session_mod, sess, sock = _make_session(mocker)
    sess.sizes = mocker.Mock()
    sess._buf = bytearray()
    sock.recv.return_value = b''

    assert sess.recv_clear(1024) == b''
    assert sess._closed is True


def test_recv_clear_incomplete_then_peer_closes(mocker):
    """Incomplete decrypt loops once; peer close then soft-EOF (covers while re-entry)."""
    _session_mod, sess, _sock = _make_session(mocker)
    sess.sizes = mocker.Mock()
    calls = {'n': 0}

    def decrypt_more():
        calls['n'] += 1
        if calls['n'] >= 2:
            sess._closed = True

    mocker.patch.object(sess, '_decrypt_more', side_effect=decrypt_more)

    assert sess.recv_clear(1024) == b''
    assert calls['n'] == 2
    assert sess._closed is True


def test_recv_clear_returns_app_data_and_retains_remainder(mocker):
    """Partial recv must keep leftover cleartext in _app_data for the next call."""
    _session_mod, sess, _sock = _make_session(mocker)
    sess._app_data = bytearray(b'abcdefgh')

    assert sess.recv_clear(3) == b'abc'
    assert sess._app_data == bytearray(b'defgh')
    assert sess.recv_clear(10) == b'defgh'
    assert sess._app_data == bytearray()


def test_decrypt_incomplete_message_reads_more(mocker):
    session_mod, sess, sock = _make_session(mocker)
    sess.sizes = mocker.Mock()
    sess._buf = bytearray(b'part')
    _patch_sspi_types(session_mod, mocker)

    secur32 = mocker.Mock()
    secur32.DecryptMessage.return_value = session_mod.win32.SEC_E_INCOMPLETE_MESSAGE
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(session_mod.win32, 'SEC_I_CONTEXT_EXPIRED', 0x90317)
    mocker.patch.object(session_mod.win32, 'SEC_I_RENEGOTIATE', 0x90321)
    sock.recv.return_value = b'more'

    sess._decrypt_more()

    sock.recv.assert_called_once()
    assert sess._buf == bytearray(b'partmore')


def test_decrypt_context_expired_closes(mocker):
    session_mod, sess, _sock = _make_session(mocker)
    sess.sizes = mocker.Mock()
    sess._buf = bytearray(b'done')
    _patch_sspi_types(session_mod, mocker)

    secur32 = mocker.Mock()
    secur32.DecryptMessage.return_value = session_mod.win32.SEC_I_CONTEXT_EXPIRED
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(session_mod.win32, 'SEC_I_CONTEXT_EXPIRED', 0x90317)

    sess._decrypt_more()

    assert sess._closed is True
    assert sess._buf == bytearray()


def test_decrypt_failure_raises(mocker):
    session_mod, sess, _sock = _make_session(mocker)
    sess.sizes = mocker.Mock()
    sess._buf = bytearray(b'bad')
    _patch_sspi_types(session_mod, mocker)

    secur32 = mocker.Mock()
    secur32.DecryptMessage.return_value = 0x80090304
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(session_mod.win32, 'SEC_I_CONTEXT_EXPIRED', 0x90317)
    mocker.patch.object(session_mod.win32, 'SEC_I_RENEGOTIATE', 0x90321)

    with pytest.raises(SchannelError, match='DecryptMessage failed'):
        sess._decrypt_more()


def test_decrypt_success_data_and_extra(mocker):
    session_mod, sess, _sock = _make_session(mocker)
    sess.sizes = mocker.Mock()
    sess._buf = bytearray(b'0123456789')
    _patch_sspi_types(session_mod, mocker)
    mocker.patch.object(session_mod, '_string_at', return_value=b'plain')

    captured = {}

    class TrackingMeta(_FakeSecBufferMeta):
        def __mul__(cls, n):
            def factory(*items):
                captured['bufs'] = list(items)
                return captured['bufs']

            return factory

    TrackingSecBuffer = TrackingMeta('TrackingSecBuffer', (FakeSecBuffer,), {})

    def decrypt(_ctx, _desc, _seq, _extra):
        bufs = captured['bufs']
        bufs[0].BufferType = session_mod.win32.SECBUFFER_DATA
        bufs[0].cbBuffer = 5
        bufs[0].pvBuffer = 0x100
        bufs[1].BufferType = session_mod.win32.SECBUFFER_EXTRA
        bufs[1].cbBuffer = 3
        return session_mod.win32.SEC_E_OK

    mocker.patch.object(session_mod.win32, 'SecBuffer', TrackingSecBuffer)
    secur32 = mocker.Mock()
    secur32.DecryptMessage.side_effect = decrypt
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(session_mod.win32, 'SEC_I_CONTEXT_EXPIRED', 0x90317)
    mocker.patch.object(session_mod.win32, 'SEC_I_RENEGOTIATE', 0x90321)

    sess._decrypt_more()

    assert sess._app_data == bytearray(b'plain')
    assert sess._buf == bytearray(b'789')


def test_decrypt_keeps_data_buffers_after_extra(mocker):
    """EXTRA before DATA must not drop the decrypted record."""
    session_mod, sess, _sock = _make_session(mocker)
    sess.sizes = mocker.Mock()
    sess._buf = bytearray(b'0123456789')
    _patch_sspi_types(session_mod, mocker)
    mocker.patch.object(session_mod, '_string_at', side_effect=[b'plain', b'text'])

    captured = {}

    class TrackingMeta(_FakeSecBufferMeta):
        def __mul__(cls, n):
            def factory(*items):
                captured['bufs'] = list(items)
                return captured['bufs']

            return factory

    TrackingSecBuffer = TrackingMeta('TrackingSecBuffer', (FakeSecBuffer,), {})

    def decrypt(_ctx, _desc, _seq, _extra):
        bufs = captured['bufs']
        bufs[0].BufferType = session_mod.win32.SECBUFFER_EXTRA
        bufs[0].cbBuffer = 3
        bufs[2].BufferType = session_mod.win32.SECBUFFER_DATA
        bufs[2].cbBuffer = 5
        bufs[2].pvBuffer = 0x100
        bufs[3].BufferType = session_mod.win32.SECBUFFER_DATA
        bufs[3].cbBuffer = 4
        bufs[3].pvBuffer = 0x200
        return session_mod.win32.SEC_E_OK

    mocker.patch.object(session_mod.win32, 'SecBuffer', TrackingSecBuffer)
    secur32 = mocker.Mock()
    secur32.DecryptMessage.side_effect = decrypt
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(session_mod.win32, 'SEC_I_CONTEXT_EXPIRED', 0x90317)
    mocker.patch.object(session_mod.win32, 'SEC_I_RENEGOTIATE', 0x90321)

    sess._decrypt_more()

    assert sess._app_data == bytearray(b'plaintext')
    assert sess._buf == bytearray(b'789')


def test_decrypt_success_data_clears_buf_when_no_extra(mocker):
    """Full record consumed: DATA present, no EXTRA → clear _buf."""
    session_mod, sess, _sock = _make_session(mocker)
    sess.sizes = mocker.Mock()
    sess._buf = bytearray(b'0123456789')
    _patch_sspi_types(session_mod, mocker)
    mocker.patch.object(session_mod, '_string_at', return_value=b'plain')

    captured = {}

    class TrackingMeta(_FakeSecBufferMeta):
        def __mul__(cls, n):
            def factory(*items):
                captured['bufs'] = list(items)
                return captured['bufs']

            return factory

    TrackingSecBuffer = TrackingMeta('TrackingSecBuffer', (FakeSecBuffer,), {})

    def decrypt(_ctx, _desc, _seq, _extra):
        bufs = captured['bufs']
        bufs[0].BufferType = session_mod.win32.SECBUFFER_DATA
        bufs[0].cbBuffer = 5
        bufs[0].pvBuffer = 0x100
        return session_mod.win32.SEC_E_OK

    mocker.patch.object(session_mod.win32, 'SecBuffer', TrackingSecBuffer)
    secur32 = mocker.Mock()
    secur32.DecryptMessage.side_effect = decrypt
    mocker.patch.object(session_mod.win32, 'secur32', secur32)
    mocker.patch.object(session_mod.win32, 'SEC_I_CONTEXT_EXPIRED', 0x90317)
    mocker.patch.object(session_mod.win32, 'SEC_I_RENEGOTIATE', 0x90321)

    sess._decrypt_more()

    assert sess._app_data == bytearray(b'plain')
    assert sess._buf == bytearray()


def test_close_deletes_context_and_closes_sock(mocker):
    session_mod, sess, sock = _make_session(mocker)
    sess.have_ctx = True

    secur32 = mocker.Mock()
    mocker.patch.object(session_mod.win32, 'secur32', secur32)

    sess.close()

    secur32.DeleteSecurityContext.assert_called_once()
    sock.close.assert_called_once()
    assert sess.have_ctx is False
    assert sess._closed is True

    # Second close is a no-op for DeleteSecurityContext; sock OSError is swallowed.
    sock.close.side_effect = OSError('already closed')
    sess.close()
    assert secur32.DeleteSecurityContext.call_count == 1
