"""
Blocking Schannel stream session (handshake and record I/O).

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import logging
from ctypes import sizeof
from typing import Optional

from tls.schannel import win32
from tls.schannel.chain import verify_client_certificate_chain
from tls.schannel.errors import SchannelError, status_hex
from tls.schannel.store import der_of

logger = logging.getLogger('tls')

_POLICY_ERROR_TO_ALERT = {
    win32.CERT_E_UNTRUSTEDROOT: win32.TLS1_ALERT_UNKNOWN_CA,
    win32.CERT_E_UNTRUSTEDTESTROOT: win32.TLS1_ALERT_UNKNOWN_CA,
    win32.CERT_E_CHAINING: win32.TLS1_ALERT_UNKNOWN_CA,
    win32.CERT_E_ISSUERCHAINING: win32.TLS1_ALERT_UNKNOWN_CA,
    win32.CERT_E_REVOKED: win32.TLS1_ALERT_CERTIFICATE_REVOKED,
    win32.CERT_E_EXPIRED: win32.TLS1_ALERT_CERTIFICATE_EXPIRED,
    win32.CERT_E_VALIDITYPERIODNESTING: win32.TLS1_ALERT_CERTIFICATE_EXPIRED,
    win32.CERT_E_WRONG_USAGE: win32.TLS1_ALERT_UNSUPPORTED_CERT,
    win32.CERT_E_PURPOSE: win32.TLS1_ALERT_UNSUPPORTED_CERT,
    win32.CERT_E_MALFORMED: win32.TLS1_ALERT_BAD_CERTIFICATE,
    win32.TRUST_E_CERT_SIGNATURE: win32.TLS1_ALERT_BAD_CERTIFICATE,
    win32.TRUST_E_BASIC_CONSTRAINTS: win32.TLS1_ALERT_BAD_CERTIFICATE,
}


def _alert_for_policy_error(policy_error: Optional[int]) -> int:
    """Map a CertVerifyCertificateChainPolicy HRESULT to a TLS alert."""
    if policy_error is None:
        return win32.TLS1_ALERT_BAD_CERTIFICATE
    return _POLICY_ERROR_TO_ALERT.get(
        policy_error & 0xFFFFFFFF,
        win32.TLS1_ALERT_BAD_CERTIFICATE,
    )


def _string_at(addr, size: int) -> bytes:  # pragma: no cover -- ctypes; tests patch this
    return bytes((win32.c_char * size).from_address(addr))


class SchannelServerSession:
    """Blocking Schannel stream session over a raw connected socket."""

    def __init__(self, sock, cred, check_client_cert: bool = False):
        win32.ensure_win32()
        self.sock = sock
        self.cred = cred
        self.check_client_cert = check_client_cert
        self.ctx = win32.CtxtHandle()
        self.have_ctx = False
        self.sizes = None
        self._buf = bytearray()
        self._app_data = bytearray()
        self._input_buffer = None
        self._closed = False
        self._peer_der: Optional[bytes] = None
        self._protocol_name = 'Schannel'
        self._cipher_tuple = ('Schannel', 'TLS', None)

    def handshake(self) -> None:
        # Always request a client cert (CertificateRequest), matching OpenSSL
        # CERT_OPTIONAL / CERT_REQUIRED. ASC_REQ_MUTUAL_AUTH does not fail the
        # handshake if the client sends no cert — that is enforced only in
        # _load_peer_certificate when check_client_cert is set.
        asc_req = win32.ASC_REQ_BASE | win32.ASC_REQ_MUTUAL_AUTH

        while True:
            if not self._buf:
                self._read_more()

            token = bytes(self._buf)
            self._input_buffer = win32.create_string_buffer(token, len(token))

            in_bufs = (win32.SecBuffer * 2)(
                win32.SecBuffer(
                    len(token), win32.SECBUFFER_TOKEN,
                    win32.cast(self._input_buffer, win32.c_void_p),
                ),
                win32.SecBuffer(0, win32.SECBUFFER_EMPTY, None),
            )
            in_desc = win32.SecBufferDesc(
                win32.SECBUFFER_VERSION, 2, win32.cast(in_bufs, win32.POINTER(win32.SecBuffer)),
            )

            out_buf = win32.SecBuffer(0, win32.SECBUFFER_TOKEN, None)
            out_desc = win32.SecBufferDesc(win32.SECBUFFER_VERSION, 1, win32.pointer(out_buf))

            attrs = win32.ULONG(0)
            expiry = win32.FILETIME()
            pinput_ctx = win32.byref(self.ctx) if self.have_ctx else None

            status = win32.secur32.AcceptSecurityContext(
                win32.byref(self.cred),
                pinput_ctx,
                win32.byref(in_desc),
                asc_req,
                win32.SECURITY_NATIVE_DREP,
                win32.byref(self.ctx),
                win32.byref(out_desc),
                win32.byref(attrs),
                win32.byref(expiry),
            )
            if status == win32.SEC_E_INCOMPLETE_MESSAGE:
                self._read_more()
                continue

            if status in (
                win32.SEC_E_OK,
                win32.SEC_I_CONTINUE_NEEDED,
                win32.SEC_I_COMPLETE_NEEDED,
                win32.SEC_I_COMPLETE_AND_CONTINUE,
            ):
                self.have_ctx = True

            if in_bufs[1].BufferType == win32.SECBUFFER_EXTRA and in_bufs[1].cbBuffer:
                keep = in_bufs[1].cbBuffer
                self._buf = self._buf[len(token) - keep:]
            else:
                self._buf.clear()

            # Finish the output token before send/free when AcceptSecurityContext
            # returns SEC_I_COMPLETE_* — see CompleteAuthToken:
            # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-completeauthtoken
            if status in (win32.SEC_I_COMPLETE_NEEDED, win32.SEC_I_COMPLETE_AND_CONTINUE):
                complete_st = win32.secur32.CompleteAuthToken(
                    win32.byref(self.ctx), win32.byref(out_desc),
                )
                if complete_st != win32.SEC_E_OK:
                    raise SchannelError(
                        f"CompleteAuthToken failed: {status_hex(complete_st)}"
                    )

            if out_buf.cbBuffer and out_buf.pvBuffer:
                payload = _string_at(out_buf.pvBuffer, out_buf.cbBuffer)
                win32.secur32.FreeContextBuffer(out_buf.pvBuffer)
                out_buf.pvBuffer = None
                self.sock.sendall(payload)

            # AcceptSecurityContext return codes:
            # https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acceptsecuritycontext
            # SEC_I_COMPLETE_NEEDED: success; after CompleteAuthToken the context is done
            # (no further Accept round). SEC_I_COMPLETE_AND_CONTINUE still needs another
            # client token. Unlikely for Schannel TLS / NRPE — handshakes normally finish
            # with SEC_E_OK or SEC_I_CONTINUE_NEEDED; CompleteAuthToken is mainly a Digest
            # SSP concern, but handle COMPLETE_* correctly if Schannel ever returns them.
            if status in (win32.SEC_E_OK, win32.SEC_I_COMPLETE_NEEDED):
                # EncryptMessage/DecryptMessage use stream buffers. Requesting
                # ASC_REQ_STREAM is not enough — Schannel must grant it.
                if not (attrs.value & win32.ASC_RET_STREAM):
                    raise SchannelError(
                        "AcceptSecurityContext did not grant a stream context "
                        f"(ASC_RET_STREAM missing, pfContextAttr={status_hex(int(attrs.value))})"
                    )
                break
            if status in (win32.SEC_I_CONTINUE_NEEDED, win32.SEC_I_COMPLETE_AND_CONTINUE):
                continue
            raise SchannelError(f"AcceptSecurityContext failed: {status_hex(status)}")

        self.sizes = win32.SecPkgContext_StreamSizes()
        st = win32.secur32.QueryContextAttributesW(
            win32.byref(self.ctx), win32.SECPKG_ATTR_STREAM_SIZES, win32.byref(self.sizes),
        )
        if st != win32.SEC_E_OK:
            raise SchannelError(f"STREAM_SIZES query failed: {status_hex(st)}")

        self._load_connection_info()
        self._load_peer_certificate()

    def _send_fatal_alert(self, alert_number: int) -> None:
        """
        Best-effort emission of a fatal TLS alert from an established context.

        ApplyControlToken selects the alert; a final AcceptSecurityContext call
        serialises it into a wire token. Alert delivery must not hide the
        certificate-validation error that caused the rejection.
        """
        if not self.have_ctx:
            return

        alert = win32.SCHANNEL_ALERT_TOKEN(
            win32.SCHANNEL_ALERT,
            win32.TLS1_ALERT_FATAL,
            alert_number,
        )
        alert_buf = win32.SecBuffer(
            sizeof(alert),
            win32.SECBUFFER_TOKEN,
            win32.cast(win32.pointer(alert), win32.c_void_p),
        )
        alert_desc = win32.SecBufferDesc(
            win32.SECBUFFER_VERSION, 1, win32.pointer(alert_buf),
        )
        st = win32.secur32.ApplyControlToken(
            win32.byref(self.ctx), win32.byref(alert_desc),
        )
        if st != win32.SEC_E_OK:
            logger.debug("ApplyControlToken for TLS alert failed: %s", status_hex(st))
            return

        out_buf = win32.SecBuffer(0, win32.SECBUFFER_TOKEN, None)
        out_desc = win32.SecBufferDesc(
            win32.SECBUFFER_VERSION, 1, win32.pointer(out_buf),
        )
        attrs = win32.ULONG(0)
        expiry = win32.FILETIME()
        st = win32.secur32.AcceptSecurityContext(
            win32.byref(self.cred),
            win32.byref(self.ctx),
            None,
            win32.ASC_REQ_BASE | win32.ASC_REQ_MUTUAL_AUTH,
            win32.SECURITY_NATIVE_DREP,
            win32.byref(self.ctx),
            win32.byref(out_desc),
            win32.byref(attrs),
            win32.byref(expiry),
        )
        try:
            if out_buf.cbBuffer and out_buf.pvBuffer:
                self.sock.sendall(_string_at(out_buf.pvBuffer, out_buf.cbBuffer))
        except OSError as ex:
            logger.debug("Could not send fatal TLS alert: %s", ex)
        finally:
            if out_buf.pvBuffer:
                win32.secur32.FreeContextBuffer(out_buf.pvBuffer)
                out_buf.pvBuffer = None
        if st != win32.SEC_E_OK:
            logger.debug(
                "AcceptSecurityContext while generating TLS alert returned %s",
                status_hex(st),
            )

    def _load_peer_certificate(self) -> None:
        """
        Cache peer leaf DER after handshake (None if none presented).

        OpenSSL CERT_OPTIONAL (check_client_cert false): missing cert OK; if a
        cert is presented it must pass OS LocalMachine base policy.
        OpenSSL CERT_REQUIRED (check_client_cert true): missing cert fails;
        presented cert must pass the same policy.
        """
        pctx = win32.POINTER(win32.CERT_CONTEXT)()
        st = win32.secur32.QueryContextAttributesW(
            win32.byref(self.ctx), win32.SECPKG_ATTR_REMOTE_CERT_CONTEXT, win32.byref(pctx),
        )
        if st != win32.SEC_E_OK or not pctx:
            self._peer_der = None
            if self.check_client_cert:
                # TLS 1.3 TLSV13_ALERT_CERTIFICATE_REQUIRED (116) is not a
                # Schannel SCHANNEL_ALERT_TOKEN dwAlertNumber; send 46 instead.
                self._send_fatal_alert(win32.TLS1_ALERT_CERTIFICATE_UNKNOWN)
                raise SchannelError(
                    "no client certificate received "
                    "(server.tls.check_client_cert requires a client certificate)"
                )
            return
        try:
            try:
                verify_client_certificate_chain(pctx)
            except SchannelError as ex:
                self._send_fatal_alert(_alert_for_policy_error(ex.winerror))
                raise
            self._peer_der = der_of(pctx) or None
        finally:
            win32.crypt32.CertFreeCertificateContext(pctx)

    def _load_connection_info(self) -> None:
        try:
            info = win32.SecPkgContext_ConnectionInfo()
            st = win32.secur32.QueryContextAttributesW(
                win32.byref(self.ctx), win32.SECPKG_ATTR_CONNECTION_INFO, win32.byref(info),
            )
            if st == win32.SEC_E_OK:  # pragma: no branch -- rare once handshake completes
                self._protocol_name = win32.PROTOCOL_FLAG_NAMES.get(
                    info.dwProtocol, f'0x{info.dwProtocol:X}',
                )
                self._cipher_tuple = (
                    f'0x{info.aiCipher:X}',
                    self._protocol_name,
                    info.dwCipherStrength,
                )
            cipher_info = win32.SecPkgContext_CipherInfo()
            cipher_info.dwVersion = win32.SECPKGCONTEXT_CIPHERINFO_V1
            st = win32.secur32.QueryContextAttributesW(
                win32.byref(self.ctx), win32.SECPKG_ATTR_CIPHER_INFO, win32.byref(cipher_info),
            )
            if st == win32.SEC_E_OK and cipher_info.szCipherSuite:  # pragma: no branch -- rare once handshake completes
                suite = cipher_info.szCipherSuite
                self._cipher_tuple = (suite, self._protocol_name, cipher_info.dwCipherLen or None)
        except Exception as ex:  # pragma: no cover -- rare once handshake completes
            logger.debug("Schannel connection info unavailable: %s", ex)

    def send_clear(self, data: bytes) -> None:
        assert self.sizes is not None
        offset = 0
        max_msg = self.sizes.cbMaximumMessage
        while offset < len(data):
            chunk = data[offset:offset + max_msg]
            offset += len(chunk)
            # Schannel stream EncryptMessage requires four buffers in this order:
            # STREAM_HEADER, DATA, STREAM_TRAILER, EMPTY (Microsoft sample).
            header = win32.create_string_buffer(self.sizes.cbHeader)
            body = win32.create_string_buffer(chunk, len(chunk))
            trailer = win32.create_string_buffer(self.sizes.cbTrailer)
            bufs = (win32.SecBuffer * 4)(
                win32.SecBuffer(
                    self.sizes.cbHeader, win32.SECBUFFER_STREAM_HEADER,
                    win32.cast(header, win32.c_void_p),
                ),
                win32.SecBuffer(
                    len(chunk), win32.SECBUFFER_DATA, win32.cast(body, win32.c_void_p),
                ),
                win32.SecBuffer(
                    self.sizes.cbTrailer, win32.SECBUFFER_STREAM_TRAILER,
                    win32.cast(trailer, win32.c_void_p),
                ),
                win32.SecBuffer(0, win32.SECBUFFER_EMPTY, None),
            )
            desc = win32.SecBufferDesc(
                win32.SECBUFFER_VERSION, 4, win32.cast(bufs, win32.POINTER(win32.SecBuffer)),
            )
            st = win32.secur32.EncryptMessage(win32.byref(self.ctx), 0, win32.byref(desc), 0)
            if st != win32.SEC_E_OK:
                raise SchannelError(f"EncryptMessage failed: {status_hex(st)}")
            # After EncryptMessage, cbBuffer holds bytes actually written — not the
            # pre-call capacities from STREAM_SIZES / len(chunk).
            self.sock.sendall(
                header.raw[: bufs[0].cbBuffer] +
                body.raw[: bufs[1].cbBuffer] +
                trailer.raw[: bufs[2].cbBuffer]
            )

    def recv_clear(self, buflen: int) -> bytes:
        while len(self._app_data) < 1:
            self._decrypt_more()
            if self._closed and not self._app_data:
                return b''
        take = min(buflen, len(self._app_data))
        out = bytes(self._app_data[:take])
        del self._app_data[:take]
        return out

    def _decrypt_more(self) -> None:
        assert self.sizes is not None
        if not self._buf:
            try:
                self._read_more()
            except ConnectionError:
                self._closed = True
                return

        message = bytes(self._buf)
        self._input_buffer = win32.create_string_buffer(message, len(message))
        bufs = (win32.SecBuffer * 4)(
            win32.SecBuffer(
                len(message), win32.SECBUFFER_DATA,
                win32.cast(self._input_buffer, win32.c_void_p),
            ),
            win32.SecBuffer(0, win32.SECBUFFER_EMPTY, None),
            win32.SecBuffer(0, win32.SECBUFFER_EMPTY, None),
            win32.SecBuffer(0, win32.SECBUFFER_EMPTY, None),
        )
        desc = win32.SecBufferDesc(
            win32.SECBUFFER_VERSION, 4, win32.cast(bufs, win32.POINTER(win32.SecBuffer)),
        )
        st = win32.secur32.DecryptMessage(win32.byref(self.ctx), win32.byref(desc), 0, None)

        if st == win32.SEC_E_INCOMPLETE_MESSAGE:
            self._read_more()
            return
        if st in (win32.SEC_I_CONTEXT_EXPIRED,):
            self._buf.clear()
            self._closed = True
            return
        if st == win32.SEC_I_RENEGOTIATE:
            msg = (
                f"DecryptMessage requested TLS renegotiation ({status_hex(st)}); "
                "Schannel NRPE does not support renegotiation"
            )
            logger.error("%s", msg)
            raise SchannelError(msg)
        if st != win32.SEC_E_OK:
            raise SchannelError(f"DecryptMessage failed: {status_hex(st)}")

        # Schannel identifies output buffers by type, not position. Copy every
        # SECBUFFER_DATA entry, then keep a SECBUFFER_EXTRA suffix if present.
        extra = None
        for i in range(4):
            buf = bufs[i]
            if buf.BufferType == win32.SECBUFFER_DATA and buf.cbBuffer and buf.pvBuffer:
                self._app_data.extend(_string_at(buf.pvBuffer, buf.cbBuffer))
            elif extra is None and buf.BufferType == win32.SECBUFFER_EXTRA and buf.cbBuffer:
                extra = buf.cbBuffer
        if extra:
            self._buf = self._buf[len(message) - extra:]
        else:
            self._buf.clear()

    def close(self) -> None:
        if self.have_ctx:
            win32.secur32.DeleteSecurityContext(win32.byref(self.ctx))
            self.have_ctx = False
        try:
            self.sock.close()
        except OSError:
            pass
        self._closed = True

    def _read_more(self) -> None:
        chunk = self.sock.recv(16384)
        if not chunk:
            raise ConnectionError("peer closed during Schannel I/O")
        self._buf.extend(chunk)
