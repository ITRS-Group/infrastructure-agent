"""
LocalMachine certificate store lookup and Schannel inbound credentials.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from typing import Optional

from cryptography import x509

from tls.schannel import win32
from tls.schannel.errors import raise_config_error, raise_store_open_error, status_hex

logger = logging.getLogger('tls')


def _thumbprint_bytes(thumbprint: str) -> bytes:
    """Normalize certmgr / PowerShell thumbprint hex for CERT_HASH_PROP_ID compare."""
    return bytes.fromhex(thumbprint.replace(" ", "").replace(":", ""))


def der_of(ctx) -> bytes:
    n = ctx.contents.cbCertEncoded
    return bytes((win32.c_char * n).from_address(ctx.contents.pbCertEncoded))


def _cert_not_after(ctx) -> datetime:
    cert = x509.load_der_x509_certificate(der_of(ctx))
    return cert.not_valid_after_utc


def _cert_get_name_string(ctx, name_type: int) -> str:
    """
    Probe-then-allocate CertGetNameStringW so long FriendlyName / SimpleName
    values are not truncated by a fixed buffer.
    """
    needed = win32.crypt32.CertGetNameStringW(ctx, name_type, 0, None, None, 0)
    if needed <= 1:
        return ''
    buf = win32.create_unicode_buffer(needed)
    n = win32.crypt32.CertGetNameStringW(ctx, name_type, 0, None, buf, needed)
    if n > 1:
        return buf.value
    return ''


# Prefer FriendlyName over SimpleName when several certs match cert_name (e.g. shared CN).
_MATCH_FRIENDLY = 2
_MATCH_SIMPLE = 1


def _match_via_label(rank: int) -> str:
    if rank == _MATCH_FRIENDLY:
        return 'FriendlyName'
    if rank == _MATCH_SIMPLE:
        return 'SimpleName'
    return 'no match'


def _evaluate_name_match(cert_name: str, ctx, store_name: str = '?') -> int:
    """
    Rank a store cert against cert_name.

    FriendlyName outranks SimpleName so labels like ``web server`` win when
    several certs share a Subject CN. DEBUG logs every candidate for ops.
    """
    wanted = cert_name.strip().casefold()
    friendly = _cert_get_name_string(ctx, win32.CERT_NAME_FRIENDLY_DISPLAY_TYPE)
    simple = _cert_get_name_string(ctx, win32.CERT_NAME_SIMPLE_DISPLAY_TYPE)
    rank = 0
    if wanted:
        friendly_l = friendly.strip().casefold() if friendly else ''
        simple_l = simple.strip().casefold() if simple else ''
        if friendly_l and friendly_l == wanted:
            rank = _MATCH_FRIENDLY
        elif simple_l and simple_l == wanted:
            rank = _MATCH_SIMPLE
    logger.debug(
        "Schannel LocalMachine\\%s candidate FriendlyName=%r "
        "SimpleName=%r vs cert_name=%r -> %s",
        store_name,
        friendly or None,
        simple or None,
        cert_name,
        _match_via_label(rank),
    )
    return rank


def find_store_cert(thumbprint: str, store_name: str = "MY"):
    """
    Resolve identity by SHA-1 thumbprint when store labels collide or are unset.

    Returns a duplicated CERT_CONTEXT; caller must CertFreeCertificateContext
    (or keep it alive while Schannel credentials reference it).
    """
    win32.ensure_win32()
    logger.debug(
        "Schannel opening LocalMachine\\%s (server.tls.schannel.identity_cert_store) for cert_thumbprint=%s",
        store_name,
        thumbprint,
    )
    wanted = _thumbprint_bytes(thumbprint)
    store = win32.crypt32.CertOpenStore(
        win32.CERT_STORE_PROV_SYSTEM_W,
        0,
        None,
        win32.CERT_SYSTEM_STORE_LOCAL_MACHINE |
        win32.CERT_STORE_READONLY_FLAG |
        win32.CERT_STORE_OPEN_EXISTING_FLAG,
        store_name.upper(),
    )
    if not store:
        raise_store_open_error(store_name, win32.kernel32.GetLastError())

    found = None
    ctx = None
    try:
        while True:
            ctx = win32.crypt32.CertEnumCertificatesInStore(store, ctx)
            if not ctx:
                break
            if hashlib.sha1(der_of(ctx)).digest() == wanted:
                found = win32.crypt32.CertDuplicateCertificateContext(ctx)
                break
    finally:
        # Enum frees the context it is given. A match returns early, so free that ctx.
        if ctx:
            win32.crypt32.CertFreeCertificateContext(ctx)
        win32.crypt32.CertCloseStore(store, 0)

    if not found:
        raise_config_error(
            f"No certificate with server.tls.schannel.identity_cert_thumbprint={thumbprint} "
            f"in LocalMachine\\{store_name} (server.tls.schannel.identity_cert_store). "
            "Windows Server configuration: open certmgr.msc (Local Computer), "
            "confirm the SHA-1 Thumbprint field in certmgr, and that the "
            "certificate is in that store."
        )
    logger.debug(
        "Schannel found certificate matching cert_thumbprint=%s in LocalMachine\\%s",
        thumbprint,
        store_name,
    )
    return found


def find_store_cert_by_name(cert_name: str, store_name: str = "MY"):
    """
    Resolve cert_name in LocalMachine\\<store>.

    Prefer FriendlyName so admins can disambiguate certs that share a Subject
    CN; within a tier take the latest NotAfter so renewals keep working without
    config changes. Returns a duplicated CERT_CONTEXT (caller frees / keeps).
    """
    win32.ensure_win32()
    logger.debug(
        "Schannel opening LocalMachine\\%s (server.tls.schannel.identity_cert_store) for cert_name=%r",
        store_name,
        cert_name,
    )
    store = win32.crypt32.CertOpenStore(
        win32.CERT_STORE_PROV_SYSTEM_W,
        0,
        None,
        win32.CERT_SYSTEM_STORE_LOCAL_MACHINE |
        win32.CERT_STORE_READONLY_FLAG |
        win32.CERT_STORE_OPEN_EXISTING_FLAG,
        store_name.upper(),
    )
    if not store:
        raise_store_open_error(store_name, win32.kernel32.GetLastError())

    best = None
    best_expiry = None
    best_rank = 0
    prev = None
    try:
        while True:
            ctx = win32.crypt32.CertEnumCertificatesInStore(store, prev)
            if not ctx:
                break
            prev = ctx
            rank = _evaluate_name_match(cert_name, ctx, store_name)
            if rank == 0:
                continue
            expiry = _cert_not_after(ctx)
            better = (
                best is None or
                rank > best_rank or
                (rank == best_rank and expiry > best_expiry)
            )
            if better:
                if best is not None:
                    win32.crypt32.CertFreeCertificateContext(best)
                best = win32.crypt32.CertDuplicateCertificateContext(ctx)
                best_expiry = expiry
                best_rank = rank
    finally:
        win32.crypt32.CertCloseStore(store, 0)

    if not best:
        raise_config_error(
            f"No certificate with exact server.tls.schannel.identity_cert_name={cert_name!r} "
            f"in LocalMachine\\{store_name} (server.tls.schannel.identity_cert_store). "
            "Match is case-insensitive exact equality against Windows "
            "FriendlyName (preferred) or SimpleName. "
            "Set the full name, or use server.tls.schannel.identity_cert_thumbprint (SHA-1)."
        )
    logger.info(
        "Schannel selected certificate for cert_name=%r via %s "
        "(NotAfter=%s) from LocalMachine\\%s",
        cert_name,
        _match_via_label(best_rank),
        best_expiry.isoformat() if best_expiry else '?',
        store_name,
    )
    return best


def acquire_server_credential(
        thumbprint: Optional[str] = None,
        store_name: str = "MY",
        cert_name: Optional[str] = None,
):
    """
    Build an inbound Schannel credential from a LocalMachine store identity.

    Uses SCH_CREDENTIALS only (Server 2019 / Win10 1809+). Protocol and cipher
    policy stay with Windows Schannel / GPO — not agent cipher_suite /
    context_options.
    """
    win32.ensure_win32()
    logger.debug(
        "Schannel acquiring inbound credential from LocalMachine\\%s cert_name=%r cert_thumbprint=%s",
        store_name,
        cert_name,
        thumbprint,
    )
    if cert_name and thumbprint:
        raise_config_error(
            "Schannel identity is ambiguous: set only one of "
            "server.tls.schannel.identity_cert_name or server.tls.schannel.identity_cert_thumbprint."
        )
    if cert_name:
        cert_ctx = find_store_cert_by_name(cert_name, store_name)
        identity_log = f"cert_name={cert_name!r}"
    elif thumbprint:
        cert_ctx = find_store_cert(thumbprint, store_name)
        identity_log = f"thumbprint={thumbprint.replace(' ', '').upper()}"
    else:
        raise_config_error(
            "Schannel requires server.tls.schannel.identity_cert_name or "
            "server.tls.schannel.identity_cert_thumbprint "
            "(optional server.tls.schannel.identity_cert_store, default MY)."
        )

    pa = (win32.POINTER(win32.CERT_CONTEXT) * 1)(cert_ctx)
    # Empty TLS_PARAMETERS: honor Windows defaults (no agent protocol disables).
    tls_params = win32.TLS_PARAMETERS()

    schcred = win32.SCH_CREDENTIALS()
    schcred.dwVersion = win32.SCH_CREDENTIALS_VERSION
    schcred.cCreds = 1
    schcred.paCred = win32.cast(pa, win32.POINTER(win32.POINTER(win32.CERT_CONTEXT)))
    schcred.hRootStore = None

    schcred.dwFlags = (
        win32.SCH_CRED_NO_SYSTEM_MAPPER |
        win32.SCH_CRED_NO_DEFAULT_CREDS
    )
    schcred.cTlsParameters = 1
    schcred.pTlsParameters = win32.pointer(tls_params)

    handle = win32.CredHandle()
    expiry = win32.FILETIME()
    logger.debug("Schannel AcquireCredentialsHandle SCH_CREDENTIALS (inbound)")
    status = win32.secur32.AcquireCredentialsHandleW(
        None,
        win32.UNISP_NAME,
        win32.SECPKG_CRED_INBOUND,
        None,
        win32.byref(schcred),
        None,
        None,
        win32.byref(handle),
        win32.byref(expiry),
    )
    if status != win32.SEC_E_OK:
        win32.crypt32.CertFreeCertificateContext(cert_ctx)
        raise_config_error(
            f"Schannel cannot use the private key for {identity_log} "
            f"in LocalMachine\\{store_name} (server.tls.schannel.identity_cert_store); "
            f"AcquireCredentialsHandle(SCH_CREDENTIALS) failed {status_hex(status)}. "
            "Windows Server configuration: grant the Infrastructure Agent service "
            "account Read on that certificate's private key "
            "(certmgr.msc → certificate → All Tasks → Manage Private Keys), "
            "or correct server.tls.schannel.identity_cert_name / identity_cert_thumbprint / "
            "identity_cert_store. "
            "Schannel requires Windows Server 2019 / Windows 10 1809 or later.",
            winerror=status,
        )
    # Schannel still references this memory. release_server_credential frees it.
    handle._keep = (pa, cert_ctx, schcred, tls_params)  # type: ignore[attr-defined]
    handle._released = False  # type: ignore[attr-defined]

    logger.info(
        "Schannel server credential acquired from LocalMachine\\%s %s "
        "(TLS protocols/ciphers from Windows Schannel / OS policy)",
        store_name,
        identity_log,
    )
    return handle


def release_server_credential(handle) -> None:
    """
    Free an inbound credential acquired by acquire_server_credential.

    FreeCredentialsHandle runs first. The certificate context is freed only
    after that succeeds, because Schannel may still reference it.
    """
    if handle is None or getattr(handle, '_released', False):
        return
    win32.ensure_win32()
    status = win32.secur32.FreeCredentialsHandle(win32.byref(handle))
    if status != win32.SEC_E_OK:
        logger.warning("FreeCredentialsHandle failed: %s", status_hex(status))
        return
    keep = getattr(handle, '_keep', None)
    cert_ctx = keep[1] if keep else None
    if cert_ctx:
        win32.crypt32.CertFreeCertificateContext(cert_ctx)
    handle._keep = None  # type: ignore[attr-defined]
    handle._released = True  # type: ignore[attr-defined]
