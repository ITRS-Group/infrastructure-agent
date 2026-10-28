"""
Schannel error types and operator-facing failure helpers.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import logging
import ssl
from typing import Optional

logger = logging.getLogger('tls')

# Win32 GetLastError codes (winerror.h) used by store-open helpers.
ERROR_ACCESS_DENIED = 5


class SchannelError(ssl.SSLError):
    """Schannel / certificate store failures surfaced as SSLError for NRPE handling."""

    def __init__(self, message: str, *, winerror: Optional[int] = None):
        # ssl.SSLError stringifies args as a tuple; keep a clear operator-facing message.
        super().__init__(message)
        self._message = message
        self.winerror = winerror

    def __str__(self) -> str:
        return self._message

    def __repr__(self) -> str:
        if self.winerror is not None:
            return f"SchannelError({self._message!r}, winerror={self.winerror})"
        return f"SchannelError({self._message!r})"


def status_hex(status: int) -> str:
    return f"0x{(status & 0xFFFFFFFF):08X}"


def raise_config_error(message: str, *, winerror: Optional[int] = None) -> None:
    """
    Raise SchannelError after logging.

    For operator-facing failures: agent TLS settings *or* Windows Server
    configuration (store ACLs, private-key permissions, service account rights).
    """
    if winerror is not None:
        logger.error("%s (winerror=%s)", message, status_hex(winerror))
    else:
        logger.error("%s", message)
    raise SchannelError(message, winerror=winerror)


def raise_store_open_error(store_name: str, err: int) -> None:
    """CertOpenStore failed — almost always Windows Server / account rights."""
    if err == ERROR_ACCESS_DENIED:
        hint = (
            "Windows Server configuration: the account running Infrastructure Agent "
            "cannot open LocalMachine certificate stores. Grant that service account "
            "permission to read Local Computer certificates (or run the service as an "
            "account that already can)."
        )
    else:
        hint = (
            "Windows Server configuration: confirm LocalMachine\\"
            f"{store_name} exists (usually MY / Personal), or correct "
            "server.tls.schannel.identity_cert_store."
        )
    raise_config_error(
        f"Cannot open certificate store LocalMachine\\{store_name} "
        f"(server.tls.schannel.identity_cert_store). GetLastError={err}. {hint}",
        winerror=err,
    )
