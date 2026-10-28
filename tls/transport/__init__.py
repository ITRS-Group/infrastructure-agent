"""
NRPE-facing TLS transport facade.

Callers import only this package. Backend packages are selected from config.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from tls.transport.capabilities import log_selection, select_backend

logger = logging.getLogger('tls')

if TYPE_CHECKING:
    from agent.config import TLSConfig
    from agent.objects import Platform


@runtime_checkable
class TlsConnection(Protocol):  # pragma: no cover
    """Socket-like TLS connection used by NRPE after wrap."""

    def getpeername(self):
        ...

    def settimeout(self, value) -> None:
        ...

    def getpeercert(self, binary_form: bool = False):
        ...

    def version(self) -> str:
        ...

    def cipher(self):
        ...

    def recv(self, buflen: int, flags: int = 0) -> bytes:
        ...

    def sendall(self, data: bytes) -> None:
        ...

    def close(self) -> None:
        ...


@runtime_checkable
class TlsServerTransport(Protocol):  # pragma: no cover
    """TLS server that wraps accepted sockets."""

    backend: str

    def wrap_accepted(self, conn) -> TlsConnection:
        ...


def _debug_tls_identity(tls_config: 'TLSConfig', name: str) -> None:
    """Log configured TLS identity keys (never PKCS#11 pins or URI pin-value)."""
    from agent.ssl_helper import redact_pkcs11_secrets

    logger.debug(
        "%s TLS server identity: connector=%s backend=%s schannel_cert_name=%r "
        "schannel_cert_thumbprint=%s schannel_cert_store=%s "
        "cert_file=%s key_file=%s ca_cert=%s ca_path=%s pkcs11_module=%s pkcs11_key_uri=%s "
        "pkcs11_cert_uri=%s check_client_cert=%s check_server_cert=%s",
        name,
        getattr(tls_config, 'connector', None),
        getattr(tls_config, 'backend', None),
        getattr(tls_config, 'schannel_cert_name', None),
        getattr(tls_config, 'schannel_cert_thumbprint', None),
        getattr(tls_config, 'schannel_cert_store', None),
        getattr(tls_config, 'cert_file', None),
        getattr(tls_config, 'key_file', None),
        getattr(tls_config, 'ca_cert', None),
        getattr(tls_config, 'ca_path', None),
        getattr(tls_config, 'pkcs11_module', None),
        redact_pkcs11_secrets(getattr(tls_config, 'pkcs11_key_uri', None)),
        redact_pkcs11_secrets(getattr(tls_config, 'pkcs11_cert_uri', None)),
        getattr(tls_config, 'check_client_cert', False),
        getattr(tls_config, 'check_server_cert', False),
    )


def create_tls_server(
        tls_config: 'TLSConfig',
        handshake_timeout: float,
        platform: 'Platform',
        max_active_connections: int,
        name: str = 'NRPE',
) -> TlsServerTransport:
    """Select and construct a TLS server transport for the NRPE listener."""
    selection = select_backend(tls_config, platform)
    log_selection(selection, name=name)
    _debug_tls_identity(tls_config, name)
    logger.debug("%s constructing TLS backend=%s", name, selection.backend)

    if selection.backend == 'schannel':
        from tls.schannel.server import SchannelTlsServer
        return SchannelTlsServer(
            tls_config,
            handshake_timeout,
            max_active_connections,
        )
    from tls.python_ssl.server import PythonSslTlsServer
    return PythonSslTlsServer(tls_config, handshake_timeout, platform)
