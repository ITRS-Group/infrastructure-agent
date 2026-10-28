"""
Schannel TLS server transport for NRPE.

Requires Windows Server 2019 / Windows 10 1809 or later.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from tls.schannel.socket_adapter import (
    SchannelSocket,
    configure_thread_pool,
    shutdown_thread_pool,
)
from tls.schannel.store import acquire_server_credential, release_server_credential

if TYPE_CHECKING:
    from agent.config import TLSConfig

logger = logging.getLogger('tls')


class SchannelTlsServer:
    """TLS server using Windows Schannel + LocalMachine certificate store."""

    backend = 'schannel'

    def __init__(
            self,
            tls_config: 'TLSConfig',
            handshake_timeout: float,
            max_active_connections: int,
    ):
        self._tls_config = tls_config
        self._handshake_timeout = handshake_timeout
        self._check_client_cert = bool(tls_config.check_client_cert)
        store = tls_config.schannel_cert_store or 'MY'
        # Align Schannel worker pool with NRPE concurrency
        configure_thread_pool(max_active_connections)
        logger.debug(
            "Schannel TLS server: opening LocalMachine\\%s schannel_cert_name=%r "
            "schannel_cert_thumbprint=%s "
            "check_client_cert=%s handshake_timeout=%s max_active_connections=%s",
            store,
            tls_config.schannel_cert_name,
            tls_config.schannel_cert_thumbprint,
            self._check_client_cert,
            handshake_timeout,
            max_active_connections,
        )
        # Store/identity failures raise SchannelError with config-fixable messages
        # (logged at ERROR in helper) and surface via NRPE startup as TLS transport errors.
        self._cred = acquire_server_credential(
            thumbprint=tls_config.schannel_cert_thumbprint,
            store_name=store,
            cert_name=tls_config.schannel_cert_name,
        )

    def wrap_accepted(self, conn):
        return SchannelSocket.wrap_accepted(
            conn,
            self._cred,
            self._handshake_timeout,
            check_client_cert=self._check_client_cert,
        )

    def close(self) -> None:
        """Release the inbound credential after pooled Schannel work has finished."""
        try:
            shutdown_thread_pool()
        finally:
            cred = self._cred
            self._cred = None
            if cred is not None:
                release_server_credential(cred)
