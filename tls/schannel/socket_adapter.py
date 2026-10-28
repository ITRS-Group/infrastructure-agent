"""
NRPE-facing Schannel socket adapter (gevent ThreadPool + raw sockets).

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import socket as socket_mod
from typing import Optional

import gevent.monkey as gevent_monkey
from cryptography import x509

from tls.schannel.errors import SchannelError
from tls.schannel.session import SchannelServerSession


def _get_raw_socket_type():
    """Blocking stdlib socket, not gevent's monkey-patched socket.socket."""
    return gevent_monkey.get_original('socket', 'socket')


_RawSocket = _get_raw_socket_type()
_thread_pool = None
_thread_pool_size: Optional[int] = None

# When no socket timeout is configured, AsyncResult.get(timeout=...) is only a
# safety net — it must not be the primary cancellation mechanism because the
# worker keeps blocking on SSPI/socket I/O after the greenlet waiter times out.
_DEFAULT_POOL_WAIT = 120.0
_HANDSHAKE_POOL_WAIT = 60.0
_CLOSE_POOL_WAIT = 5.0


def configure_thread_pool(max_workers: int) -> None:
    """
    Size the shared Schannel ThreadPool from NRPE max_active_connections.

    Call from SchannelTlsServer construction before the first wrap/handshake.
    """
    global _thread_pool, _thread_pool_size
    size = max(1, int(max_workers))
    if _thread_pool is not None and _thread_pool_size == size:
        return
    from gevent.threadpool import ThreadPool
    _thread_pool_size = size
    _thread_pool = ThreadPool(size)


def _get_thread_pool():
    if _thread_pool is None:
        raise SchannelError(
            "Schannel thread pool is not configured; max_active_connections must be "
            "passed when constructing the Schannel TLS server."
        )
    return _thread_pool


def shutdown_thread_pool() -> None:
    """Finish queued Schannel work and stop the shared pool."""
    global _thread_pool, _thread_pool_size
    pool = _thread_pool
    _thread_pool = None
    _thread_pool_size = None
    if pool is None:
        return
    try:
        pool.join()
    finally:
        pool.kill()


def _normalize_timeout(value) -> Optional[float]:
    if value is None or value == 0 or value == 0.0:
        return None
    return float(value)


def _apply_socket_timeout(sock, timeout: Optional[float]) -> None:
    """Apply a blocking socket timeout inside a thread-pool worker."""
    sock.setblocking(True)
    sock.settimeout(timeout)


def _run_on_pool(sock, timeout, func, *, pool_wait: float = _DEFAULT_POOL_WAIT):
    """
    Run blocking Schannel work on the shared thread pool.

    When *timeout* is set, apply it on the raw socket inside the worker so
    blocking recv/send/SSPI I/O returns and releases the pool slot. Do not rely
    on AsyncResult.get(timeout=...) alone — that abandons the greenlet waiter
    while the worker remains blocked.
    """
    effective = _normalize_timeout(timeout)

    def _worker():
        _apply_socket_timeout(sock, effective)
        return func()

    async_result = _get_thread_pool().spawn(_worker)
    if effective is not None:
        return async_result.get()
    return async_result.get(timeout=pool_wait)


def _reraise_from_pool(ex: BaseException) -> None:
    """Unwrap exceptions raised inside a thread-pool worker."""
    if isinstance(ex, SchannelError):
        raise ex
    if isinstance(ex, socket_mod.timeout):
        raise ex
    cause = ex
    while cause is not None:
        if isinstance(cause, SchannelError):
            raise cause from ex
        if isinstance(cause, socket_mod.timeout):
            raise cause from ex
        cause = cause.__cause__ or cause.__context__
    raise ex


def peercert_dict_from_der(der: bytes) -> dict:
    """Build an ssl.getpeercert()-like dict from certificate DER."""
    cert = x509.load_der_x509_certificate(der)
    subject = []
    for attr in cert.subject:
        subject.append(((attr.oid._name, attr.value),))
    san_list = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san.value:
            if isinstance(name, x509.DNSName):
                san_list.append(('DNS', name.value))
            elif isinstance(name, x509.IPAddress):
                san_list.append(('IP Address', str(name.value)))
    except x509.ExtensionNotFound:
        pass
    result = {'subject': tuple(subject)}
    if san_list:
        result['subjectAltName'] = tuple(san_list)
    return result


class SchannelSocket:
    """
    Socket-like wrapper used by NRPEListener after accept.

    Blocking Schannel work is dispatched to a gevent ThreadPool.
    """

    def __init__(self, raw_sock, session: SchannelServerSession, peername):
        self._raw = raw_sock
        self._session = session
        self._peername = peername
        self._timeout: Optional[float] = None

    @classmethod
    def wrap_accepted(
            cls,
            conn,
            cred,
            handshake_timeout: float,
            check_client_cert: bool = False,
    ) -> 'SchannelSocket':
        """Detach/accept path: make blocking, handshake on thread pool, return wrapper."""
        fileno = conn.fileno()
        peername = conn.getpeername()
        std_sock = _RawSocket(socket_mod.AF_INET, socket_mod.SOCK_STREAM, fileno=fileno)
        try:
            conn.detach()
        except (AttributeError, OSError):
            pass

        std_sock.setblocking(True)

        session = SchannelServerSession(std_sock, cred, check_client_cert=check_client_cert)

        try:
            _run_on_pool(
                std_sock,
                handshake_timeout,
                session.handshake,
                pool_wait=_HANDSHAKE_POOL_WAIT,
            )
        except SchannelError:
            try:
                session.close()
            except Exception:  # pragma: no cover -- best-effort close after handshake failure
                pass
            # Preserve actionable SchannelError text (do not wrap as generic handshake failed).
            raise
        except socket_mod.timeout:
            try:
                session.close()
            except Exception:  # pragma: no cover -- best-effort close after handshake failure
                pass
            raise
        except Exception as ex:
            try:
                session.close()
            except Exception:  # pragma: no cover -- best-effort close after handshake failure
                pass
            cause = ex
            while cause is not None:
                if isinstance(cause, (SchannelError, socket_mod.timeout)):
                    raise cause from ex
                cause = cause.__cause__ or cause.__context__
            raise SchannelError(f"Schannel handshake failed: {ex}") from ex

        wrapped = cls(std_sock, session, peername)
        wrapped.settimeout(None)
        return wrapped

    def getpeername(self):
        return self._peername

    def settimeout(self, value):
        self._timeout = value
        try:
            self._raw.settimeout(value if value not in (0, 0.0) else None)
        except OSError:
            pass

    def getpeercert(self, binary_form=False):
        der = self._session._peer_der
        if not der:
            return None
        return der if binary_form else peercert_dict_from_der(der)

    def version(self) -> str:
        return self._session._protocol_name

    def cipher(self):
        return self._session._cipher_tuple

    def recv(self, buflen: int, flags: int = 0) -> bytes:
        try:
            return _run_on_pool(
                self._raw,
                self._timeout,
                lambda: self._session.recv_clear(buflen),
            )
        except (SchannelError, socket_mod.timeout):
            raise
        except Exception as ex:
            _reraise_from_pool(ex)

    def sendall(self, data: bytes):
        payload = data if isinstance(data, (bytes, bytearray)) else bytes(data)
        try:
            _run_on_pool(
                self._raw,
                self._timeout,
                lambda: self._session.send_clear(payload),
            )
        except (SchannelError, socket_mod.timeout):
            raise
        except Exception as ex:
            _reraise_from_pool(ex)

    def close(self):
        try:
            _run_on_pool(
                self._raw,
                _CLOSE_POOL_WAIT,
                self._session.close,
                pool_wait=_CLOSE_POOL_WAIT,
            )
        except Exception:
            try:
                self._session.close()
            except Exception:
                pass
