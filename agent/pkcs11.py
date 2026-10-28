"""
PKCS#11 identity loading for python_ssl (OpenSSL 3 provider + OSSL_STORE).

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import atexit
import logging
import os
import sys
import tempfile
from functools import wraps
from typing import TYPE_CHECKING, Optional

from agent.config import VAR_DIR_NAME, get_agent_root

if TYPE_CHECKING:
    from agent.config import TLSConfig
    from agent.ssl_helper import OpenSSLLibraries

logger = logging.getLogger(__name__)

# OpenSSL 3 OSSL_STORE_INFO types (ossl_store.h).
OSSL_STORE_INFO_PKEY = 4
OSSL_STORE_INFO_CERT = 5
PKCS11_PROVIDER_SO = 'pkcs11.so'
PIN_FILE_NAME = 'agent-pkcs11-pin'
# Fail closed unless the bundled CPython SSLContext layout is the one we tested.
PKCS11_REQUIRED_PYTHON = (3, 14)


class _PKCS11ProviderHandle:
    """Provider reference that must outlive SSL objects using token keys."""

    def __init__(
            self,
            openssl: 'OpenSSLLibraries',
            provider,
            pin_files: Optional['_EphemeralPinFiles'] = None,
    ):
        self.openssl = openssl
        self.provider = provider
        self.pin_files = pin_files

    def close(self):
        """Unload the provider after a failed setup. Never call after attach."""
        if self.pin_files:
            self.pin_files.close()
            self.pin_files = None
        if self.provider:
            self.openssl.crypto.OSSL_PROVIDER_unload(self.provider)
            self.provider = None


# Successful PKCS#11 loads keep provider refs here until process exit.
_PKCS11_PROVIDER_KEEPALIVES: list[_PKCS11ProviderHandle] = []


def require_pkcs11_runtime(context):
    """Reject runtimes whose SSLContext layout was not tested."""
    from agent.ssl_helper import AgentSSLError

    if sys.implementation.name != 'cpython':
        raise AgentSSLError("PKCS#11 identity loading requires CPython")
    if sys.version_info[:2] != PKCS11_REQUIRED_PYTHON:
        raise AgentSSLError(
            "PKCS#11 identity loading is only validated with CPython 3.14"
        )
    gil_enabled = getattr(sys, '_is_gil_enabled', lambda: True)
    if not gil_enabled():
        raise AgentSSLError(
            "PKCS#11 identity loading is not supported on free-threaded CPython"
        )
    try:
        import _ssl
    except ImportError as ex:
        raise AgentSSLError("PKCS#11 identity loading requires the _ssl module") from ex
    if not isinstance(context, _ssl._SSLContext):
        raise AgentSSLError("PKCS#11 identity loading requires a stdlib SSLContext")


def _pkcs11_provider_modules_dir() -> str:
    """Directory that contains the bundled ossl-modules/pkcs11.so.

    Uses the same lib directories as the packaged OpenSSL lookup, so a source
    run finds the provider under the dev Python prefix.
    """
    from agent.ssl_helper import AgentSSLError, _packaged_openssl_lib_dirs

    for lib_dir in _packaged_openssl_lib_dirs():
        directory = os.path.join(lib_dir, 'ossl-modules')
        if os.path.isfile(os.path.join(directory, PKCS11_PROVIDER_SO)):
            return os.path.abspath(directory)
    raise AgentSSLError(
        "Bundled OpenSSL PKCS#11 provider pkcs11.so was not found"
    )


def _pkcs11_uri_has_pin_attribute(uri: str) -> bool:
    """True when ``pin-value`` or ``pin-source`` is already a URI attribute.

    Path attributes are separated by ``;`` and query attributes by ``&``.
    A substring inside another attribute value does not count.
    """
    path, _, query = uri.partition('?')
    for component, separator in ((path, ';'), (query, '&')):
        for attr in component.split(separator):
            name = attr.split('=', 1)[0]
            if name.lower() in ('pin-value', 'pin-source'):
                return True
    return False


def _pkcs11_uri_for_store(uri: str, pin: Optional[str], pin_files: '_EphemeralPinFiles') -> str:
    """
    Bind ``pin`` as a ``pin-source`` query attribute through an ephemeral file.

    RFC 7512 places ``pin-source`` and ``pin-value`` in the query component.
    ``?`` starts that component and ``&`` separates further query attributes.
    The configured PIN is never inserted as ``pin-value=``. The URI is
    returned unchanged when ``pin`` is missing, or when it already has a
    ``pin-value`` or ``pin-source`` attribute.
    """
    if (not pin) or _pkcs11_uri_has_pin_attribute(uri):
        return uri
    pin_path = pin_files.write(PIN_FILE_NAME, pin.encode('utf-8'))
    attr = f'pin-source=file:{pin_path}'
    if '?' in uri:
        if uri.endswith(('?', '&')):
            return f'{uri}{attr}'
        return f'{uri}&{attr}'
    return f'{uri}?{attr}'


def _ossl_store_load_object(
        openssl: 'OpenSSLLibraries',
        uri: str,
        info_type: int,
        getter_name: str,
        action: str,
):
    """Load the first matching object from an OSSL_STORE URI."""
    from agent.ssl_helper import openssl_check

    store = openssl.crypto.OSSL_STORE_open(uri.encode('utf-8'), None, None, None, None)
    openssl_check(store, openssl, action)
    found = None
    try:
        while not openssl.crypto.OSSL_STORE_eof(store):
            info = openssl.crypto.OSSL_STORE_load(store)
            if not info:
                if openssl.crypto.OSSL_STORE_error(store):
                    openssl_check(0, openssl, action)
                break
            try:
                if openssl.crypto.OSSL_STORE_INFO_get_type(info) == info_type:
                    found = getattr(openssl.crypto, getter_name)(info)
                    if found:
                        break
            finally:
                openssl.crypto.OSSL_STORE_INFO_free(info)
    finally:
        openssl.crypto.OSSL_STORE_close(store)
    openssl_check(found, openssl, action)
    return found


def _restore_pkcs11_module_environment(function):
    """Restore the process-global provider module setting after setup."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        missing = object()
        previous = os.environ.get('PKCS11_PROVIDER_MODULE', missing)
        try:
            return function(*args, **kwargs)
        finally:
            if previous is missing:
                os.environ.pop('PKCS11_PROVIDER_MODULE', None)
            else:
                os.environ['PKCS11_PROVIDER_MODULE'] = previous
    return wrapped


@_restore_pkcs11_module_environment
def load_pkcs11_into_context(context, tls_config: 'TLSConfig'):
    """
    Load a PKCS#11 private key and identity certificate into SSLContext.

    The certificate is read from cert_file (identity_cert_file) when set,
    otherwise from identity_cert.uri. The bundled OpenSSL 3 pkcs11 provider
    remains loaded for the process lifetime because handshakes use the
    non-extractable key.
    """
    from agent.ssl_helper import (
        AgentSSLError,
        OpenSSLLibraries,
        get_ssl_ctx_pointer,
        openssl_check,
        check_file_access,
    )

    if sys.platform == 'win32':
        raise AgentSSLError("PKCS#11 TLS identity is only supported on Linux")

    require_pkcs11_runtime(context)
    check_file_access(tls_config.pkcs11_module)
    if tls_config.cert_file:
        check_file_access(tls_config.cert_file)

    modules_dir = _pkcs11_provider_modules_dir()
    os.environ['PKCS11_PROVIDER_MODULE'] = os.path.abspath(tls_config.pkcs11_module)
    # Load pkcs11.so by path. Do not set OPENSSL_MODULES or replace the
    # provider search path: freeze libcrypto's default provider must stay
    # available for X509 verify (ca_cert: system).

    openssl = OpenSSLLibraries()
    openssl.crypto.ERR_clear_error()
    provider_path = os.path.join(modules_dir, PKCS11_PROVIDER_SO)
    provider = openssl.crypto.OSSL_PROVIDER_load(None, os.fsencode(provider_path))
    openssl_check(provider, openssl, "load the bundled PKCS#11 provider")

    handle = _PKCS11ProviderHandle(openssl, provider)
    pin_files = _EphemeralPinFiles()
    handle.pin_files = pin_files
    private_key = None
    certificate = None
    failed = False
    try:
        key_uri = _pkcs11_uri_for_store(
            tls_config.pkcs11_key_uri, tls_config.pkcs11_key_pin, pin_files
        )
        private_key = _ossl_store_load_object(
            openssl,
            key_uri,
            OSSL_STORE_INFO_PKEY,
            'OSSL_STORE_INFO_get1_PKEY',
            "load the PKCS#11 private key",
        )

        ssl_ctx = get_ssl_ctx_pointer(context, openssl)
        if tls_config.cert_file:
            openssl_check(
                openssl.ssl.SSL_CTX_use_certificate_chain_file(
                    ssl_ctx, os.fsencode(tls_config.cert_file)
                ),
                openssl,
                "load the PKCS#11 identity certificate",
            )
        else:
            cert_uri = _pkcs11_uri_for_store(
                tls_config.pkcs11_cert_uri,
                tls_config.pkcs11_cert_pin,
                pin_files,
            )
            certificate = _ossl_store_load_object(
                openssl,
                cert_uri,
                OSSL_STORE_INFO_CERT,
                'OSSL_STORE_INFO_get1_CERT',
                "load the PKCS#11 identity certificate from the token",
            )
            openssl_check(
                openssl.ssl.SSL_CTX_use_certificate(ssl_ctx, certificate),
                openssl,
                "attach the PKCS#11 identity certificate",
            )
        openssl_check(
            openssl.ssl.SSL_CTX_use_PrivateKey(ssl_ctx, private_key),
            openssl,
            "attach the PKCS#11 private key",
        )
        openssl_check(
            openssl.ssl.SSL_CTX_check_private_key(ssl_ctx),
            openssl,
            "match the PKCS#11 key and certificate",
        )
        openssl.crypto.ERR_clear_error()

        # Keep the PIN file so later sign operations can re-read pin-source.
        # Agent.stop unlinks it, and atexit is the backstop for a normal
        # interpreter exit. SIGKILL cannot run either; startup removes leftovers.
        _PKCS11_PROVIDER_KEEPALIVES.append(handle)
        context._pkcs11_provider_handle = handle
    except Exception:
        failed = True
        raise
    finally:
        # Free the key and certificate before OSSL_PROVIDER_unload. PKCS#11
        # key teardown can re-enter the provider. finally runs before the
        # exception leaves this function.
        try:
            if private_key:
                openssl.crypto.EVP_PKEY_free(private_key)
            if certificate:
                openssl.crypto.X509_free(certificate)
        finally:
            if failed:
                handle.close()


def _agent_var_dir() -> str:
    """Agent var directory. System temp cleaners such as tmpwatch do not scan it."""
    directory = get_agent_root() / VAR_DIR_NAME
    os.makedirs(directory, exist_ok=True)
    return str(directory)


def _live_pin_paths() -> set[str]:
    live = set()
    for handle in _PKCS11_PROVIDER_KEEPALIVES:
        pin_files = handle.pin_files
        if pin_files is None:
            continue
        for path in pin_files.paths():
            live.add(os.path.abspath(path))
    return live


def close_pin_files() -> None:
    """Unlink PIN files kept so OpenSSL can re-read pin-source.

    Does not unload the PKCS#11 provider. Call this after the listener has
    stopped signing. Safe to call more than once.
    """
    for handle in _PKCS11_PROVIDER_KEEPALIVES:
        pin_files = handle.pin_files
        if pin_files is not None:
            pin_files.close()
            handle.pin_files = None


def remove_stale_pin_files() -> list[str]:
    """Unlink PIN files left when a previous process was killed.

    SIGKILL cannot run atexit or Agent.stop. Call this at startup, before this
    process creates a PIN file. Files still owned by this process are kept.
    """
    directory = get_agent_root() / VAR_DIR_NAME
    if not directory.is_dir():
        return []
    live = _live_pin_paths()
    removed = []
    for path in directory.glob(f'{PIN_FILE_NAME}-*'):
        if not path.is_file():
            continue
        if os.path.abspath(path) in live:
            continue
        try:
            path.unlink()
        except OSError:
            logger.warning("Failed to remove stale PKCS#11 PIN file %s", path)
            continue
        removed.append(str(path))
    return removed


class _EphemeralPinFiles:
    """
    Hold PKCS#11 PINs in 0o600 files under the agent var directory.

    OpenSSL reads them through pin-source=file: while the agent is running.
    close() unlinks them. Agent.stop calls close(); atexit covers a normal
    interpreter exit. A killed process leaves the files for the next startup.
    """

    def __init__(self):
        self._paths: list[str] = []
        atexit.register(self.close)

    def paths(self) -> list[str]:
        return list(self._paths)

    def write(self, name: str, data: bytes) -> str:
        fd, path = tempfile.mkstemp(prefix=f'{name}-', dir=_agent_var_dir())
        try:
            os.chmod(path, 0o600)
            os.write(fd, data)
            os.close(fd)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        self._paths.append(path)
        return path

    def close(self):
        atexit.unregister(self.close)
        while self._paths:
            path = self._paths.pop()
            try:
                os.unlink(path)
            except OSError:
                pass
