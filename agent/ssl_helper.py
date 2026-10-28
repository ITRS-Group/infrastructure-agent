"""
Infrastructure Agent: SSL helper functions
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations


import ctypes
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agent.config import get_agent_root

if TYPE_CHECKING:
    from agent.config import TLSConfig

logger = logging.getLogger(__name__)

SELF_SIGNED_CERTIF_DIR = 'var'
# YAML sentinel (not an OpenSSL cipher name or file path).
TLS_SYSTEM_SENTINEL = 'system'
OPENSSL_CIPHERS_TIMEOUT = 5
SYSTEM_CIPHER_EXCLUSIONS = ('!aNULL', '!MD5', '!DSS', '!RC4', '!3DES')
# Host CA locations for ca_cert: system (freeze OPENSSLDIR is not used).
HOST_CA_BUNDLE_FILES = (
    '/etc/pki/tls/cert.pem',
    '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
    '/etc/ssl/certs/ca-certificates.crt',
    '/etc/ssl/ca-bundle.pem',
    '/etc/ssl/cert.pem',
)
HOST_CA_BUNDLE_DIRS = (
    '/etc/ssl/certs',
)
# Extra operator CAs (update-ca-trust / update-ca-certificates). Loaded in
# addition to the distro bundle so freeze OpenSSL still trusts local anchors
# if the mega-bundle parse drops them.
HOST_CA_ANCHOR_DIRS = (
    '/etc/pki/ca-trust/source/anchors',
    '/usr/local/share/ca-certificates',
    '/etc/ca-certificates/trust-source/anchors',
)
HOST_CA_ANCHOR_SUFFIXES = ('.pem', '.crt')
# RHEL/Fedora crypto-policies OpenSSL backend (MinProtocol / MaxProtocol).
HOST_CRYPTO_POLICY_OPENSSLCNF = Path('/etc/crypto-policies/back-ends/opensslcnf.config')
HOST_OPENSSL = '/usr/bin/openssl'
_TLS_VERSION_NAMES = {
    'SSLv3': ssl.TLSVersion.SSLv3,
    'TLSv1': ssl.TLSVersion.TLSv1,
    'TLSv1.0': ssl.TLSVersion.TLSv1,
    'TLSv1.1': ssl.TLSVersion.TLSv1_1,
    'TLSv1.2': ssl.TLSVersion.TLSv1_2,
    'TLSv1.3': ssl.TLSVersion.TLSv1_3,
}
_OPENSSL_TLS_VERSION_PROBES = (
    ('-tls1', ssl.TLSVersion.TLSv1),
    ('-tls1_1', ssl.TLSVersion.TLSv1_1),
    ('-tls1_2', ssl.TLSVersion.TLSv1_2),
    ('-tls1_3', ssl.TLSVersion.TLSv1_3),
)
# Exponent set based on IETF recommendations https://www.ietf.org/rfc/rfc4871.txt
KEY_PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048


class AgentSSLError(Exception):
    """SSL exceptions"""

    pass


def get_ssl_context(tls_config: TLSConfig, name: str, client_mode=False) -> ssl.SSLContext:
    """Validate the TLS configuration and set up the SSL context"""
    # NRPE Schannel uses tls.schannel when connector=schannel — not OpenSSL PEM load.
    if (
        not client_mode and
        getattr(tls_config, 'connector', None) == 'schannel' and
        sys.platform.startswith('win')
    ):
        raise AgentSSLError(
            f"{name}: connector=schannel — use tls.schannel instead of OpenSSL PEM load_cert_chain"
        )

    logger.debug("%s: Using OpenSSL version '%s'", name, ssl.OPENSSL_VERSION)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if client_mode else ssl.PROTOCOL_TLS_SERVER)
    use_system_ca = tls_config.ca_cert == TLS_SYSTEM_SENTINEL
    has_file_ca = bool((tls_config.ca_cert and not use_system_ca) or tls_config.ca_path)
    has_supplied_ca = use_system_ca or has_file_ca
    has_identity = bool(tls_config.cert_file or tls_config.pkcs11_key_uri)
    if client_mode:
        if tls_config.check_server_cert:
            logger.debug("%s: Check server certificate", name)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    else:
        if tls_config.check_client_cert:
            logger.debug("%s: Check client certificate", name)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_OPTIONAL
        if not has_identity:
            if not tls_config.key_file and not has_supplied_ca:
                tls_config.key_file, tls_config.cert_file = create_self_signed_cert(name, SELF_SIGNED_CERTIF_DIR)
            else:
                error = f"{name}: TLS identity is not configured"
                logger.error(error)
                raise AgentSSLError(error)

    if tls_config.log_all_messages:
        logger.debug("%s: Logging all TLS messages", name)
        context._msg_callback = ssl_debug_message_callback

    if use_system_ca:
        logger.debug("%s: Loading system default CA certificates", name)
        try:
            load_system_ca_certs(context, name)
            if tls_config.ca_path:
                logger.debug("%s: Adding configured CA path to system trust", name)
                os.listdir(tls_config.ca_path)
                context.load_verify_locations(None, tls_config.ca_path)
        except AgentSSLError:
            raise
        except Exception as ex:
            raise AgentSSLError(f"{name}: {str(ex)}")
    elif has_file_ca:
        logger.debug("%s: Using configured CA Certificate(s)", name)
        # check access - load_verify_locations() does not indicate which item failed
        try:
            if tls_config.ca_cert:
                check_file_access(tls_config.ca_cert)
            if tls_config.ca_path:
                os.listdir(tls_config.ca_path)
            context.load_verify_locations(tls_config.ca_cert, tls_config.ca_path)
        except Exception as ex:
            raise AgentSSLError(f"{name}: {str(ex)}")
    else:
        logger.debug("%s: Loading system default CA certificates", name)
        context.load_default_certs(purpose=ssl.Purpose.CLIENT_AUTH)

    if tls_config.pkcs11_key_uri:
        logger.debug("%s: Using configured TLS PKCS#11 identity", name)
        try:
            from agent.pkcs11 import load_pkcs11_into_context
            load_pkcs11_into_context(context, tls_config)
        except AgentSSLError:
            raise
        except Exception as ex:
            raise AgentSSLError(f"{name}: {str(ex)}")
    elif tls_config.cert_file:
        logger.debug("%s: Using configured TLS cert_file%s", name, " and key_file" if tls_config.key_file else "")
        try:
            # check access - load_cert_chain() does not indicate which item failed
            check_file_access(tls_config.cert_file)
            if tls_config.key_file:
                check_file_access(tls_config.key_file)
            # None lets OpenSSL prompt on a TTY and raise OSError otherwise.
            # This callback runs only when the private key is encrypted.

            def _missing_key_passphrase():
                error = f"{name}: encrypted TLS private key requires key_passphrase"
                logger.error(error)
                raise AgentSSLError(error)

            key_password = tls_config.key_passphrase or _missing_key_passphrase
            context.load_cert_chain(
                tls_config.cert_file, tls_config.key_file, password=key_password
            )
        except AgentSSLError:
            raise
        except ssl.SSLError:
            files = f"{tls_config.cert_file} {tls_config.key_file if tls_config.key_file else ''}"
            error = f"{name}: TLS key missing or does not match the certificate: {files.strip()}"
            logger.error(error)
            raise AgentSSLError(error)
        except Exception as ex:
            raise AgentSSLError(f"{name}: {str(ex)}")

    host_tls12_ciphers = True
    if tls_config.cipher_suite == TLS_SYSTEM_SENTINEL:
        logger.debug("%s: Using host OpenSSL TLS ciphers", name)
        try:
            tls12_ciphers, tls13_ciphersuites = get_system_cipher_lists()
            host_tls12_ciphers = bool(tls12_ciphers)
            if tls12_ciphers:
                context.set_ciphers(tls12_ciphers)
                logger.debug("%s: Host TLS 1.2 cipher string '%s'", name, tls12_ciphers)
            else:
                # Do not leave freeze default TLS 1.2 ciphers when the host
                # list is empty. Require TLS 1.3 until protocol policy is applied.
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                logger.debug("%s: No host TLS 1.2 ciphers; requiring TLS 1.3", name)
            if tls13_ciphersuites:
                _apply_tls13_ciphersuites(context, tls13_ciphersuites)
                logger.debug("%s: Host TLS 1.3 ciphersuites '%s'", name, tls13_ciphersuites)
        except AgentSSLError:
            raise
        except Exception as ex:
            raise AgentSSLError(f"{name}: failed to apply host TLS ciphers: {ex}") from ex
    elif tls_config.cipher_suite:
        logger.debug("%s: Using configured TLS ciphers", name)
        context.set_ciphers(tls_config.cipher_suite)

    # Set custom SSL options
    if tls_config.context_options == TLS_SYSTEM_SENTINEL:
        logger.debug("%s: Using host TLS protocol versions", name)
        try:
            min_ver, max_ver = get_system_tls_versions()
            if not host_tls12_ciphers:
                min_ver = max(min_ver, ssl.TLSVersion.TLSv1_3)
                if min_ver > max_ver:
                    raise AgentSSLError(
                        "host TLS 1.2 cipher list is empty and TLS 1.3 is not enabled"
                    )
            context.minimum_version = min_ver
            context.maximum_version = max_ver
        except AgentSSLError:
            raise
        except Exception as ex:
            raise AgentSSLError(f"{name}: failed to apply host TLS versions: {ex}") from ex
        logger.debug("%s: Host TLS versions %s-%s", name, min_ver.name, max_ver.name)
    else:
        for option in tls_config.context_options:
            try:
                context.options |= getattr(ssl, f'OP_{option}')
                logger.debug("%s: Setting Context property 'ssl.OP_%s'", name, option)
            except AttributeError:
                logger.error("Invalid %s tls_context_option '%s' in config.", name, option)
                raise

    return context


def get_system_cipher_lists() -> tuple[str, str]:
    """Return host TLS 1.2 cipher string and TLS 1.3 ciphersuites from OpenSSL."""
    tls12_names = _host_openssl_cipher_names('-tls1_2')
    tls13_names = _host_openssl_cipher_names('-tls1_3')
    tls12_ciphers = _system_tls12_cipher_string(tls12_names)
    tls13_ciphersuites = ':'.join(dict.fromkeys(
        name for name in tls13_names if name.startswith('TLS_')
    ))
    if not tls12_ciphers and not tls13_ciphersuites:
        raise AgentSSLError(
            "could not determine host TLS cipher list for cipher_suite 'system'"
        )
    return tls12_ciphers, tls13_ciphersuites


def get_system_tls_versions() -> tuple[ssl.TLSVersion, ssl.TLSVersion]:
    """Return host TLS min and max versions from crypto-policies or openssl."""
    versions = _tls_versions_from_crypto_policy()
    if versions:
        return versions
    versions = _tls_versions_from_openssl_ciphers()
    if versions:
        return versions
    raise AgentSSLError(
        "could not determine host TLS versions for context_options 'system'"
    )


def _tls_versions_from_crypto_policy() -> Optional[tuple[ssl.TLSVersion, ssl.TLSVersion]]:
    """Parse MinProtocol/MaxProtocol from the host crypto-policies OpenSSL backend."""
    try:
        text = HOST_CRYPTO_POLICY_OPENSSLCNF.read_text(encoding='utf-8')
    except FileNotFoundError:
        return None
    except OSError as ex:
        logger.debug("Host crypto-policies OpenSSL backend unreadable: %s", ex)
        return None
    return _parse_crypto_policy_opensslcnf(text)


def _parse_crypto_policy_opensslcnf(text: str) -> Optional[tuple[ssl.TLSVersion, ssl.TLSVersion]]:
    """Extract TLS min/max from opensslcnf.config text.

    Values starting with ``DTLS`` are ignored. Older crypto-policies repeat
    unprefixed ``MinProtocol`` and ``MaxProtocol`` for TLS and then DTLS.
    """
    min_name = None
    max_name = None
    tls_min_name = None
    tls_max_name = None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line or '=' not in line:
            continue
        key, value = (part.strip() for part in line.split('=', 1))
        if value.startswith('DTLS'):
            continue
        if key == 'MinProtocol':
            min_name = value
        elif key == 'MaxProtocol':
            max_name = value
        elif key == 'TLS.MinProtocol':
            tls_min_name = value
        elif key == 'TLS.MaxProtocol':
            tls_max_name = value
    min_name = tls_min_name or min_name
    max_name = tls_max_name or max_name
    if not min_name and not max_name:
        return None
    min_ver = _tls_version_from_name(min_name) if min_name else ssl.TLSVersion.TLSv1_2
    max_ver = _tls_version_from_name(max_name) if max_name else ssl.TLSVersion.TLSv1_3
    if min_ver > max_ver:
        raise AgentSSLError(
            f"host TLS MinProtocol {min_ver.name} is greater than MaxProtocol {max_ver.name}"
        )
    return min_ver, max_ver


def _tls_version_from_name(name: str) -> ssl.TLSVersion:
    try:
        return _TLS_VERSION_NAMES[name]
    except KeyError as ex:
        raise AgentSSLError(f"unsupported host TLS protocol '{name}'") from ex


def _tls_versions_from_openssl_ciphers() -> Optional[tuple[ssl.TLSVersion, ssl.TLSVersion]]:
    """Infer allowed TLS versions from host openssl ciphers -s per protocol."""
    allowed: list[ssl.TLSVersion] = []
    for flag, version in _OPENSSL_TLS_VERSION_PROBES:
        if _host_openssl_cipher_names(flag):
            allowed.append(version)
    if not allowed:
        return None
    return allowed[0], allowed[-1]


def _host_openssl_cipher_names(protocol: str) -> list[str]:
    """Query the host openssl binary for supported ciphers of one protocol."""
    attempts = (
        [HOST_OPENSSL, 'ciphers', '-s', protocol, '-policy', 'SYSTEM'],
        [HOST_OPENSSL, 'ciphers', '-s', protocol],
    )
    last_error = None
    for cmd in attempts:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=OPENSSL_CIPHERS_TIMEOUT,
                check=False,
            )
        except FileNotFoundError as ex:
            raise AgentSSLError(
                f"{HOST_OPENSSL} not found; cannot query host TLS policy"
            ) from ex
        except subprocess.TimeoutExpired as ex:
            last_error = ex
            continue
        except OSError as ex:
            last_error = ex
            continue
        if result.returncode != 0:
            last_error = result.stderr.strip() or f"openssl exited {result.returncode}"
            continue
        names = _parse_openssl_cipher_output(result.stdout)
        if names:
            return names
    if last_error:
        logger.debug("Host openssl cipher query failed: %s", last_error)
    return []


def _parse_openssl_cipher_output(stdout: str) -> list[str]:
    """Parse a colon-separated ``openssl ciphers`` list, or one name per line."""
    names: list[str] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if ' - ' in stripped:
            names.append(stripped.split(' - ', 1)[1].split()[0])
            continue
        if ':' in stripped:
            names.extend(part for part in stripped.split(':') if part)
            continue
        if ' ' not in stripped:
            names.append(stripped)
    return names


def _system_tls12_cipher_string(openssl_names: list[str]) -> str:
    """Join host TLS 1.2 OpenSSL cipher names plus extra exclusions.

    Names are applied as returned by host openssl so cipher_suite: system does
    not widen (ECDH+AESGCM groups) or drop (CHACHA20) the host policy.
    TLS 1.3 IANA names (TLS_*) belong in set_ciphersuites, not set_ciphers.
    """
    names = list(dict.fromkeys(
        name for name in openssl_names if name and not name.startswith('TLS_')
    ))
    if not names:
        return ''
    return ':'.join(names + list(SYSTEM_CIPHER_EXCLUSIONS))


def _packaged_openssl_lib_dirs() -> tuple[str, ...]:
    """Directories that hold the OpenSSL libssl this process loaded.

    Freeze copies come first (``bin/lib``). A source run then checks the
    interpreter prefix, where the dev Python keeps ``libssl.so.3`` and
    ``ossl-modules/pkcs11.so``. That prefix is skipped when frozen so a
    packaged agent does not attach to a dev tree installed on the same host.
    """
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    root = get_agent_root()
    directories = [
        os.path.join(exe_dir, 'lib'),
        str(root / 'bin' / 'lib'),
        str(root / 'lib'),
    ]
    if not getattr(sys, 'frozen', False):
        base_prefix = getattr(sys, 'base_prefix', '') or ''
        if base_prefix:
            directories.append(os.path.join(base_prefix, 'lib'))
            directories.append(os.path.join(base_prefix, 'lib64'))
    return tuple(dict.fromkeys(os.path.normpath(directory) for directory in directories))


def _packaged_openssl_candidates(lib_dir: Path, stem: str, major: int) -> list[Path]:
    """Return ``libcrypto`` or ``libssl`` names for this OpenSSL major.

    cx_Freeze copies the library as ``libssl-<hash>.so.3``. The dynamic
    linker often maps the plain soname ``libssl.so.3`` instead, so both names
    are returned. Hashed names come first.
    """
    patterns = (f'{stem}-*.so.{major}', f'{stem}.so.{major}')
    return [
        path
        for pattern in patterns
        for path in sorted(lib_dir.glob(pattern))
        if path.is_file()
    ]


def _mapped_library(paths: list[Path]) -> Optional[str]:
    """First candidate already mapped into this process.

    Each path is tried as written, then as its real path, so a soname symlink
    matches the file the loader recorded.
    """
    for path in paths:
        for name in dict.fromkeys((str(path), os.path.realpath(path))):
            try:
                OpenSSLLibraries._load_mapped_library(name)
            except AgentSSLError as ex:
                if 'not already loaded' not in str(ex):
                    raise
                continue
            return name
    return None


def _packaged_openssl_libraries() -> tuple[Optional[str], Optional[str]]:
    """Return libcrypto and libssl from the first directory that contains both.

    A directory with only one of the two libraries is skipped so the pair
    cannot come from different OpenSSL builds. Within the directory, use the
    filename this process already mapped. A cx_Freeze hash name that is not
    the loaded soname is skipped.
    """
    major = ssl.OPENSSL_VERSION_INFO[0]
    for directory in _packaged_openssl_lib_dirs():
        lib_dir = Path(directory)
        if not lib_dir.is_dir():
            continue
        cryptos = _packaged_openssl_candidates(lib_dir, 'libcrypto', major)
        ssl_libs = _packaged_openssl_candidates(lib_dir, 'libssl', major)
        if not cryptos or not ssl_libs:
            continue
        crypto = _mapped_library(cryptos)
        ssl_lib = _mapped_library(ssl_libs)
        if crypto and ssl_lib:
            return crypto, ssl_lib
    return None, None


class OpenSSLLibraries:
    """Typed access to the packaged OpenSSL already loaded by CPython _ssl."""

    def __init__(self):
        crypto_name, ssl_name = _packaged_openssl_libraries()
        if not crypto_name or not ssl_name:
            raise AgentSSLError("Packaged OpenSSL libraries could not be found")

        self.crypto = self._load_mapped_library(crypto_name)
        self.ssl = self._load_mapped_library(ssl_name)

        self._declare(
            self.crypto,
            'OSSL_PROVIDER_load',
            [ctypes.c_void_p, ctypes.c_char_p],
            ctypes.c_void_p,
        )
        self._declare(
            self.crypto, 'OSSL_PROVIDER_unload', [ctypes.c_void_p], ctypes.c_int
        )
        self._declare(
            self.crypto,
            'OSSL_STORE_open',
            [
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ],
            ctypes.c_void_p,
        )
        self._declare(
            self.crypto, 'OSSL_STORE_load', [ctypes.c_void_p], ctypes.c_void_p
        )
        self._declare(
            self.crypto, 'OSSL_STORE_eof', [ctypes.c_void_p], ctypes.c_int
        )
        self._declare(
            self.crypto, 'OSSL_STORE_error', [ctypes.c_void_p], ctypes.c_int
        )
        self._declare(
            self.crypto, 'OSSL_STORE_close', [ctypes.c_void_p], ctypes.c_int
        )
        self._declare(
            self.crypto,
            'OSSL_STORE_INFO_get_type',
            [ctypes.c_void_p],
            ctypes.c_int,
        )
        self._declare(
            self.crypto,
            'OSSL_STORE_INFO_get1_PKEY',
            [ctypes.c_void_p],
            ctypes.c_void_p,
        )
        self._declare(
            self.crypto,
            'OSSL_STORE_INFO_get1_CERT',
            [ctypes.c_void_p],
            ctypes.c_void_p,
        )
        self._declare(
            self.crypto, 'OSSL_STORE_INFO_free', [ctypes.c_void_p], None
        )
        self._declare(
            self.crypto, 'EVP_PKEY_free', [ctypes.c_void_p], None
        )
        self._declare(
            self.crypto, 'X509_free', [ctypes.c_void_p], None
        )
        self._declare(
            self.crypto, 'ERR_clear_error', [], None
        )
        self._declare(
            self.crypto, 'ERR_get_error', [], ctypes.c_ulong
        )
        self._declare(
            self.crypto,
            'ERR_error_string_n',
            [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t],
            None,
        )

        self._declare(
            self.ssl,
            'SSL_CTX_use_certificate',
            [ctypes.c_void_p, ctypes.c_void_p],
            ctypes.c_int,
        )
        self._declare(
            self.ssl,
            'SSL_CTX_use_certificate_chain_file',
            [ctypes.c_void_p, ctypes.c_char_p],
            ctypes.c_int,
        )
        self._declare(
            self.ssl,
            'SSL_CTX_use_PrivateKey',
            [ctypes.c_void_p, ctypes.c_void_p],
            ctypes.c_int,
        )
        self._declare(
            self.ssl,
            'SSL_CTX_check_private_key',
            [ctypes.c_void_p],
            ctypes.c_int,
        )
        self._declare(
            self.ssl,
            'SSL_CTX_get_options',
            [ctypes.c_void_p],
            ctypes.c_ulong,
        )
        self._declare(
            self.ssl,
            'SSL_CTX_set_ciphersuites',
            [ctypes.c_void_p, ctypes.c_char_p],
            ctypes.c_int,
        )

    @staticmethod
    def _load_mapped_library(name: str):
        """Attach to the OpenSSL already loaded by _ssl. Never map a second copy."""
        noload = getattr(os, 'RTLD_NOLOAD', 0)
        if not noload:
            raise AgentSSLError(
                "OpenSSL cannot be attached without RTLD_NOLOAD"
            )
        now = getattr(os, 'RTLD_NOW', 0)
        if not now:
            raise AgentSSLError(
                "OpenSSL cannot be attached without RTLD_NOW"
            )
        try:
            return ctypes.CDLL(name, mode=now | noload)
        except OSError as ex:
            raise AgentSSLError(
                f"OpenSSL library '{name}' is not already loaded by this process"
            ) from ex

    @staticmethod
    def _declare(library, name, argtypes, restype):
        try:
            function = getattr(library, name)
        except AttributeError as ex:
            raise AgentSSLError(
                f"OpenSSL does not provide required PKCS#11 API '{name}'"
                f" (loaded {getattr(library, '_name', 'unknown library')})"
            ) from ex
        function.argtypes = argtypes
        function.restype = restype

    def errors(self) -> str:
        """Drain and format the current thread's OpenSSL error queue."""
        messages = []
        while error_code := self.crypto.ERR_get_error():
            buffer = ctypes.create_string_buffer(256)
            self.crypto.ERR_error_string_n(error_code, buffer, len(buffer))
            messages.append(buffer.value.decode('utf-8', errors='replace'))
        return redact_pkcs11_secrets('; '.join(messages))


_PKCS11_PIN_ATTR_RE = re.compile(r'(?i)(pin-value|pin-source)=')
_PKCS11_PIN_VALUE_STOP = set(' \t\r\n\'"')


def redact_pkcs11_secrets(text: str | None) -> str | None:
    """Strip pin-value / pin-source material from a PKCS#11 URI or error text.

    RFC 7512 places those attributes in the query component, where ``&``
    separates attributes. ``;`` ends a value only in the path component, so a
    legacy path-style pin does not swallow the next path attribute and a
    semicolon inside a query value is still removed.
    """
    if not text:
        return text
    pieces: list[str] = []
    cursor = 0
    for match in _PKCS11_PIN_ATTR_RE.finditer(text):
        if match.start() < cursor:
            continue
        token_start = match.start()
        while token_start > 0 and text[token_start - 1] not in ' \t\r\n':
            token_start -= 1
        in_query = '?' in text[token_start:match.start()]
        end = match.end()
        while end < len(text):
            char = text[end]
            if char in _PKCS11_PIN_VALUE_STOP or char == '&':
                break
            if char == ';' and not in_query:
                break
            end += 1
        pieces.append(text[cursor:match.end()])
        pieces.append('***')
        cursor = end
    pieces.append(text[cursor:])
    return ''.join(pieces)


def _path_is_inside_agent_install(path: str | None) -> bool:
    """True when a freeze runtime points SSL_CERT_* at bundled OPENSSLDIR."""
    if not path or not getattr(sys, 'frozen', False):
        return False
    try:
        resolved = Path(path).resolve()
        root = get_agent_root().resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    return resolved == root or root in resolved.parents


def load_system_ca_certs(context: ssl.SSLContext, name: str):
    """Load host trust for ca_cert: system. Freeze OPENSSLDIR is not used."""
    ssl_cert_file = os.environ.get('SSL_CERT_FILE') or None
    ssl_cert_dir = os.environ.get('SSL_CERT_DIR') or None
    if _path_is_inside_agent_install(ssl_cert_file):
        logger.debug("%s: Ignoring freeze SSL_CERT_FILE '%s'", name, ssl_cert_file)
        ssl_cert_file = None
    if _path_is_inside_agent_install(ssl_cert_dir):
        logger.debug("%s: Ignoring freeze SSL_CERT_DIR '%s'", name, ssl_cert_dir)
        ssl_cert_dir = None
    if ssl_cert_file or ssl_cert_dir:
        try:
            if ssl_cert_file:
                check_file_access(ssl_cert_file)
            if ssl_cert_dir:
                os.listdir(ssl_cert_dir)
            context.load_verify_locations(ssl_cert_file, ssl_cert_dir)
        except Exception as ex:
            raise AgentSSLError(f"{name}: {str(ex)}") from ex
        return

    loaded = False
    for cafile in HOST_CA_BUNDLE_FILES:
        if os.path.isfile(cafile):
            context.load_verify_locations(cafile, None)
            loaded = True
            break
    if not loaded:
        for capath in HOST_CA_BUNDLE_DIRS:
            if os.path.isdir(capath):
                context.load_verify_locations(None, capath)
                loaded = True
                break
    loaded_anchors = _load_host_ca_anchors(context, name)
    if not loaded and not loaded_anchors:
        raise AgentSSLError(
            f"{name}: could not find a host CA trust store for ca_cert 'system'"
        )


def _load_host_ca_anchors(context: ssl.SSLContext, name: str) -> bool:
    """Append operator-installed CA files from distro trust-anchor directories."""
    loaded = False
    for directory in HOST_CA_ANCHOR_DIRS:
        if not os.path.isdir(directory):
            continue
        try:
            names = sorted(os.listdir(directory))
        except OSError as ex:
            logger.warning("%s: Cannot list CA anchor directory '%s' (%s)", name, directory, ex)
            continue
        for filename in names:
            if not filename.endswith(HOST_CA_ANCHOR_SUFFIXES):
                continue
            path = os.path.join(directory, filename)
            if not os.path.isfile(path):
                continue
            try:
                check_file_access(path)
                if os.path.getsize(path) <= 0:
                    continue
                # Per-file cafile: concatenated PEM cadata is not trusted by freeze OpenSSL.
                context.load_verify_locations(path)
                loaded = True
            except Exception as ex:
                logger.warning("%s: Skipping CA anchor '%s' (%s)", name, path, ex)
    return loaded


def _apply_tls13_ciphersuites(context: ssl.SSLContext, ciphersuites: str) -> None:
    """Apply TLS 1.3 IANA suites to freeze OpenSSL.

    CPython SSLContext has no set_ciphersuites; set_ciphers only changes TLS
    1.2 and below. Call SSL_CTX_set_ciphersuites on the context's SSL_CTX.
    """
    set_ciphersuites = getattr(context, 'set_ciphersuites', None)
    if set_ciphersuites:
        set_ciphersuites(ciphersuites)
        return
    openssl = OpenSSLLibraries()
    openssl.crypto.ERR_clear_error()
    ssl_ctx = get_ssl_ctx_pointer(context, openssl)
    applied = openssl.ssl.SSL_CTX_set_ciphersuites(
        ssl_ctx, ciphersuites.encode('ascii')
    )
    openssl_check(applied, openssl, "apply host TLS 1.3 ciphersuites")


def get_ssl_ctx_pointer(context: ssl.SSLContext, openssl: OpenSSLLibraries):
    """Return the SSL_CTX pointer held by a CPython ssl.SSLContext.

    CPython 3.14 ``Modules/_ssl.c`` ``PySSLContext`` stores ``SSL_CTX *ctx``
    immediately after ``PyObject_HEAD``. ``object.__basicsize__`` is that
    header size, including the 3.12+ immortal-object layout. Real
    ``ssl.SSLContext`` objects fail closed unless the PKCS#11-validated
    CPython 3.14 runtime is in use; the options-mutation probe rejects a
    coincidental match on the wrong pointer.
    """
    if isinstance(context, ssl.SSLContext):
        from agent.pkcs11 import require_pkcs11_runtime
        require_pkcs11_runtime(context)
    ssl_ctx = ctypes.c_void_p.from_address(id(context) + object.__basicsize__).value
    if not ssl_ctx:
        raise AgentSSLError("Could not access the OpenSSL SSL_CTX")
    if int(openssl.ssl.SSL_CTX_get_options(ssl_ctx)) != int(context.options):
        raise AgentSSLError("Could not verify the OpenSSL SSL_CTX pointer")
    # Mutate via the Python API (not the guessed pointer) and confirm the C
    # view tracks. A coincidental options match on the wrong object is dropped.
    probe = ssl.OP_CIPHER_SERVER_PREFERENCE
    context.options ^= probe
    try:
        if int(openssl.ssl.SSL_CTX_get_options(ssl_ctx)) != int(context.options):
            raise AgentSSLError("Could not verify the OpenSSL SSL_CTX pointer")
    finally:
        context.options ^= probe
    return ssl_ctx


def openssl_check(result, openssl: OpenSSLLibraries, action: str):
    if result:
        return
    details = openssl.errors()
    message = f"OpenSSL failed to {action}"
    if details:
        message = f"{message}: {details}"
    raise AgentSSLError(message)


def ssl_debug_message_callback(
        _conn: ssl.SSLSocket,
        direction: str,
        version: ssl.TLSVersion,
        content_type: ssl._TLSContentType,
        msg_type: ssl._TLSMessageType,
        _data: bytes):
    """
    Called after every TLS protocol message (not application messages) this function debug logs:
      * the direction of the message (read/write)
      * the message type
      * the version of the packet
      * the content type of the packet

    Full details on args can be found in ssl.SSLContext._msg_callback
    """
    logger.debug(
        f"| tls message {direction: <5} | {version.name: <7} | {msg_type.name: <20} | {content_type.name: <20}"
    )


def check_file_access(filename):
    """Check a file can be read"""
    with open(filename):
        pass


def create_self_signed_cert(config_name: str, output_dir: str) -> tuple[str, str]:
    """Creates new self-signed private key and certificate in a specified directory.

    Returns the private-key path and the certificate path.
    """
    os.makedirs(output_dir, exist_ok=True)
    hostname = f'{socket.gethostname()}-{config_name}'
    fqdn = socket.getfqdn()
    base_path = get_agent_root() / output_dir / hostname
    private_key_path = base_path.with_suffix('.key')
    cert_path = base_path.with_suffix('.crt')
    if private_key_path.exists() and cert_path.exists():
        return private_key_path.resolve(), cert_path.resolve()

    logger.info("%s: Creating new self-signed certificate for '%s'", config_name, fqdn)
    private_key = rsa.generate_private_key(
        KEY_PUBLIC_EXPONENT,
        KEY_SIZE,
        backend=default_backend(),
    )
    # Create the private key file (only readable/writable by current user)
    with open(private_key_path, 'wb', opener=open_with_mode(0o600)) as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "London"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "EC2"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITRS Group Ltd"),
        x509.NameAttribute(NameOID.COMMON_NAME, fqdn),
    ])

    now = datetime.now(timezone.utc)

    # Create the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=100 * 365))  # Good for a long time
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(fqdn)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), backend=default_backend())
    )
    with open(cert_path, 'wb', opener=open_with_mode(0o644)) as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return private_key_path.resolve(), cert_path.resolve()


def open_with_mode(mode):
    """Creates a new file opener with a specific mode"""

    def opener(path, flags):
        return os.open(path, flags, mode)

    return opener
