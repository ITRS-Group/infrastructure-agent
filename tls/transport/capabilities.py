"""
TLS connector selection and capability sets for Infrastructure Agent.

``server.tls.connector`` selects the identity source: file, pkcs11, or schannel.
OpenSSL vs Schannel is an internal mapping (file/pkcs11 → python_ssl).

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import dataclasses
import logging
from typing import TYPE_CHECKING, Literal, Optional

from agent.config import ConfigurationError

if TYPE_CHECKING:
    from agent.config import TLSConfig
    from agent.objects import Platform

logger = logging.getLogger('tls')

BackendName = Literal['python_ssl', 'schannel']
ConnectorName = Literal['file', 'pkcs11', 'schannel']

CONNECTOR_NAMES: tuple[ConnectorName, ...] = ('file', 'pkcs11', 'schannel')

# Windows Server 2019 / Windows 10 1809 — SCH_CREDENTIALS (v5) baseline.
SCHANNEL_MIN_WINDOWS_BUILD = 17763

SCHANNEL_IDENTITY_KEYS = ('schannel_cert_name', 'schannel_cert_thumbprint')
PKCS11_IDENTITY_KEYS = (
    'pkcs11_module',
    'pkcs11_key_uri',
    'pkcs11_key_pin',
    'pkcs11_cert_uri',
    'pkcs11_cert_pin',
)
OS_MANAGED_SECURITY_BACKENDS: tuple[BackendName, ...] = ('schannel',)


@dataclasses.dataclass(frozen=True)
class TlsSelection:
    """Result of selecting a TLS backend from config."""

    backend: BackendName
    ignored_keys: tuple[str, ...]
    ignored_context_options: tuple[str, ...] = ()
    connector: ConnectorName = 'file'


def _nonempty(tls_config: 'TLSConfig', keys: tuple[str, ...]) -> list[str]:
    present = []
    for key in keys:
        val = getattr(tls_config, key, None)
        if val is None:
            continue
        if isinstance(val, str) and not val.strip():
            continue
        present.append(key)
    return present


def yaml_value_set(value) -> bool:
    """True when a YAML nest or scalar should count as configured."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict):
        return any(yaml_value_set(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(yaml_value_set(item) for item in value)
    return True


def normalize_connector(connector: Optional[str]) -> Optional[ConnectorName]:
    """Normalize server.tls.connector to a canonical name."""
    if connector is None:
        return None
    cleaned = str(connector).strip().lower()
    if not cleaned:
        return None
    if cleaned not in CONNECTOR_NAMES:
        raise ConfigurationError(
            "Invalid TLS connector "
            f"'{connector}' (choices: {', '.join(CONNECTOR_NAMES)})."
        )
    return cleaned  # type: ignore[return-value]


def transport_backend_for_connector(connector: ConnectorName) -> BackendName:
    if connector == 'schannel':
        return 'schannel'
    return 'python_ssl'


def _windows_build_number(platform: 'Platform') -> int:
    """
    Windows build from ``platform.win32_ver()`` as stored on Platform.

    Real Windows returns e.g. ``('10', '10.0.17763', 'SP0', 'Multiprocessor Free')``;
    the build is the third component of the version string at index 1.
    """
    windows_version = platform.windows_version
    build = int(str(windows_version[1]).split('.')[2])
    logger.debug(
        "Parsed Windows build %s from windows_version=%s",
        build,
        windows_version,
    )
    return build


def _validate_backend_platform(backend: BackendName, platform: 'Platform') -> None:
    if backend == 'schannel':
        if not platform.is_windows:
            raise ConfigurationError(
                "TLS connector=schannel is only available on Windows."
            )
        build = _windows_build_number(platform)
        if build < SCHANNEL_MIN_WINDOWS_BUILD:
            raise ConfigurationError(
                "TLS connector=schannel requires Windows Server 2019 / Windows 10 1809 "
                f"or later (build {SCHANNEL_MIN_WINDOWS_BUILD}+); "
                f"this host reports build {build}. "
                "Use connector=file on older Windows, or upgrade the OS."
            )


def validate_identity_keys(tls_config: 'TLSConfig') -> None:
    """Identity keys must match the selected connector only."""
    connector = tls_config.connector
    schannel_keys = _nonempty(tls_config, SCHANNEL_IDENTITY_KEYS)
    pkcs11_keys = _nonempty(tls_config, PKCS11_IDENTITY_KEYS)
    schannel_cert_store = getattr(tls_config, 'schannel_cert_store', None)

    if connector == 'file':
        if pkcs11_keys:
            raise ConfigurationError(
                "PKCS#11 identity keys require server.tls.connector=pkcs11 "
                f"({', '.join(pkcs11_keys)})."
            )
        if schannel_keys:
            raise ConfigurationError(
                "Schannel identity keys require server.tls.connector=schannel "
                f"({', '.join(schannel_keys)})."
            )
        if schannel_cert_store:
            raise ConfigurationError(
                "server.tls.schannel.identity_cert_store requires "
                "server.tls.connector=schannel."
            )
        return

    if connector == 'pkcs11':
        if schannel_keys or schannel_cert_store:
            extra = list(schannel_keys)
            if schannel_cert_store:
                extra.append('schannel_cert_store')
            raise ConfigurationError(
                "TLS connector=pkcs11 cannot be combined with "
                f"schannel settings ({', '.join(extra)})."
            )
        if not tls_config.pkcs11_module:
            raise ConfigurationError(
                "TLS connector=pkcs11 requires server.tls.pkcs11.module_path."
            )
        if not tls_config.pkcs11_key_uri:
            raise ConfigurationError(
                "TLS connector=pkcs11 requires server.tls.pkcs11.identity_key.uri."
            )
        if not tls_config.pkcs11_key_uri.startswith('pkcs11:'):
            raise ConfigurationError(
                "TLS config 'pkcs11.identity_key.uri' must start with 'pkcs11:'"
            )
        has_cert_uri = bool(tls_config.pkcs11_cert_uri)
        has_cert_file = bool(tls_config.cert_file)
        if has_cert_uri and has_cert_file:
            raise ConfigurationError(
                "TLS connector=pkcs11 must set only one of pkcs11.identity_cert "
                "or pkcs11.identity_cert_file, not both."
            )
        if not has_cert_uri and not has_cert_file:
            raise ConfigurationError(
                "TLS connector=pkcs11 requires pkcs11.identity_cert "
                "or pkcs11.identity_cert_file."
            )
        if has_cert_uri and not tls_config.pkcs11_cert_uri.startswith('pkcs11:'):
            raise ConfigurationError(
                "TLS config 'pkcs11.identity_cert.uri' must start with 'pkcs11:'"
            )
        return

    if schannel_keys and tls_config.schannel_cert_name and tls_config.schannel_cert_thumbprint:
        raise ConfigurationError(
            "TLS config must set only one Schannel identity: "
            "identity_cert_name or identity_cert_thumbprint, not both."
        )
    if not schannel_keys:
        raise ConfigurationError(
            "TLS connector=schannel requires server.tls.schannel.identity_cert_name "
            "or identity_cert_thumbprint."
        )
    if pkcs11_keys:
        raise ConfigurationError(
            "TLS connector=schannel cannot be combined with "
            f"pkcs11 settings ({', '.join(pkcs11_keys)})."
        )


def _os_managed_ignored_keys(
        tls_config: 'TLSConfig',
) -> tuple[list[str], list[str]]:
    """Non-security keys ignored on OS-managed stacks (logged at startup).

    The listener does not verify a remote server certificate, so
    check_server_cert is always ignored.
    """
    ignored: list[str] = []
    if tls_config.log_all_messages:
        ignored.append('log_all_messages')
    ignored.append('check_server_cert')
    return ignored, []


def select_backend(tls_config: 'TLSConfig', platform: 'Platform') -> TlsSelection:
    """
    Choose TLS transport from server.tls.connector (default file → python_ssl).

    Raises ConfigurationError on platform/build mismatch.
    """
    connector: ConnectorName = normalize_connector(
        getattr(tls_config, 'connector', None)
    ) or 'file'
    backend = transport_backend_for_connector(connector)

    _validate_backend_platform(backend, platform)

    ignored: list[str] = []
    ignored_opts: list[str] = []
    if backend in OS_MANAGED_SECURITY_BACKENDS:
        ignored, ignored_opts = _os_managed_ignored_keys(tls_config)

    return TlsSelection(
        backend=backend,
        ignored_keys=tuple(ignored),
        ignored_context_options=tuple(ignored_opts),
        connector=connector,
    )


def log_selection(selection: TlsSelection, name: str = 'NRPE') -> None:
    """Log selected connector/backend and ignored keys once at INFO."""
    parts = [
        f"{name} TLS connector={selection.connector} "
        f"backend={selection.backend}"
    ]
    ignored = list(selection.ignored_keys)
    if selection.ignored_context_options and 'context_options' not in ignored:
        ignored.append(
            'context_options[' + ','.join(selection.ignored_context_options) + ']'
        )
    if ignored:
        if selection.backend in OS_MANAGED_SECURITY_BACKENDS:
            parts.append('OS-managed extras (agent ignores): ' + ', '.join(ignored))
        else:
            parts.append('ignoring: ' + ', '.join(ignored))
    logger.info('; '.join(parts))
