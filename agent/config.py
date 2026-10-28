"""
Infrastructure Agent: Read agent configuration
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import dataclasses
import enum
import glob
import os
import pathlib
import re
import shlex
import sys
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from agent.helpers import merge_dictionary, parse_byte_string

if TYPE_CHECKING:
    from typing import Callable, Iterable, Optional, Union

    # Typing for CommandConfig dict from before parsing into a CommandConfig object
    DictCommandConfig = dict[str, Union[bool, int, str, dict]]

AGENT_NAME = "Infrastructure Agent"

RELATIVE_BASE_PATH_SRC = '../'
RELATIVE_BASE_PATH_FROZEN = '../../../'

DEFAULT_CONFIG_NAME = 'agent.default.yml'
IMPORTED_CONFIG_NAME = 'imported.yml'
CONFIG_DIR_NAME = 'cfg'
VAR_DIR_NAME = 'var'
USER_CONFIG_REL_PATH = CONFIG_DIR_NAME + '/custom/agent.yml'
STARTUP_LOG_REL_PATH = VAR_DIR_NAME + '/startup.log'
USER_CONFIG_SUBDIR = 'custom'
YAML_EXTENSIONS = {'yml', 'yaml'}
TRUE_STRINGS = ('true', 'y', 'yes', '1')
MERGE_LISTS = ('allowed_hosts',)
VERSION_FILE_NAME = 'version'

PLUGIN_ARG_FORMAT_RE = re.compile(r'\$ARG(\d+)\$')
ESCAPE_PATH_STRINGS = ('{', '}')
TLS_SYSTEM_SENTINEL = 'system'

DEFAULT_USER_CONFIG_CONTENT = """---
# This file has been created as a placeholder for your custom
#  configuration overrides. YAML configuration files in the "custom"
#  directory will be read in alphanumeric order.
"""

startup_log: Callable = None


class ExecutionStyle(enum.StrEnum):
    COMMAND_LINE_ARGS = 'COMMAND_LINE_ARGS'
    STDIN_ARGS = 'STDIN_ARGS'
    LONGRUNNING_STDIN_ARGS = 'LONGRUNNING_STDIN_ARGS'


DEFAULT_EXECUTION_STYLE = ExecutionStyle.COMMAND_LINE_ARGS

STDIN_EXECUTION_STYLES = (
    ExecutionStyle.STDIN_ARGS,
    ExecutionStyle.LONGRUNNING_STDIN_ARGS,
)


def read_bool_from_envar(var: str) -> bool:
    """Interpret an environment variable as a Boolean"""
    return os.environ.get(var, '').lower() in TRUE_STRINGS


class ConfigurationError(Exception):
    """An error has been encountered in the configuration"""
    pass


class AbstractConfig:
    """
    Base abstract Config class.
    Provides a simple from_dict method to be used to spin up instances of its subclasses.
    """
    # noinspection PyArgumentList
    # This should NEVER be called on the Abstract class but allows
    # us to define simple *Config classes below.
    NAME: str = ''

    @classmethod
    def from_dict(cls, config: dict):
        """Build the object from a dict"""
        try:
            return cls(**config)
        except TypeError as ex:
            # catch common errors and make them meaningful
            import re

            # __init__() missing 1 required positional argument: 'receive_data_timeout'
            match = re.match(r'.*__init__\(\) missing .*: (.*)$', str(ex))
            if match:
                raise ConfigurationError(f"Configuration missing from '{cls.NAME}': {match.group(1)}")

            # __init__() got an unexpected keyword argument 'foo'
            match = re.search(r"unexpected keyword argument '([^']+)'", str(ex))
            if match:
                raise ConfigurationError(f"Unexpected configuration in '{cls.NAME}': '{match.group(1)}'")

            # some other error
            raise


@dataclasses.dataclass
class CommandConfig(AbstractConfig):
    """
    Class to store configuration for Agent commands.
    """
    name: str
    path: str
    _path: str = dataclasses.field(init=False, repr=False)
    runtime: Optional[str] = None
    cache_manager: bool = False
    stderr: bool = True
    long_running_key: Optional[str] = None
    execution_style: ExecutionStyle = DEFAULT_EXECUTION_STYLE
    environment_variables: Optional[EnvironmentVariableConfig] = None

    max_unique_arg_index: int = dataclasses.field(init=False)

    NAME: str = dataclasses.field(default='commands', repr=False)

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value: str):
        """Setter for CommandConfig.path - also updates max_unique_arg_index"""
        # Duplicate { and } chars so that they're not incorrectly formatted later
        value = self._duplicate_chars(value, ESCAPE_PATH_STRINGS)
        unique_args = set()

        def _arg_repl(match: re.Match) -> str:
            """Returns a format string to replace an $ARGX$ substr"""
            arg_no = int(match.groups()[0])
            if arg_no > 0:
                unique_args.add(arg_no)
                return f'{{{arg_no - 1}}}'
            return match.group(0)

        # Replace ARGX strings with format-able '{0} {1}' strings
        self._path = PLUGIN_ARG_FORMAT_RE.sub(_arg_repl, value)
        self.max_unique_arg_index = max(unique_args, default=0)

    @cached_property
    def uses_stdin(self) -> bool:
        return self.execution_style in STDIN_EXECUTION_STYLES

    @staticmethod
    def _duplicate_chars(base_str: str, chars: tuple[str, ...]) -> str:
        """
        For each instance of each character in chars in base_str duplicates the character

        For example:
            _duplicate_chars("check_example -a '{thing}'", '{', '}') -> "check_example -a '{{thing}}'"
        """
        for char in chars:
            base_str = base_str.replace(char, char * 2)
        return base_str

    @staticmethod
    def _get_execution_style(command_cfg: DictCommandConfig, name: str) -> ExecutionStyle:
        """
        Reads the execution_style key from the command_cfg dictionary
        """
        old_use_stdin = None
        try:
            old_use_stdin = command_cfg['use_stdin']
        except KeyError:
            pass

        try:
            execution_style = ExecutionStyle(command_cfg['execution_style'])

            if old_use_stdin is not None:
                # The legacy config option 'use_stdin' is set, we need to always warn about this in the startup log
                # and then check if it's valid to use it with the new 'execution_style' option.
                if old_use_stdin is False and execution_style in STDIN_EXECUTION_STYLES:
                    raise ConfigurationError(
                        f"'use_stdin' is deprecated AND is set to False for command '{name}' with a stdin "
                        f"execution_style ({execution_style}). Please only set 'execution_style'."
                    )
                elif old_use_stdin is True and execution_style not in STDIN_EXECUTION_STYLES:
                    raise ConfigurationError(
                        f"'use_stdin' is deprecated AND is set to True for command '{name}' with a non-stdin "
                        f"execution_style ({execution_style}). Please only set 'execution_style'."
                    )
                else:
                    startup_log(
                        f"Both 'use_stdin' and 'execution_style' are set for command '{name}'. "
                        "Please only set 'execution_style'.",
                        prefix='[WARNING]'
                    )
            return execution_style
        except KeyError:
            # execution_style is not set, see if 'use_stdin' is set and use that (after complaining), else
            # default to DEFAULT_EXECUTION_STYLE
            if old_use_stdin is not None:
                startup_log(
                    f"'use_stdin' is deprecated, please use 'execution_style' instead "
                    f"(found in command '{name}').",
                    prefix='[WARNING]'
                )
                if old_use_stdin:
                    return ExecutionStyle.STDIN_ARGS

            return DEFAULT_EXECUTION_STYLE
        except ValueError:
            raise ConfigurationError(
                f"Invalid execution_style for command '{name}': {command_cfg['execution_style']}"
            )

    @staticmethod
    def _get_long_running_key(
            command_cfg: DictCommandConfig, execution_style: ExecutionStyle, name: str, path: str
    ) -> str:
        """
        Parses the long_running_key and execution_style to ensure they are both valid together,
        returning None if the check isn't a long-running check or the processes key if it else.
        Raises a ConfigurationError if the check is invalidly set up.
        """
        try:
            long_running_key = command_cfg['long_running_key']
        except KeyError:
            long_running_key = None

        # Long-running checks require both long_running_key to be set
        # and execution_style to be set to LONGRUNNING_STDIN_ARGS.
        # bool(long_running_key) iff (execution_style == LONGRUNNING_STDIN_ARGS)
        if execution_style == ExecutionStyle.LONGRUNNING_STDIN_ARGS:
            if not long_running_key:
                raise ConfigurationError(
                    f"long_running_key not specified for command '{name}' but execution_style is "
                    f"set to '{ExecutionStyle.LONGRUNNING_STDIN_ARGS}'"
                )
        elif long_running_key:
            raise ConfigurationError(
                f"long_running_key specified for command '{name}' but execution_style is not "
                f"set to '{ExecutionStyle.LONGRUNNING_STDIN_ARGS}'"
            )

        if long_running_key == '$PATH$':
            return shlex.split(path)[0]
        elif long_running_key == '$NAME$':
            return name

        return long_running_key

    @classmethod
    def from_dict(
            cls, config: dict[str, DictCommandConfig], global_environment_variables: EnvironmentVariableConfig
    ) -> dict[str, CommandConfig]:
        """
        Creates a dictionary mapping command names (str) to CommandConfig objects containing
        configuration for a given command.
        """
        # TODO OP-71502 - Add schema validation to config dict read from YAML(s)
        commands = {}

        try:
            for name, command_cfg in config.items():
                path = command_cfg['path']
                execution_style = cls._get_execution_style(command_cfg, name)

                # Default to using the global environment variable config...
                environment_variables = global_environment_variables

                try:
                    # ...Unless this command has its own environment_variables
                    environment_variables_dict: dict = command_cfg['environment_variables']
                    if environment_variables_dict is None:
                        # An explicitly set null value will disable Environment Vars entirely
                        startup_log(f"Command '{name}' has explicitly disabled ALL environment variables.")
                        environment_variables = EnvironmentVariableConfig()
                    else:
                        for section in ('custom', 'passthrough'):
                            try:
                                # Check if this dict has a value for this
                                if not environment_variables_dict[section]:
                                    startup_log(
                                        f"Command '{name}' has explicitly disabled "
                                        f"'{section}' environment variables"
                                    )
                            except KeyError:
                                environment_variables_dict[section] = getattr(global_environment_variables, section)
                        environment_variables = EnvironmentVariableConfig.from_dict(environment_variables_dict)
                except KeyError:
                    pass

                commands[name] = cls(
                    name=name,
                    path=path,
                    runtime=command_cfg.get('runtime'),
                    cache_manager=command_cfg.get('cache_manager', False),
                    stderr=command_cfg.get('stderr', True),
                    long_running_key=cls._get_long_running_key(command_cfg, execution_style, name, path),
                    execution_style=execution_style,
                    environment_variables=environment_variables
                )
        except KeyError as ex:
            raise ConfigurationError(f"Missing '{cls.NAME}' configuration for '{name}', section: {ex}")
        return commands


# Default python_ssl TLS policy (applied when connector is file).
PYTHON_SSL_DEFAULT_CIPHER_SUITE = 'ECDH+AESGCM:ECDH+AES256:ECDH+AES128:!aNULL:!MD5:!DSS'
PYTHON_SSL_DEFAULT_CONTEXT_OPTIONS = ('NO_SSLv3', 'NO_TLSv1', 'NO_TLSv1_1')
_PKCS11_NEST_KEYS = {'module_path', 'identity_cert', 'identity_cert_file', 'identity_key'}
_PKCS11_URI_NEST_KEYS = {'uri', 'pin'}
_SCHANNEL_NEST_KEYS = {
    'identity_cert_name',
    'identity_cert_thumbprint',
    'identity_cert_store',
}


def _strip_optional_str(value) -> Optional[str]:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _strip_optional_secret(value, field: str) -> Optional[str]:
    """Return a stripped secret. Reject YAML numbers/bools (quote the value, e.g. pin: "0123")."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigurationError(f"TLS config '{field}' must be a string")
    cleaned = value.strip()
    return cleaned or None


def _file_key_configured(tls_config: 'TLSConfig', key: str) -> bool:
    value = getattr(tls_config, key, None)
    if key == 'context_options':
        if value is None or value == []:
            return False
        return True
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True


@dataclasses.dataclass
class TLSConfig(AbstractConfig):
    """
    Class to store TLS configuration.

    ``connector`` defaults to file (PEM paths, optional encrypted PKCS#8
    ``key_passphrase``). pkcs11 uses a token identity; schannel uses the
    Windows cert store. PKCS#12 archives are not supported.
    """
    ca_cert: Optional[str] = None
    ca_path: Optional[str] = None
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    check_client_cert: bool = True
    check_server_cert: bool = True
    cipher_suite: Optional[str] = None
    # List of ssl.OP_* names (without OP_), or the sentinel string 'system'.
    context_options: str | list[str] = dataclasses.field(default_factory=list)
    # Windows Schannel: Prefer FriendlyName over SimpleName so shared Subject
    # CNs remain selectable; thumbprint when the store label is ambiguous.
    # schannel_cert_store defaults to MY when a Schannel identity is set.
    schannel_cert_name: Optional[str] = None
    schannel_cert_thumbprint: Optional[str] = None
    schannel_cert_store: Optional[str] = None
    pkcs11_module: Optional[str] = None
    pkcs11_key_uri: Optional[str] = None
    pkcs11_key_pin: Optional[str] = dataclasses.field(default=None, repr=False)
    pkcs11_cert_uri: Optional[str] = None
    pkcs11_cert_pin: Optional[str] = dataclasses.field(default=None, repr=False)
    connector: str = 'file'
    key_passphrase: Optional[str] = dataclasses.field(default=None, repr=False)

    log_all_messages: bool = read_bool_from_envar('AGENT_TLS_LOG_MESSAGES')

    NAME: str = dataclasses.field(default='tls', repr=False)

    @property
    def backend(self) -> str:
        from tls.transport.capabilities import (
            normalize_connector,
            transport_backend_for_connector,
        )

        connector = normalize_connector(self.connector) or 'file'
        return transport_backend_for_connector(connector)

    @classmethod
    def from_dict(cls, config: dict, *, section: str | None = None):
        """Build TLSConfig from YAML, flattening connector-specific nests.

        ``section`` is the parent block (``server``, ``cachemanager``,
        ``forwarders``). ``pkcs11`` and ``schannel`` are only valid under
        ``server``.
        """
        from tls.transport.capabilities import normalize_connector, yaml_value_set

        raw = dict(config or {})
        pkcs11_nest = raw.pop('pkcs11', None)
        schannel_nest = raw.pop('schannel', None)
        if pkcs11_nest is None:
            pkcs11_nest = {}
        elif not isinstance(pkcs11_nest, dict):
            raise ConfigurationError("TLS config 'pkcs11' must be a mapping")
        if schannel_nest is None:
            schannel_nest = {}
        elif not isinstance(schannel_nest, dict):
            raise ConfigurationError("TLS config 'schannel' must be a mapping")

        extra_pkcs11 = set(pkcs11_nest) - _PKCS11_NEST_KEYS
        if extra_pkcs11:
            unexpected = sorted(extra_pkcs11)[0]
            raise ConfigurationError(
                f"Unexpected configuration in 'tls.pkcs11': '{unexpected}'"
            )
        extra_schannel = set(schannel_nest) - _SCHANNEL_NEST_KEYS
        if extra_schannel:
            unexpected = sorted(extra_schannel)[0]
            raise ConfigurationError(
                f"Unexpected configuration in 'tls.schannel': '{unexpected}'"
            )

        connector = normalize_connector(raw.get('connector')) or 'file'
        if connector in ('pkcs11', 'schannel') and section != 'server':
            where = f"{section}.tls" if section else 'tls'
            raise ConfigurationError(
                f"TLS connector={connector} is only supported under server.tls "
                f"(rejected in {where})."
            )
        pkcs11_set = yaml_value_set(pkcs11_nest)
        schannel_set = yaml_value_set(schannel_nest)
        if connector == 'file' and (pkcs11_set or schannel_set):
            which = []
            if pkcs11_set:
                which.append('pkcs11')
            if schannel_set:
                which.append('schannel')
            raise ConfigurationError(
                "TLS connector=file cannot set " +
                ' or '.join(which) +
                " (use connector=pkcs11 or connector=schannel)."
            )
        if connector == 'pkcs11' and schannel_set:
            raise ConfigurationError(
                "TLS connector=pkcs11 cannot be combined with a schannel nest."
            )
        if connector == 'schannel' and pkcs11_set:
            raise ConfigurationError(
                "TLS connector=schannel cannot be combined with a pkcs11 nest."
            )

        if connector == 'pkcs11':
            cls._flatten_pkcs11_nest(raw, pkcs11_nest)
        elif connector == 'schannel':
            cls._flatten_schannel_nest(raw, schannel_nest)

        try:
            return cls(**raw)
        except TypeError as ex:
            match = re.search(r"unexpected keyword argument '([^']+)'", str(ex))
            if match:
                raise ConfigurationError(
                    f"Unexpected configuration in '{cls.NAME}': '{match.group(1)}'"
                )
            match = re.match(r'.*__init__\(\) missing .*: (.*)$', str(ex))
            if match:
                raise ConfigurationError(
                    f"Configuration missing from '{cls.NAME}': {match.group(1)}"
                )
            raise

    @staticmethod
    def _flatten_pkcs11_nest(raw: dict, nest: dict) -> None:
        raw['pkcs11_module'] = nest.get('module_path')
        identity_key = nest.get('identity_key')
        if identity_key is None:
            identity_key = {}
        elif not isinstance(identity_key, dict):
            raise ConfigurationError("TLS config 'pkcs11.identity_key' must be a mapping")
        extra = set(identity_key) - _PKCS11_URI_NEST_KEYS
        if extra:
            unexpected = sorted(extra)[0]
            raise ConfigurationError(
                f"Unexpected configuration in 'tls.pkcs11.identity_key': '{unexpected}'"
            )
        raw['pkcs11_key_uri'] = identity_key.get('uri')
        raw['pkcs11_key_pin'] = identity_key.get('pin')
        identity_cert = nest.get('identity_cert')
        identity_cert_file = nest.get('identity_cert_file')
        if identity_cert is not None and not isinstance(identity_cert, dict):
            raise ConfigurationError("TLS config 'pkcs11.identity_cert' must be a mapping")
        if identity_cert:
            extra = set(identity_cert) - _PKCS11_URI_NEST_KEYS
            if extra:
                unexpected = sorted(extra)[0]
                raise ConfigurationError(
                    f"Unexpected configuration in 'tls.pkcs11.identity_cert': '{unexpected}'"
                )
            raw['pkcs11_cert_uri'] = identity_cert.get('uri')
            raw['pkcs11_cert_pin'] = identity_cert.get('pin')
            # Token cert replaces a leftover top-level cert_file; identity_cert_file
            # still wins below so xor validation can reject both sources.
            raw['cert_file'] = None
        if identity_cert_file:
            raw['cert_file'] = identity_cert_file

    @staticmethod
    def _flatten_schannel_nest(raw: dict, nest: dict) -> None:
        raw['schannel_cert_name'] = nest.get('identity_cert_name')
        raw['schannel_cert_thumbprint'] = nest.get('identity_cert_thumbprint')
        raw['schannel_cert_store'] = nest.get('identity_cert_store')

    def __post_init__(self):
        from tls.transport.capabilities import validate_identity_keys, normalize_connector

        self.connector = normalize_connector(self.connector) or 'file'
        self.schannel_cert_name = _strip_optional_str(self.schannel_cert_name)
        if self.schannel_cert_thumbprint:
            cleaned = str(self.schannel_cert_thumbprint).replace(' ', '').replace(':', '').replace('-', '')
            self.schannel_cert_thumbprint = cleaned.upper()
        self.pkcs11_key_pin = _strip_optional_secret(
            self.pkcs11_key_pin, 'pkcs11.identity_key.pin'
        )
        self.pkcs11_cert_pin = _strip_optional_secret(
            self.pkcs11_cert_pin, 'pkcs11.identity_cert.pin'
        )
        self.key_passphrase = _strip_optional_secret(
            self.key_passphrase, 'key_passphrase'
        )
        for attr in (
            'pkcs11_module',
            'pkcs11_key_uri',
            'pkcs11_cert_uri',
            'ca_cert',
            'ca_path',
            'cert_file',
            'key_file',
        ):
            setattr(self, attr, _strip_optional_str(getattr(self, attr)))

        leftover = []
        if self.connector in ('pkcs11', 'schannel'):
            keys = [
                'ca_cert', 'ca_path', 'key_file', 'key_passphrase', 'cipher_suite', 'context_options',
            ]
            if self.connector == 'schannel':
                keys.insert(2, 'cert_file')
            for key in keys:
                if _file_key_configured(self, key):
                    leftover.append(key)
                    if key == 'context_options':
                        self.context_options = []
                    else:
                        setattr(self, key, None)
            if leftover:
                startup_log(
                    "Ignoring leftover TLS file options with connector="
                    f"{self.connector}: {', '.join(leftover)}",
                    prefix='[WARNING]',
                )
            mtls_overridden = []
            if not self.check_client_cert:
                mtls_overridden.append('check_client_cert')
                self.check_client_cert = True
            if not self.check_server_cert:
                mtls_overridden.append('check_server_cert')
                self.check_server_cert = True
            if mtls_overridden:
                startup_log(
                    "Forcing mTLS for connector="
                    f"{self.connector} (overriding {', '.join(mtls_overridden)})",
                    prefix='[WARNING]',
                )

        if self.connector == 'pkcs11':
            self.ca_cert = TLS_SYSTEM_SENTINEL
            self.ca_path = None
            self.key_file = None
            self.key_passphrase = None
            self.cipher_suite = TLS_SYSTEM_SENTINEL
            self.context_options = TLS_SYSTEM_SENTINEL

        if self.context_options is None:
            self.context_options = []
        elif isinstance(self.context_options, str):
            if self.connector == 'file' or self.context_options != TLS_SYSTEM_SENTINEL:
                raise ConfigurationError(
                    "TLS config 'context_options' must be a list of option names"
                    if self.connector == 'file'
                    else "TLS config 'context_options' must be 'system' or a list of option names"
                )
        elif isinstance(self.context_options, list):
            if 'system' in self.context_options:
                raise ConfigurationError(
                    "TLS config cannot set 'system' inside the 'context_options' list"
                )
        else:
            raise ConfigurationError(
                "TLS config 'context_options' must be a list of option names"
            )

        if self.connector == 'file':
            if self.key_passphrase and not (self.cert_file or self.key_file):
                raise ConfigurationError(
                    "TLS config must set 'cert_file' or 'key_file' when 'key_passphrase' is configured"
                )
            if self.ca_cert == TLS_SYSTEM_SENTINEL:
                raise ConfigurationError(
                    "TLS connector=file does not support ca_cert: system"
                )
            if self.cipher_suite == TLS_SYSTEM_SENTINEL:
                raise ConfigurationError(
                    "TLS connector=file does not support cipher_suite: system"
                )
            if not self.cipher_suite:
                self.cipher_suite = PYTHON_SSL_DEFAULT_CIPHER_SUITE
            if not self.context_options:
                self.context_options = list(PYTHON_SSL_DEFAULT_CONTEXT_OPTIONS)

        validate_identity_keys(self)

        if self.connector == 'schannel':
            if self.schannel_cert_store:
                self.schannel_cert_store = str(self.schannel_cert_store).upper()
            else:
                self.schannel_cert_store = 'MY'


@dataclasses.dataclass
class CacheManagerConfig(AbstractConfig):
    """
    Class to store configuration for the Agent's cachemanager.
    """

    host: str
    port: int
    housekeeping_interval: int
    timestamp_error_margin: int
    # The 2 max_* attributes will be read as ints once we've finished initialising this
    # config object, but are read as strings from the config so we that users can
    # use values like "1GB" instead of having to type 107374182
    max_cache_size: int
    max_item_size: int
    tls_enabled: bool = False
    tls: Optional[TLSConfig] = None

    NAME: str = dataclasses.field(default='cachemanager', repr=False)

    def __post_init__(self):
        self.max_cache_size = parse_byte_string(self.max_cache_size) or 107374182  # 1GB
        self.max_item_size = parse_byte_string(self.max_item_size)
        # Parse tls whenever it is present so pkcs11/schannel are rejected
        # even when TLS is disabled. Only keep the object when TLS is on.
        if self.tls is not None:
            parsed = TLSConfig.from_dict(self.tls, section=self.NAME)
            self.tls = parsed if self.tls_enabled else None
        elif self.tls_enabled:
            self.tls = TLSConfig.from_dict({}, section=self.NAME)
        else:
            self.tls = None


@dataclasses.dataclass
class ExecutionConfig(AbstractConfig):
    """
    Class to store configuration for the Execution of scripts.
    """
    execution_timeout: int

    NAME: str = dataclasses.field(default='execution', repr=False)


@dataclasses.dataclass
class EnvironmentVariableConfig(AbstractConfig):
    """
    Class to store configuration for environment variables.
    """
    # Environment variables to pass directly through to the executing plugin
    passthrough: list[str] = dataclasses.field(default_factory=list)

    # Environment variables to set for the executing plugin
    custom: dict[str, str] = dataclasses.field(default_factory=dict)

    NAME: str = dataclasses.field(default='environment_variables', repr=False)

    def __post_init__(self):
        # Environment variables must be strings!
        self.custom = {key: str(val) for key, val in self.custom.items()}
        self._validate_var_names(self.passthrough, 'passthrough')
        self._validate_var_names(self.custom.keys(), 'custom')

    @staticmethod
    def _validate_var_names(key_names: Iterable[str], section_name: str):
        for var_name in key_names:
            if not isinstance(var_name, str):
                raise ConfigurationError(
                    f"'{section_name}' environment variable names must be strings "
                    f"(found {type(var_name).__name__} {var_name})"
                )

            var_bad_type = None
            for bad_type in (int, float):
                try:
                    bad_type(var_name)
                except ValueError:
                    pass
                else:
                    var_bad_type = bad_type
                    break

            if var_bad_type:
                raise ConfigurationError(
                    f"'{section_name}' environment variable names must not be numbers "
                    f"(found {var_bad_type.__name__} '{var_name}')"
                )

    @classmethod
    def from_dict(cls, config: dict):
        return cls(
            passthrough=config.get('passthrough') or [],
            custom=config.get('custom') or {}
        )


@dataclasses.dataclass
class ForwarderClientConfig(AbstractConfig):
    """
    Class to store configuration for the ForwarderClient.
    """
    host: str
    port: int
    tls_enabled: bool
    tls: Optional[TLSConfig] = None
    concurrency: int = 0
    connection_timeout: int = 30
    network_timeout: int = 60
    idle_timeout: int = 12
    user: Optional[str] = None
    password: Optional[str] = None

    NAME: str = dataclasses.field(default='forwarder_client', repr=False)
    MIN_IDLE_TIMEOUT_SECS = 4

    def __post_init__(self):
        self.tls = TLSConfig.from_dict(self.tls or {}, section='forwarders')
        if self.idle_timeout < self.MIN_IDLE_TIMEOUT_SECS:
            raise ConfigurationError(
                f"Idle timeout for forwarder '{self.NAME}' must be at least {self.MIN_IDLE_TIMEOUT_SECS} seconds"
            )


@dataclasses.dataclass
class ForwardersConfig(AbstractConfig):
    """
    Class to store configuration for the Forwarders.
    """
    forwarder_by_name: dict[str, ForwarderClientConfig] = dataclasses.field(default_factory=dict)

    NAME: str = dataclasses.field(default='forwarders', repr=False)

    @classmethod
    def from_dict(cls, config: dict) -> ForwardersConfig:
        return cls(forwarder_by_name={
            name: ForwarderClientConfig.from_dict(fcc) for name, fcc in config.items()
        })


@dataclasses.dataclass
class ServerConfig(AbstractConfig):
    """
    Class to store configuration for the Agents Server.
    """
    allowed_hosts: list
    max_queued_connections: int
    max_active_connections: int
    port: int
    tls_enabled: bool
    tls_handshake_timeout: int
    tls: TLSConfig
    max_request_time: int
    receive_data_timeout: int
    housekeeping_interval: int
    allow_multi_packet_response: bool

    NAME: str = dataclasses.field(default='server', repr=False)
    bind_address: str = ''

    def __post_init__(self):
        self.tls = TLSConfig.from_dict(self.tls, section=self.NAME)
        if self.tls.connector in ('pkcs11', 'schannel'):
            # Null/unset would block every client; treat it as an empty list
            # (no host filter). A configured list is still applied.
            if self.allowed_hosts is None:
                startup_log(
                    f"Forcing allowed_hosts to [] for connector={self.tls.connector}",
                    prefix='[WARNING]',
                )
                self.allowed_hosts = []
            if not self.tls_enabled:
                startup_log(
                    f"Forcing tls_enabled for connector={self.tls.connector}",
                    prefix='[WARNING]',
                )
            self.tls_enabled = True


@dataclasses.dataclass
class PollerScheduleConfig(AbstractConfig):
    """
    Class to store configuration for the Poller.
    """
    script: str
    interval: int
    forwarder: Optional[str] = None
    hostname: Optional[str] = None
    servicecheckname: Optional[str] = None

    NAME: str = dataclasses.field(default='poller_schedule', repr=False)

    @classmethod
    def from_dict(cls, config: dict) -> dict[str, PollerScheduleConfig]:
        pollers: dict[str, PollerScheduleConfig] = {}
        for script, data in config.items():
            if isinstance(data, dict):
                # New style, with all attributes
                pollers[script] = cls(
                    script=script,
                    interval=data['interval'],
                    forwarder=data.get('forwarder'),
                    hostname=data.get('hostname'),
                    servicecheckname=data.get('servicecheckname')
                )
            else:
                # Old style, just a poll interval
                pollers[script] = cls(script=script, interval=data)
        return pollers


@dataclasses.dataclass
class AgentConfig(AbstractConfig):
    """
    Class to store configuration for the entire Agent.

    dataclasses.field(repr=False) is used to stop the repr() output for an AgentConfig
    object being thousands of characters long.
    """
    agent_name: str
    cachemanager: CacheManagerConfig = dataclasses.field(repr=False)
    commands: dict[str, CommandConfig] = dataclasses.field(repr=False)
    case_sensitive_commands: bool
    execution: ExecutionConfig = dataclasses.field(repr=False)
    logging: dict = dataclasses.field(repr=False)
    poller_schedule: dict[str, PollerScheduleConfig] = dataclasses.field(repr=False)

    server: ServerConfig = dataclasses.field(repr=False)
    forwarders: ForwardersConfig = dataclasses.field(repr=False)
    # A dictionary mapping runtime names (i.e. python) to the path the binary is stored in.
    # This is required on Windows to run non-executable files (python/perl scripts).
    windows_runtimes: dict[str, str] = dataclasses.field(repr=False)
    environment_variables: EnvironmentVariableConfig = dataclasses.field(repr=False)
    version: str
    process_recycle_time: int

    @classmethod
    def from_dict(cls, config: dict):
        """Build the agent configuration from a dict"""
        try:
            environment_variables = EnvironmentVariableConfig.from_dict(config['environment_variables'])
            commands = CommandConfig.from_dict(config['commands'], environment_variables)
            case_sensitive_commands = has_command_case_conflicts(commands.keys())
            if not case_sensitive_commands:
                commands = {k.lower(): v for k, v in commands.items()}
            agent_config: AgentConfig = cls(
                agent_name=AGENT_NAME,
                cachemanager=CacheManagerConfig.from_dict(config['cachemanager']),
                commands=commands,
                case_sensitive_commands=case_sensitive_commands,
                execution=ExecutionConfig.from_dict(config['execution']),
                logging=config['logging'],
                poller_schedule=PollerScheduleConfig.from_dict(config['poller_schedule']),
                server=ServerConfig.from_dict(config['server']),
                forwarders=ForwardersConfig.from_dict(config.get('forwarders', {})),
                version=config['version'],
                windows_runtimes=config.get('windows_runtimes', {}),
                environment_variables=environment_variables,
                process_recycle_time=config['process_recycle_time'],
            )
            return agent_config
        except KeyError as ex:
            raise ConfigurationError(f'Missing configuration section: {ex}')


def has_command_case_conflicts(command_names: Iterable[str]) -> bool:
    """
    Check if there are any command names that are the same when case is ignored.
    This is important for Windows where the file system is case insensitive.
    """
    item_list = list(command_names)
    return len(set(i.lower() for i in item_list)) < len(item_list)


def get_agent_root() -> Path:  # pragma: no cover
    """
    Returns the root dir of the Agent installation.
    This is dependent on whether the Agent has been frozen.
    """
    relative_path = RELATIVE_BASE_PATH_FROZEN if getattr(sys, 'frozen', False) else RELATIVE_BASE_PATH_SRC
    base_path = Path(__file__).parent
    return base_path / relative_path


def get_startup_log_path() -> Path:
    """Returns the path of startup.log file"""
    return (get_agent_root() / STARTUP_LOG_REL_PATH).resolve()


def create_default_user_config_if_required() -> bool:
    """Writes a new user config file if one does not already exist."""
    agent_config_path = (get_agent_root() / USER_CONFIG_REL_PATH).resolve()
    if os.path.isfile(agent_config_path):
        return False
    os.makedirs(os.path.dirname(agent_config_path), exist_ok=True)
    with open(agent_config_path, 'w') as f:
        f.write(DEFAULT_USER_CONFIG_CONTENT)
    return True


def get_config(logger: Callable) -> AgentConfig:
    """Reads the configuration file(s) and returns an AgentConfig from the contents within."""
    def open_yaml(path: Union[str, Path]):
        startup_log(f"Reading config file '{path}'")
        with open(path, 'r') as f:
            return yaml.safe_load(f)

    # Set the file's startup_log function
    global startup_log
    startup_log = logger

    # Location of the  base directory
    # When cx_Freeze is used (frozen) this is a couple of levels higher
    relative_path = RELATIVE_BASE_PATH_FROZEN if getattr(sys, 'frozen', False) else RELATIVE_BASE_PATH_SRC
    base_path = Path(__file__).parent
    config_dir = (base_path / relative_path / CONFIG_DIR_NAME).resolve()
    default_config_path = config_dir / DEFAULT_CONFIG_NAME
    imported_config_path = config_dir / IMPORTED_CONFIG_NAME
    custom_config_path = (config_dir / USER_CONFIG_SUBDIR).resolve()

    # Ensure config files are added in the correct order:
    #  1) agent.default.yml
    #  2) imported.yml (if exists)
    #  3) config files in the custom directory (sorted alphanumerically)
    config_files = [default_config_path]
    if imported_config_path.is_file():
        config_files.append(imported_config_path)
    custom_config_files: list[str] = []
    for extension in YAML_EXTENSIONS:
        custom_config_files += glob.glob(f'{custom_config_path}/*.{extension}')
    config_files += sorted(custom_config_files)

    # Process ordered config files
    config: dict = {}
    for cfg in [d for d in [open_yaml(cfg_path) for cfg_path in config_files] if d is not None]:
        merge_dictionary(config, cfg, MERGE_LISTS)

    var_dir = (base_path / relative_path / VAR_DIR_NAME).resolve()
    config['version'] = _read_version_info(var_dir)  # Version always comes from file

    if read_bool_from_envar('AGENT_DUMP_FINAL_CONFIG'):
        startup_log(f"Config dict = {config}", prefix='[DEBUG]')

    return AgentConfig.from_dict(config)


def _read_version_info(var_dir: pathlib.Path) -> str:
    """Reads the version number from the version file."""
    file_path = (var_dir / VERSION_FILE_NAME).resolve()
    try:
        with open(file_path, 'r') as f_in:
            raw_version = f_in.read().strip()
        version = raw_version.partition('-')[0]
    except FileNotFoundError:
        version = '0.0.0'
        startup_log(f"Failed to read version file '{file_path}'. Setting to '{version}'", prefix='[WARNING]')
    return version
