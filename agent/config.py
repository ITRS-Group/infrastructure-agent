"""
Infrastructure Agent: Read agent configuration
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import dataclasses
import glob
import os
import pathlib
import re
import shlex
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from agent.helpers import merge_dictionary, parse_byte_string

if TYPE_CHECKING:
    from typing import Optional, Union

AGENT_NAME = "Infrastructure Agent"

RELATIVE_BASE_PATH_SRC = '../'
RELATIVE_BASE_PATH_FROZEN = '../../../'

DEFAULT_CONFIG_NAME = 'agent.default.yml'
IMPORTED_CONFIG_NAME = 'imported.yml'
CONFIG_DIR_NAME = 'cfg'
VAR_DIR_NAME = 'var'
USER_CONFIG_REL_PATH = CONFIG_DIR_NAME + '/custom/agent.yml'
USER_CONFIG_SUBDIR = 'custom'
YAML_EXTENSIONS = {'yml', 'yaml'}
TRUE_STRINGS = ('true', 'y', 'yes', '1')
MERGE_LISTS = ('allowed_hosts',)
VERSION_FILE_NAME = 'version'

PLUGIN_ARG_FORMAT_RE = re.compile(r'\$ARG(\d+)\$')
ESCAPE_PATH_STRINGS = ('{', '}')

DEFAULT_USER_CONFIG_CONTENT = """---
# This file has been created as a placeholder for your custom
#  configuration overrides. YAML configuration files in the "custom"
#  directory will be read in alphanumeric order.
"""


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
            match = re.match(r'__init__\(\) missing .*: (.*)$', str(ex))
            if match:
                raise ConfigurationError(f"Configuration missing from '{cls.NAME}': {match.group(1)}")

            # __init__() got an unexpected keyword argument 'foo'
            match = re.match(r"__init__\(\) got an unexpected .* '(.*)'$", str(ex))
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
    use_stdin: bool = False

    max_unique_arg_index: int = dataclasses.field(init=False)

    NAME: str = 'commands'

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

    @staticmethod
    def _duplicate_chars(base_str: str, chars: tuple[str]) -> str:
        """
        For each instance of each character in chars in base_str duplicates the character

        For example:
            _duplicate_chars("check_example -a '{thing}'", '{', '}') -> "check_example -a '{{thing}}'"
        """
        for char in chars:
            base_str = base_str.replace(char, char * 2)
        return base_str

    @classmethod
    def from_dict(cls, config: dict) -> dict[str, CommandConfig]:
        """
        Creates a dictionary mapping command names (str) to CommandConfig objects containing
        configuration for a given command.
        """
        commands = {}
        try:
            for name in config:
                path: str = config[name]['path']
                long_running_key: str = config[name].get('long_running_key')
                if long_running_key == '$PATH$':
                    long_running_key = shlex.split(path)[0]
                elif long_running_key == '$NAME$':
                    long_running_key = name
                command = cls(
                    name=name,
                    path=path,
                    runtime=config[name].get('runtime'),
                    cache_manager=config[name].get('cache_manager', False),
                    stderr=config[name].get('stderr', True),
                    long_running_key=long_running_key,
                    use_stdin=config[name].get('use_stdin', bool(long_running_key)),
                )
                if command.long_running_key and not command.use_stdin:
                    raise ConfigurationError(
                        f"Long running key '{long_running_key}' for command '{name}' cannot have 'use_stdin=false'")
                commands[name] = command
        except KeyError as ex:
            raise ConfigurationError(f"Missing '{cls.NAME}' configuration for '{name}', section: {ex}")
        return commands


@dataclasses.dataclass
class TLSConfig(AbstractConfig):
    """
    Class to store configuration for a servers TLS.
    """
    ca_cert: str
    ca_path: str
    cert_file: str
    key_file: str
    check_client_cert: str
    cipher_suite: str
    context_options: list[str]

    log_all_messages: bool = read_bool_from_envar('AGENT_TLS_LOG_MESSAGES')


@dataclasses.dataclass
class CacheManagerConfig(AbstractConfig):
    """
    Class to store configuration for the Agent's cachemanager.
    """

    host: str
    port: int
    housekeeping_interval: int
    timestamp_error_margin: int
    # The 2 max* attributes will be read as ints once we've finished initialising this
    # config object but are read as strings from the config so we that users can
    # use values like "1GB" instead of having to type 107374182
    max_cache_size: int
    max_item_size: int
    tls_enabled: bool = False
    tls: TLSConfig = None

    NAME: str = 'cachemanager'

    def __post_init__(self):
        self.max_cache_size: int = parse_byte_string(self.max_cache_size) or 107374182  # 1GB
        self.max_item_size: int = parse_byte_string(self.max_item_size)
        self.tls = TLSConfig.from_dict(self.tls) if self.tls_enabled else None


@dataclasses.dataclass
class ExecutionConfig(AbstractConfig):
    """
    Class to store configuration for the Execution of scripts.
    """
    execution_timeout: int

    NAME: str = 'execution'


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

    NAME: str = 'server'
    bind_address: str = ''

    def __post_init__(self):
        self.tls = TLSConfig.from_dict(self.tls)


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
    execution: ExecutionConfig = dataclasses.field(repr=False)
    logging: dict = dataclasses.field(repr=False)
    poller_schedule: dict[str, int] = dataclasses.field(repr=False)
    server: ServerConfig = dataclasses.field(repr=False)
    # A dictionary mapping runtime names (i.e. python) to the path the binary is stored in.
    # This is required on Windows to run non-executable files (python/perl scripts).
    windows_runtimes: dict[str, str] = dataclasses.field(repr=False)
    version: str
    process_recycle_time: int

    @classmethod
    def from_dict(cls, config: dict):
        """Build the agent configuration from a dict"""
        try:
            return cls(
                agent_name=AGENT_NAME,
                cachemanager=CacheManagerConfig.from_dict(config['cachemanager']),
                commands=CommandConfig.from_dict(config['commands']),
                execution=ExecutionConfig.from_dict(config['execution']),
                logging=config['logging'],
                poller_schedule=config['poller_schedule'],
                server=ServerConfig.from_dict(config['server']),
                version=config['version'],
                windows_runtimes=config.get('windows_runtimes', {}),
                process_recycle_time=config['process_recycle_time'],
            )
        except KeyError as ex:
            raise ConfigurationError(f'Missing configuration section: {ex}')


def get_agent_root() -> Path:  # pragma: no cover
    """Returns the root dir of the Agent installation.
    This is dependent on whether the Agent has been frozen.
    """
    relative_path = RELATIVE_BASE_PATH_FROZEN if getattr(sys, 'frozen', False) else RELATIVE_BASE_PATH_SRC
    base_path = Path(__file__).parent
    return base_path / relative_path


def create_default_user_config_if_required() -> bool:
    """Writes a new user config file if one does not already exist."""
    agent_config_path = (get_agent_root() / USER_CONFIG_REL_PATH).resolve()
    if os.path.isfile(agent_config_path):
        return False
    os.makedirs(os.path.dirname(agent_config_path), exist_ok=True)
    with open(agent_config_path, 'w') as f:
        f.write(DEFAULT_USER_CONFIG_CONTENT)
    return True


def get_config() -> AgentConfig:
    """Reads the configuration file(s) and returns an AgentConfig from the contents within."""
    def open_yaml(path: Union[Path, str]):
        print(f"Reading config file '{path}'")
        with open(path, 'r') as f:
            return yaml.safe_load(f)

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
    custom_config_files: list[Path] = []
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
        print(f"Config dict = {config}")

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
        print(f"Failed to read version file '{file_path}'. Setting to '{version}'")
    return version
