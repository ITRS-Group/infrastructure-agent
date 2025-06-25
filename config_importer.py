#!/usr/bin/env python

from __future__ import annotations

import configparser
import hashlib
import logging
import os
import pathlib
import platform
import re
import shutil
import sys
import yaml
from abc import ABC, abstractmethod
from agent.config import AgentConfig, get_config
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

HASH_BLOCK_SIZE = 65536
YAML_LINE_WIDTH = 999

KEY_IP_ALLOWED_HOSTS = 'allowed_hosts'
KEY_IP_SERVER_PORT = 'server_port'

KEY_OP_SERVER = 'server'
KEY_OP_SERVER_ALLOWED_HOSTS = 'allowed_hosts'
KEY_OP_SERVER_PORT = 'port'
KEY_OP_COMMANDS = 'commands'

AGENT_PATH_LINUX = '/opt/opsview/agent'
AGENT_PATH_WINDOWS = 'C:/Program Files/Opsview Agent'

OLD_AGENT_CONFIG_COPY_DIR = '/opt/itrs/infrastructure-agent/var/old_agent_config_copy'

RE_COMMAND_NIX = re.compile(r'(?P<dir>[\w/\-.]*/)?(?P<check>check_[\w\-.]+)')
RE_COMMAND_WIN = re.compile(r'(?P<dir>(?:[A-Z]:)?[\w \\\-/)(.]+[\\/])?(?P<check>check_[\w\-.]+)')

logger: Optional[logging.Logger] = None


def is_windows() -> bool:
    """Determine if we are running on Windows"""
    return 'windows' in platform.system().lower()


def clean_partition(line: str, delim='=') -> tuple[str, str] | tuple[None, None]:
    """Helper method to perform a string partition providing stripped parts"""
    pt1, dv, pt2 = line.partition(delim)
    return (pt1.strip(), pt2.strip()) if dv == delim else (None, None)


def clean_split(line: str, delim=','):
    """Helper method to convert a delimited string into a clean list"""
    if line is None:
        return line
    if not line.strip():
        return []
    parts: list[str] = line.split(delim)
    return [p.strip() for p in parts]


def hash_file(file_path: str) -> str:
    """Produce a SHA256 hash of a file"""
    file_hash = hashlib.sha256()
    with open(file_path, 'rb') as f_in:
        fb = f_in.read(HASH_BLOCK_SIZE)
        while len(fb):
            file_hash.update(fb)
            fb = f_in.read(HASH_BLOCK_SIZE)
    return file_hash.hexdigest()


def copy_file_if_different(src_file_path: str, dst_file_path: str) -> bool:
    """Helper method to copy a file if there is no destination file, or they are different"""
    src_hash = hash_file(src_file_path)
    dst_hash = hash_file(dst_file_path) if os.path.exists(dst_file_path) else None
    if src_hash != dst_hash:
        shutil.copy2(src_file_path, dst_file_path)
        return True
    return False


class BaseReader(ABC):
    """Abstract base class for configuration file readers"""

    @abstractmethod
    def scan_config(self, existing_plugins: set[str]) -> tuple[bool, dict[str, str], str, int]:
        command_dict: dict[str, str] = {}
        scanned_config_successfully: bool = False
        allowed_hosts: str = ''
        server_port: int = 0
        return scanned_config_successfully, command_dict, allowed_hosts, server_port

    @abstractmethod
    def get_agent_dir(self) -> str:
        return ''

    def write_path(self, cmd_line) -> str:
        """Allows paths to be re-written according to the OS"""
        return cmd_line


class CfgReader(BaseReader):
    """Manages reading from NRPE bases config files (Linux)"""

    RE_COMMAND = re.compile(r'command\[([\w-]+)]')

    def scan_config(self, existing_plugins: set[str]) -> tuple[bool, dict[str, str], str, int]:
        # On linux, we make a copy of the old config file that is readable by the infra agent user
        # as well as any referenced included files
        data_dict = self._read_file_data(os.path.join(OLD_AGENT_CONFIG_COPY_DIR, 'nrpe.cfg'))
        command_dict = {}
        allowed_hosts = None
        server_port = None
        for key, value in data_dict.items():
            if key == KEY_IP_SERVER_PORT:
                server_port = int(value)
            elif key == KEY_IP_ALLOWED_HOSTS:
                allowed_hosts = clean_split(value)
            else:
                m_command = self.RE_COMMAND.match(key)
                if m_command:
                    command_name: str = m_command.group(1)
                    if command_name not in existing_plugins:
                        command_dict[command_name] = value
                        logger.debug("Command: %s: %s", command_name, value)
        return bool(data_dict), command_dict, allowed_hosts, server_port

    def get_agent_dir(self) -> str:
        return AGENT_PATH_LINUX

    @classmethod
    def _read_file_data(cls, file_path) -> dict[str, str]:
        logger.debug("Importing file: %s", file_path)
        file_dir = os.path.dirname(file_path)
        data_dict: dict[str, str] = {}
        try:
            with open(file_path) as f:
                for line in f:
                    clean_line: str = line.strip()
                    if not clean_line or clean_line.startswith('#'):
                        continue
                    key, value = clean_partition(clean_line)
                    if not value:
                        logger.warning("Invalid option value for %s", key)
                        continue
                    if key == 'include':
                        child_data_dict = cls._read_file_data(os.path.join(file_dir, value))
                        data_dict.update(child_data_dict)
                    elif key == 'include_dir':
                        child_dir = os.path.join(file_dir, value)
                        logger.debug("Including dir: %s", child_dir)
                        for child_file in pathlib.Path(child_dir).rglob('*.cfg'):
                            child_data_dict = cls._read_file_data(os.path.join(file_dir, child_file))
                            data_dict.update(child_data_dict)
                    else:
                        data_dict[key] = value
        except (FileNotFoundError, PermissionError) as ex:
            logger.warning("Cannot import from '%s': %s", file_path, ex)
        return data_dict


class IniReader(BaseReader):
    """Manages reading from NSClient bases config files (Windows)"""

    # These checks are included in the existing Opsview Agent, but are not yet
    #  included in the new Agent (we can't just copy over, since they have dependencies)
    ORIGINAL_CHECKS = {
        'check_mountpoint',
        'check_services',
        'check_clustergroup',
        'check_windows_base',
        'check_msmq',
        'check_ms_iis',
        'check_ms_dns',
        'check_ms_sql_database_states',
        'check_ms_sql_performance',
        'check_ms_sql_system',
        'check_ms_hyperv_server',
        'check_microsoft_exchange2016_backpressure',
        'check_microsoft_exchange2013_backpressure',
        'check_microsoft_exchange_counters',
        'check_microsoft_exchange',
        'check_active_directory',
        'check_windows_updates',
        'check_file_age',
        'check_http',
        'check_ssl',
    }

    def scan_config(self, existing_plugins: set[str]) -> tuple[bool, dict, str, int]:
        config = configparser.ConfigParser(allow_no_value=True, strict=False)
        config.read(os.path.join(AGENT_PATH_WINDOWS, 'opsview.ini'))
        custom_plugins = {}
        try:
            commands = config['NRPE Handlers']
            for name, command_line in commands.items():
                if name not in self.ORIGINAL_CHECKS and name not in existing_plugins:
                    custom_plugins[name] = command_line
            logger.debug("custom_plugins=%s", custom_plugins)
        except KeyError:
            pass
        try:
            server_port = int(config['NRPE']['port'])
            logger.debug("server_port=%d", server_port)
        except KeyError:
            server_port = None
        try:
            allowed_hosts = clean_split(config['Settings']['allowed_hosts'])
            logger.debug("allowed_hosts=%s", allowed_hosts)
        except KeyError:
            allowed_hosts = None
        return bool(config), custom_plugins, allowed_hosts, server_port

    def get_agent_dir(self) -> str:
        return AGENT_PATH_WINDOWS

    def write_path(self, cmd_line) -> str:
        # Attempt to fix windows paths to be of the form: "C:/Program\ Files/something"
        return cmd_line.replace('\\ ', ' ').replace('\\', '/').replace(' ', '\\ ')


def create_config_reader(is_win: bool):
    """Factory method for creating a config reader"""
    return IniReader() if is_win else CfgReader()


class ConfigImporter:
    """Responsible for importing the configuration from previous """

    def __init__(self, existing_config: AgentConfig, is_win: bool):
        self._existing_config = existing_config
        self._is_win = is_win
        self._re_cmd = RE_COMMAND_WIN if is_win else RE_COMMAND_NIX
        base_dir = pathlib.Path(__file__).parent
        if getattr(sys, 'frozen', False):
            base_dir = base_dir / '../../../'
        base_dir_abs = base_dir.resolve()
        logger.info("ConfigImporter base_dir_abs = '%s'", base_dir_abs)
        self._old_config_file_path = base_dir_abs / 'cfg/custom/imported.yml'
        self._output_config_file_path = base_dir_abs / 'cfg/imported.yml'
        self._output_script_dir = base_dir_abs / 'plugins/imported'

    def run_if_required(self) -> bool:
        """Runs the import if it hasn't already been run.
        Returns True if the config has changed and needs reading again.
        """
        if os.path.isfile(self._output_config_file_path):
            logger.info("Imported config file already exists at '%s'", self._output_config_file_path)
            return False
        if os.path.isfile(self._old_config_file_path):
            os.replace(self._old_config_file_path, self._output_config_file_path)
            logger.info("Moved imported config file to '%s'", self._output_config_file_path)
            return True
        output_config_dir = self._output_config_file_path.parent
        os.makedirs(output_config_dir, exist_ok=True)
        rdr: BaseReader = create_config_reader(self._is_win)
        existing_plugins = set(self._existing_config.commands.keys())
        scanned_config_successfully, custom_plugins, allowed_hosts, server_port = rdr.scan_config(existing_plugins)
        data_dict = {}
        if custom_plugins:
            copied_plugins = {}
            for command_name, command_line in custom_plugins.items():
                try:
                    new_command_line: str = self._copy_custom_plugin(rdr, command_line)
                except FileNotFoundError as ex:
                    logger.warning("Could not import '%s': %s", command_name, ex)
                    continue
                if new_command_line:
                    copied_plugins[command_name] = {'path': new_command_line}
            if copied_plugins:
                data_dict[KEY_OP_COMMANDS] = copied_plugins

        # Some logic follows to migrate over `allowed_hosts` satisfactorily for all cases.
        #
        # Note on `allowed_hosts` variable at this point, assuming we read old config successfully:
        # If it is [], that means it was set without a value in the old agent.
        # If it is None, it means the old agent did not have `allowed_hosts` set at all in config.
        #
        # On either platform, if `allowed_hosts` was set to some values, we want to migrate that.
        add_allowed_hosts_warning = False
        insert_allowed_hosts = bool(allowed_hosts)

        # Then handle some edge cases where we still want to migrate to equivalent behaviour.
        # We only do this if `scanned_config_successfully` is True. If not, there may have been issues reading the
        # old config, so we should just default to the new agent's secure behaviour of blocking all hosts.
        if scanned_config_successfully and not insert_allowed_hosts:

            # for old windows agent:
            if self._is_win:
                # `allowed_hosts` being set without a value means allow all hosts.
                if allowed_hosts == []:  # noqa to avoid IDE 'simplifications' that break the logic...
                    insert_allowed_hosts = True
                    add_allowed_hosts_warning = True
                # `allowed_hosts` not being set means block all hosts - no action, this is the default in the new agent.

            # for old linux agent:
            else:
                # `allowed_hosts` not being set means allow all hosts, which we want to migrate.
                if allowed_hosts is None:
                    insert_allowed_hosts = True
                    add_allowed_hosts_warning = True
                    allowed_hosts = []
                # `allowed_hosts` being set without a value is not supported at all in the linux agent.

        if insert_allowed_hosts or server_port:
            server_section = {}
            if insert_allowed_hosts:
                server_section[KEY_OP_SERVER_ALLOWED_HOSTS] = allowed_hosts
            if server_port:
                server_section[KEY_OP_SERVER_PORT] = server_port
            data_dict[KEY_OP_SERVER] = server_section

        logger.info("Creating imported config file: '%s'", self._output_config_file_path)
        with open(self._output_config_file_path, 'w') as f_out:
            f_out.write('---\n')
            f_out.write('# Imported configuration file.\n\n')
            f_out.write('# Warning:\n')
            f_out.write('#   If this file is deleted/moved, the import process will be\n')
            f_out.write('#   automatically run again when the Agent next starts.\n\n')

            if add_allowed_hosts_warning:
                f_out.write('# Warning:\n')
                f_out.write('#   Your migrated `allowed_hosts` config currently allows any host to connect.\n')
                f_out.write('#   This could be a security risk. We recommend limiting to expected hosts.\n\n')

                logger.warning(
                    "The migrated `allowed_hosts` config will allow any host to connect. "
                    "This could be a security risk. We recommend limiting to expected hosts."
                )

            if data_dict:
                yaml.dump(data_dict, f_out, width=YAML_LINE_WIDTH)
        os.chmod(self._output_config_file_path, 0o640)

        return True

    def _copy_custom_plugin(self, rdr: BaseReader, command_line: str) -> Optional[str]:
        """Copies the existing plugin to the new location and updates the path"""
        def check_path_matcher(matcher: re.Match) -> str:
            dir_name: str = matcher.group('dir')
            check_name: str = matcher.group('check')
            agent_dir = rdr.get_agent_dir()
            src_file_path = os.path.join(agent_dir, dir_name or '', check_name)
            dest_file_path = os.path.join(self._output_script_dir, check_name)
            os.makedirs(self._output_script_dir, exist_ok=True)
            os.chmod(self._output_script_dir, 0o750)
            if copy_file_if_different(src_file_path, dest_file_path):
                logger.debug("Copied file '%s' -> '%s'", src_file_path, dest_file_path)
            did_sub.append(True)
            return rdr.write_path(dest_file_path)

        did_sub: list[bool] = []
        modified_cmd = self._re_cmd.sub(check_path_matcher, command_line)
        return modified_cmd if did_sub else None


def init_logging():
    """Initialises the logging for this module.
    Allows for using this file direct from the command lines, as well as via function call.
    """
    global logger
    logger = logging.getLogger(__name__)
    if not len(logger.parent.handlers):
        logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.DEBUG)


def import_config_if_required(existing_config: AgentConfig) -> bool:
    """Main launcher function for running the config import if it hasn't been run before"""
    init_logging()
    is_win: bool = is_windows()
    ci = ConfigImporter(existing_config, is_win)
    return ci.run_if_required()


if __name__ == '__main__':
    try:
        existing_config: AgentConfig = get_config()
        import_config_if_required(existing_config)
    except KeyboardInterrupt:
        pass
