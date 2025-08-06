"""
Infrastructure Agent
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import logging
import platform
from typing import TYPE_CHECKING

import gevent
import shlex

from cache.expirycache import ExpiryCache
from nrpe.server import NRPEListener
from .cachemanager import CacheManager
from .forwarderclient import ForwarderClient
from .objects import Platform
from .poller import Poller
from .processmanager import ProcessManager
from .scriptrunner import ScriptRunner
from .self_check import format_platform_info

if TYPE_CHECKING:
    from collections.abc import Callable
    from .config import AgentConfig

logger = logging.getLogger(__name__)


class Agent:
    """infrastructure agent"""
    def __init__(self, cache_manager: CacheManager, config: AgentConfig):
        self._cache_manager = cache_manager
        self._cache_manager.agent = self
        self._config = config
        logger.info("Agent commands are case %ssensitive", "" if self._config.case_sensitive_commands else "in")
        self._process_manager = ProcessManager()
        platform_data = self.get_platform()
        runtimes = {name: shlex.split(line) for name, line in self._config.windows_runtimes.items()}
        self._script_runner = ScriptRunner(
            platform=platform_data,
            command_config=self._config.commands,
            case_sensitive_commands=self._config.case_sensitive_commands,
            runtime_config=runtimes,
            execution_config=self._config.execution,
            cache_manager=self._cache_manager,
            process_manager=self._process_manager,
            platform_desc=format_platform_info(self._config.agent_name, self._config.version, platform_data.is_windows),
        )
        # The Poller just needs the base cache, without locking mechanisms
        cache: ExpiryCache = cache_manager.get_cache().get_locking_cache().get_expiry_cache()
        forwarder_clients = {n: ForwarderClient(n, c) for n, c in self._config.forwarders.forwarder_by_name.items()}
        self._poller = Poller(config.poller_schedule, self._script_runner, cache, forwarder_clients)
        self._script_runner.set_poller_env_callback(self._poller.get_poller_env_for_script_exec)

        self._greenlets: list[gevent.Greenlet] = []
        self._terminated_with_error: bool = False
        self._process_recycle_time = config.process_recycle_time

    def run(self) -> int:
        """Spawn the cache manager and NRPE server"""
        self.nrpe_listener = NRPEListener(
            platform=self.get_platform(),
            server_config=self._config.server,
            script_runner=self._script_runner,
        )

        self._greenlets = [
            gevent.spawn(self._gproxy, self._cache_manager.run),
            gevent.spawn(self._gproxy, self.nrpe_listener.command_listener),
            gevent.spawn(self._gproxy, self._poller.run),
            gevent.spawn(self._gproxy, self._process_recycler),
        ]
        gevent.joinall(self._greenlets)
        return 1 if self._terminated_with_error else 0

    def stop(self, is_error: bool = True):
        """Terminate the agent"""
        if is_error:
            self._terminated_with_error = True
        if self._poller:
            self._poller.close()
            self._poller = None
        if self._greenlets:
            gevent.killall(self._greenlets, block=False)
            self._greenlets.clear()
        if self._process_manager:
            self._process_manager.kill_all()
            self._process_manager = None
        if self._script_runner:
            self._script_runner.kill_running()
            self._script_runner = None

    def _gproxy(self, func: Callable, *args):
        """Proxies the greenlet function allowing any exceptions to kill the process."""
        try:
            func(*args)
        except Exception as ex:
            logger.error('Error thrown for %s (%s)', func.__name__, ex)
            self.stop()

    def _process_recycler(self):
        """Handles recycling of long-running processes"""
        while True:
            gevent.sleep(self._process_recycle_time)
            logger.debug("About to recycle processes ...")
            self._process_manager.recycle_all()

    @staticmethod
    def get_platform() -> Platform:
        """Determine the system platform"""
        system = platform.system()
        windows_version = platform.win32_ver() if system == 'Windows' else tuple()
        return Platform(
            system=system,
            architecture=platform.machine(),
            windows_version=windows_version
        )
