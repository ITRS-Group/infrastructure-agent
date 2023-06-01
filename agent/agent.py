"""
Infrastructure Agent
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import logging
import platform
from typing import TYPE_CHECKING

import gevent
import gevent.monkey
import shlex

from cache.expirycache import ExpiryCache
from nrpe.server import NRPEListener
from .cachemanager import CacheManager
from .objects import Platform
from .poller import Poller
from .processmanager import ProcessManager
from .scriptrunner import ScriptRunner
from .self_check import format_platform_info

if TYPE_CHECKING:
    from .config import AgentConfig

logger = logging.getLogger(__name__)

gevent.monkey.patch_all()


class Agent:
    """infrastructure agent"""
    def __init__(self, cache_manager: CacheManager, config: AgentConfig):
        logger.info("Starting Agent")
        self._cache_manager = cache_manager
        self._cache_manager.agent = self
        self._config = config
        self._process_manager = ProcessManager()
        platform_data = self.get_platform()
        runtimes = {name: shlex.split(line) for name, line in self._config.windows_runtimes.items()}
        self.script_runner = ScriptRunner(
            platform=platform_data,
            command_config=self._config.commands,
            runtime_config=runtimes,
            execution_config=self._config.execution,
            cache_manager=self._cache_manager,
            process_manager=self._process_manager,
            platform_desc=format_platform_info(self._config.agent_name, self._config.version, platform_data.is_windows),
        )
        # The Poller just needs the base cache, without locking mechanisms
        cache: ExpiryCache = cache_manager.get_cache().get_locking_cache().get_expiry_cache()
        self._poller = Poller(config.poller_schedule, self.script_runner, cache)
        self.script_runner.set_poller_env_callback(self._poller.get_poller_env_for_script_exec)

        self._greenlets: list[gevent.Greenlet] = []
        self._running: bool = False
        self._terminated_with_error: bool = False
        self._process_recycle_time = config.process_recycle_time

    def run(self) -> int:
        """Spawn the cache manager and NRPE server"""
        self._running = True
        self.nrpe_listener = NRPEListener(
            platform=self.get_platform(),
            server_config=self._config.server,
            script_runner=self.script_runner,
        )

        self._greenlets = [
            gevent.spawn(self._gproxy, self._cache_manager.run),
            gevent.spawn(self._gproxy, self.nrpe_listener.command_listener),
            gevent.spawn(self._gproxy, self._poller.run),
            gevent.spawn(self._gproxy, self._process_recycler),
        ]

        gevent.joinall(self._greenlets)
        self._running = False
        return 1 if self._terminated_with_error else 0

    def stop(self, is_error: bool = True):
        """Terminate the agent"""
        if is_error:
            self._terminated_with_error = True
        gevent.killall(self._greenlets, block=False)
        self._process_manager.kill_all()

    def is_running(self) -> bool:
        return self._running

    def _gproxy(self, func: callable, *args):
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
