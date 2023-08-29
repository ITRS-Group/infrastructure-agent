"""
Opsview Agent Poller
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import gevent
import logging
import time

from dataclasses import dataclass
from sortedcontainers import SortedDict
from typing import TYPE_CHECKING
from cache.exceptions import ConfigError
from .scriptrunner import ScriptRunner

if TYPE_CHECKING:
    from cache.expirycache import ExpiryCache, CacheEntry


POLLER_DATA_PREFIX = 'PollerData'
POLLER_EXEC_PREFIX = 'PollerExec'
ENV_AGENT_POLLER_DATA = 'AGENT_POLLER_DATA'
ENV_AGENT_POLLER_EXEC = 'AGENT_POLLER_EXEC'
POLLER_EXEC_NORMAL = '1'
POLLER_EXEC_CALLED = '2'
CACHE_TIME_SECS = 1800

logger = logging.getLogger(__name__)


@dataclass
class PollerScriptInfo:
    """Represents information about the script to poll"""
    interval: int
    script: str


def to_script_name(script: str) -> str:
    """Returns the script name part of a script"""
    return script.partition('!')[0]


class Poller:
    """Represents the Poller which schedules and executes background polling checks"""

    def __init__(self, poller_config: dict, script_runner: ScriptRunner, cache: ExpiryCache):
        self._poller_config: dict[str, PollerScriptInfo] = {
            to_script_name(script): PollerScriptInfo(interval, script)
            for script, interval in poller_config.items()
        }
        if len(self._poller_config) != len(poller_config):
            raise ConfigError("Duplicate script name detected in 'poller_schedule' config")
        self._script_runner: ScriptRunner = script_runner
        self._cache: ExpiryCache = cache

        # The execution slots contains lists of scripts to run, keyed by the next time to run them
        self._exec_slots: SortedDict[int, list] = SortedDict()

    def get_poller_env_for_script_exec(self, script_name: str) -> dict[str, str]:
        """Called during general script execution to fetch Poller environment data.
        Side effect is to mark the script as being executed for use by the next poll.
        """
        if script_name not in self._poller_config:
            return {}
        data_key: str = f'{POLLER_DATA_PREFIX}|{script_name}'
        existing_data: CacheEntry = self._cache.get(data_key)
        usage_key: str = f'{POLLER_EXEC_PREFIX}|{script_name}'
        now: int = int(time.time())
        logger.debug("Marking script '%s' as executed", script_name)
        self._cache.set(usage_key, str(now), CACHE_TIME_SECS)  # Mark that the EXEC is taking place
        return {
            ENV_AGENT_POLLER_DATA: (existing_data.data or '') if existing_data else '',
        }

    def run(self):
        """Blocking entry point to run the Poller"""
        if not self._poller_config:
            logger.info("No pollers scheduled")
            return
        self._schedule_all_pollers()
        while True:
            next_slot: int = next(iter(self._exec_slots))
            now: int = int(time.time())
            wait_time: int = next_slot - now
            if wait_time > 0:
                gevent.sleep(wait_time)
            script_names = self._exec_slots.pop(next_slot)
            greenlets = [
                gevent.spawn(self._gproxy, self._exec_script, script_name, next_slot)
                for script_name in script_names
            ]
            gevent.joinall(greenlets)

    def _gproxy(self, func: callable, *args):
        """Proxies the greenlet function allowing any exceptions to kill the process."""
        try:
            func(*args)
        except Exception as ex:
            logger.error("Error thrown for %s (%s)", func.__name__, ex)
            raise

    def _exec_script(self, script_name: str, current_slot: int):
        """Executes the specified script"""
        data_key: str = f'{POLLER_DATA_PREFIX}|{script_name}'
        existing_data: CacheEntry = self._cache.get(data_key)
        usage_key: str = f'{POLLER_EXEC_PREFIX}|{script_name}'
        called_flag = self._cache.get(usage_key)
        self._cache.delete(usage_key)
        script_info = self._poller_config[script_name]
        env = {
            ENV_AGENT_POLLER_EXEC: POLLER_EXEC_CALLED if called_flag else POLLER_EXEC_NORMAL,
            ENV_AGENT_POLLER_DATA: (existing_data.data or '') if existing_data else '',
        }
        logger.debug("_exec_script: About to poll '%s'", script_info.script)
        exit_code, stdout, stderr, _ = self._script_runner.run_script(script_info.script, [], env)
        if exit_code == 0:
            self._cache.set(data_key, stdout, CACHE_TIME_SECS)
        else:
            err_text = stderr or stdout
            logger.error("Error code %d executing '%s': %s", exit_code, script_name, err_text)

        self._schedule_next_exec_time(script_name, script_info, current_slot)

    def _schedule_all_pollers(self):
        """Schedules all configured pollers"""
        now: int = int(time.time())
        for script_name, script_info in self._poller_config.items():
            exec_time: int = now + script_info.interval
            self._exec_slots.setdefault(exec_time, []).append(script_name)

    def _schedule_next_exec_time(self, script_name: str, script_info: PollerScriptInfo, current_slot: int):
        """Updates the next execution time for the script"""
        now: int = int(time.time())
        next_exec_time: int = max(current_slot + script_info.interval, now + 1)
        self._exec_slots.setdefault(next_exec_time, []).append(script_name)
