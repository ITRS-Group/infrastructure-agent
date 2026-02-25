"""
Opsview Agent Poller
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import gevent
import logging
import platform
import time

from sortedcontainers import SortedDict
from typing import TYPE_CHECKING

from gevent.event import Event

from .config import ConfigurationError
from .scriptrunner import ScriptRunner

if TYPE_CHECKING:
    from typing import Callable
    from cache.expirycache import ExpiryCache
    from .forwarderclient import ForwarderClient
    from .config import PollerScheduleConfig


POLLER_DATA_PREFIX = 'PollerData'
POLLER_EXEC_PREFIX = 'PollerExec'
ENV_AGENT_POLLER_DATA = 'AGENT_POLLER_DATA'
ENV_AGENT_POLLER_EXEC = 'AGENT_POLLER_EXEC'
ENV_POLLER_INTERVAL = 'POLLER_INTERVAL'
POLLER_EXEC_NORMAL = '1'
POLLER_EXEC_CALLED = '2'
CACHE_TIME_SECS = 1800
POLL_SETTLE_TIME_SECS = 1

logger = logging.getLogger(__name__)


class Poller:
    """Represents the Poller which schedules and executes background polling checks"""

    def __init__(self, poller_config: dict[str, PollerScheduleConfig], script_runner: ScriptRunner, cache: ExpiryCache,
                 clients: dict[str, ForwarderClient]):
        self._poller_config = poller_config
        self._client_by_name = clients
        self._validate_forwarder_clients()
        self._script_runner: ScriptRunner = script_runner
        self._cache: ExpiryCache = cache
        self._hostname = platform.node()  # Get the hostname of the machine running the agent
        # The execution slots contains lists of scripts to run, keyed by the next time to run them
        self._exec_slots: SortedDict[int, list] = SortedDict()
        self._greenlets: set[gevent.Greenlet] = set()
        self._waiter = Event()  # Used to wait for the next execution slot

    def _validate_forwarder_clients(self):
        """Validates that all forwarder clients are configured correctly."""
        for poller in self._poller_config.values():
            if poller.forwarder and (poller.forwarder not in self._client_by_name):
                raise ConfigurationError(f"Forwarder client '{poller.forwarder}' is not defined in the configuration")

    def get_poller_env_for_script_exec(self, script_name: str) -> dict[str, str]:
        """Called during general script execution to fetch Poller environment data.
        Side effect is to mark the script as being executed for use by the next poll.
        """
        if script_name not in self._poller_config:
            return {}
        data_key: str = f'{POLLER_DATA_PREFIX}|{script_name}'
        existing_data = self._cache.get(data_key)
        usage_key: str = f'{POLLER_EXEC_PREFIX}|{script_name}'
        now: int = int(time.time())
        self._cache.set(usage_key, str(now), CACHE_TIME_SECS)  # Mark that the EXEC is taking place
        return {
            ENV_AGENT_POLLER_DATA: (existing_data.data or '') if existing_data else '',
            ENV_POLLER_INTERVAL: str(self._poller_config[script_name].interval),
        }

    def run(self) -> None:
        """Blocking entry point to run the Poller"""
        if not self._poller_config:
            logger.info("No pollers scheduled")
            return
        self._schedule_all_pollers()
        while True:
            while True:
                # Inner loop to wait for the next execution slot. It also allows the wait timeout
                #  to be interrupted (kicked) after a completed execution re-schedules
                if not self._exec_slots:
                    wait_time = None  # Nothing scheduled yet, so just wait until kicked
                else:
                    next_slot: int = next(iter(self._exec_slots))
                    now = int(time.time())
                    wait_time = next_slot - now
                    if wait_time <= 0:
                        break  # No need to wait, we can execute immediately
                self._waiter.clear()  # Reset the waiter kicked flag
                if not self._waiter.wait(wait_time):
                    break  # Normal timeout, we can execute now
            script_names = self._exec_slots.pop(next_slot)
            self._greenlets.update([
                gevent.spawn(self._gproxy, self._exec_script, script_name, next_slot)
                for script_name in script_names
            ])

    def close(self):
        """Close the Poller, cleaning up any resources."""
        logger.info("Closing Poller")
        if self._greenlets:
            gevent.killall(self._greenlets, block=False)
            self._greenlets.clear()
        for client in self._client_by_name.values():
            client.close()

    def _gproxy(self, func: Callable, *args):
        """Proxies the greenlet function allowing any exceptions to kill the process."""
        try:
            func(*args)
        except Exception as ex:
            logger.error("Error thrown for %s (%s)", func.__name__, ex)
            raise
        finally:
            self._greenlets.discard(gevent.getcurrent())

    def _exec_script(self, script_name: str, current_slot: int):
        """Executes the specified script"""
        script_info = self._poller_config[script_name]

        if script_info.forwarder:
            env = {}
        else:
            data_key: str = f'{POLLER_DATA_PREFIX}|{script_name}'
            existing_data = self._cache.get(data_key)
            usage_key: str = f'{POLLER_EXEC_PREFIX}|{script_name}'
            called_flag = self._cache.get(usage_key)
            self._cache.delete(usage_key)
            env = {
                ENV_AGENT_POLLER_EXEC: POLLER_EXEC_CALLED if called_flag else POLLER_EXEC_NORMAL,
                ENV_AGENT_POLLER_DATA: (existing_data.data or '') if existing_data else '',
                ENV_POLLER_INTERVAL: str(script_info.interval),
            }

        try:
            logger.debug("Executing script '%s'", script_name)
            logger.debug("Poller scheduled as %d seconds", script_info.interval)
            exit_code, stdout, stderr, _ = self._script_runner.run_script(script_info.script, [], env)
        except Exception as e:
            logger.error("Error executing script '%s': %s", script_name, e)
        else:
            if script_info.forwarder:
                hostname = script_info.hostname or self._hostname
                servicecheckname = script_info.servicecheckname or script_name
                output = stdout
                if stderr:
                    out = stdout.split('|', 1)
                    if len(out) > 1:
                        output = f'{out[0]}; {stderr} |{out[1]}' # noqa E702
                    else:
                        output = f'{stdout} ; {stderr}' # noqa E203,E702
                client = self._client_by_name[script_info.forwarder]
                now = int(time.time())
                client.queue_result(hostname, servicecheckname, exit_code, output, now)
            else:
                if exit_code == 0:
                    self._cache.set(data_key, stdout, CACHE_TIME_SECS)
                else:
                    err_text = stderr or stdout
                    logger.error("Error code %d executing '%s': %s", exit_code, script_name, err_text)
        self._schedule_next_exec_time(script_name, script_info, current_slot)

    def _schedule_all_pollers(self) -> None:
        """
        Schedules all configured pollers.
        The first poller is scheduled to run after POLL_SETTLE_TIME_SECS, and the rest are staggered by 1 second.
        """
        now: int = int(time.time())
        for index, script_name in enumerate(self._poller_config.keys(), POLL_SETTLE_TIME_SECS):
            exec_time: int = now + index
            self._exec_slots.setdefault(exec_time, []).append(script_name)

    def _schedule_next_exec_time(self, script_name: str, script_info: PollerScheduleConfig, current_slot: int):
        """Updates the next execution time for the script"""
        now: int = int(time.time())
        next_exec_time: int = max(current_slot + script_info.interval, now + 1)
        self._exec_slots.setdefault(next_exec_time, []).append(script_name)
        self._waiter.set()
