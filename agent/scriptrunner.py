"""
Infrastructure Agent: Platform independent Script Runner class for executing commands.
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import dataclasses
import enum
import json
import logging
import os
import shlex
import signal
from typing import TYPE_CHECKING

import gevent
from gevent import subprocess
from gevent.lock import BoundedSemaphore
from gevent.subprocess import PIPE, TimeoutExpired

from .config import ExecutionStyle
from .processmanager import ProcessManager

if TYPE_CHECKING:
    from typing import Callable, Optional
    from gevent.greenlet import Greenlet

    from .cachemanager import CacheManager
    from .config import CommandConfig, EnvironmentVariableConfig, ExecutionConfig
    from .objects import Platform

EMPTY_CHECK = "_NRPE_CHECK"
ENV_LONG_RUNNING_PROCESS = 'LONG_RUNNING_PROCESS'

logger = logging.getLogger(__name__)


class CommandError(Exception):
    """An error occurred while verifying the commands"""
    pass


class ServiceReturnCodes(enum.Enum):
    """Standard service return codes"""
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


@dataclasses.dataclass
class ScriptRunner:
    """Platform independent Script Runner class for executing commands"""

    cache_manager: CacheManager
    command_config: dict[str, CommandConfig]
    execution_config: ExecutionConfig
    platform: Platform
    cache_manager: CacheManager
    runtime_config: dict[str, list[str]]
    process_manager: ProcessManager
    platform_desc: str

    # The reference to the poller environment callback function (to prevent circular imports)
    _poller_env_fn: Callable[[str], dict[str, str]] = None

    EXIT_CODE_CRITICAL = ServiceReturnCodes.CRITICAL.value
    EXIT_CODE_UNKNOWN = ServiceReturnCodes.UNKNOWN.value

    def set_poller_env_callback(self, poller_env_fn: Callable[[str], dict[str, str]]):
        """Sets the poller environment callback function"""
        self._poller_env_fn = poller_env_fn

    def run_script(
        self, command: str, arguments: list[str], poller_env: Optional[dict[str, str]] = None
    ) -> tuple[int, str, str, bool]:
        """Run the script"""
        if command == EMPTY_CHECK:
            exit_code = 0
            response_stdout = self.platform_desc
            response_stderr = ''
            early_timeout = False
            return exit_code, response_stdout, response_stderr, early_timeout

        try:
            command_config = self.command_config[command]
        except KeyError:
            logger.warning("Command '%s' requested but not configured", command)
            return ServiceReturnCodes.UNKNOWN.value, f"COMMAND UNKNOWN: Command '{command}' not defined.", "", False

        if command_config.max_unique_arg_index > len(arguments):
            # If request has less args than the command is configured for then pad out the args list with empty strings
            arguments = arguments + [''] * (command_config.max_unique_arg_index - len(arguments))

        try:
            args, kwargs = self._setup_args(
                command=command_config,
                script_args=shlex.split(command_config.path.format(*arguments)),
                poller_env=poller_env,
            )
        except Exception:
            # Do not log the arguments since they may contain sensitive data.
            logger.warning("Command '%s' Unable to parse arguments", command)
            return ServiceReturnCodes.UNKNOWN.value, "COMMAND FAILURE: Failed to parse command arguments.", "", False

        return self._execute(command, command_config, args, kwargs)

    def _setup_args(
        self, command: CommandConfig, script_args: list[str], poller_env: Optional[dict[str, str]] = None
    ) -> tuple[list[str], dict[str, str]]:
        """Set up the arguments and environment"""

        args: list[str]

        # If agent is running on Windows and command has a runtime, prepend the runtime to the execution args
        if self.platform.is_windows and command.runtime:
            runtime = self.runtime_config.get(command.runtime)
            if runtime:
                args = [*runtime, *script_args]
            else:
                logger.warning("Windows runtime '%s' could not be found", command.runtime)
                args = script_args
        else:
            args = script_args

        if not poller_env and self._poller_env_fn:
            poller_env = self._poller_env_fn(command.name)

        subprocess_kwargs = {
            'env': self._build_env(
                command.environment_variables, command.cache_manager,
                self.cache_manager, command.name, poller_env
            ),
            'stdin': PIPE if command.uses_stdin else None,
            'stdout': PIPE,
            'stderr': PIPE,
            'shell': False,
        }

        if not self.platform.is_windows:
            # Creates a new process group for the process, so the group can be killed
            subprocess_kwargs['preexec_fn'] = os.setsid

        return args, subprocess_kwargs

    def _execute(
        self, plugin: str, command: CommandConfig, args: list[str], kwargs: dict
    ) -> tuple[int, str, str, bool]:
        """
        Execute the command script.
        Kill the command if it does not complete in time.
        """
        logger.debug("Executing %s", args)
        stdin_data: Optional[bytes] = None
        proc_lock: Optional[BoundedSemaphore] = None

        try:
            command_path = args[0]
            if command.uses_stdin:
                env: dict = kwargs['env']
                if command.execution_style == ExecutionStyle.LONGRUNNING_STDIN_ARGS:
                    proc, proc_lock = self.process_manager.get_managed_process(command.long_running_key, command_path)
                    env[ENV_LONG_RUNNING_PROCESS] = '1'
                else:
                    proc = subprocess.Popen(command_path, **kwargs)

                if len(args) > 1:
                    stdin_obj = {'cmd': args[1:], 'env': env}
                    stdin_data = json.dumps(stdin_obj).encode('utf-8')
            else:
                # execution_style is ExecutionStyle.COMMAND_LINE_ARGS:
                proc = subprocess.Popen(args, **kwargs)
        except FileNotFoundError:
            logger.warning("Unable to find command '%s'", command_path)
            return (
                ServiceReturnCodes.UNKNOWN.value,
                f"COMMAND FAILURE: Command not found: '{command_path}'.", "", False)

        pid = proc.pid
        max_wait_secs = self.execution_config.execution_timeout
        clean_stdout = ''
        clean_stderr: str
        try:
            if stdin_data:
                proc.stdin.write(stdin_data + b'\n')
                if command.long_running_key:
                    proc.stdin.flush()
            exit_code, clean_stdout, stderr = self._read_output(
                plugin, proc, command.uses_stdin, command.long_running_key, timeout=max_wait_secs
            )
            clean_stderr = stderr if command.stderr else ''
            early_timeout = False
        except TimeoutExpired:
            # Attempt to end the process gracefully (sending SIGTERM),
            proc.terminate()
            command_name: str = args[0] if len(args) > 0 else ''
            gevent.sleep(1)
            add_text: str = ""
            poll = proc.poll()
            if poll is None:
                # kill it (SIGKILL) and all its child processes
                if self.platform.is_windows:
                    # SIGKILL doesn't exist on Windows, send a CTRL_C_EVENT signal instead
                    os.kill(pid, signal.CTRL_C_EVENT)
                else:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)  # Kill the process group (all children)
                add_text = " (and was killed)"
            logger.error("Process '%s' did not exit within %s seconds%s.", command_name, max_wait_secs, add_text)
            clean_stderr = f"ERROR: Command '{plugin}' did not exit within {max_wait_secs} seconds{add_text}."
            exit_code = self.EXIT_CODE_CRITICAL
            early_timeout = True
        finally:
            if proc_lock:
                proc_lock.release()

        del proc
        return exit_code, clean_stdout, clean_stderr, early_timeout

    def _read_output(
        self, name: str, proc: subprocess.Popen, use_stdin: bool, long_running_key: str, timeout: int = 60
    ) -> tuple[int, str, str]:
        timer = gevent.Timeout(timeout)
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        capture_greenlets: list[Greenlet] = []
        timer.start()
        try:
            if long_running_key:
                stdout = proc.stdout.readline().strip()
            else:
                capture_greenlets = [
                    gevent.spawn(self._pipe_reader, proc.stdout, stdout_buffer),
                    gevent.spawn(self._pipe_reader, proc.stderr, stderr_buffer),
                ]
                if use_stdin:
                    try:
                        proc.stdin.close()
                    except OSError:
                        logger.exception("Failed to close STDIN for '%s'", name)
                proc.wait()
                gevent.wait(capture_greenlets)  # Allow reader greenlets to complete
                stdout = stdout_buffer.decode('utf-8').strip()
            if long_running_key or (use_stdin and stdout.startswith('{')):
                return self._process_json_stdout(stdout)
            stderr = stderr_buffer.decode('utf-8').strip()
        except gevent.Timeout:
            logger.error("Failed to read stdout from process '%s' (pid=%d) within %ds", name, proc.pid, timeout)
            raise TimeoutExpired(name, timeout)
        finally:
            if capture_greenlets:
                gevent.killall(capture_greenlets, block=False)
            timer.close()
        return proc.returncode, stdout, stderr

    @staticmethod
    def _pipe_reader(pipe, buffer: bytearray):
        """Async greenlet method to ensure we read all buffered data from the process pipe,
        otherwise, the process "wait" will potentially block (e.g. 4K buffer size on Windows).
        """
        try:
            while True:
                temp_buffer = pipe.read()
                if not temp_buffer:
                    break
                buffer += temp_buffer
        except Exception:
            logger.exception("Failed to read from pipe")

    def _process_json_stdout(self, raw_stdout: str) -> tuple[int, str, str]:
        try:
            decoded = json.loads(raw_stdout)
            return decoded['exitcode'], decoded['stdout'], decoded['stderr']
        except json.JSONDecodeError:
            return self.EXIT_CODE_UNKNOWN, '', f"Failed to decode json output: {raw_stdout}"

    def _build_env(
        self, environment_variables: EnvironmentVariableConfig, uses_cachemanager: bool,
        cache_manager: CacheManager, plugin_name: str, poller_env: dict[str, str]
    ) -> dict[str, str]:
        """Set up the environment variables to be used by the command"""
        env = {
            var_name: os.environ[var_name] for var_name in environment_variables.passthrough if var_name in os.environ
        } | environment_variables.custom

        if poller_env:
            env |= poller_env

        if uses_cachemanager:
            cm_env = cache_manager.get_env(plugin_name)
            for key in cm_env:
                if isinstance(cm_env[key], bytes):
                    cm_env[key] = cm_env[key].decode('utf-8')
            env |= cm_env
        return env
