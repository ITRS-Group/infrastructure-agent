"""
Infrastructure Agent: Unit tests for objects
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""

import json
import os
import shlex
import signal

import gevent
import pytest
from gevent.subprocess import TimeoutExpired

from agent.config import CommandConfig, ExecutionStyle
from agent.scriptrunner import ScriptRunner

EXIT_CODE_UNKNOWN = 3
DYNAMIC_ENV_KEYS = ('LANG',)

PATCH_PREFIX = 'agent.scriptrunner.'


@pytest.fixture
def scriptrunner(agent_config, platform_linux, mocker) -> ScriptRunner:
    runtimes = {name: shlex.split(line) for name, line in agent_config.windows_runtimes.items()}
    yield ScriptRunner(
        platform=platform_linux,
        command_config=agent_config.commands,
        runtime_config=runtimes,
        execution_config=agent_config.execution,
        cache_manager=mocker.Mock(),
        process_manager=mocker.Mock(),
        platform_desc=mocker.Mock(),
    )


@pytest.mark.parametrize(
    'uses_cm, env_vars', [
        pytest.param(False, 0, id="no_cachemanager"),
        pytest.param(True, 3, id="cachemanager"),
    ])
def test_scriptrunner_build_env(uses_cm, env_vars, scriptrunner, cachemanager):
    env = scriptrunner._build_env(uses_cm, cachemanager, 'foo', {})
    assert len(env) == env_vars + len(DYNAMIC_ENV_KEYS)


@pytest.mark.parametrize(
    'script, arguments, runtime, is_windows, script_args, expected, logexp', [
        pytest.param('_NRPE_CHECK', [], None, False, None, (0, 'foo', '', False), [], id="success_without_args"),
        pytest.param('command', [], None, False, ['/bin/cmd'], (42, '', '', False), [], id="success"),
        pytest.param(
            'command', [], 'valid_runtime', True,
            ['valid_runtime', 'p1', '/bin/cmd'],
            (42, '', '', False), [],
            id="success_with_valid_runtime"),
        pytest.param(
            'command', [], 'invalid_runtime', True,
            ['/bin/cmd'],
            (42, '', '', False),
            ['WARNING', "Windows runtime 'invalid_runtime' could not be found"],
            id="warning_with_invalid_runtime"),
        pytest.param('command', ['foo'], None, False, ['/bin/cmd'], (42, '', '', False), [], id="success_with_args"),
        pytest.param(
            'unknown', [], None, False, None,
            (3, "COMMAND UNKNOWN: Command 'unknown' not defined.", '', False),
            ['WARNING ', "Command 'unknown' requested but not configured"],
            id="unknown_with_args"),
        pytest.param(
            'unknown', ['foo'], None, False, None,
            (3, "COMMAND UNKNOWN: Command 'unknown' not defined.", '', False),
            ['WARNING ', "Command 'unknown' requested but not configured"],
            id="unknown_with_args"),
    ])
def test_scriptrunner_run_script(script, arguments, runtime, is_windows, script_args,
                                 expected, logexp, scriptrunner, mocker, caplog):

    scriptrunner.platform_desc = 'foo'
    scriptrunner.command_config['command'] = CommandConfig(
        name='check_foo', runtime=runtime, cache_manager=False, path='/bin/cmd',
        stderr=False, long_running_key=None, execution_style=ExecutionStyle.COMMAND_LINE_ARGS
    )

    scriptrunner.platform = mocker.Mock(is_windows=is_windows)
    mock_proc = mocker.Mock(returncode=42)
    mock_proc.stdout.read.return_value = b''
    mock_proc.stderr.read.return_value = b''
    mock_subp = mocker.patch(PATCH_PREFIX + 'subprocess')
    mock_subp.Popen.return_value = mock_proc
    assert scriptrunner.run_script(script, arguments) == expected
    if script_args:
        first_arg = mock_subp.Popen.call_args[0][0]
        assert first_arg == script_args
    else:
        mock_subp.Popen.assert_not_called()
    if logexp:
        for text in logexp:
            assert text in caplog.text
    else:
        for text in ('WARNING', 'ERROR'):
            assert text not in caplog.text


@pytest.mark.parametrize(
    'plugin, args, long_running, expected_stdin, stdin_err', [
        pytest.param(
            'lrp', ['arg1'], True, {'cmd': ['lrp', 'arg1'], 'env': {'LONG_RUNNING_PROCESS': '1'}}, None,
            id="long_running"
        ),
        pytest.param(
            'lrp', ['arg1'], False, {'cmd': ['lrp', 'arg1'], 'env': {}}, None,
            id="stdin_only"
        ),
        pytest.param(
            'lrp', ['arg1'], False, {'cmd': ['lrp', 'arg1'], 'env': {}}, OSError(),
            id="stdin_with_err"
        ),
        pytest.param(
            '', [''], False, None, None,
            id="stdin_no_input"
        ),
    ])
def test_scriptrunner_long_running(plugin, args, long_running, expected_stdin, stdin_err, scriptrunner, mocker, caplog):
    if isinstance(expected_stdin, dict):
        expected_stdin['env'] = _update_dynamic_env(expected_stdin['env'])
    script = f'/bin/cmd {plugin} $ARG1$' if plugin else '/bin/cmd'

    long_running_key = script if long_running else None
    execution_style = ExecutionStyle.LONGRUNNING_STDIN_ARGS if long_running else ExecutionStyle.STDIN_ARGS

    command_name = 'command'

    scriptrunner.command_config[command_name] = CommandConfig(
        name=command_name, runtime=None, cache_manager=False, path=script,
        long_running_key=long_running_key, execution_style=execution_style
    )

    expected_stdout = 'expected stdout'
    output_json = json.dumps({'exitcode': 0, 'stdout': expected_stdout, 'stderr': ''}).encode('utf-8') + b'\n'

    mock_process = mocker.Mock()
    mock_process.wait.side_effect = gevent.sleep

    if long_running:
        scriptrunner.process_manager.get_managed_process.return_value = (mock_process, mocker.Mock())
        mock_process.stdout.readline.return_value = output_json
    else:
        mocker.patch(PATCH_PREFIX + 'subprocess.Popen', return_value=mock_process)
        mock_process.stdout.read.side_effect = WaitAfterFirstCall(output_json).side_effect
        mock_process.stderr.read.side_effect = WaitAfterFirstCall(None).side_effect

    if stdin_err:
        mock_process.stdin.close.side_effect = stdin_err

    exit_code, stdout, stderr, ended_early = scriptrunner.run_script(command_name, args)

    assert ended_early is False
    if expected_stdin:
        expected_stdin_bytes = json.dumps(expected_stdin).encode('utf-8')
        mock_process.stdin.write.assert_called_with(expected_stdin_bytes + b'\n')
    else:
        mock_process.stdin.write.assert_not_called()
    if stdin_err:
        assert f"Failed to close STDIN for '{command_name}'" in caplog.text
    assert stdout == expected_stdout


def test_scriptrunner_long_running_invalid_json(scriptrunner, mocker):
    command_name = 'command'
    scriptrunner.command_config[command_name] = CommandConfig(
        name=command_name, runtime=None, cache_manager=False, path='/bin/cmd arg1',
        stderr=True, long_running_key='key', execution_style=ExecutionStyle.LONGRUNNING_STDIN_ARGS
    )
    mock_process = mocker.Mock()
    mock_process.stdout.readline.return_value = "some rubbish that isn't json"
    scriptrunner.process_manager.get_managed_process.return_value = (mock_process, mocker.Mock())
    exit_code, stdout, stderr, ended_early = scriptrunner.run_script(command_name, [])
    assert exit_code == EXIT_CODE_UNKNOWN
    assert stdout == ''
    assert 'Failed to decode json output' in stderr


def test_scriptrunner_long_running_with_timeout(scriptrunner, mocker):
    script = '/bin/cmd lrp $ARG1$'
    command_name = 'command'
    scriptrunner.command_config[command_name] = CommandConfig(
        name=command_name, runtime=None, cache_manager=False, path=script,
        stderr=False, long_running_key=script, execution_style=ExecutionStyle.LONGRUNNING_STDIN_ARGS
    )
    mock_process = mocker.Mock(pid=1)
    mock_process.stdout.readline.side_effect = gevent.Timeout
    scriptrunner.process_manager.get_managed_process.return_value = (mock_process, mocker.Mock())

    exit_code, stdout, stderr, ended_early = scriptrunner.run_script(command_name, [])
    assert exit_code == 2
    assert ended_early is True
    assert "Command 'command' did not exit within" in stderr


@pytest.mark.parametrize(
    'poller_env, poller_fn_env, expected_env', [
        pytest.param({'k1': 'v1'}, None, {'k1': 'v1'}, id="with direct poller_env"),
        pytest.param(None, {'k2': 'v2'}, {'k2': 'v2'}, id="with poller_env from callback fn"),
    ])
def test_scriptrunner_run_script_with_poller(poller_env, poller_fn_env, expected_env, scriptrunner, mocker):
    expected_env = _update_dynamic_env(expected_env)
    script_name = 'myscript'

    scriptrunner.command_config[script_name] = CommandConfig(
        name=script_name, runtime=None, cache_manager=False, path='/path',
        stderr=False, long_running_key=None
    )

    poller_fn = None
    if poller_fn_env:
        poller_fn = mocker.Mock(return_value=poller_fn_env)
        scriptrunner.set_poller_env_callback(poller_fn)
    mock_proc = mocker.Mock(returncode=0)
    mock_proc.communicate.return_value = (b'', b'')
    mock_subp = mocker.patch(PATCH_PREFIX + 'subprocess')
    mock_subp.Popen.return_value = mock_proc
    scriptrunner.run_script(script_name, [], poller_env=poller_env)
    mock_subp.Popen.assert_called_with(
        mocker.ANY, env=expected_env,
        stdin=mocker.ANY, stdout=mocker.ANY, stderr=mocker.ANY, shell=mocker.ANY, preexec_fn=mocker.ANY,
    )
    if poller_fn:
        poller_fn.assert_called_with(script_name)


@pytest.mark.parametrize(
    'windows, stderr, comm, poll, expected, logexp', [
        pytest.param(
            False, False, (b'', b''), None, (42, '', '', False), [],
            id="linux_success"),
        pytest.param(
            False, False, (b'foo', b'bar'), None, (42, 'foo', '', False), [],
            id="linux_success_with_data"),
        pytest.param(
            False, False, (b'', b'bar'), None, (42, '', '', False), [],
            id="linux_success_just_stderr"),
        pytest.param(
            False, True, (b'', b''), None, (42, '', '', False), [],
            id="linux_stderr"),
        pytest.param(
            False, True, (b'foo', b'bar'), None, (42, 'foo', 'bar', False), [],
            id="linux_stderr_with_data"),
        pytest.param(
            False, True, (b'', b'bar'), None, (42, '', 'bar', False), [],
            id="linux_stderr_just_stderr"),
        pytest.param(
            True, False, (b'', b''), None, (42, '', '', False), [],
            id="win_success"),
        pytest.param(
            False, False, TimeoutExpired('foo', 1), True,
            (2, '', "ERROR: Command 'command' did not exit within 60 seconds.", True),
            ['ERROR ', "Process '/bin/cmd' did not exit within 60 seconds"],
            id="timeout"),
        pytest.param(
            True, False, TimeoutExpired('foo', 1), True,
            (2, '', "ERROR: Command 'command' did not exit within 60 seconds.", True),
            ['ERROR ', "Process '/bin/cmd' did not exit within 60 seconds"],
            id="timeout_windows"),
        pytest.param(
            False, False, TimeoutExpired('foo', 1), None,
            (2, '', "ERROR: Command 'command' did not exit within 60 seconds (and was killed).", True),
            ['ERROR ', "Process '/bin/cmd' did not exit within 60 seconds (and was killed)"],
            id="killed"),
        pytest.param(
            True, False, TimeoutExpired('foo', 1), None,
            (2, '', "ERROR: Command 'command' did not exit within 60 seconds (and was killed).", True),
            ['ERROR ', "Process '/bin/cmd' did not exit within 60 seconds (and was killed)"],
            id="killed_windows"),
    ])
def test_scriptrunner_execute(
        windows, stderr, comm, poll,
        expected, logexp,
        mocker, monkeypatch, scriptrunner, platform_win, caplog):
    orig_gsleep = gevent.sleep

    mocker.patch(PATCH_PREFIX + 'gevent.sleep')

    mock_kill = mocker.patch(PATCH_PREFIX + 'os.kill')
    mock_killpg = mocker.patch(PATCH_PREFIX + 'os.killpg')

    mocker.patch(PATCH_PREFIX + 'os.getpgid', return_value=-42)

    if windows:
        scriptrunner.platform = platform_win
        # signal.CTRL_C_EVENT won't be defined when running tests on Linux so we need to mock it
        # SIGKILL will need similar mocking if/when we support running unit tests on Windows
        mocker.patch(PATCH_PREFIX + 'signal.CTRL_C_EVENT', 0, create=True)

    command_config = CommandConfig(name='name', path='/path/to/no/where', stderr=stderr)

    mock_proc = mocker.Mock()
    if isinstance(comm, Exception):
        mock_proc.wait.side_effect = comm
    else:
        mock_proc.wait.side_effect = orig_gsleep
        mock_proc.stdout.read.side_effect = WaitAfterFirstCall(comm[0]).side_effect
        mock_proc.stderr.read.side_effect = WaitAfterFirstCall(comm[1]).side_effect
    mock_proc.poll.return_value = poll
    mock_proc.pid = 707
    mock_proc.returncode = 42

    mock_subp = mocker.patch(PATCH_PREFIX + 'subprocess')
    mock_subp.Popen.return_value = mock_proc

    assert scriptrunner._execute('command', command_config, ['/bin/cmd', 'arg1'], {}) == expected

    if isinstance(comm, TimeoutExpired) and not poll:
        if windows:
            assert not mock_killpg.called
            mock_kill.assert_called_once_with(707, 0)  # PID, CTRL_C_EVENT
        else:
            assert not mock_kill.called
            mock_killpg.assert_called_once_with(-42, signal.SIGKILL)  # PGID, SIGKILL

    for text in logexp:
        assert text in caplog.text


def test_scriptrunner_execute_file_not_found(mocker, scriptrunner):
    cmd_path = '/somewhere/not-found'

    mock_subp = mocker.patch(PATCH_PREFIX + 'subprocess')

    exc = FileNotFoundError()
    exc.filename = cmd_path
    mock_subp.Popen.side_effect = exc

    cmd_config = CommandConfig(
        name='check_foo', runtime=None, cache_manager=False, path='/path',
        stderr=False, long_running_key=None
    )

    with pytest.raises(FileNotFoundError) as ex:
        scriptrunner._execute('command', cmd_config, [cmd_path, 'arg'], {})
    expected = f"Cannot find command: '{cmd_path}'"
    assert expected in str(ex)


class WaitAfterFirstCall:
    """Returns data on first call of side_effect, then just gevent-waits forever on subsequent calls"""

    def __init__(self, data):
        self._counter = 0
        self._data = data

    def side_effect(self):
        self._counter += 1
        if self._counter > 1:
            gevent.wait()
        return self._data


def _update_dynamic_env(env_dict: dict[str, str]):
    """Updates an environment dict with actual environment values (adding these first)"""
    updated_env_dict = {key: os.environ.get(key, '') for key in DYNAMIC_ENV_KEYS}
    updated_env_dict.update(env_dict)
    return updated_env_dict
