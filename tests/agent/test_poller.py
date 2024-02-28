"""
Infrastructure Agent: Unit tests for Poller
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""
import pytest
from mock import call
from cache.exceptions import ConfigError
from cache.expirycache import CacheEntry
from agent.poller import (
    Poller,
    to_script_name,
    POLLER_EXEC_PREFIX,
    CACHE_TIME_SECS,
    POLLER_EXEC_NORMAL,
    POLLER_EXEC_CALLED,
)


class BreakException(Exception):
    pass


def spawn_side_effect(*args):
    """A gevent side effect to directly call the spawned function"""
    fn = args[0]
    fn(*args[1:])


@pytest.fixture
def empty_poller(mocker) -> Poller:
    mocker.patch('agent.poller.time.time', return_value=0)
    poller_config = mocker.MagicMock()
    poller_config.items.return_value = {}
    poller_config.__len__.return_value = 0
    return Poller(poller_config, mocker.Mock(), mocker.Mock())


@pytest.mark.parametrize('script, script_name', [
    pytest.param('script1.py', 'script1.py'),
    pytest.param('script2.py!--arg 23', 'script2.py'),
])
def test_to_script_name(script, script_name):
    assert to_script_name(script) == script_name


def test_poller_duplicate_script(mocker):
    poller_config = {
        'script1': 1,
        'script1!--arg 1': 1,
    }
    with pytest.raises(ConfigError) as err:
        Poller(poller_config, mocker.Mock(), mocker.Mock())
    assert 'Duplicate script name' in str(err)


def test_poller_run_with_no_pollers(empty_poller, caplog):
    empty_poller.run()
    assert 'No pollers scheduled' in caplog.text


@pytest.mark.parametrize('script, interval, cache_data, executed, exit_code, arguments, expected_env', [
    pytest.param(
        'script1.py', 1, 'cd1', False, 0, [],
        {'AGENT_POLLER_EXEC': POLLER_EXEC_NORMAL, 'AGENT_POLLER_DATA': 'cd1'},
        id="Normal schedule after 1 second"
    ),
    pytest.param(
        'script1.py', 0, 'cd1', False, 0, [],
        {'AGENT_POLLER_EXEC': POLLER_EXEC_NORMAL, 'AGENT_POLLER_DATA': 'cd1'},
        id="Instant schedule"
    ),
    pytest.param(
        'script1.py', 1, 'cd2', True, 0, [],
        {'AGENT_POLLER_EXEC': POLLER_EXEC_CALLED, 'AGENT_POLLER_DATA': 'cd2'},
        id="Plugin called"
    ),
    pytest.param(
        'script1.py', 1, 'cd1', False, 1, [],
        {'AGENT_POLLER_EXEC': POLLER_EXEC_NORMAL, 'AGENT_POLLER_DATA': 'cd1'},
        id="Script error"
    ),
])
def test_poller_run(mocker, script, interval, cache_data, executed, exit_code, arguments, expected_env, caplog):
    poller_config = {script: interval}
    script_runner_mock = mocker.Mock()
    cache_mock = mocker.Mock()
    mocker.patch('agent.poller.time.time', return_value=0)
    poller = Poller(poller_config, script_runner_mock, cache_mock)
    gevent_mock = mocker.patch('agent.poller.gevent')
    gevent_mock.joinall.side_effect = BreakException()
    gevent_mock.spawn.side_effect = spawn_side_effect

    def cache_get_side_effect(key):
        """Handles cache reads for EXEC and DATA"""
        if key.startswith(POLLER_EXEC_PREFIX):
            return CacheEntry('1', 0) if executed else None
        return CacheEntry(cache_data, 0)

    cache_mock.get.side_effect = cache_get_side_effect
    script_runner_mock.run_script.return_value = [exit_code, '', '', False]

    with pytest.raises(BreakException):
        poller.run()
    if interval:
        gevent_mock.sleep.assert_called_with(interval)
    else:
        gevent_mock.assert_not_called()
    script_runner_mock.run_script.assert_called_with(script, arguments, expected_env)
    if exit_code:
        assert 'Error code 1' in caplog.text
    else:
        assert 'ERROR' not in caplog.text


def test_poller_script_failure(mocker):
    poller_config = {'script1.py': 1}
    script_runner_mock = mocker.Mock()
    bad_exception_text = "Something bad"
    script_runner_mock.run_script.side_effect = Exception(bad_exception_text)
    mocker.patch('agent.poller.time.time', return_value=0)
    poller = Poller(poller_config, script_runner_mock, mocker.Mock())
    gevent_mock = mocker.patch('agent.poller.gevent')
    gevent_mock.spawn.side_effect = spawn_side_effect
    with pytest.raises(Exception) as ex:
        poller.run()
    assert bad_exception_text in str(ex)


@pytest.mark.parametrize('poller_config, loops, exec_calls, sleep_calls', [
    pytest.param(
        {'script1.py': 2},
        4,
        ['script1.py', 'script1.py', 'script1.py', 'script1.py'],
        [2, 4, 6, 8],
        id="Single script every 2s"
    ),
    pytest.param(
        {'script1.py': 2, 'script2.py': 3},
        4,
        ['script1.py', 'script2.py', 'script1.py', 'script2.py', 'script1.py'],
        [2, 3, 4, 6],
        id="Multiple overlapping scripts"
    ),
])
def test_poller_multiple_loops(mocker, poller_config, loops, exec_calls, sleep_calls):
    script_runner_mock = mocker.Mock()
    mocker.patch('agent.poller.time.time', return_value=0)
    poller = Poller(poller_config, script_runner_mock, mocker.Mock())
    gevent_mock = mocker.patch('agent.poller.gevent')
    # The loop_control allows us to precisely control how many scheduling loops execute
    loop_contol = [None] * (loops - 1) + [BreakException()]
    gevent_mock.joinall.side_effect = loop_contol
    gevent_mock.spawn.side_effect = spawn_side_effect
    script_runner_mock.run_script.return_value = [0, '', '', False]
    with pytest.raises(BreakException):
        poller.run()
    script_calls = [call(s, [], mocker.ANY) for s in exec_calls]
    script_runner_mock.run_script.assert_has_calls(script_calls)
    sleep_calls = [call(s) for s in sleep_calls]
    gevent_mock.sleep.assert_has_calls(sleep_calls)


def test_get_poller_env_no_config(empty_poller):
    assert empty_poller.get_poller_env_for_script_exec('script1.py') == {}


@pytest.mark.parametrize('poller_script, search_script, interval, cache_data, cache_set_called, expected_env', [
    pytest.param('script1.py', 'script1.py', 1, 'cd1', True, {'AGENT_POLLER_DATA': 'cd1'}, id="Valid search script"),
    pytest.param('script1.py', 'script2.py', 1, 'cd1', False, {}, id="Invalid search script"),
])
def test_get_poller_env(mocker, poller_script, search_script, interval, cache_data, cache_set_called, expected_env):
    poller_config = {poller_script: interval}
    script_runner_mock = mocker.Mock()
    cache_mock = mocker.Mock()
    cache_mock.get.return_value = CacheEntry(cache_data, 0)
    mocker.patch('agent.poller.time.time', return_value=0)
    poller = Poller(poller_config, script_runner_mock, cache_mock)
    assert poller.get_poller_env_for_script_exec(search_script) == expected_env
    if cache_set_called:
        key = f'{POLLER_EXEC_PREFIX}|{poller_script}'
        cache_mock.set.assert_called_with(key, mocker.ANY, CACHE_TIME_SECS)
    else:
        cache_mock.set.assert_not_called()
