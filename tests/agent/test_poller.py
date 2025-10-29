"""
Infrastructure Agent: Unit tests for Poller
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""
import gevent
import mock
import pytest
from cache.expirycache import CacheEntry
from agent.config import ConfigurationError, PollerScheduleConfig
from agent.poller import (
    Poller,
    POLLER_EXEC_PREFIX,
    CACHE_TIME_SECS,
    POLLER_EXEC_NORMAL,
    POLLER_EXEC_CALLED,
)

PATCH_PREFIX = 'agent.poller.'


class BreakException(Exception):
    pass


greenlet_error_log = []


def spawn_side_effect(*args):
    """A gevent side effect to directly call the spawned function"""
    fn = args[0]
    try:
        fn(*args[1:])
    except Exception as e:
        # Capture the error in a log for testing purposes
        greenlet_error_log.append(str(e))


@pytest.fixture
def empty_poller(mocker) -> Poller:
    mocker.patch(PATCH_PREFIX + 'time.time', return_value=0)
    yield Poller({}, mocker.Mock(), mocker.Mock(), mocker.Mock(**{'values.return_value': []}))


def test_poller_run_with_no_pollers(empty_poller, caplog):
    empty_poller.run()
    assert 'No pollers scheduled' in caplog.text


@pytest.mark.parametrize('script, interval, cache_data, executed, exit_code, arguments, expected_env', [
    pytest.param(
        'script1.py', 1, 'cd1', False, 0, [],
        {'AGENT_POLLER_EXEC': POLLER_EXEC_NORMAL, 'AGENT_POLLER_DATA': 'cd1', 'POLLER_INTERVAL': '1'},
        id="Normal schedule after 1 second"
    ),
    pytest.param(
        'script1.py', 0, 'cd1', False, 0, [],
        {'AGENT_POLLER_EXEC': POLLER_EXEC_NORMAL, 'AGENT_POLLER_DATA': 'cd1', 'POLLER_INTERVAL': '0'},
        id="Instant schedule"
    ),
    pytest.param(
        'script1.py', 1, 'cd2', True, 0, [],
        {'AGENT_POLLER_EXEC': POLLER_EXEC_CALLED, 'AGENT_POLLER_DATA': 'cd2', 'POLLER_INTERVAL': '1'},
        id="Plugin called"
    ),
    pytest.param(
        'script1.py', 1, 'cd1', False, 1, [],
        {'AGENT_POLLER_EXEC': POLLER_EXEC_NORMAL, 'AGENT_POLLER_DATA': 'cd1', 'POLLER_INTERVAL': '1'},
        id="Script error"
    ),
])
def test_poller_run(mocker, script, interval, cache_data, executed, exit_code, arguments, expected_env, caplog):
    poller_config = {script: PollerScheduleConfig(script, interval)}
    script_runner_mock = mocker.Mock()
    cache_mock = mocker.Mock()
    gevent_mock, event_mock = _patch_poller(mocker, time_now=0)
    clients = {}
    poller = Poller(poller_config, script_runner_mock, cache_mock, clients)

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
        event_mock.wait.assert_called_with(interval)
    else:
        gevent_mock.assert_not_called()
    script_runner_mock.run_script.assert_called_with(script, arguments, expected_env)
    if exit_code:
        assert 'Error code 1' in caplog.text
    else:
        assert 'ERROR' not in caplog.text


@pytest.mark.parametrize('config, exec_slots, now, waiter, logexp', [
    pytest.param(None, None, range(10), [], 'No pollers scheduled', id="no_config"),
    pytest.param(mock.Mock(), {}, range(10), [{}, {2: ['fee']}, {}], '', id="nothing_scheduled_initially"),
    pytest.param(
        mock.Mock(), {1: ['s1'], 1.1: ['s2', 's3'], 1.2: ['s4', 's5']}, range(2, 12), [{}, {}, {}], '',
        id="scheduled_pollers"),
])
def test_poller_run_unit(config, exec_slots, now, waiter, logexp, mocker, empty_poller, caplog):
    poller = empty_poller
    poller._poller_config = config
    poller._exec_slots = None if exec_slots is None else exec_slots.copy()
    mocker.patch.object(poller, '_schedule_all_pollers')

    def _wait(_wait_time):
        retval = 0 if poller._exec_slots else 1
        data = waiter.pop()
        poller._exec_slots.update(data)
        return retval

    waiter.reverse()
    mock_waiter = mocker.patch.object(poller, '_waiter')
    mock_waiter.wait.side_effect = _wait

    iterations = 0 if exec_slots is None else sum([len(x) for x in exec_slots.values()])
    mock_spawn = mocker.patch(PATCH_PREFIX + 'gevent.spawn', side_effect=([None] * (iterations - 1) + [StopIteration]))
    mocker.patch(PATCH_PREFIX + 'time.time', side_effect=now)

    if not config:
        poller.run()
    else:
        with pytest.raises(StopIteration):
            poller.run()

    if exec_slots is not None:
        n = 0
        for next_slot, scripts in exec_slots.items():
            for script in scripts:
                assert mock_spawn.call_args_list[n][0][2] == script
                assert mock_spawn.call_args_list[n][0][3] == next_slot
                n += 1
        assert n == iterations
    assert logexp in caplog.text


def test_poller_script_failure(mocker, caplog):
    poller_config = _dict_to_poller_config({'script1.py': 1})
    script_runner_mock = mocker.Mock()
    bad_exception_text = "Something bad"
    script_runner_mock.run_script.side_effect = Exception(bad_exception_text)
    _patch_poller(mocker)
    poller = Poller(poller_config, script_runner_mock, mocker.Mock(), {})
    gevent_mock = mocker.patch(PATCH_PREFIX + 'gevent')
    gevent_mock.spawn.side_effect = spawn_side_effect
    with pytest.raises(BreakException):
        poller.run()
    assert bad_exception_text in caplog.text


@pytest.mark.parametrize('config_dict, loops, exec_calls, sleep_calls', [
    pytest.param(
        {'script1.py': 2},
        4,
        ['script1.py', 'script1.py', 'script1.py', 'script1.py'],
        [1, 3, 5, 7],
        id="Single script every 2s"
    ),
    pytest.param(
        {'script1.py': 2, 'script2.py': 3},
        4,
        ['script1.py', 'script2.py', 'script1.py', 'script2.py', 'script1.py'],
        [1, 2, 3, 5],
        id="Multiple overlapping scripts"
    ),
])
def test_poller_multiple_loops(mocker, config_dict, loops, exec_calls, sleep_calls):
    script_runner_mock = mocker.Mock()
    script_runner_mock.run_script.return_value = [0, '', '', False]
    poller_config = _dict_to_poller_config(config_dict)
    _, event_mock = _patch_poller(mocker, loops=loops)

    poller = Poller(poller_config, script_runner_mock, mocker.Mock(), {})
    with pytest.raises(BreakException):
        poller.run()

    script_calls = [mock.call(s, [], mocker.ANY) for s in exec_calls]
    script_runner_mock.run_script.assert_has_calls(script_calls)
    event_mock.wait.assert_has_calls([mock.call(s) for s in sleep_calls])


def test_get_poller_env_no_config(empty_poller):
    assert empty_poller.get_poller_env_for_script_exec('script1.py') == {}


@pytest.mark.parametrize('poller_script, search_script, interval, cache_data, cache_set_called, expected_env', [
    pytest.param(
        'script1.py', 'script1.py', 1, 'cd1', True,
        {'AGENT_POLLER_DATA': 'cd1', 'POLLER_INTERVAL': '1'},
        id="Valid search script"
    ),
    pytest.param('script1.py', 'script2.py', 1, 'cd1', False, {}, id="Invalid search script"),
])
def test_get_poller_env(mocker, poller_script, search_script, interval, cache_data, cache_set_called, expected_env):
    poller_config = _dict_to_poller_config({poller_script: interval})
    script_runner_mock = mocker.Mock()
    cache_mock = mocker.Mock()
    cache_mock.get.return_value = CacheEntry(cache_data, 0)
    _patch_poller(mocker)

    poller = Poller(poller_config, script_runner_mock, cache_mock, {})
    assert poller.get_poller_env_for_script_exec(search_script) == expected_env
    if cache_set_called:
        key = f'{POLLER_EXEC_PREFIX}|{poller_script}'
        cache_mock.set.assert_called_with(key, mocker.ANY, CACHE_TIME_SECS)
    else:
        cache_mock.set.assert_not_called()


def _dict_to_poller_config(config_dict: dict[str, int]) -> dict[str, PollerScheduleConfig]:
    """Helper function to convert a dictionary of script names and intervals to PollerScheduleConfig objects."""
    return {script: PollerScheduleConfig(script, interval) for script, interval in config_dict.items()}


def test_poller_forwarder_missing_client(mocker):
    """Test that the Poller validates forwarder clients."""
    poller_config = {
        'script1.py': PollerScheduleConfig('script1.py', 1, forwarder='forwarder1'),
    }
    err_text = "Forwarder client 'forwarder1' is not defined in the configuration"
    with pytest.raises(ConfigurationError, match=err_text):
        Poller(poller_config, mocker.Mock(), mocker.Mock(), {})


@pytest.mark.parametrize('hostname, servicecheckname, exit_code, stdout, stderr, expected', [
    pytest.param('host1', 'service1', 0, 'Normal output from script', '', 'Normal output from script'),
    pytest.param('host2', 'service2', 2, 'Some output', 'Some error', 'Some output ; Some error'),
    pytest.param('host2', 'service2', 2, 'Some output | data', 'Some error', 'Some output ; Some error | data'),
])
def test_poller_forwarding(mocker, hostname, servicecheckname, exit_code, stdout, stderr, expected):
    """Test that the Poller correctly forwards execution to a client."""
    time_logged = 0
    script_runner_mock = mocker.Mock()
    script_runner_mock.run_script.return_value = [exit_code, stdout, stderr, False]
    forwarder_client_name = 'forwarder1'
    poller_config = {
        'script1.py': PollerScheduleConfig(
            'script1.py',
            1,
            forwarder=forwarder_client_name,
            hostname=hostname,
            servicecheckname=servicecheckname,
        ),
    }
    client_mock = mocker.Mock()
    clients = {forwarder_client_name: client_mock}
    _patch_poller(mocker)
    poller = Poller(poller_config, script_runner_mock, mocker.Mock(), clients)
    with pytest.raises(BreakException):
        poller.run()
    client_mock.queue_result.assert_called_once_with(
        hostname, servicecheckname, exit_code, expected, time_logged
    )


@pytest.mark.parametrize('launch_script, clients', [
    pytest.param(False, {}),
    pytest.param(True, {'client1': mock.Mock()}),
])
def test_poller_close(mocker, launch_script, clients):
    poller_config = _dict_to_poller_config({'script1.py': 1})
    script_runner_mock = mocker.Mock()
    script_runner_mock.run_script.return_value = [0, '', '', False]
    _patch_poller(mocker)
    poller = Poller(poller_config, script_runner_mock, mocker.Mock(), clients)
    gevent.spawn(poller.run)
    if launch_script:
        gevent.sleep(0)  # Allow time for the script to start
    poller.close()


def test_poller_script_greenlet_fail(mocker, caplog):
    """Test that the Poller can handle script execution greenlet failing."""
    poller_config = _dict_to_poller_config({'script1.py': 1})
    script_runner_mock = mocker.Mock()
    script_runner_mock.run_script.return_value = [0, '', '', False]
    _, event_mock = _patch_poller(mocker)
    error_text = "Simulated execption in greenlet"
    event_mock.set.side_effect = Exception(error_text)
    poller = Poller(poller_config, script_runner_mock, mocker.Mock(), {})

    greenlet_error_log.clear()  # Clear any previous captured errors
    with pytest.raises(BreakException):
        poller.run()
    assert len(greenlet_error_log) == 1
    assert error_text in greenlet_error_log[0]


def _patch_poller(mocker, loops=1, time_now=0):
    """Helper function to patch the Poller for testing."""

    # Patch time to control the current time
    mocker.patch(PATCH_PREFIX + 'time.time', return_value=time_now)

    # This is a bit of a hack, but it allows us to control the number of loops in Poller.run()
    event_mock = mocker.patch(PATCH_PREFIX + 'Event').return_value
    event_mock.clear.side_effect = [None] * loops + [BreakException]
    event_mock.wait.return_value = 0

    # Patch gevent.spawn to directly call the function instead of spawning a greenlet
    gevent_mock = mocker.patch(PATCH_PREFIX + 'gevent')
    gevent_mock.spawn.side_effect = spawn_side_effect

    return gevent_mock, event_mock
