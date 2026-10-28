"""
Infrastructure Agent: Unit tests for agent
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

import builtins
import types

import pytest

import agent.agent as agent_module
from agent.agent import Agent


@pytest.fixture(autouse=True)
def _reset_shutdown_requested():
    agent_module.shutdown_requested = False
    yield
    agent_module.shutdown_requested = False


@pytest.fixture
def cache_manager(mocker):
    cm = mocker.Mock()
    yield cm


@pytest.fixture
def process_manager(mocker):
    pm_mock = mocker.Mock()
    mocker.patch('agent.agent.ProcessManager', return_value=pm_mock)
    yield pm_mock


@pytest.fixture
def agent(cache_manager, agent_config, process_manager) -> Agent:
    ag = Agent(cache_manager, agent_config)
    yield ag


def test_agent_run(agent, mocker):
    mock_gevent = mocker.patch('agent.agent.gevent')
    mock_nrpe = mocker.patch('agent.agent.NRPEListener')
    assert agent.run() == 0
    assert mock_nrpe.called
    assert mock_gevent.joinall.called


@pytest.mark.parametrize('poller, process_manager, script_runner, error', [
    pytest.param(True, True, True, False, id="success_stop_all"),
    pytest.param(True, False, False, False, id="success_stop_poller"),
    pytest.param(False, True, False, False, id="success_stop_process_manager"),
    pytest.param(False, False, True, False, id="success_stop_script_runner"),
    pytest.param(False, False, False, False, id="success_stop_none"),
    pytest.param(True, True, True, True, id="error_stop_all"),
    pytest.param(True, False, False, True, id="error_stop_poller"),
    pytest.param(False, True, False, True, id="error_stop_process_manager"),
    pytest.param(False, False, True, True, id="error_stop_script_runner"),
    pytest.param(False, False, False, True, id="error_stop_none"),
])
def test_agent_stop(poller, process_manager, script_runner, error, agent, mocker):
    mocker.patch('agent.agent.gevent')
    if not poller:
        agent._poller = None
    if not process_manager:
        agent._process_manager = None
    if not script_runner:
        agent._script_runner = None
    agent.stop(error)
    assert agent._terminated_with_error == error
    assert agent._poller is None
    assert agent._process_manager is None
    assert agent._script_runner is None


def test_agent_stop_closes_nrpe_listener(agent, mocker):
    mocker.patch('agent.agent.gevent')
    listener = mocker.Mock()
    agent.nrpe_listener = listener

    agent.stop(False)

    listener.close.assert_called_once()
    assert agent.nrpe_listener is None


def test_agent_stop_continues_when_nrpe_close_fails(agent, mocker):
    mocker.patch('agent.agent.gevent')
    listener = mocker.Mock()
    listener.close.side_effect = RuntimeError('close failed')
    agent.nrpe_listener = listener

    agent.stop(False)

    listener.close.assert_called_once()
    assert agent.nrpe_listener is None
    assert agent._poller is None


@pytest.mark.parametrize(
    'func, error', [
        pytest.param('foo', False, id="success"),
        pytest.param(Exception('bar'), True, id="error"),
    ])
def test_agent_gproxy(func, error, agent, mocker):
    mock_func = mocker.Mock(side_effect=[func], __name__='mock_func')
    agent._gproxy(mock_func)
    assert agent._terminated_with_error == error


def test_agent_run_returns_when_shutdown_already_requested(agent, mocker):
    mock_gevent = mocker.patch('agent.agent.gevent')
    mock_nrpe = mocker.patch('agent.agent.NRPEListener')
    agent_module.shutdown_requested = True

    assert agent.run() == 0

    mock_nrpe.assert_not_called()
    mock_gevent.joinall.assert_not_called()


def test_agent_run_stops_when_sigterm_arrives_during_spawn(agent, mocker):
    mocker.patch('agent.agent.gevent')
    mocker.patch('agent.agent.NRPEListener')

    def _request_stop(*_args, **_kwargs):
        agent_module.shutdown_requested = True
        return mocker.Mock()

    mocker.patch('agent.agent.gevent.spawn', side_effect=_request_stop)

    assert agent.run() == 0
    assert agent._terminated_with_error is False
    assert agent._poller is None


def test_handle_sigterm_stops_without_error_exit(agent, mocker):
    mocker.patch('agent.agent.gevent')
    close = mocker.patch('agent.pkcs11.close_pin_files')

    agent_module.handle_sigterm(agent)

    assert agent_module.shutdown_requested is True
    assert agent._terminated_with_error is False
    close.assert_called_once()


def test_handle_sigterm_before_agent_starts():
    agent_module.handle_sigterm(None)
    assert agent_module.shutdown_requested is True


def test_install_sigterm_handler(mocker):
    import signal

    callback = mocker.Mock()
    signal_handler = mocker.patch('gevent.signal_handler')

    assert agent_module.install_sigterm_handler(callback) is True

    signal_handler.assert_called_once_with(signal.SIGTERM, callback)


def test_install_sigterm_handler_rejects_unsupported_platform(mocker):
    mocker.patch('gevent.signal_handler', side_effect=ValueError('unsupported'))

    assert agent_module.install_sigterm_handler(mocker.Mock()) is False


def test_install_sigterm_handler_without_gevent(mocker):
    real_import = builtins.__import__

    def _import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'gevent':
            raise ImportError('gevent missing')
        return real_import(name, globals, locals, fromlist, level)

    mocker.patch('builtins.__import__', side_effect=_import)

    assert agent_module.install_sigterm_handler(mocker.Mock()) is False


def test_install_sigterm_handler_without_sigterm(mocker):
    mocker.patch.dict('sys.modules', {'signal': types.SimpleNamespace()})

    assert agent_module.install_sigterm_handler(mocker.Mock()) is False


def test_agent_stop_closes_pkcs11_pin_files(agent, mocker):
    mocker.patch('agent.agent.gevent')
    close = mocker.patch('agent.pkcs11.close_pin_files')

    agent.stop(False)

    close.assert_called_once()


def test_agent_stop_logs_pin_cleanup_failure(agent, mocker, caplog):
    mocker.patch('agent.agent.gevent')
    mocker.patch('agent.pkcs11.close_pin_files', side_effect=RuntimeError('cleanup failed'))

    agent.stop(False)

    assert 'PKCS#11 PIN file cleanup failed' in caplog.text


def test_agent_stop_unlinks_pins_when_teardown_raises(agent, mocker):
    mock_gevent = mocker.patch('agent.agent.gevent')
    greenlet = mocker.Mock()
    poller = mocker.Mock()
    agent._greenlets = [greenlet]
    agent._poller = poller
    close = mocker.patch('agent.pkcs11.close_pin_files')
    order = []
    mock_gevent.killall.side_effect = lambda *_args, **_kwargs: order.append('kill')

    def _close_poller():
        order.append('poller')
        raise RuntimeError('poller close failed')

    poller.close.side_effect = _close_poller
    close.side_effect = lambda: order.append('pins')

    with pytest.raises(RuntimeError, match='poller close failed'):
        agent.stop(False)

    assert order == ['kill', 'poller', 'pins']
    mock_gevent.killall.assert_called_once_with([greenlet], block=False)
    assert agent._greenlets == []


def test_agent_stop_keeps_pin_files_when_greenlet_kill_fails(agent, mocker, caplog):
    mock_gevent = mocker.patch('agent.agent.gevent')
    greenlet = mocker.Mock()
    poller = mocker.Mock()
    agent._greenlets = [greenlet]
    agent._poller = poller
    mock_gevent.killall.side_effect = RuntimeError('kill failed')
    close = mocker.patch('agent.pkcs11.close_pin_files')

    agent.stop(False)

    close.assert_not_called()
    poller.close.assert_not_called()
    assert agent._greenlets == [greenlet]
    assert 'Failed to stop agent greenlets' in caplog.text


def test_agent_process_recycler(process_manager, agent, mocker):
    mock_sleep = mocker.patch('agent.agent.gevent.sleep')
    mocker.patch('agent.agent.NRPEListener')
    sleep_result = [None, None, Exception]
    mock_sleep.side_effect = sleep_result
    agent.run()
    assert mock_sleep.call_count == len(sleep_result)
    assert process_manager.recycle_all.call_count == len(sleep_result) - 1
