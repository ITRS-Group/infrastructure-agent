"""
Infrastructure Agent: Unit tests for agent
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

import pytest
from agent.agent import Agent


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


@pytest.mark.parametrize(
    'func, error', [
        pytest.param('foo', False, id="success"),
        pytest.param(Exception('bar'), True, id="error"),
    ])
def test_agent_gproxy(func, error, agent, mocker):
    mock_func = mocker.Mock(side_effect=[func], __name__='mock_func')
    agent._gproxy(mock_func)
    assert agent._terminated_with_error == error


def test_agent_process_recycler(process_manager, agent, mocker):
    mock_sleep = mocker.patch('agent.agent.gevent.sleep')
    mocker.patch('agent.agent.NRPEListener')
    sleep_result = [None, None, Exception]
    mock_sleep.side_effect = sleep_result
    agent.run()
    assert mock_sleep.call_count == len(sleep_result)
    assert process_manager.recycle_all.call_count == len(sleep_result) - 1
