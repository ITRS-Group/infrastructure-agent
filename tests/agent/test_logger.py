"""
Infrastructure Agent: Unit tests for logger
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""

import pytest
from mock import call

import agent.logger
from agent.config import ConfigurationError


@pytest.fixture(autouse=True)
def patch_logger(mocker):
    mocker.patch('agent.logger.logger')


@pytest.mark.parametrize(
    'config, exception', [
        pytest.param({}, None, id="no_extra_config"),
        pytest.param({'handlers': {'file': {'filename': '/tmp/foo'}}}, None, id="log_filename"),
        pytest.param({'handlers': {'scoobydoo': {}}}, ConfigurationError, id="invalid_handler"),
        pytest.param({'handlers': None}, ConfigurationError, id="empty_handler"),
    ])
def test_logger_init_logging(config, exception, mocker):
    mocker.patch('logging.config')
    if not exception:
        agent.logger.init_logging(config)
    else:
        with pytest.raises(exception):
            agent.logger.init_logging(config)


@pytest.mark.parametrize(
    'data, expected', [
        pytest.param({}, [call(99, 'foo')], id="empty"),
        pytest.param(
            {1: 'one', 2: 'two', 3: 'three'},
            [
                call(99, 'foo'),
                call(99, '%s%s: %s', '├─ ', 1, 'one'),
                call(99, '%s%s: %s', '├─ ', 2, 'two'),
                call(99, '%s%s: %s', '└─ ', 3, 'three'),
            ],
            id="one_level",
        ),
    ])
def test_logger_log_dict(data, expected):
    agent.logger.log_dict(99, data, 'foo')
    assert agent.logger.logger.log.call_args_list == expected


class X:
    pass


@pytest.mark.parametrize(
    'data, expected', [
        pytest.param(
            X(),
            [
                call(42, 'bar'),
                call(42, '%s%s: %s', '├─ ', '__doc__', None),
                call(42, '%s%s: %s', '└─ ', '__weakref__', None),
            ],
            id="simple_object",
        ),
    ])
def test_logger_log_object_attr(data, expected):
    agent.logger.log_object_attr(42, data, 'bar')
    for callarg in expected:
        assert callarg in agent.logger.logger.log.call_args_list
