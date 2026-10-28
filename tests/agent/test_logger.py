"""
Infrastructure Agent: Unit tests for logger
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from mock import call

import agent.logger
from agent.config import ConfigurationError


@pytest.fixture(autouse=True)
def patch_logger(mocker):
    yield mocker.patch('agent.logger.logger')


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


def test_init_logging_reconfigures_loggers_created_before_configuration(tmp_path):
    """A logger created before init_logging still writes to the configured file.

    Runs in a subprocess so dictConfig does not change logger levels for the
    rest of the suite.
    """
    log_path = tmp_path / 'agent.log'
    script = """
import logging
import agent.logger

log_path = %r
early = logging.getLogger('nrpe.server')
agent.logger.init_logging({'handlers': {'file': {'filename': log_path}}})
early.warning("Connection rejected: host 'example'")
text = open(log_path, encoding='utf-8').read()
if "Connection rejected: host 'example'" not in text:
    raise SystemExit('expected warning was not written to ' + log_path)
""" % str(log_path)
    env = os.environ.copy()
    src_root = Path(__file__).resolve().parents[2]
    env['PYTHONPATH'] = os.pathsep.join(filter(None, (str(src_root), env.get('PYTHONPATH'))))
    completed = subprocess.run(
        [sys.executable, '-c', script],
        cwd=str(src_root),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


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
def test_logger_log_dict(data, expected, patch_logger):
    agent.logger.log_dict(99, data, 'foo')
    assert patch_logger.log.call_args_list == expected


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
def test_logger_log_object_attr(data, expected, patch_logger):
    agent.logger.log_object_attr(42, data, 'bar')
    for callarg in expected:
        assert callarg in patch_logger.log.call_args_list
