"""
Infrastructure Agent: Unit tests for config classes and functions.
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""
import os
import pytest
import tempfile
from mock import patch
from pathlib import Path

from agent.config import (
    DEFAULT_USER_CONFIG_CONTENT,
    create_default_user_config_if_required,
    get_config,
    parse_byte_string,
    AbstractConfig,
    CommandConfig,
    ExecutionConfig,
    AgentConfig,
    ConfigurationError,
)

MUL_KB = 1024
MUL_MB = MUL_KB * 1024
MUL_GB = MUL_MB * 1024


@pytest.mark.parametrize(
    'text, expected', [
        (11, 11),
        ('11', 11),
        ('11B', 11),
        ('11 B', 11),
        ('11KB', 11 * MUL_KB),
        ('11 KB', 11 * MUL_KB),
        ('11MB', 11 * MUL_MB),
        ('11 MB', 11 * MUL_MB),
        ('11GB', 11 * MUL_GB),
        ('11 GB', 11 * MUL_GB),
    ])
def test_byte_string_parse(text, expected):
    assert parse_byte_string(text) == expected


@pytest.mark.parametrize(
    'string', [
        pytest.param('11-MB', id="invalid_format"),
        pytest.param('11.2', id="invalid_decimal"),
        pytest.param('foo', id="invalid_number"),
    ])
def test_invalid_format(string):
    with pytest.raises(ValueError):
        parse_byte_string(string)


class PassingConfig(AbstractConfig):

    def __init__(*args, **kwargs):
        pass


class FailingConfig(AbstractConfig):

    NAME = 'failingconfig'

    def __init__(*args, **kwargs):
        raise TypeError("__init__() missing 2 parameters: 'foo' and 'bar'")


class FailingExtra(AbstractConfig):

    NAME = 'failingextra'

    def __init__(*args, **kwargs):
        raise TypeError("__init__() got an unexpected keyword argument 'foo'")


class FailingOther(AbstractConfig):

    def __init__(*args, **kwargs):
        raise TypeError("Failed 'foo'")


@pytest.mark.parametrize(
    'testclass, expected, exception', [
        pytest.param(PassingConfig, PassingConfig, None, id="success"),
        pytest.param(FailingOther, "Failed 'foo'", TypeError, id="failure"),
        pytest.param(
            FailingConfig,
            "Configuration missing from 'failingconfig': 'foo' and 'bar'",
            ConfigurationError, id="failed_configuration"),
        pytest.param(
            FailingExtra,
            "Unexpected configuration in 'failingextra': 'foo'",
            ConfigurationError, id="failed_extra_config"),
    ])
def test_abstractconfig_from_dict(testclass, expected, exception):
    if not exception:
        assert type(testclass.from_dict({})) == expected
    else:
        with pytest.raises(exception) as exp:
            testclass.from_dict({})
        assert expected in str(exp)


@pytest.mark.parametrize(
    'config_dict, expected, exception', [
        pytest.param(
            {'execution_timeout': 42},
            ExecutionConfig(execution_timeout=42, NAME='execution'),
            None,
            id="success"),
        pytest.param(
            {},
            "Configuration missing from 'execution': 'execution_timeout'",
            ConfigurationError,
            id="missing_execution_timeout"),
        pytest.param(
            {'execution_timeout': 42, 'foo': 'bar'},
            "Unexpected configuration in 'execution': 'foo'",
            ConfigurationError,
            id="unexpected_item_in_bagging_area"),
    ])
def test_executionconfig_from_dict(config_dict, expected, exception):
    if not exception:
        assert ExecutionConfig.from_dict(config_dict) == expected
    else:
        with pytest.raises(exception) as exp:
            ExecutionConfig.from_dict(config_dict)
        assert expected in str(exp)


@pytest.mark.parametrize(
    'config_dict, expected, exception', [
        pytest.param(
            {'foo': {'path': 'P'}},
            {'foo': CommandConfig(name='foo', path='P', runtime=None, cache_manager=False, NAME='commands')},
            None,
            id="success"),
        pytest.param(
            {'foo': {'path': 'P', 'runtime': 'R'}},
            {'foo': CommandConfig(name='foo', path='P', runtime='R', cache_manager=False, NAME='commands')},
            None,
            id="success_with_runtime"),
        pytest.param(
            {'foo': {'path': 'P', 'cache_manager': True}},
            {'foo': CommandConfig(name='foo', path='P', runtime=None, cache_manager=True, NAME='commands')},
            None,
            id="success_using_cache_manager"),
        pytest.param(
            {'foo': {'runtime': 'R'}},
            "Missing 'commands' configuration for 'foo', section: 'path'",
            ConfigurationError,
            id="missing_path"),
        pytest.param(
            {'foo': {'path': 'P', 'long_running_key': '$PATH$'}},
            {'foo': CommandConfig(name='foo', path='P', runtime=None, long_running_key='P', use_stdin=True)},
            None,
            id="long_running_key_path"),
        pytest.param(
            {'foo': {'path': 'P', 'long_running_key': '$NAME$'}},
            {'foo': CommandConfig(name='foo', path='P', runtime=None, long_running_key='foo', use_stdin=True)},
            None,
            id="long_running_key_name"),
        pytest.param(
            {'foo': {'path': 'P', 'long_running_key': '$NAME$', 'use_stdin': False}},
            "Long running key 'foo' for command 'foo' cannot have 'use_stdin=false'",
            ConfigurationError,
            id="long_running_key_stdin_err"),
    ])
def test_commandconfig_from_dict(config_dict, expected, exception):
    if not exception:
        assert CommandConfig.from_dict(config_dict) == expected
    else:
        with pytest.raises(exception) as exp:
            CommandConfig.from_dict(config_dict)
        assert expected in str(exp)


@pytest.mark.parametrize('path, expected_parsed_path, expected_max_unique_arg_index', [
    # Valid Config Tests
    pytest.param('/bin/cmd', '/bin/cmd', 0, id="no-args"),
    pytest.param('/bin/cmd $ARG1$', '/bin/cmd {0}', 1, id="one-arg-first"),
    pytest.param('/bin/cmd $ARG1$ $ARG2$', '/bin/cmd {0} {1}', 2, id="two-arg-ordered"),
    pytest.param('/bin/cmd $ARG2$ $ARG1$', '/bin/cmd {1} {0}', 2, id="two-arg-reversed"),
    pytest.param(
        '/bin/cmd $ARG1$ $ARG2$ $ARG3$ $ARG4$ $ARG5$ $ARG6$ $ARG7$ $ARG8$ $ARG9$',
        '/bin/cmd {0} {1} {2} {3} {4} {5} {6} {7} {8}',
        9, id="nine-args-ordered"
    ),
    pytest.param('/bin/cmd $ARG3$', '/bin/cmd {2}', 3, id="one-arg-third"),
    pytest.param('/bin/cmd -a $ARG1$ -b $ARG2$', '/bin/cmd -a {0} -b {1}', 2, id="two-arg-split-up"),
    pytest.param('/bin/cmd -a $ARG2$ -b $ARG1$', '/bin/cmd -a {1} -b {0}', 2, id="two-arg-split-up-reversed"),

    pytest.param('/bin/cmd {test} $ARG1$', '/bin/cmd {{test}} {0}', 1, id="one-arg-curly-brace-text"),

    # Invalid Config Tests
    pytest.param('/bin/cmd $ARG0$', '/bin/cmd $ARG0$', 0, id="one-arg-invalid"),
    pytest.param('/bin/cmd $ARG0$ $ARG1$', '/bin/cmd $ARG0$ {0}', 1, id="two-arg-one-invalid-zero"),
    pytest.param('/bin/cmd $ARGOPSVIEW$ $ARG1$', '/bin/cmd $ARGOPSVIEW$ {0}', 1, id="two-arg-one-invalid-word"),
])
def test_commandconfig_arg_parsing(path, expected_parsed_path, expected_max_unique_arg_index):
    config = CommandConfig(
        name='check_foo', path=path, runtime=None, cache_manager=False,
        stderr=False, long_running_key=None, use_stdin=False
    )
    assert config.path == expected_parsed_path
    assert config.max_unique_arg_index == expected_max_unique_arg_index


@pytest.mark.parametrize(
    'config_dict, expected, exception', [
        pytest.param(
            {}, "Missing configuration section: 'cachemanager'", ConfigurationError,
            id="Missing cachemanager"),
    ])
def test_agentconfig_from_dict(config_dict, expected, exception):
    with pytest.raises(exception) as exp:
        AgentConfig.from_dict(config_dict)
    assert expected in str(exp)


@pytest.mark.parametrize(
    'cfgdir, cm_max_item_size, server_port, expected_version, path, debug_print', [
        pytest.param('simple', 0, 9997, '1.2.3', None, True, id="simple-debug"),
        pytest.param('simple', 0, 9997, '1.2.3', None, False, id="simple"),
        pytest.param('extra', 42, 2112, '1.2.3', '/path/to/item', True, id="extra-debug"),
        pytest.param('extra', 42, 2112, '1.2.3', '/path/to/item', False, id="extra"),
        pytest.param('noversion', 0, 9997, '0.0.0', None, False, id="noversion"),
    ])
def test_get_config(cfgdir, cm_max_item_size, server_port, expected_version, path, debug_print):
    os.environ['AGENT_DUMP_FINAL_CONFIG'] = "y" if debug_print else "n"
    configs = __file__.replace('agent/test_config.py', f'resources/{cfgdir}/foo/bar.py')
    with patch('agent.config.__file__', configs):
        cfg = get_config()
    assert cfg.cachemanager.max_item_size == cm_max_item_size
    assert cfg.server.port == server_port
    assert cfg.version == expected_version
    if path:
        assert cfg.commands['check_item'].path == path
    else:
        assert len(cfg.commands) == 0


@pytest.mark.parametrize(
    'existing_content, expected_content', [
        pytest.param(None, DEFAULT_USER_CONFIG_CONTENT, id="new-config"),
        pytest.param('existing', 'existing', id="existing-config"),
    ])
def test_create_default_user_config(mocker, existing_content: str, expected_content: str):
    with tempfile.TemporaryDirectory() as tmp_dir:
        base_dir = Path(tmp_dir)
        cfg_path = base_dir / 'cfg/custom/agent.yml'
        if existing_content:
            os.makedirs(cfg_path.parent)
            with open(cfg_path, 'w') as f:
                f.write(existing_content)
        mocker.patch('agent.config.get_agent_root', return_value=base_dir)
        should_create_config_file = (existing_content is None)
        assert create_default_user_config_if_required() == should_create_config_file
        assert os.path.isfile(cfg_path)
        with open(cfg_path, 'r') as f:
            assert f.read() == expected_content
