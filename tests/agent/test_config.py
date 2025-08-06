"""
Infrastructure Agent: Unit tests for config classes and functions.
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

import contextlib
import os
from inspect import isclass
from pathlib import Path

import pytest

from agent.config import (
    DEFAULT_USER_CONFIG_CONTENT,
    STARTUP_LOG_REL_PATH,
    AbstractConfig,
    AgentConfig,
    CommandConfig,
    ConfigurationError,
    EnvironmentVariableConfig,
    ExecutionConfig,
    ExecutionStyle,
    ForwarderClientConfig,
    PollerScheduleConfig,
    create_default_user_config_if_required,
    get_config,
    get_startup_log_path,
    parse_byte_string,
)
from tests.conftest import GLOBAL_ENVVAR_CFG

MUL_KB = 1024
MUL_MB = MUL_KB * 1024
MUL_GB = MUL_MB * 1024

PATCH_PREFIX = 'agent.config.'


@pytest.fixture(autouse=True)
def _set_startup_log(mocker):
    mocker.patch(PATCH_PREFIX + 'startup_log', return_value=lambda *args, **kwargs: print(*args, kwargs))


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


@pytest.mark.parametrize('config_dict, expected, exception', [
    pytest.param(
        {'foo': {'path': 'P'}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                environment_variables=GLOBAL_ENVVAR_CFG)
        },
        None,
        id="success"),
    pytest.param(
        {'foo': {'path': 'P', 'runtime': 'R'}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime='R', cache_manager=False,
                environment_variables=GLOBAL_ENVVAR_CFG
            )
        },
        None,
        id="success_with_runtime"),
    pytest.param(
        {'foo': {'path': 'P', 'cache_manager': True}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=True,
                environment_variables=GLOBAL_ENVVAR_CFG
            )
        },
        None,
        id="success_using_cache_manager"),
    pytest.param(
        {'foo': {'runtime': 'R'}},
        "Missing 'commands' configuration for 'foo', section: 'path'",
        ConfigurationError,
        id="missing_path"),
    pytest.param(
        {
            'foo': {
                'path': 'P', 'long_running_key': '$PATH$',
                'execution_style': ExecutionStyle.LONGRUNNING_STDIN_ARGS.value
            }
        },
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None,
                long_running_key='P', execution_style=ExecutionStyle.LONGRUNNING_STDIN_ARGS,
                environment_variables=GLOBAL_ENVVAR_CFG
            )
        },
        None,
        id="long_running_key_path"),
    pytest.param(
        {
            'foo': {
                'path': 'P', 'long_running_key': '$NAME$',
                'execution_style': ExecutionStyle.LONGRUNNING_STDIN_ARGS.value
            }
        },
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None,
                long_running_key='foo', execution_style=ExecutionStyle.LONGRUNNING_STDIN_ARGS,
                environment_variables=GLOBAL_ENVVAR_CFG
            )
        },
        None,
        id="long_running_key_name"),
    pytest.param(
        {'foo': {'path': 'P', 'long_running_key': '$NAME$'}},
        "long_running_key specified for command 'foo' but execution_style is not set to 'LONGRUNNING_STDIN_ARGS'",
        ConfigurationError,
        id="long_running_key_exe_style_err"),
    pytest.param(
        {'foo': {'path': 'P', 'execution_style': ExecutionStyle.LONGRUNNING_STDIN_ARGS.value}},
        "long_running_key not specified for command 'foo' but execution_style is set to 'LONGRUNNING_STDIN_ARGS'",
        ConfigurationError,
        id="exe_style_no_long_running_key_err"),
    pytest.param(
        {'foo': {'path': 'P', 'execution_style': 'bar'}},
        "Invalid execution_style for command 'foo': bar",
        ConfigurationError,
        id="invalid_execution_style"),

    # use_stdin legacy paths
    # No execution_style set
    pytest.param(
        {'foo': {'path': 'P', 'use_stdin': False}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                execution_style=ExecutionStyle.COMMAND_LINE_ARGS,
                environment_variables=GLOBAL_ENVVAR_CFG
            )
        },
        None,
        id="old_use_stdin_false_no_style"),
    pytest.param(
        {'foo': {'path': 'P', 'use_stdin': True}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                execution_style=ExecutionStyle.STDIN_ARGS,
                environment_variables=GLOBAL_ENVVAR_CFG
            )
        },
        None,
        id="old_use_stdin_true_no_style"),

    # COMMAND_LINE_ARGS execution_style set
    pytest.param(
        {'foo': {'use_stdin': True, 'path': 'P', 'execution_style': ExecutionStyle.COMMAND_LINE_ARGS.value}},
        "'use_stdin' is deprecated AND is set to True for command 'foo' with a non-stdin execution_style "
        "(COMMAND_LINE_ARGS). Please only set 'execution_style'.",
        ConfigurationError,
        id="old_use_stdin_true_cmd_style"),

    pytest.param(
        {'foo': {'use_stdin': False, 'path': 'P', 'execution_style': ExecutionStyle.COMMAND_LINE_ARGS.value}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                execution_style=ExecutionStyle.COMMAND_LINE_ARGS,
                environment_variables=GLOBAL_ENVVAR_CFG
            )
        },
        None,
        id="old_use_stdin_false_cmd_style"),

    # STDIN_ARGS execution_style set
    pytest.param(
        {'foo': {'use_stdin': True, 'path': 'P', 'execution_style': ExecutionStyle.STDIN_ARGS.value}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                execution_style=ExecutionStyle.STDIN_ARGS,
                environment_variables=GLOBAL_ENVVAR_CFG
            )
        },
        None,
        id="old_use_stdin_true_stdin_style"),

    pytest.param(
        {'foo': {'use_stdin': False, 'path': 'P', 'execution_style': ExecutionStyle.STDIN_ARGS.value}},
        "'use_stdin' is deprecated AND is set to False for command 'foo' with a stdin execution_style "
        "(STDIN_ARGS). Please only set 'execution_style'.",
        ConfigurationError,
        id="old_use_stdin_false_stdin_style"),

    # LONGRUNNING_STDIN_ARGS execution_style set
    pytest.param(
        {
            'foo': {
                'use_stdin': True, 'path': 'P',
                'long_running_key': '$PATH', 'execution_style': ExecutionStyle.LONGRUNNING_STDIN_ARGS.value,
            }
        },
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                long_running_key='$PATH', execution_style=ExecutionStyle.LONGRUNNING_STDIN_ARGS,
                environment_variables=GLOBAL_ENVVAR_CFG
            )
        },
        None,
        id="old_use_stdin_true_lr_stdin_style"),

    pytest.param(
        {'foo': {'use_stdin': False, 'path': 'P', 'execution_style': ExecutionStyle.LONGRUNNING_STDIN_ARGS.value}},
        "'use_stdin' is deprecated AND is set to False for command 'foo' with a stdin execution_style "
        "(LONGRUNNING_STDIN_ARGS). Please only set 'execution_style'.",
        ConfigurationError,
        id="old_use_stdin_false_lr_stdin_style"),

    # Tests for custom environment variables
    pytest.param(
        {'foo': {'path': 'P', 'environment_variables': None}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                environment_variables=EnvironmentVariableConfig())
        },
        None,
        id="no-envvars"
    ),

    pytest.param(
        {'foo': {'path': 'P', 'environment_variables': {'passthrough': None}}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                environment_variables=EnvironmentVariableConfig(
                    passthrough=[], custom={'C_VAR1': 'strval-override', 'C_VAR2': '222'})
            )
        },
        None,
        id="no-passthrough-vars"
    ),

    pytest.param(
        {'foo': {'path': 'P', 'environment_variables': {'custom': None}}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                environment_variables=EnvironmentVariableConfig(
                    passthrough=['PT_VAR1', 'PT_VAR2'], custom={})
            )
        },
        None,
        id="no-custom-vars"
    ),

    pytest.param(
        {'foo': {'path': 'P', 'environment_variables': {'passthrough': ['A', 'B']}}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                environment_variables=EnvironmentVariableConfig(
                    passthrough=['A', 'B'], custom={'C_VAR1': 'strval-override', 'C_VAR2': '222'})
            )
        },
        None,
        id="override-passthrough"
    ),

    pytest.param(
        {'foo': {'path': 'P', 'environment_variables': {'custom': {'C': 'D'}}}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                environment_variables=EnvironmentVariableConfig(passthrough=['PT_VAR1', 'PT_VAR2'], custom={'C': 'D'}))
        },
        None,
        id="override-custom"
    ),

    pytest.param(
        {'foo': {'path': 'P', 'environment_variables': {'passthrough': ['A', 'B'], 'custom': {'C': 'D'}}}},
        {
            'foo': CommandConfig(
                name='foo', path='P', runtime=None, cache_manager=False,
                environment_variables=EnvironmentVariableConfig(passthrough=['A', 'B'], custom={'C': 'D'}))
        },
        None,
        id="override-passthrough-and-custom"
    ),

])
def test_commandconfig_from_dict(config_dict, expected, exception, agent_config):
    with pytest.raises(exception) if exception else contextlib.nullcontext() as e:
        assert CommandConfig.from_dict(config_dict, agent_config.environment_variables) == expected
    if exception:
        assert expected in str(e)


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
        stderr=False, long_running_key=None
    )
    assert config.path == expected_parsed_path
    assert config.max_unique_arg_index == expected_max_unique_arg_index


@pytest.mark.parametrize(
    'config_dict, expected, exception', [
        pytest.param(
            {}, "Missing configuration section: 'environment_variables'", ConfigurationError,
            id="missing-environment_variables"),
        pytest.param(
            {'environment_variables': {}}, "Missing configuration section: 'commands'", ConfigurationError,
            id="missing-cachemanager"),
        pytest.param(
            {'commands': {}, 'environment_variables': {}},
            "Missing configuration section: 'cachemanager'", ConfigurationError,
            id="missing-cachemanager"),
        pytest.param(
            {
                'commands': {},
                'environment_variables': {},
                'cachemanager': {
                    'host': 'foo.com', 'port': 12345, 'housekeeping_interval': 42, 'timestamp_error_margin': 99,
                    'max_cache_size': 2112, 'max_item_size': '123B',
                },
                'execution': {'execution_timeout': 42},
                'logging': {},
                'poller_schedule': {},
                'server': {
                    'allowed_hosts': [], 'max_queued_connections': 10, 'max_active_connections': 12, 'port': 9876,
                    'tls_enabled': False, 'tls_handshake_timeout': 60, 'tls': {}, 'max_request_time': 99,
                    'receive_data_timeout': 30, 'housekeeping_interval': 1800, 'allow_multi_packet_response': True,
                },
                'forwarders': {},
                'version': 99,
                'windows_run_times': {},
                'process_recycle_time': {},
            },
            '', None,
            id="success"),
        pytest.param(
            {
                'commands': {
                    'fee': {
                        'path': 'P',
                        'environment_variables': {'passthrough': ['A', 'B'], 'custom': {'C': 'D'}}
                    },
                    'fie': {
                        'path': 'P',
                        'environment_variables': {'passthrough': ['A', 'B'], 'custom': {'C': 'D'}}
                    },
                    'foo': {
                        'path': 'P',
                        'environment_variables': {'passthrough': ['A', 'B'], 'custom': {'C': 'D'}}
                    },
                },
                'environment_variables': {},
                'cachemanager': {
                    'host': 'foo.com', 'port': 12345, 'housekeeping_interval': 42, 'timestamp_error_margin': 99,
                    'max_cache_size': 2112, 'max_item_size': '123B',
                },
                'execution': {'execution_timeout': 42},
                'logging': {},
                'poller_schedule': {},
                'server': {
                    'allowed_hosts': [], 'max_queued_connections': 10, 'max_active_connections': 12, 'port': 9876,
                    'tls_enabled': False, 'tls_handshake_timeout': 60, 'tls': {}, 'max_request_time': 99,
                    'receive_data_timeout': 30, 'housekeeping_interval': 1800, 'allow_multi_packet_response': True,
                },
                'forwarders': {},
                'version': 99,
                'windows_run_times': {},
                'process_recycle_time': {},
            },
            '', None,
            id="success_with_commands"),
        pytest.param(
            {
                'commands': {
                    'fee': {
                        'path': 'P',
                        'environment_variables': {'passthrough': ['A', 'B'], 'custom': {'C': 'D'}}
                    },
                    'feE': {
                        'path': 'P',
                        'environment_variables': {'passthrough': ['A', 'B'], 'custom': {'C': 'D'}}
                    },
                    'FEe': {
                        'path': 'P',
                        'environment_variables': {'passthrough': ['A', 'B'], 'custom': {'C': 'D'}}
                    },
                },
                'environment_variables': {},
                'cachemanager': {
                    'host': 'foo.com', 'port': 12345, 'housekeeping_interval': 42, 'timestamp_error_margin': 99,
                    'max_cache_size': 2112, 'max_item_size': '123B',
                },
                'execution': {'execution_timeout': 42},
                'logging': {},
                'poller_schedule': {},
                'server': {
                    'allowed_hosts': [], 'max_queued_connections': 10, 'max_active_connections': 12, 'port': 9876,
                    'tls_enabled': False, 'tls_handshake_timeout': 60, 'tls': {}, 'max_request_time': 99,
                    'receive_data_timeout': 30, 'housekeeping_interval': 1800, 'allow_multi_packet_response': True,
                },
                'forwarders': {},
                'version': 99,
                'windows_run_times': {},
                'process_recycle_time': {},
            },
            '', None,
            id="success_with_case_sensitive_commands"),
    ])
def test_agentconfig_from_dict(config_dict, expected, exception):
    if exception:
        with pytest.raises(exception) as exp:
            AgentConfig.from_dict(config_dict)
        assert expected in str(exp)
    else:
        AgentConfig.from_dict(config_dict)


@pytest.mark.parametrize(
    'cfgdir, cm_max_item_size, server_port, expected_version, path, debug_print', [
        pytest.param('simple', 0, 9997, '1.2.3', None, True, id="simple-debug"),
        pytest.param('simple', 0, 9997, '1.2.3', None, False, id="simple"),
        pytest.param('extra', 42, 2112, '1.2.3', '/path/to/item', True, id="extra-debug"),
        pytest.param('extra', 42, 2112, '1.2.3', '/path/to/item', False, id="extra"),
        pytest.param('noversion', 0, 9997, '0.0.0', None, False, id="noversion"),
    ])
def test_get_config(cfgdir, cm_max_item_size, server_port, expected_version, path, debug_print, mocker):
    os.environ['AGENT_DUMP_FINAL_CONFIG'] = "y" if debug_print else "n"
    configs = __file__.replace('agent/test_config.py', f'resources/{cfgdir}/foo/bar.py')
    mocker.patch(PATCH_PREFIX + '__file__', configs)
    cfg = get_config(logger=mocker.Mock())

    assert cfg.cachemanager.max_item_size == cm_max_item_size
    assert cfg.server.port == server_port
    assert cfg.version == expected_version
    if path:
        assert cfg.commands['check_item'].path == path
    else:
        assert len(cfg.commands) == 0


def test_get_startup_log_path():
    assert STARTUP_LOG_REL_PATH in str(get_startup_log_path())


@pytest.mark.parametrize(
    'existing_content, expected_content', [
        pytest.param(None, DEFAULT_USER_CONFIG_CONTENT, id="new-config"),
        pytest.param('existing', 'existing', id="existing-config"),
    ])
def test_create_default_user_config(mocker, existing_content: str, expected_content: str, tmp_path: Path):
    cfg_path = tmp_path / 'cfg/custom/agent.yml'

    if existing_content:
        cfg_path.parent.mkdir(parents=True)
        with cfg_path.open('w') as f:
            f.write(existing_content)

    mocker.patch(PATCH_PREFIX + 'get_agent_root', return_value=tmp_path)
    should_create_config_file = (existing_content is None)
    assert create_default_user_config_if_required() == should_create_config_file
    assert cfg_path.is_file()
    with cfg_path.open('r') as f:
        assert f.read() == expected_content


@pytest.mark.parametrize('passthrough, custom, expected', [
    pytest.param([], {}, EnvironmentVariableConfig([], {}), id='empty-cfg'),
    pytest.param(['a', 'b'], {}, EnvironmentVariableConfig(['a', 'b'], {}), id='just-pt'),
    pytest.param([], {'c': 'd'}, EnvironmentVariableConfig([], {'c': 'd'}), id='just-custom'),
    pytest.param(["707"], {}, ConfigurationError, id='integer-pt'),
    pytest.param(["7.07"], {}, ConfigurationError, id='decimal-pt'),
    pytest.param([707], {}, ConfigurationError, id='raw-integer-pt'),
    pytest.param([7.07], {}, ConfigurationError, id='raw-decimal-pt'),

    pytest.param([], {"7": 'd'}, ConfigurationError, id='integer-custom-key'),
    pytest.param([], {"7.07": 'd'}, ConfigurationError, id='decimal-custom-key'),
    pytest.param([], {7: 'd'}, ConfigurationError, id='raw-integer-custom-key'),
    pytest.param([], {7.07: 'd'}, ConfigurationError, id='raw-decimal-custom-key'),
])
def test_environment_variable_config_validation(passthrough, custom, expected):
    if isclass(expected) and issubclass(expected, Exception):
        exception_context = pytest.raises(expected)
    else:
        exception_context = contextlib.nullcontext()

    with exception_context:
        cfg = EnvironmentVariableConfig(passthrough=passthrough, custom=custom)
        assert cfg == expected


@pytest.mark.parametrize('idle_timeout, exception', [
    pytest.param(ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS + 1, None, id="success"),
    pytest.param(ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS, None, id="success"),
    pytest.param(ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS - 1, ConfigurationError, id="failure"),
])
def test_forwarder_client_config(idle_timeout, exception):
    if not exception:
        ForwarderClientConfig(host='host', port=99, tls_enabled=False, idle_timeout=idle_timeout)
    else:
        with pytest.raises(exception):
            ForwarderClientConfig(host='host', port=99, tls_enabled=False, idle_timeout=idle_timeout)


@pytest.mark.parametrize('config, count', [
    pytest.param({}, 0, id="no_items"),
    pytest.param({'scriptfoo': 'data'}, 1, id="old_style"),
    pytest.param(
        {
            'script1': {'interval': 2, 'forwarder': 'fwd', 'hostname': 'host', 'servicecheckname': 'scn'},
            'script2': {'interval': 5},
        },
        2, id="many_items"),
    pytest.param(
        {
            'script1': {'interval': 2, 'forwarder': 'fwd', 'hostname': 'host', 'servicecheckname': 'scn'},
            'script2': {'interval': 5},
            'scriptfoo': 'data',
        },
        3, id="mix_and_match"),
])
def test_poller_schedule_config(config, count):
    psc = PollerScheduleConfig.from_dict(config)
    assert len(psc) == count
