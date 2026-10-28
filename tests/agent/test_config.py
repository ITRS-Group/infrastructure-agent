"""
Infrastructure Agent: Unit tests for config classes and functions.
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
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
    CacheManagerConfig,
    CommandConfig,
    ConfigurationError,
    EnvironmentVariableConfig,
    ExecutionConfig,
    ExecutionStyle,
    ForwarderClientConfig,
    PollerScheduleConfig,
    PYTHON_SSL_DEFAULT_CIPHER_SUITE,
    PYTHON_SSL_DEFAULT_CONTEXT_OPTIONS,
    ServerConfig,
    TLSConfig,
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


def test_tls_config_pkcs12_rejected():
    with pytest.raises(ConfigurationError, match="Unexpected configuration in 'tls': 'p12_path'"):
        TLSConfig.from_dict({'p12_path': 'identity.p12'})


def test_tls_config_key_passphrase_ok():
    cfg = TLSConfig(
        cert_file='cert.pem',
        key_file='key.pem',
        key_passphrase='secret',
    )
    assert cfg.key_passphrase == 'secret'
    assert 'secret' not in repr(cfg)


def test_tls_config_key_passphrase_requires_pem_identity():
    with pytest.raises(ConfigurationError, match="must set 'cert_file' or 'key_file'"):
        TLSConfig(key_passphrase='secret')


@pytest.mark.parametrize('key_passphrase', [1234, True])
def test_tls_config_key_passphrase_rejects_unquoted_scalar(key_passphrase):
    with pytest.raises(ConfigurationError, match="TLS config 'key_passphrase' must be a string"):
        TLSConfig(cert_file='cert.pem', key_file='key.pem', key_passphrase=key_passphrase)


def test_tls_config_key_passphrase_from_dict_rejects_numeric_passphrase():
    with pytest.raises(ConfigurationError, match="TLS config 'key_passphrase' must be a string"):
        TLSConfig.from_dict({
            'cert_file': 'cert.pem',
            'key_file': 'key.pem',
            'key_passphrase': 1234,
        })


def test_tls_config_key_passphrase_strips_whitespace():
    cfg = TLSConfig(cert_file='cert.pem', key_file='key.pem', key_passphrase='  secret  ')
    assert cfg.key_passphrase == 'secret'


def test_tls_config_pkcs11_ignores_leftover_key_passphrase(monkeypatch):
    messages = []
    monkeypatch.setattr(
        'agent.config.startup_log',
        lambda message, prefix='[INFO]': messages.append(f'{prefix} {message}'),
    )
    cfg = TLSConfig.from_dict(section='server', config={
        'connector': 'pkcs11',
        'key_passphrase': 'secret',
        'pkcs11': {
            'module_path': 'token.so',
            'identity_key': {'uri': 'pkcs11:object=key'},
            'identity_cert': {'uri': 'pkcs11:object=cert'},
        },
    })
    assert cfg.key_passphrase is None
    assert any(
        line.startswith('[WARNING] Ignoring leftover TLS file options') and 'key_passphrase' in line
        for line in messages
    )


@pytest.mark.parametrize('connector', ['pkcs11', 'schannel'])
@pytest.mark.parametrize('key_passphrase', [1234, True])
def test_tls_config_unquoted_key_passphrase_rejected_before_leftover_clear(connector, key_passphrase):
    config = {'connector': connector, 'key_passphrase': key_passphrase}
    if connector == 'pkcs11':
        config['pkcs11'] = {
            'module_path': 'token.so',
            'identity_key': {'uri': 'pkcs11:object=key'},
            'identity_cert': {'uri': 'pkcs11:object=cert'},
        }
    else:
        config['schannel'] = {'identity_cert_name': 'host'}
    with pytest.raises(ConfigurationError, match="TLS config 'key_passphrase' must be a string"):
        TLSConfig.from_dict(section='server', config=config)


def test_tls_config_pkcs11_xor_cert_sources():
    with pytest.raises(ConfigurationError, match='only one of pkcs11.identity_cert'):
        TLSConfig(
            connector='pkcs11',
            pkcs11_module='token.so',
            pkcs11_key_uri='pkcs11:object=key',
            pkcs11_cert_uri='pkcs11:object=cert',
            cert_file='cert.pem',
        )


def test_tls_config_pkcs11_requires_module():
    with pytest.raises(ConfigurationError, match='pkcs11.module_path'):
        TLSConfig(
            connector='pkcs11',
            pkcs11_key_uri='pkcs11:object=key',
            pkcs11_cert_uri='pkcs11:object=cert',
        )


def test_tls_config_pkcs11_requires_pkcs11_uri_scheme():
    with pytest.raises(ConfigurationError, match="must start with 'pkcs11:'"):
        TLSConfig(
            connector='pkcs11',
            pkcs11_module='token.so',
            pkcs11_key_uri='file:/tmp/key.pem',
            pkcs11_cert_uri='pkcs11:object=cert',
        )


def test_tls_config_pkcs11_rejects_numeric_pin():
    with pytest.raises(ConfigurationError, match="must be a string"):
        TLSConfig(
            connector='pkcs11',
            pkcs11_module='token.so',
            pkcs11_key_uri='pkcs11:object=key',
            pkcs11_cert_uri='pkcs11:object=cert',
            pkcs11_key_pin=1234,
        )


def test_tls_config_pkcs11_from_dict_rejects_numeric_pin():
    with pytest.raises(ConfigurationError, match="pkcs11.identity_key.pin"):
        TLSConfig.from_dict(section='server', config={
            'connector': 'pkcs11',
            'pkcs11': {
                'module_path': 'token.so',
                'identity_key': {'uri': 'pkcs11:object=key', 'pin': 1234},
                'identity_cert': {'uri': 'pkcs11:object=cert'},
            },
        })


def test_tls_config_pkcs11_from_dict_rejects_numeric_cert_pin():
    with pytest.raises(ConfigurationError, match="pkcs11.identity_cert.pin"):
        TLSConfig.from_dict(section='server', config={
            'connector': 'pkcs11',
            'pkcs11': {
                'module_path': 'token.so',
                'identity_key': {'uri': 'pkcs11:object=key'},
                'identity_cert': {'uri': 'pkcs11:object=cert', 'pin': 5678},
            },
        })


def test_tls_config_pkcs11_ok():
    cfg = TLSConfig(
        connector='pkcs11',
        cert_file='cert.pem',
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key',
        pkcs11_key_pin='1234',
    )
    assert cfg.pkcs11_module == 'token.so'
    assert cfg.pkcs11_key_uri == 'pkcs11:object=key'
    assert cfg.pkcs11_key_pin == '1234'
    assert cfg.cert_file == 'cert.pem'
    assert cfg.ca_cert == 'system'
    assert '1234' not in repr(cfg)


def test_tls_config_secrets_omitted_from_repr():
    cfg = TLSConfig(
        connector='pkcs11',
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key',
        pkcs11_cert_uri='pkcs11:object=cert',
        pkcs11_key_pin='pin-secret',
        pkcs11_cert_pin='cert-secret',
    )
    assert 'pin-secret' not in repr(cfg)
    assert 'cert-secret' not in repr(cfg)


def test_tls_config_key_passphrase_omitted_from_repr():
    cfg = TLSConfig(
        cert_file='cert.pem',
        key_file='key.pem',
        key_passphrase='pem-secret',
    )
    assert 'pem-secret' not in repr(cfg)


def test_tls_config_pkcs11_engine_rejected():
    with pytest.raises(ConfigurationError, match="Unexpected configuration in 'tls': 'pkcs11_engine'"):
        TLSConfig.from_dict(section='server', config={
            'connector': 'pkcs11',
            'pkcs11_engine': 'pkcs11.so',
            'pkcs11': {
                'module_path': 'token.so',
                'identity_key': {'uri': 'pkcs11:object=key'},
                'identity_cert': {'uri': 'pkcs11:object=cert'},
            },
        })


def test_tls_config_pkcs11_from_dict_nested():
    cfg = TLSConfig.from_dict(section='server', config={
        'connector': 'pkcs11',
        'pkcs11': {
            'module_path': 'token.so',
            'identity_key': {'uri': 'pkcs11:object=key', 'pin': '1234'},
            'identity_cert': {'uri': 'pkcs11:object=cert', 'pin': '5678'},
        },
    })
    assert cfg.pkcs11_key_uri == 'pkcs11:object=key'
    assert cfg.pkcs11_cert_uri == 'pkcs11:object=cert'
    assert cfg.pkcs11_key_pin == '1234'
    assert cfg.pkcs11_cert_pin == '5678'
    assert cfg.check_client_cert is True


def test_tls_config_pkcs11_from_dict_identity_cert_file():
    cfg = TLSConfig.from_dict(section='server', config={
        'connector': 'pkcs11',
        'ca_cert': '/ignored.pem',
        'pkcs11': {
            'module_path': 'token.so',
            'identity_key': {'uri': 'pkcs11:object=key'},
            'identity_cert_file': '/path/to/identity/cert.pem',
        },
    })
    assert cfg.cert_file == '/path/to/identity/cert.pem'
    assert cfg.ca_cert == 'system'


def test_tls_config_file_rejects_pkcs11_nest():
    with pytest.raises(ConfigurationError, match='connector=file cannot set pkcs11'):
        TLSConfig.from_dict({
            'connector': 'file',
            'pkcs11': {
                'module_path': 'token.so',
                'identity_key': {'uri': 'pkcs11:object=key'},
            },
        })


def test_tls_config_pkcs11_rejects_schannel_nest():
    with pytest.raises(ConfigurationError, match='cannot be combined with a schannel nest'):
        TLSConfig.from_dict(section='server', config={
            'connector': 'pkcs11',
            'pkcs11': {
                'module_path': 'token.so',
                'identity_key': {'uri': 'pkcs11:object=key'},
                'identity_cert': {'uri': 'pkcs11:object=cert'},
            },
            'schannel': {'identity_cert_name': 'host'},
        })


def test_tls_config_schannel_from_dict_nested():
    cfg = TLSConfig.from_dict(section='server', config={
        'connector': 'schannel',
        'schannel': {
            'identity_cert_name': 'host.example.com',
            'identity_cert_store': 'my',
        },
    })
    assert cfg.schannel_cert_name == 'host.example.com'
    assert cfg.schannel_cert_store == 'MY'
    assert cfg.check_client_cert is True
    assert cfg.check_server_cert is True


def test_tls_config_empty_nests_with_file_ok():
    cfg = TLSConfig.from_dict({
        'connector': 'file',
        'pkcs11': {'module_path': None, 'identity_key': {'uri': None}},
        'schannel': {'identity_cert_name': None},
    })
    assert cfg.connector == 'file'


def test_tls_config_file_rejects_system_context_options():
    with pytest.raises(ConfigurationError, match="must be a list of option names"):
        TLSConfig.from_dict({'context_options': 'system'})


def test_tls_config_context_options_list():
    cfg = TLSConfig.from_dict({'context_options': ['NO_SSLv3', 'NO_TLSv1']})
    assert cfg.context_options == ['NO_SSLv3', 'NO_TLSv1']


def test_tls_config_context_options_none():
    cfg = TLSConfig(context_options=None)
    assert cfg.context_options == list(PYTHON_SSL_DEFAULT_CONTEXT_OPTIONS)


def test_tls_config_context_options_invalid_string():
    with pytest.raises(ConfigurationError, match="must be a list of option names"):
        TLSConfig(context_options='NO_SSLv3')


def test_tls_config_context_options_system_in_list():
    with pytest.raises(ConfigurationError, match="cannot set 'system' inside"):
        TLSConfig(context_options=['system', 'NO_SSLv3'])


def test_tls_config_context_options_wrong_type():
    with pytest.raises(ConfigurationError, match="must be a list of option names"):
        TLSConfig(context_options={'NO_SSLv3': True})


def test_tls_config_file_rejects_system_ca_cert():
    with pytest.raises(ConfigurationError, match='does not support ca_cert: system'):
        TLSConfig(ca_cert='system')


def test_tls_config_cert_thumbprint_normalized():
    tls = TLSConfig(schannel_cert_thumbprint='aa:bb cc-dd', connector='schannel')
    assert tls.schannel_cert_thumbprint == 'AABBCCDD'
    assert tls.schannel_cert_store == 'MY'
    tls2 = TLSConfig(schannel_cert_thumbprint='ABCD', schannel_cert_store='my', connector='schannel')
    assert tls2.schannel_cert_store == 'MY'
    tls_pem = TLSConfig()
    assert tls_pem.schannel_cert_thumbprint is None
    assert tls_pem.schannel_cert_store is None


def test_tls_config_cert_name_defaults_store():
    tls = TLSConfig(schannel_cert_name=' host.example.com ', connector='schannel')
    assert tls.schannel_cert_name == 'host.example.com'
    assert tls.schannel_cert_store == 'MY'


def test_tls_config_pkcs11_fields_stripped():
    tls = TLSConfig(
        connector='pkcs11',
        pkcs11_module=' /m.so ',
        pkcs11_key_uri=' pkcs11:x ',
        pkcs11_cert_uri=' pkcs11:cert ',
        pkcs11_key_pin=' 12 ',
    )
    assert tls.backend == 'python_ssl'
    assert tls.pkcs11_module == '/m.so'
    assert tls.pkcs11_key_uri == 'pkcs11:x'
    assert tls.pkcs11_key_pin == '12'


def test_tls_config_connector_normalized():
    assert TLSConfig(connector=' FILE ').connector == 'file'
    assert TLSConfig(connector=None).connector == 'file'
    assert TLSConfig(connector='  ').connector == 'file'


def test_tls_config_schannel_ignores_cipher_suite():
    tls = TLSConfig(connector='schannel', schannel_cert_name='host', cipher_suite='ECDH+AESGCM')
    assert tls.cipher_suite is None


def test_tls_config_schannel_forces_mtls():
    import agent.config as agent_config
    tls = TLSConfig(
        connector='schannel',
        schannel_cert_name='host',
        check_client_cert=False,
        check_server_cert=False,
    )
    assert tls.check_client_cert is True
    assert tls.check_server_cert is True
    agent_config.startup_log.assert_any_call(
        'Forcing mTLS for connector=schannel (overriding check_client_cert, check_server_cert)',
        prefix='[WARNING]',
    )


def test_tls_config_pkcs11_forces_mtls():
    import agent.config as agent_config
    tls = TLSConfig.from_dict(section='server', config={
        'connector': 'pkcs11',
        'check_client_cert': False,
        'pkcs11': {
            'module_path': 'token.so',
            'identity_key': {'uri': 'pkcs11:object=key'},
            'identity_cert': {'uri': 'pkcs11:object=cert'},
        },
    })
    assert tls.check_client_cert is True
    assert tls.check_server_cert is True
    agent_config.startup_log.assert_any_call(
        'Forcing mTLS for connector=pkcs11 (overriding check_client_cert)',
        prefix='[WARNING]',
    )


_SERVER_ALLOWED_HOSTS_DEFAULT = object()


def _server_config_dict(tls: dict, allowed_hosts=_SERVER_ALLOWED_HOSTS_DEFAULT, tls_enabled=True):
    if allowed_hosts is _SERVER_ALLOWED_HOSTS_DEFAULT:
        allowed_hosts = ['1.2.3.4']
    return {
        'allowed_hosts': allowed_hosts,
        'max_queued_connections': 10,
        'max_active_connections': 12,
        'port': 9876,
        'tls_enabled': tls_enabled,
        'tls_handshake_timeout': 60,
        'tls': tls,
        'max_request_time': 99,
        'receive_data_timeout': 30,
        'housekeeping_interval': 1800,
        'allow_multi_packet_response': True,
    }


def test_server_config_schannel_null_allowed_hosts_becomes_empty():
    import agent.config as agent_config
    cfg = ServerConfig.from_dict(_server_config_dict({
        'connector': 'schannel',
        'schannel': {'identity_cert_name': 'host'},
    }, allowed_hosts=None))
    assert cfg.allowed_hosts == []
    agent_config.startup_log.assert_any_call(
        'Forcing allowed_hosts to [] for connector=schannel',
        prefix='[WARNING]',
    )


def test_server_config_pkcs11_null_allowed_hosts_becomes_empty():
    import agent.config as agent_config
    cfg = ServerConfig.from_dict(_server_config_dict({
        'connector': 'pkcs11',
        'pkcs11': {
            'module_path': 'token.so',
            'identity_key': {'uri': 'pkcs11:object=key'},
            'identity_cert': {'uri': 'pkcs11:object=cert'},
        },
    }, allowed_hosts=None))
    assert cfg.allowed_hosts == []
    agent_config.startup_log.assert_any_call(
        'Forcing allowed_hosts to [] for connector=pkcs11',
        prefix='[WARNING]',
    )


def test_server_config_pkcs11_keeps_empty_allowed_hosts():
    import agent.config as agent_config
    cfg = ServerConfig.from_dict(_server_config_dict({
        'connector': 'pkcs11',
        'pkcs11': {
            'module_path': 'token.so',
            'identity_key': {'uri': 'pkcs11:object=key'},
            'identity_cert': {'uri': 'pkcs11:object=cert'},
        },
    }, allowed_hosts=[]))
    assert cfg.allowed_hosts == []
    messages = [call.args[0] for call in agent_config.startup_log.call_args_list]
    assert not any(message.startswith('Forcing allowed_hosts') for message in messages)


def test_server_config_schannel_keeps_allowed_hosts():
    cfg = ServerConfig.from_dict(_server_config_dict({
        'connector': 'schannel',
        'schannel': {'identity_cert_name': 'host'},
    }, allowed_hosts=['opsview.example']))
    assert cfg.allowed_hosts == ['opsview.example']


def test_server_config_pkcs11_keeps_allowed_hosts():
    cfg = ServerConfig.from_dict(_server_config_dict({
        'connector': 'pkcs11',
        'pkcs11': {
            'module_path': 'token.so',
            'identity_key': {'uri': 'pkcs11:object=key'},
            'identity_cert': {'uri': 'pkcs11:object=cert'},
        },
    }, allowed_hosts=['opsview.example']))
    assert cfg.allowed_hosts == ['opsview.example']


def test_server_config_file_connector_keeps_allowed_hosts():
    cfg = ServerConfig.from_dict(_server_config_dict({'connector': 'file'}, allowed_hosts=['10.0.0.1']))
    assert cfg.allowed_hosts == ['10.0.0.1']


def test_server_config_file_connector_keeps_null_allowed_hosts():
    cfg = ServerConfig.from_dict(_server_config_dict({'connector': 'file'}, allowed_hosts=None))
    assert cfg.allowed_hosts is None


def test_server_config_schannel_forces_tls_enabled():
    import agent.config as agent_config
    cfg = ServerConfig.from_dict(_server_config_dict({
        'connector': 'schannel',
        'schannel': {'identity_cert_name': 'host'},
    }, allowed_hosts=[], tls_enabled=False))
    assert cfg.tls_enabled is True
    agent_config.startup_log.assert_any_call(
        'Forcing tls_enabled for connector=schannel',
        prefix='[WARNING]',
    )


def test_server_config_pkcs11_forces_tls_enabled():
    import agent.config as agent_config
    cfg = ServerConfig.from_dict(_server_config_dict({
        'connector': 'pkcs11',
        'pkcs11': {
            'module_path': 'token.so',
            'identity_key': {'uri': 'pkcs11:object=key'},
            'identity_cert': {'uri': 'pkcs11:object=cert'},
        },
    }, allowed_hosts=[], tls_enabled=False))
    assert cfg.tls_enabled is True
    agent_config.startup_log.assert_any_call(
        'Forcing tls_enabled for connector=pkcs11',
        prefix='[WARNING]',
    )


def test_server_config_pkcs11_tls_enabled_is_silent():
    import agent.config as agent_config
    cfg = ServerConfig.from_dict(_server_config_dict({
        'connector': 'pkcs11',
        'pkcs11': {
            'module_path': 'token.so',
            'identity_key': {'uri': 'pkcs11:object=key'},
            'identity_cert': {'uri': 'pkcs11:object=cert'},
        },
    }, allowed_hosts=[]))
    assert cfg.tls_enabled is True
    messages = [call.args[0] for call in agent_config.startup_log.call_args_list]
    assert not any(message.startswith('Forcing tls_enabled') for message in messages)


def test_tls_config_pkcs11_rejected_outside_server():
    with pytest.raises(ConfigurationError, match='only supported under server.tls'):
        TLSConfig.from_dict({'connector': 'pkcs11'})


def test_tls_config_schannel_rejected_outside_server():
    with pytest.raises(ConfigurationError, match='only supported under server.tls'):
        TLSConfig.from_dict({'connector': 'schannel'})


@pytest.mark.parametrize('section', ['cachemanager', 'forwarders'])
@pytest.mark.parametrize('connector', ['pkcs11', 'schannel'])
def test_tls_config_token_connector_rejected_for_section(section, connector):
    with pytest.raises(
        ConfigurationError,
        match=f'connector={connector} is only supported under server.tls \\(rejected in {section}.tls\\)',
    ):
        TLSConfig.from_dict({'connector': connector}, section=section)


@pytest.mark.parametrize('tls_enabled', [True, False])
def test_cachemanager_rejects_pkcs11_and_schannel(tls_enabled):
    base = {
        'host': '127.0.0.1',
        'port': 8184,
        'housekeeping_interval': 60,
        'timestamp_error_margin': 30,
        'max_cache_size': '1GB',
        'max_item_size': 0,
        'tls_enabled': tls_enabled,
    }
    for connector in ('pkcs11', 'schannel'):
        with pytest.raises(ConfigurationError, match='rejected in cachemanager.tls'):
            CacheManagerConfig.from_dict({**base, 'tls': {'connector': connector}})


def test_cachemanager_tls_enabled_without_tls_block():
    cfg = CacheManagerConfig.from_dict({
        'host': '127.0.0.1',
        'port': 8184,
        'housekeeping_interval': 60,
        'timestamp_error_margin': 30,
        'max_cache_size': '1GB',
        'max_item_size': 0,
        'tls_enabled': True,
    })
    assert cfg.tls.connector == 'file'


def test_cachemanager_disabled_file_tls_is_not_kept():
    cfg = CacheManagerConfig.from_dict({
        'host': '127.0.0.1',
        'port': 8184,
        'housekeeping_interval': 60,
        'timestamp_error_margin': 30,
        'max_cache_size': '1GB',
        'max_item_size': 0,
        'tls_enabled': False,
        'tls': {'connector': 'file', 'ca_cert': 'ca.pem'},
    })
    assert cfg.tls is None


def test_cachemanager_file_connector_ok():
    cfg = CacheManagerConfig.from_dict({
        'host': '127.0.0.1',
        'port': 8184,
        'housekeeping_interval': 60,
        'timestamp_error_margin': 30,
        'max_cache_size': '1GB',
        'max_item_size': 0,
        'tls_enabled': True,
        'tls': {'connector': 'file', 'cert_file': 'cert.pem', 'key_file': 'key.pem'},
    })
    assert cfg.tls.connector == 'file'
    assert cfg.tls.cert_file == 'cert.pem'


@pytest.mark.parametrize('tls_enabled', [True, False])
def test_forwarder_rejects_pkcs11_and_schannel(tls_enabled):
    for connector in ('pkcs11', 'schannel'):
        with pytest.raises(ConfigurationError, match='rejected in forwarders.tls'):
            ForwarderClientConfig(
                host='host', port=99, tls_enabled=tls_enabled, tls={'connector': connector},
            )


def test_forwarder_file_connector_ok():
    cfg = ForwarderClientConfig(
        host='host',
        port=99,
        tls_enabled=True,
        tls={'connector': 'file', 'ca_cert': 'ca.pem'},
    )
    assert cfg.tls.connector == 'file'
    assert cfg.tls.ca_cert == 'ca.pem'


def test_server_config_file_connector_keeps_tls_disabled():
    cfg = ServerConfig.from_dict(_server_config_dict(
        {'connector': 'file'}, allowed_hosts=[], tls_enabled=False,
    ))
    assert cfg.tls_enabled is False


def test_tls_config_schannel_requires_identity():
    with pytest.raises(ConfigurationError, match='identity_cert_name'):
        TLSConfig(connector='schannel')
    with pytest.raises(ConfigurationError, match='identity_cert_name'):
        TLSConfig(connector='schannel', schannel_cert_store='MY')


def test_tls_config_schannel_rejects_both_identities():
    with pytest.raises(ConfigurationError, match='only one Schannel identity'):
        TLSConfig(connector='schannel', schannel_cert_name='host', schannel_cert_thumbprint='AABB')


def test_tls_config_schannel_store_with_identity_uppercased():
    tls = TLSConfig(connector='schannel', schannel_cert_name='host', schannel_cert_store='my')
    assert tls.schannel_cert_store == 'MY'


def test_tls_config_schannel_defaults_store_to_my():
    tls = TLSConfig(connector='schannel', schannel_cert_name='host')
    assert tls.schannel_cert_store == 'MY'


def test_tls_config_file_rejects_cert_store():
    with pytest.raises(ConfigurationError, match='identity_cert_store requires'):
        TLSConfig(schannel_cert_store='my')


def test_tls_config_file_rejects_schannel_identity():
    with pytest.raises(ConfigurationError, match='require server.tls.connector=schannel'):
        TLSConfig(schannel_cert_name='host.example.com')


def test_tls_config_rejects_python_ssl_connector():
    with pytest.raises(ConfigurationError, match='Invalid TLS connector'):
        TLSConfig(connector='python_ssl')


def test_tls_config_file_applies_defaults():
    tls = TLSConfig()
    assert tls.connector == 'file'
    assert tls.backend == 'python_ssl'
    assert tls.cipher_suite == PYTHON_SSL_DEFAULT_CIPHER_SUITE
    assert tls.context_options == list(PYTHON_SSL_DEFAULT_CONTEXT_OPTIONS)


def test_tls_config_file_rejects_system_cipher_suite():
    with pytest.raises(ConfigurationError, match='does not support cipher_suite: system'):
        TLSConfig(cipher_suite='system')


def test_tls_config_pkcs11_nest_must_be_mapping():
    with pytest.raises(ConfigurationError, match="'pkcs11' must be a mapping"):
        TLSConfig.from_dict({'pkcs11': 'token.so'})


def test_tls_config_schannel_nest_must_be_mapping():
    with pytest.raises(ConfigurationError, match="'schannel' must be a mapping"):
        TLSConfig.from_dict({'schannel': 'MY'})


def test_tls_config_rejects_unknown_pkcs11_nest_key():
    with pytest.raises(ConfigurationError, match="Unexpected configuration in 'tls.pkcs11': 'slot'"):
        TLSConfig.from_dict(section='server', config={
            'connector': 'pkcs11',
            'pkcs11': {'slot': 1},
        })


def test_tls_config_rejects_unknown_schannel_nest_key():
    with pytest.raises(ConfigurationError, match="Unexpected configuration in 'tls.schannel': 'slot'"):
        TLSConfig.from_dict(section='server', config={
            'connector': 'schannel',
            'schannel': {'slot': 1},
        })


def test_tls_config_file_rejects_schannel_nest():
    with pytest.raises(ConfigurationError, match='connector=file cannot set schannel'):
        TLSConfig.from_dict({
            'connector': 'file',
            'schannel': {'identity_cert_name': 'host'},
        })


def test_tls_config_file_rejects_both_unused_nests():
    with pytest.raises(ConfigurationError, match='cannot set pkcs11 or schannel'):
        TLSConfig.from_dict({
            'connector': 'file',
            'pkcs11': {'module_path': '/m.so'},
            'schannel': {'identity_cert_name': 'host'},
        })


def test_tls_config_schannel_rejects_pkcs11_nest():
    with pytest.raises(ConfigurationError, match='cannot be combined with a pkcs11 nest'):
        TLSConfig.from_dict(section='server', config={
            'connector': 'schannel',
            'schannel': {'identity_cert_name': 'host'},
            'pkcs11': {'module_path': '/m.so'},
        })


def test_tls_config_pkcs11_from_dict_warns_leftover_context_options(monkeypatch):
    messages = []
    monkeypatch.setattr(
        'agent.config.startup_log',
        lambda message, prefix='[INFO]': messages.append(f'{prefix} {message}'),
    )
    cfg = TLSConfig.from_dict(section='server', config={
        'connector': 'pkcs11',
        'context_options': ['NO_SSLv3'],
        'pkcs11': {
            'module_path': 'token.so',
            'identity_key': {'uri': 'pkcs11:object=key'},
            'identity_cert': {'uri': 'pkcs11:object=cert'},
        },
    })
    assert cfg.context_options == 'system'
    assert any(
        line.startswith('[WARNING] Ignoring leftover TLS file options') and 'context_options' in line
        for line in messages
    )


def test_tls_config_pkcs11_constructor_clears_leftover_context_options():
    cfg = TLSConfig(
        connector='pkcs11',
        context_options=['NO_SSLv3'],
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key',
        pkcs11_cert_uri='pkcs11:object=cert',
    )
    assert cfg.context_options == 'system'


def test_tls_config_pkcs11_identity_key_must_be_mapping():
    with pytest.raises(ConfigurationError, match="'pkcs11.identity_key' must be a mapping"):
        TLSConfig.from_dict(section='server', config={
            'connector': 'pkcs11',
            'pkcs11': {
                'module_path': 'token.so',
                'identity_key': 'pkcs11:object=key',
                'identity_cert': {'uri': 'pkcs11:object=cert'},
            },
        })


def test_tls_config_pkcs11_identity_key_rejects_extra_key():
    with pytest.raises(ConfigurationError, match="'tls.pkcs11.identity_key': 'label'"):
        TLSConfig.from_dict(section='server', config={
            'connector': 'pkcs11',
            'pkcs11': {
                'module_path': 'token.so',
                'identity_key': {'uri': 'pkcs11:object=key', 'label': 'x'},
                'identity_cert': {'uri': 'pkcs11:object=cert'},
            },
        })


def test_tls_config_pkcs11_identity_cert_must_be_mapping():
    with pytest.raises(ConfigurationError, match="'pkcs11.identity_cert' must be a mapping"):
        TLSConfig.from_dict(section='server', config={
            'connector': 'pkcs11',
            'pkcs11': {
                'module_path': 'token.so',
                'identity_key': {'uri': 'pkcs11:object=key'},
                'identity_cert': 'pkcs11:object=cert',
            },
        })


def test_tls_config_pkcs11_identity_cert_rejects_extra_key():
    with pytest.raises(ConfigurationError, match="'tls.pkcs11.identity_cert': 'label'"):
        TLSConfig.from_dict(section='server', config={
            'connector': 'pkcs11',
            'pkcs11': {
                'module_path': 'token.so',
                'identity_key': {'uri': 'pkcs11:object=key'},
                'identity_cert': {'uri': 'pkcs11:object=cert', 'label': 'x'},
            },
        })


def test_tls_config_pkcs11_missing_identity_key_requires_uri():
    with pytest.raises(ConfigurationError, match='identity_key.uri'):
        TLSConfig.from_dict(section='server', config={
            'connector': 'pkcs11',
            'pkcs11': {
                'module_path': 'token.so',
                'identity_cert': {'uri': 'pkcs11:object=cert'},
            },
        })


def test_tls_config_pkcs11_requires_cert_source():
    with pytest.raises(ConfigurationError, match='identity_cert or pkcs11.identity_cert_file'):
        TLSConfig(
            connector='pkcs11',
            pkcs11_module='token.so',
            pkcs11_key_uri='pkcs11:object=key',
        )


def test_tls_config_pkcs11_requires_key_uri():
    with pytest.raises(ConfigurationError, match='identity_key.uri'):
        TLSConfig(
            connector='pkcs11',
            pkcs11_module='token.so',
            pkcs11_cert_uri='pkcs11:object=cert',
        )


def test_tls_config_pkcs11_cert_uri_scheme():
    with pytest.raises(ConfigurationError, match="identity_cert.uri' must start with 'pkcs11:'"):
        TLSConfig(
            connector='pkcs11',
            pkcs11_module='token.so',
            pkcs11_key_uri='pkcs11:object=key',
            pkcs11_cert_uri='file:/tmp/cert.pem',
        )


def test_tls_config_file_rejects_pkcs11_identity_fields():
    with pytest.raises(ConfigurationError, match='require server.tls.connector=pkcs11'):
        TLSConfig(pkcs11_module='token.so')


def test_tls_config_pkcs11_rejects_schannel_fields():
    with pytest.raises(ConfigurationError, match='cannot be combined with schannel settings'):
        TLSConfig(
            connector='pkcs11',
            pkcs11_module='token.so',
            pkcs11_key_uri='pkcs11:object=key',
            pkcs11_cert_uri='pkcs11:object=cert',
            schannel_cert_name='host',
        )


def test_tls_config_pkcs11_rejects_cert_store():
    with pytest.raises(ConfigurationError, match='schannel settings'):
        TLSConfig(
            connector='pkcs11',
            pkcs11_module='token.so',
            pkcs11_key_uri='pkcs11:object=key',
            pkcs11_cert_uri='pkcs11:object=cert',
            schannel_cert_store='MY',
        )


def test_tls_config_from_dict_reraises_other_type_error(monkeypatch):
    def boom(self, *args, **kwargs):
        raise TypeError('unrelated construction failure')

    monkeypatch.setattr(TLSConfig, '__init__', boom)
    with pytest.raises(TypeError, match='unrelated construction failure'):
        TLSConfig.from_dict({})


def test_tls_config_from_dict_maps_missing_init_argument(monkeypatch):
    def boom(self, *args, **kwargs):
        raise TypeError("__init__() missing 1 required positional argument: 'ca_cert'")

    monkeypatch.setattr(TLSConfig, '__init__', boom)
    with pytest.raises(ConfigurationError, match="Configuration missing from 'tls'"):
        TLSConfig.from_dict({})


def test_file_key_configured_non_string_leftover():
    cfg = TLSConfig(
        connector='pkcs11',
        cipher_suite=1,
        pkcs11_module='token.so',
        pkcs11_key_uri='pkcs11:object=key',
        pkcs11_cert_uri='pkcs11:object=cert',
    )
    assert cfg.cipher_suite == 'system'
