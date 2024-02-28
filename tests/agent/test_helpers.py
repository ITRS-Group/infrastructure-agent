"""
Infrastructure Agent: Unit tests for helper
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""

import pytest

from agent.helpers import merge_dictionary, parse_byte_string, is_host_in_net_list


@pytest.mark.parametrize(
    'config, updates, merge_lists, expected', [
        pytest.param({'a': 'one'}, {'b': 'two'}, (), {'a': 'one', 'b': 'two'}, id="simple_merge"),
        pytest.param({'a': 'one'}, {'a': 'ONE'}, (), {'a': 'ONE'}, id="simple_update"),
        pytest.param(
            {'a': 'one', 'b': {'two': 'TWO'}}, {'b': {'three': 'THREE'}}, (),
            {'a': 'one', 'b': {'two': 'TWO', 'three': 'THREE'}},
            id="simple_nesting"),
        pytest.param({'a': None}, {'a': []}, (), {'a': []}, id="simple_update_over_null"),
        pytest.param({'a': ['old']}, {'a': ['new']}, (), {'a': ['new']}, id="simple_update_over_data"),
        pytest.param({'a': ['old']}, {'a': ['new']}, ('a'), {'a': ['old', 'new']}, id="simple_append_list"),
        pytest.param(
            {'a': ['olda'], 'b': ['oldb']},
            {'a': ['newa'], 'b': ['newb']},
            ('a'),
            {'a': ['olda', 'newa'], 'b': ['newb']},
            id="append_list"),
        pytest.param(
            {'a': ['olda'], 'b': ['oldb']},
            {'a': ['newa'], 'b': ['newb']},
            ('b'),
            {'a': ['newa'], 'b': ['oldb', 'newb']},
            id="append_other_list"),
    ])
def test_helpers_merge_dictionary(config, updates, merge_lists, expected):
    merge_dictionary(config, updates, merge_lists)
    assert config == expected


@pytest.mark.parametrize(
    'string, expected', [
        pytest.param('1B', 2**0, id="a_byte"),
        pytest.param('1024', 2**10, id="one_k"),
        pytest.param('1024B', 2**10, id="one_kilobyte"),
        pytest.param('1KB', 2**10, id="a_kilobyte"),
        pytest.param('1048576', 2**20, id="one_meg"),
        pytest.param('1048576B', 2**20, id="a_megabyte"),
        pytest.param('1024KB', 2**20, id="one_megabyte"),
        pytest.param('1MB', 2**20, id="a_megabyte"),
        pytest.param('1GB', 2**30, id="a_gigabyte"),
        pytest.param('42', 42, id="bare_number"),
    ])
def test_parse_byte_string(string: str, expected: int):
    assert parse_byte_string(string) == expected


@pytest.mark.parametrize('host, net_list, expected_result', [
    pytest.param('192.168.0.1', ['192.168.0.1'], True, id="direct ip"),
    pytest.param('host1', ['host1'], True, id="direct host"),
    pytest.param('192.168.0.2', ['192.168.0.1', '192.168.0.2', '192.168.0.3'], True, id="ip in list"),
    pytest.param('host2', ['host1', 'host2', '192.168.0.3'], True, id="host in list"),
    pytest.param('192.168.0.4', ['192.168.0.1', '192.168.0.2', '192.168.0.3'], False, id="ip not in list"),
    pytest.param('host4', ['host1', 'host2', 'host3'], False, id="host not in list"),
    pytest.param('192.168.0.2', ['192.168.0.0/24'], True, id="single subnet success"),
    pytest.param('192.168.1.2', ['192.168.0.0/24'], False, id="single subnet fail"),
    pytest.param('10.0.2.15', ['10.0.0.0/16'], True, id="multiple subnets success"),
    pytest.param('10.1.2.15', ['10.0.0.0/16'], False, id="multiple subnets fail"),
])
def test_host_in_net_list(host, net_list, expected_result):
    assert is_host_in_net_list(host, net_list) == expected_result
