"""
Infrastructure Agent: Unit tests for objects
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

import agent.self_check
from pathlib import Path
import pytest

RELATIVE_RESOURCES_PATH = '../resources'
BASE_PATH = Path(__file__).parent
RESOURCES_PATH = (BASE_PATH / RELATIVE_RESOURCES_PATH).resolve()


@pytest.mark.parametrize(
    'agent_name, agent_version, is_windows, expected', [
        pytest.param(
            'agent_name', '10.0.1', False,
            "agent_name 10.0.1; hostname=my-machine osname=Linux osvers=18.0 desc=Ubuntu",
            id="Linux",
        ),
        pytest.param(
            'agent_name', '18.0', True,
            "agent_name 18.0; hostname=my-machine osname=Windows osvers=10.0.1 desc=ServerStandard",
            id="Windows",
        )
    ])
def test_format_platform_info(agent_name, agent_version, is_windows, expected, mocker):
    mock_node = mocker.patch('agent.self_check.platform')
    mock_node.system.return_value = "Windows" if is_windows else "Linux"
    mock_gld = mocker.patch('agent.self_check.get_linux_distro')
    mock_gld.return_value = "Ubuntu"

    if is_windows:
        mock_node.version.return_value = "10.0.1"
        mock_node.win32_edition.return_value = "ServerStandard"
    else:
        mock_node.release.return_value = "18.0"
        mock_node.version.return_value = "Ubuntu"

    mock_node.node.return_value = "my-machine"
    platform_info_str = agent.self_check.format_platform_info(agent_name, agent_version, is_windows)
    assert platform_info_str == expected


@pytest.mark.parametrize(
    'os_release_file, expected', [
        pytest.param('os-release', "Ubuntu 20.04.5 LTS", id="pretty_name exists"),
        pytest.param('os-release-void', "10.0.1", id="pretty_name doesn't exist")
    ])
def test_get_linux_distro(os_release_file, expected, mocker):
    mock_node = mocker.patch('agent.self_check.platform')
    mock_node.version.return_value = "10.0.1"
    agent.self_check.OS_RELEASE_PATH = f'{RESOURCES_PATH}/{os_release_file}'
    linux_distro = agent.self_check.get_linux_distro()
    assert linux_distro == expected
