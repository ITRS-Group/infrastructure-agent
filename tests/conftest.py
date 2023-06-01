"""
Infrastructure Agent: Fixtures for all unit tests
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

import logging
import pytest
import yaml

from pathlib import Path

from agent.config import AgentConfig
from agent.objects import Platform

BASE_PATH = Path(__file__).parent
TEST_CONFIG_RELATIVE_PATH = "resources/config.yml"
TEST_CONFIG__PATH = (BASE_PATH / TEST_CONFIG_RELATIVE_PATH).resolve()


@pytest.fixture(autouse=True)
def logging_debug(caplog):
    caplog.set_level(logging.DEBUG)


@pytest.fixture()
def agent_config() -> AgentConfig:
    with open(TEST_CONFIG__PATH, 'r') as f:
        config_dict = yaml.safe_load(f)
    return AgentConfig.from_dict(config_dict)


@pytest.fixture
def platform_win() -> Platform:
    yield Platform('Windows', 'x86_64', ('Server', '2016'))


@pytest.fixture
def platform_linux() -> Platform:
    yield Platform('Linux', 'x86_64', tuple())
