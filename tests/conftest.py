"""
Infrastructure Agent: Fixtures for all unit tests
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

import logging
from copy import deepcopy

import pytest
import yaml

from pathlib import Path

from agent.config import AgentConfig, EnvironmentVariableConfig
from agent.objects import Platform

BASE_PATH = Path(__file__).parent
TEST_CONFIG_RELATIVE_PATH = "resources/config.yml"
TEST_CONFIG_PATH = (BASE_PATH / TEST_CONFIG_RELATIVE_PATH).resolve()

RAW_AGENT_CONFIG = yaml.safe_load(TEST_CONFIG_PATH.read_text())
GLOBAL_ENVVAR_CFG = EnvironmentVariableConfig.from_dict(RAW_AGENT_CONFIG['environment_variables'])


@pytest.fixture(autouse=True)
def logging_debug(caplog):
    caplog.set_level(logging.DEBUG)


@pytest.fixture()
def agent_config() -> AgentConfig:
    yield AgentConfig.from_dict(deepcopy(RAW_AGENT_CONFIG))


@pytest.fixture
def platform_win() -> Platform:
    yield Platform('Windows', 'x86_64', ('Server', '2016'))


@pytest.fixture
def platform_linux() -> Platform:
    yield Platform('Linux', 'x86_64', tuple())
