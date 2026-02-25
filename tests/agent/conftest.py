"""
Infrastructure Agent: Fixtures for agent unit tests
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from agent.cachemanager import CacheManager

if TYPE_CHECKING:
    from agent.config import EnvironmentVariableConfig


@pytest.fixture()
def global_environment_variables(agent_config) -> EnvironmentVariableConfig:
    return agent_config.environment_variables


@pytest.fixture
def cachemanager(agent_config, mocker) -> CacheManager:
    cm = CacheManager(agent_config.cachemanager)
    cm._encoder = mocker.Mock()
    cm._encoder.encode.side_effect = lambda x: ('ENC: ' + x).encode('utf-8')
    cm._unique_ref = '42'
    yield cm
