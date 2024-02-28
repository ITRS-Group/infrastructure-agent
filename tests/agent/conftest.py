"""
Infrastructure Agent: Fixtures for agent unit tests
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""

import pytest

from agent.cachemanager import CacheManager


@pytest.fixture
def cachemanager(agent_config, mocker) -> CacheManager:
    cm = CacheManager(agent_config.cachemanager)
    cm._encoder = mocker.Mock()
    cm._encoder.encode.side_effect = lambda x: ('ENC: ' + x).encode('utf-8')
    cm._unique_ref = '42'
    yield cm
