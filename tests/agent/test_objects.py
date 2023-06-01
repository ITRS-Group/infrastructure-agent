"""
Infrastructure Agent: Unit tests for objects
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

import pytest
import uuid

from agent.objects import Platform, Result


def test_result():
    result = Result(rc=42, stdout='foo', uuid=uuid.uuid4())
    assert result.rc == 42


@pytest.mark.parametrize(
    'system, arch, winver, expected', [
        pytest.param('Linux', 'x86-64', None, 'Linux (x86-64)', id="Linux"),
        pytest.param('Windows', 'i386', (42, 2112), 'Windows (i386) (42, 2112)', id="Windows"),
    ])
def test_platform(system, arch, winver, expected):
    platform = Platform(system, arch, winver)
    assert str(platform) == expected
