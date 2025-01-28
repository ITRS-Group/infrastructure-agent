"""
Infrastructure Agent: Unit tests for cache manager exception definitions
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

import pytest

from cache.exceptions import (
    ClientApiError,
    ServerApiError,
    ConfigError,
    UnicodeKeyError,
    CacheItemSizeError,
    CacheTTLError,
    InvalidCharacterError,
)


@pytest.mark.parametrize(
    'exception', [
        ClientApiError,
        ServerApiError,
        ConfigError,
        UnicodeKeyError,
        CacheItemSizeError,
        CacheTTLError,
        InvalidCharacterError,
    ])
def test_exception(exception):
    assert isinstance(exception(42), Exception)
