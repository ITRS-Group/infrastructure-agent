# -*- coding: utf-8 -*-
"""
Infrastructure Agent: Unit tests for cache manager expiry cache
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

import pytest
import sys

from gevent.event import Event

from cache.exceptions import CacheItemSizeError, CacheTTLError
from cache.expirycache import ExpiryCache


KEY1 = 'foo'
KEY2 = 'footoo'
KEY3 = 'fefo'
UNKNOWN = 'fubar'
DATA1 = '0123456789'
DATA2 = '01234567890'
DATA3 = '01234567896'
DATATINY = 'ant'
DATABIG = 'This elephant is mahoosive'
START = 1


@pytest.fixture(scope='function')
def cache() -> ExpiryCache:
    yield ExpiryCache()


@pytest.mark.parametrize(
    'keyin, datain, keyout, dataout', [
        pytest.param(KEY1, 'foo', KEY2, None, id="not_there"),
        pytest.param(KEY1, 'foo', KEY1, 'foo', id="found"),
        pytest.param(KEY1, 'Some unicode data ☠', KEY1, 'Some unicode data ☠', id="unicode"),
    ])
def test_expirycache_basic_data(keyin, datain, keyout, dataout, cache):
    cache.set(keyin, datain, 1)
    if dataout:
        assert cache.get(keyout).data == dataout
    else:
        assert cache.get(keyout) is None


def test_expirycache_expiry(cache, mocker):
    mock_time = mocker.patch('cache.expirycache.time.time')
    mock_time.return_value = START
    cache.set(KEY1, DATA1, 10)

    mock_time.return_value = START + 9
    assert KEY1 in cache
    assert cache.get(KEY1).data == DATA1

    mock_time.return_value = START + 10
    assert cache.get(KEY1) is None


@pytest.mark.parametrize(
    'delkey', [
        pytest.param(KEY1, id="present"),
        pytest.param(UNKNOWN, id="missing"),
    ])
def test_expirycache_delete(cache, delkey):
    cache.set(KEY1, DATA1, 1)
    cache.delete(delkey)
    assert cache.get(delkey) is None


def test_expirycache_delete_item_if_cache_size_exceeded():
    cache = ExpiryCache(max_total_size=1000)
    cache.set(KEY1, '0123456789' * 90, 1)  # 900 bytes
    assert cache.get(KEY1) is not None
    cache.set(KEY2, '0123456789' * 90, 1)  # 900 bytes
    # KEY1 should have been bumped out
    assert cache.get(KEY1) is None


@pytest.mark.parametrize(
    'cachesize, maxitem, item, ttl, exception', [
        pytest.param(1000, 100, DATA1 * 11, 1, CacheItemSizeError, id="max_item_size_exceeded"),
        pytest.param(1000, 0, DATA1 * 110, 1, CacheItemSizeError, id="cache_size_exceeded"),
        pytest.param(1000, 1001, DATA1 * 110, 1, CacheItemSizeError, id="item_size_larger_than_cache"),
        pytest.param(1000, 0, DATA1, 0.1, CacheTTLError, id="ttl_too_short"),
    ])
def test_expirycache_reject(cachesize, maxitem, item, ttl, exception):
    cache = ExpiryCache(max_total_size=cachesize, max_item_size=maxitem)
    with pytest.raises(exception):
        cache.set(KEY1, item, ttl)


def test_expirycache_cleanup(cache, mocker):
    mock_time = mocker.patch('cache.expirycache.time.time')
    mock_time.return_value = START
    cache.set(KEY1, DATA1, 1)
    cache.set(KEY3, DATA1, 3)
    cache.set(KEY2, DATA1, 2)
    assert len(cache) == 3

    mock_time.return_value = START + 2
    assert KEY1 in cache
    assert KEY2 in cache
    assert KEY3 in cache
    cache.cleanup_expired()
    assert KEY1 not in cache
    assert KEY2 not in cache
    assert KEY3 in cache
    assert len(cache) == 1
    assert cache.get(KEY3) is not None


def test_expirycache_cleanup_identical_keys(cache, mocker):
    mock_time = mocker.patch('cache.expirycache.time.time')
    mock_time.return_value = START
    cache.set(KEY1, DATA1, 1)
    cache.set(KEY1, DATA2, 1)
    cache.set(KEY1, DATA3, 5)
    assert len(cache) == 1

    mock_time.return_value = START + 2
    assert cache.cleanup_expired() == 0
    assert len(cache) == 1
    assert len(cache._keys_by_expiry) == 1

    mock_time.return_value = START + 6
    assert cache.cleanup_expired() == 1
    assert len(cache) == 0
    assert len(cache._keys_by_expiry) == 0


def test_expirycache_cleanup_expired_event(cache, mocker):
    mock_time = mocker.patch('cache.expirycache.time.time')
    mock_time.return_value = START

    assert len(cache) == 0
    assert len(cache._keys_by_expiry) == 0

    data = Event()
    cache.set(KEY1, data, 1)
    assert len(cache) == 1
    assert len(cache._keys_by_expiry) == 1
    assert not data.is_set()

    mock_time.return_value = START + 2
    assert cache.cleanup_expired() == 1
    assert len(cache) == 0
    assert len(cache._keys_by_expiry) == 0
    assert data.is_set()


@pytest.mark.parametrize(
    'delete', [
        pytest.param(True, id="delete"),
        pytest.param(False, id="no_delete"),
    ])
def test_expirycache_cleanup_delete(delete, cache, mocker):
    cache.delete = mocker.Mock(return_value=delete)
    mock_time = mocker.patch('cache.expirycache.time.time')
    mock_time.return_value = START
    cache.set(KEY1, DATA1, 1)
    mock_time.return_value = START + 2
    assert cache.cleanup_expired() == (1 if delete else 0)


def test_expirycache_max_recorded_item_size(cache):
    data = DATABIG
    cache.set(KEY1, data, 1)
    assert cache.max_recorded_item_size == sys.getsizeof(data)

    data += DATABIG
    cache.set(KEY1, data, 1)
    assert cache.max_recorded_item_size == sys.getsizeof(data)

    cache.set(KEY1, DATATINY, 1)
    assert cache.max_recorded_item_size == sys.getsizeof(data)
