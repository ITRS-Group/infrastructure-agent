# -*- coding: utf-8 -*-
"""
Infrastructure Agent: Unit tests for cache manager locking cache
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

import pytest

import gevent
import sys

from cache.exceptions import InvalidCharacterError
from cache.lockingcache import LockingCache


NS1 = 'ns1'
NS2 = 'ns2'
KEY1 = 'foo'
KEY2 = 'footoo'
KEY3 = 'fefo'
DATA1 = '0123456789'
DATA2 = '01234567890'
DATA3 = '01234567896'
DATATINY = 'ant'
DATABIG = 'itrsgroup' * 80
START = 1


@pytest.fixture(scope='function')
def cache() -> LockingCache:
    yield LockingCache()


def test_lockingcache_get_expiry_cache(cache):
    assert cache.get_expiry_cache() == cache._data


@pytest.mark.parametrize(
    'keyin, datain, keyout, dataout', [
        pytest.param(KEY1, 'foo', KEY2, None, id="not_there"),
        pytest.param(KEY1, 'foo', KEY1, 'foo', id="found"),
        pytest.param(KEY1, 'Some unicode data ☠', KEY1, 'Some unicode data ☠', id="unicode"),
    ])
def test_lockingcache_basic_data(keyin, datain, keyout, dataout, cache: LockingCache):
    cache.set_data(NS1, keyin, datain, 1)
    assert cache.get_data(NS1, keyout).data == dataout


def test_lockingcache_lock(cache: LockingCache):
    lockers = [0]

    def g1(cache: LockingCache):
        entry = cache.get_data(NS1, KEY1, max_wait_time=10)
        if entry.lock:
            lockers[0] += 1
            gevent.sleep(0.1)  # yuk - sleeping in a unit test
            cache.set_data(NS1, KEY1, DATA1, 1)
        else:
            assert entry.data == DATA1

    # spawn 4 workers, one should get the lock whilst the others should wait
    workers = [gevent.spawn(g1, cache) for _ in range(4)]
    gevent.joinall(workers)
    assert lockers[0] == 1  # Only one greenlet should have got the lock

    # Lastly, now the data is set, there should be no wait/lock
    actual = cache.get_data(NS1, KEY1, max_wait_time=10)
    assert (actual.data, actual.lock) == (DATA1, False)


def test_lockingcache_lock_expiry(cache: LockingCache, mocker):
    mock_time = mocker.patch('cache.expirycache.time.time')
    mock_time.return_value = START
    lock_timeout_secs = 1

    # For the first call, we expect to get no data, but a lock (that we're going to ignore)
    actual_data, actual_lock, actual_expiry = cache.get_data(
        NS1, KEY1, max_wait_time=lock_timeout_secs)
    assert (actual_data, actual_lock) == (None, True)

    # Move forward until the lock has expired
    mock_time.return_value = START + lock_timeout_secs
    cache.cleanup_expired_data()

    # We should now get a new lock
    actual_data, actual_lock, actual_expiry = cache.get_data(
        NS1, KEY1, max_wait_time=lock_timeout_secs)
    assert (actual_data, actual_lock) == (None, True)


@pytest.mark.parametrize(
    'namespace, key', [
        pytest.param('|', KEY1),
        pytest.param('a|', KEY1),
        pytest.param('|a', KEY1),
        pytest.param(NS1, '|'),
        pytest.param(NS1, 'a|'),
        pytest.param(NS1, '|a'),
    ])
def test_lockingcache_invalid_character(namespace, key, cache: LockingCache):
    with pytest.raises(InvalidCharacterError):
        cache.get_data(namespace, key)
    with pytest.raises(InvalidCharacterError):
        cache.set_data(namespace, key, '', 1)


def test_lockingcache_delete_data(cache: LockingCache):
    cache.set_data(NS1, KEY1, DATA1, 1)
    cache.set_data(NS1, KEY2, DATA2, 1)
    cache.set_data(NS2, KEY1, DATA3, 1)
    assert len(cache) == 3

    assert cache.delete_data(NS1, KEY1) is True
    assert len(cache) == 2


def test_lockingcache_len_and_size(cache: LockingCache):
    assert len(cache) == 0
    assert cache.size == 0

    cache.set_data(NS1, KEY1, DATA1, 1)
    for _ in range(2):
        # Write to Namespace 1/Key2 twice with the same data to check that
        # it's getting overwritten and not increasing size or length of the cache
        cache.set_data(NS1, KEY2, DATA1, 1)

    assert len(cache) == 2
    assert cache.size == (sys.getsizeof(DATA1) * 2)


def test_locking_cache_max_recorded_item_size(cache: LockingCache):
    cache.set_data(NS1, KEY1, DATATINY, 1)
    cache.set_data(NS1, KEY2, DATABIG, 1)
    cache.set_data(NS1, KEY3, DATA1, 1)
    assert cache.max_recorded_item_size == sys.getsizeof(DATABIG)
