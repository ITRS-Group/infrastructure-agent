"""
Infrastructure Agent: Locking cache, namespaced and in-memory
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

import logging
import time
from collections import namedtuple

from gevent.event import Event

from .exceptions import InvalidCharacterError
from .expirycache import ExpiryCache

CACHE_KEY_SEP_CHAR = '|'

LockingCacheEntry = namedtuple('LockingCacheEntry', ['data', 'lock', 'expiry'])
logger = logging.getLogger(__name__)


class LockingCache:
    """
    Represents a namespaced, locking in-memory cache.

    Locks can be acquired by callers when reading data. While a lock is in place,
    any other caller that tries to read the data will be blocked. Once any caller
    sets the data, all waiting callers will be released.

    Namespaces provide a level of isolation to the callers.
    """

    def __init__(self, max_total_size: int = 0, max_item_size: int = 0):
        logger.info(
            "Creating local cache (max_total_size=%d, max_item_size=%d).",
            max_total_size, max_item_size)
        self._data = ExpiryCache(max_total_size=max_total_size, max_item_size=max_item_size)

    def get_expiry_cache(self) -> ExpiryCache:
        """Returns a reference to the underlying expiry cache"""
        return self._data

    def get_data(self, namespace: str, key: str, max_wait_time: int = 0) -> LockingCacheEntry:
        """Fetch the data for the key in namespace"""
        effective_key, lock_key = self._get_keys(namespace, key)
        lock: bool = False
        if max_wait_time == 0:
            data_entry = self._data.get(effective_key)
        else:
            data_entry = None
            wait_time_left = max_wait_time
            t_end = time.time() + wait_time_left
            while not data_entry and not lock and (wait_time_left > 0):
                data_entry = self._data.get(effective_key)
                if not data_entry:
                    lock_ev_entry = self._data.get(lock_key)
                    if lock_ev_entry:
                        lock_ev = lock_ev_entry.data
                        # There's a lock in place, so wait for it
                        lock_ev.wait(timeout=wait_time_left)
                        # Lock freed or timeout so try to get data again with any remaining time
                        wait_time_left = t_end - time.time()
                    else:
                        # No lock yet, but also no data, so grab a lock
                        ev = Event()
                        self._data.set(lock_key, ev, wait_time_left)
                        lock = True
        if data_entry:
            return LockingCacheEntry(data_entry.data, lock, data_entry.expiry)
        return LockingCacheEntry(None, lock, 0)

    def set_data(self, namespace: str, key: str, data: str, ttl: int):
        """Add the data for the key in the namespace, with time-to-live"""
        effective_key, lock_key = self._get_keys(namespace, key)
        self._data.set(effective_key, data, ttl)
        lock_ev_entry = self._data.get(lock_key)
        if lock_ev_entry:
            lock_ev = lock_ev_entry.data
            lock_ev.set()  # Notify all listeners that the lock is released
            self._data.delete(lock_key)  # No need to keep this now
        return None

    def delete_data(self, namespace: str, key: str):
        """Remove the data for key in namespace"""
        effective_key, _ = self._get_keys(namespace, key)
        return self._data.delete(effective_key)

    def cleanup_expired_data(self):
        return self._data.cleanup_expired()

    def __len__(self) -> int:
        return len(self._data)

    @property
    def size(self) -> int:
        return self._data.size

    @property
    def max_recorded_item_size(self) -> int:
        return self._data.max_recorded_item_size

    @staticmethod
    def _get_keys(namespace: str, key: str) -> (str, str):
        """Generate the cache key and the lock key"""
        if CACHE_KEY_SEP_CHAR in namespace:
            raise InvalidCharacterError(f"Namespace '{namespace}' must not contain '{CACHE_KEY_SEP_CHAR}'")
        if CACHE_KEY_SEP_CHAR in key:
            raise InvalidCharacterError(f"Key '{key}' must not contain '{CACHE_KEY_SEP_CHAR}'")

        cache_key = f'{namespace}{CACHE_KEY_SEP_CHAR}{key}'
        lock_key = f'{cache_key}{CACHE_KEY_SEP_CHAR}lock'

        return cache_key, lock_key
