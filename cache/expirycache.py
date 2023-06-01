"""
Infrastructure Agent: Expiry cache
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

import logging
import sys
import time
from gevent.event import Event
from collections import namedtuple, OrderedDict

from sortedcontainers import SortedDict

from .exceptions import CacheTTLError, CacheItemSizeError

CacheEntry = namedtuple('CacheEntry', ['data', 'expiry'])

logger = logging.getLogger(__name__)


class ExpiryCache:
    """Represents an in-memory cache.

    Items expire after a specified TTL time.
    If the max_size is exceeded, the oldest items added are deleted.
    Size is only accurate if strings are used for data.
    """

    def __init__(self, max_total_size: int = 0, max_item_size: int = 0):
        self._max_total_size: int = max_total_size
        self._max_item_size: int = max_item_size
        if self._max_total_size > 0:
            if max_item_size == 0:
                self._max_item_size = self._max_total_size
            elif max_item_size > self._max_total_size:
                logger.warning(
                    "'max_item_size' is greater than 'max_cache_size' - capping at %d bytes.",
                    self._max_total_size)
                self._max_item_size = self._max_total_size
        self._data_cache = OrderedDict()
        self._keys_by_expiry = SortedDict()
        self._total_size: int = 0
        self._max_recorded_item_size: int = 0

    def set(self, key: str, data: str, ttl: int):
        """Sets the cache item with a TTL in seconds."""
        if ttl < 1:
            raise CacheTTLError(f"TTL must be at least one second (value={ttl})")
        item_size: int = sys.getsizeof(data)
        if self._max_item_size and (item_size > self._max_item_size):
            raise CacheItemSizeError("Cache item '{key}' is too large (size={item_size}, max={self._max_item_size})")
        if item_size > self._max_recorded_item_size:
            logger.debug("Setting new max recorded item size to: %d", item_size)
            self._max_recorded_item_size = item_size
        expiry: int = int(time.time() + ttl)
        self.delete(key)
        self._data_cache[key] = CacheEntry(data, expiry)
        self._keys_by_expiry.setdefault(expiry, set()).add(key)
        self._update_total_size(item_size)

    def get(self, key: str) -> str:
        """Retrieves a previously cached item (unless it has expired)."""
        data_block: bytes = self._data_cache.get(key)
        if data_block:
            if data_block.expiry > int(time.time()):
                return data_block
            self.delete(key)
        return None

    def delete(self, key: str) -> bool:
        """Deletes an item from the cache if it exists."""
        if key in self._data_cache:
            old_data = self._data_cache[key]
            logger.debug("Deleting key %s", key)
            old_size = sys.getsizeof(old_data.data)
            self._total_size -= old_size
            del self._data_cache[key]
            return True
        return False

    def cleanup_expired(self) -> int:
        """Removes any expired items from the cache."""
        num_expired: int = 0
        now: int = int(time.time())
        # Iterate through the (ordered) oldest items, deleting as we go
        while self._keys_by_expiry:
            expiry, item_keys = self._keys_by_expiry.peekitem(0)
            if expiry > now:
                break  # No more expired items
            self._keys_by_expiry.popitem(0)
            for key in item_keys:
                try:
                    is_expired = self._data_cache[key]
                    if is_expired.expiry > now:
                        break
                    if isinstance(is_expired.data, Event):
                        is_expired.data.set()  # Release the lock before deleting
                    if self.delete(key):
                        num_expired += 1
                except KeyError:  # pragma: no cover
                    pass  # We don't previously remove keys from _keys_by_expiry, so this is fine.
        return num_expired

    def __len__(self) -> int:
        return len(self._data_cache)

    def _update_total_size(self, item_size: int):
        """Updates the size of the cache and actively removes the oldest items
        if the cache gets too big.
        """
        self._total_size += item_size
        if self._max_total_size > 0:
            while self._total_size > self._max_total_size:
                oldest_key = next(self._data_cache.__iter__())
                self.delete(oldest_key)

    def __contains__(self, key: str) -> bool:
        return key in self._data_cache

    @property
    def size(self) -> int:
        return self._total_size

    @property
    def max_recorded_item_size(self) -> int:
        return self._max_recorded_item_size
