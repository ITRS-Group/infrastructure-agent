"""
Infrastructure Agent: Cache Manager
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING
from uuid import uuid4

import gevent
from gevent.pywsgi import WSGIServer

from cache.aesencoder import AesEncoder
from cache.cachemanagerhelper import decode_namespace
from cache.exceptions import ServerApiError, ClientApiError
from cache.lockingcache import LockingCache
from .ssl_helper import get_ssl_context

if TYPE_CHECKING:
    from typing import Any
    from gevent.pywsgi import WSGIHandler
    from .agent import Agent
    from .config import CacheManagerConfig


logger = logging.getLogger(__name__)

PLUGIN_NAMESPACE_PREFIX = 'PLUGIN#'


class CacheManager:
    """Cache Manager HTTP server"""

    def __init__(self, config: CacheManagerConfig):
        logger.info("Starting Cache Manager")
        self._config = config
        self._unique_ref: str = str(uuid4())
        self._encoder = AesEncoder()
        self._cache = Cache(self._config, self._encoder)
        self._running: bool = False
        self._time_start: float = None
        self.agent: Agent = None

    def get_env(self, ns_plugin_name: str) -> dict:
        """Environment variables to be passed to plugin"""
        namespace: str = PLUGIN_NAMESPACE_PREFIX + ns_plugin_name
        namespace_token: str = f'namespace={namespace}&timestamp={int(time.time())}'
        return {
            'OPSVIEW_CACHE_MANAGER_NAMESPACE': self._encoder.encode(namespace_token),
            'OPSVIEW_CACHE_MANAGER_HOST': self._config.host,
            'OPSVIEW_CACHE_MANAGER_PORT': str(self._config.port),
        }

    def get_cache(self) -> Cache:
        """Returns a reference to the underlying cache object"""
        return self._cache

    def run(self):
        """Launch the web server"""
        environ: dict = {'SERVER_NAME': ''}

        server_args: dict = {
            'listener': (self._config.host, self._config.port),
            'application': self._handler,
            'environ': environ
        }

        if self._config.tls_enabled:
            try:
                server_args['ssl_context'] = get_ssl_context(self._config.tls, 'cachemanager')
            except Exception:
                logger.error("Error setting up Cache Manager SSL Context")
                raise

        server = WSGIServer(**server_args)

        self._time_start = time.time()
        self._running = True
        gevent.spawn(self._gproxy, self.housekeeping, self._config.housekeeping_interval)
        logger.debug("Starting cache manager server on %s, port %d", self._config.host, self._config.port)
        server.serve_forever()

    def _shutdown(self):
        """Terminate the cache manager"""
        self._running = False
        if self.agent:
            self.agent.stop()

    def _handler(self, environ: dict, start_response: WSGIHandler.start_response):
        """Request handler"""
        method = environ['REQUEST_METHOD']
        path = environ['PATH_INFO']
        logger.debug("<%s> %s from %s", method, path, environ.get('HTTP_', '<unknown>'))

        if method == 'GET':
            if path == '/':
                return self.handle_webroot(start_response)
            if path == '/status':
                return self.handle_status(start_response)
        elif method == 'POST':
            if path == '/':
                return self.handle_webroot(start_response)
            raw_data = environ['wsgi.input'].read().decode('utf-8')
            json_data = json.loads(raw_data)
            if path == '/get_data':
                return self.handle_get_data(start_response, json_data)
            if path == '/set_data':
                return self.handle_set_data(start_response, json_data)

        # reject anything else
        start_response('400 Invalid Request', [('Content-Type', 'text/text')])
        return []

    @staticmethod
    def json_response(start_response: callable, data: Any):
        """Send a JSON response"""
        start_response('200 OK', [('Content-Type', 'application/json')])
        return [json.dumps(data).encode('utf-8')]

    @staticmethod
    def error_response(start_response: callable, error: str):
        """Send an error response"""
        start_response(error, [('Content-Type', 'text/text')])
        return []

    @staticmethod
    def handle_webroot(start_response: callable):
        """Handle web root requests"""
        logger.debug("version request")
        start_response('200 OK', [('Content-Type', 'text/text')])
        return ["ITRS Group Cache Manager API".encode('utf-8')]

    def handle_get_data(self, start_response: callable, params: dict):
        """Handle POST /get_data requests"""
        logger.debug("handle_get_data()")
        try:
            data, lock, expiry = self._cache.get_data(params)
            return self.json_response(start_response, {'data': data, 'lock': lock, 'expiry': expiry})
        except ServerApiError as ex:
            logger.error("Server error: %s", ex)
            return self.error_response(start_response, '500 Server Error')
        except Exception as ex:
            logger.error("Client error: %s", ex)
            return self.error_response(start_response, '400 Invalid Request')

    def handle_set_data(self, start_response: callable, params: dict):
        """Handle POST /set_data requests"""
        logger.debug("handle_set_data()")
        try:
            self._cache.set_data(params)
            return self.json_response(start_response, 'ok')
        except ServerApiError as ex:
            logger.error("Server error: %s", ex)
            return self.error_response(start_response, '500 Server Error')
        except Exception as ex:
            logger.error("Client error: %s", ex)
            return self.error_response(start_response, '400 Invalid Request')

    def handle_status(self, start_response: callable):
        """Handle GET /status requests"""
        logger.debug("Status")
        uptime = int(time.time() - self._time_start)
        peer_status = []
        actual_cache_size = self._cache.size
        return self.json_response(start_response, {
            'ref': self._unique_ref,
            'uptime': uptime,
            'peers': peer_status,
            'cache_items': len(self._cache),
            'cache_size': actual_cache_size,
            'cache_percent': round((actual_cache_size * 100) / self._config.max_cache_size, 1),
            'max_item_size': self._cache.max_recorded_item_size,
        })

    def housekeeping(self, interval: int):
        """Keep the cache tidy"""
        logger.debug("Housekeeping spawned (CacheManager)")
        while self._running:
            gevent.sleep(interval)
            self._cache.housekeeping()
        logger.debug("Housekeeping done")

    def _gproxy(self, func: callable, *args):
        """Proxies the greenlet function allowing any exceptions to kill the process."""
        try:
            func(*args)
        except Exception as ex:
            logger.error('Error thrown for %s (%s)', func.__name__, ex)
            self._shutdown()


class Cache:
    """
    Cache implementation using LockingCache and ExpiryCache
    """

    NAMESPACE_VALIDATION_STRING = 'namespace'

    def __init__(self, config: CacheManagerConfig, encoder: AesEncoder):
        self._config = config
        self._encoder = encoder
        self._cache = LockingCache(max_total_size=config.max_cache_size, max_item_size=config.max_item_size)
        logger.debug("Cache initialised. Max size %d, max item %d", config.max_cache_size, config.max_item_size)

    def __len__(self) -> int:
        return len(self._cache)

    def get_locking_cache(self) -> LockingCache:
        """Returns a reference to the underlying locking cache"""
        return self._cache

    @property
    def size(self) -> int:
        """Total size of the cache"""
        return self._cache.size

    @property
    def max_recorded_item_size(self) -> int:
        """Size of the largest item added to the cache"""
        return self._cache.max_recorded_item_size

    def get_data(self, params: dict) -> (str, bool, int):
        """Fetch data from the cache"""
        try:
            orig_namespace: str = params['namespace']
            key: str = params['key']
            max_wait_time: int = int(params.get('max_wait_time', 0))
        except KeyError as e:
            raise ClientApiError(f"Missing parameter: {e}")

        namespace = decode_namespace(
            orig_namespace=orig_namespace,
            ns_encoder=self._encoder,
            timestamp_error_margin=self._config.timestamp_error_margin
        )

        response = self._cache.get_data(namespace, key, max_wait_time)
        return response.data, response.lock, response.expiry

    def set_data(self, params: dict) -> str:
        """Add data to the cache"""
        try:
            orig_namespace: str = params['namespace']
            key: str = params['key']
            data: str = params['data']
            ttl: int = int(params['ttl'])
        except KeyError as e:
            raise ClientApiError(f"Missing parameter: {e}")
        except (TypeError, ValueError) as e:
            raise ClientApiError(f"Invalid TTL parameter: {e}")
        if not isinstance(data, str):
            raise ClientApiError(f"Data needs to be a string type, not {type(data)}")

        namespace = decode_namespace(
            orig_namespace=orig_namespace,
            ns_encoder=self._encoder,
            timestamp_error_margin=self._config.timestamp_error_margin
        )

        self._cache.set_data(namespace, key, data, ttl)
        data = 'ok'
        return json.dumps(data)

    def housekeeping(self):
        """Remove expired data"""
        purged_count = self._cache.cleanup_expired_data()
        if purged_count:
            pl = '' if purged_count == 1 else 's'
            logger.info("Cache purged %d expired item%s.", purged_count, pl)
