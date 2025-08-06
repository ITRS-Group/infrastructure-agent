"""
Infrastructure Agent: Client to send JSON result data to a Results-Forwarder service.
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Optional, NamedTuple

import gevent

from gevent import ssl
from gevent.queue import Queue, Empty
from geventhttpclient import HTTPClient

from .helpers import basic_auth
from .ssl_helper import get_ssl_context

if TYPE_CHECKING:
    from .config import ForwarderClientConfig


logger = logging.getLogger(__name__)


class ResultRecord(NamedTuple):
    """
    Represents a single result record to be sent to the forwarder.
    """
    host: str
    service: str
    status: int
    output: str
    result_time: int  # Timestamp when the result was generated


class ForwarderClient:
    """
    Respresents a client that sends JSON result data to a Results-Forwarder service.
    Uses JIT HTTP connections with idle timeout to avoid keeping connections open.
    """

    DEFAULT_CONCURRENCY = 1
    NOSPAWN_IDLE_DIVISOR = 4  # Divide the idle timeout by this value to get the no-respawn time
    MAX_IDLE_NOSPAWN_SECS = 10  # Upper limit for no-respawn time
    BATCH_QUEUE_WAIT_SECS = 1
    MAX_QUEUE_SIZE = 100  # Maximum size of the send queue

    def __init__(self, name: str, config: ForwarderClientConfig):
        self._name = name
        self._config = config
        self._client: Optional[HTTPClient] = None
        self._idle_timer: gevent.Greenlet = None
        self._idle_timer_created = 0.0
        self._idle_timeout = config.idle_timeout
        self._idle_nospawn_secs = min(
            self.MAX_IDLE_NOSPAWN_SECS, self._idle_timeout // self.NOSPAWN_IDLE_DIVISOR
        )
        self._send_queue = Queue(self.MAX_QUEUE_SIZE)
        self._puller = gevent.spawn(self._queue_puller)

        self._headers = {'Content-Type': 'application/json'}
        if self._config.user and self._config.password and self._config.tls_enabled:
            # do not use basic authorisation without TLS as it would expose the credentials
            self._headers['Authorization'] = basic_auth(self._config.user, self._config.password)

    def queue_result(self, host: str, service: str, status: int, output: str, result_time: int) -> None:
        """
        Queue a result to be sent to the forwarder.
        This method could protentially block if the queue is full.
        """
        logger.debug(
            f"ForwarderClient: Queuing result for host={host!r}, service={service!r}, status={status},"
            f" output={output!r}, result_time={result_time}"
        )
        self._send_queue.put(ResultRecord(host, service, status, output, result_time))

    def _queue_puller(self) -> None:
        batch: list[ResultRecord] = []
        while True:
            batch.append(self._send_queue.get())  # Wait for a result
            gevent.sleep(self.BATCH_QUEUE_WAIT_SECS)  # Wait for results to accumulate
            try:
                while True:
                    batch.append(self._send_queue.get_nowait())
            except Empty:
                pass
            try:
                self._send_result_batch(batch)
            except Exception as e:
                logger.error("ForwarderClient: Error sending batch to forwarder '%s': %s", self._name, e)
            except:  # noqa: E722
                logger.exception("ForwarderClient: Unexpected error sending batch to forwarder '%s'", self._name)
                self._close_connection()  # Close the client on any unexpected error
            batch.clear()

    def _send_result_batch(self, batch: list[ResultRecord]) -> None:
        if not self._client:
            self._client = self._connect()
        self._reset_idle_timer()
        result_data = [{
            'hostname': record.host,
            'servicecheckname': record.service,
            'state': record.status,
            'output': record.output,
            'result_time': record.result_time,
        } for record in batch]
        logger.debug("ForwarderClient: Sending results batch (size=%d) ", len(result_data))
        response = self._client.request(
            'POST',
            '/',
            body=json.dumps(result_data),
            headers=self._headers
        )
        raw_response = response.read()
        if response.status_code != 200:
            try:
                decoded = json.loads(raw_response)
            except json.JSONDecodeError:
                decoded = raw_response.decode('utf-8', errors='replace')
            logger.error(f"ForwarderClient: Response from forwarder: {response.status_code} {decoded}")

    def _reset_idle_timer(self) -> None:
        now = time.time()
        if (now - self._idle_timer_created) >= self._idle_nospawn_secs:
            logger.debug("ForwarderClient: Resetting idle timeout to %d seconds", self._idle_timeout)
            if self._idle_timer:
                self._idle_timer.kill()
            self._idle_timer = gevent.spawn_later(self._idle_timeout, self._on_idle_timeout)
            self._idle_timer_created = now

    def _on_idle_timeout(self):
        logger.debug("ForwarderClient: Idle timeout occurred, closing client")
        self._close_connection()

    def _connect(self) -> HTTPClient:
        def ssl_context_factory() -> ssl.SSLContext:  # pragma: no cover
            return get_ssl_context(self._config.tls, 'FowarderClient', client_mode=True)

        logger.debug("ForwarderClient: Connecting to forwarder")
        return HTTPClient(
            self._config.host,
            port=self._config.port,
            concurrency=self._config.concurrency or self.DEFAULT_CONCURRENCY,
            connection_timeout=self._config.connection_timeout,
            network_timeout=self._config.network_timeout,
            ssl=self._config.tls_enabled,
            insecure=True,  # Allows us to set this with the context
            ssl_context_factory=ssl_context_factory if self._config.tls_enabled else None,
        )

    def close(self) -> None:
        # Close all resources and connections
        if self._puller:
            self._puller.kill()
            self._puller = None
        if self._idle_timer:
            self._idle_timer.kill()
            self._idle_timer = None
        self._close_connection()

    def _close_connection(self) -> None:
        """
        Close the client connection and clean up resources.
        This method is called when the ForwarderClient is no longer needed.
        """
        if self._client:
            logger.debug("ForwarderClient: Closing connection to forwarder '%s'", self._name)
            self._client.close()
            self._client = None
