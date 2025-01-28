"""
Infrastructure Agent: NRPE Server to listen and respond to NRPE packets sent by clients.
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import ssl
import time
import traceback
from typing import TYPE_CHECKING
from uuid import uuid4

from gevent import sleep, socket, spawn, kill, greenlet
from gevent.lock import Semaphore

from agent.config import ConfigurationError
from agent.helpers import is_host_in_net_list
from agent.objects import Result
from agent.scriptrunner import ScriptRunner
from agent.ssl_helper import get_ssl_context, verify_certificate
from .packet import AbstractPacket, NRPEPacketV2, NRPEPacketException

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from agent.config import ServerConfig
    from agent.objects import Platform
    from ssl import SSLSocket
    from typing import Optional, Type, Union
    from uuid import UUID


class NRPETimeout(Exception):
    """Timeout waiting for client request data"""

    def __init__(self, value):
        super(NRPETimeout, self).__init__(f"Timed out waiting for client data ({value}s)")


@dataclasses.dataclass
class NRPEListener:
    """NRPE Server to listen and respond to NRPE packets sent by clients"""
    platform: Platform
    server_config: ServerConfig
    script_runner: ScriptRunner

    _host_filtering: bool = True
    _socket: Union[socket.socket, SSLSocket] = None

    MAX_PACKET_SIZE = 1036
    SOCKET_BUFFER_SIZE = 2048

    def __post_init__(self):
        self._connected_sockets: dict[(str, int), (socket.socket, greenlet)] = {}
        if self.server_config.allowed_hosts is None:
            # allowed_hosts must be explicitly configured to [] to disable host checks
            error = "'allowed_hosts' has not been configured"
            logger.error(error)
            raise ConfigurationError(error)

        if isinstance(self.server_config.allowed_hosts, list) and len(self.server_config.allowed_hosts):
            self._host_filtering = True
            logged_warning = False

            for allowed_host in self.server_config.allowed_hosts:
                logger.debug("NRPE server allows connections from: %s", allowed_host)
                if self.server_config.tls_enabled and self.server_config.tls.check_client_cert:
                    try:
                        ipaddress.ip_address(allowed_host)
                        if not logged_warning:
                            logger.warning(
                                "'check_client_cert' is enabled. "
                                "Any IP addresses configured in 'allowed_hosts' will be ignored."
                            )
                            logged_warning = True
                    except ValueError:
                        pass
        else:
            self._host_filtering = False
            logger.warning("NRPE server allows connections from any host. This is not recommended.")

        if not self.server_config.bind_address:
            self.server_config.bind_address = socket.gethostname()
        self._running: bool = False

        # Set up the Socket
        logger.info("Setting up NRPE packet server%s", " with TLS" if self.server_config.tls_enabled else "")
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # get instance
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # make it fast...
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allow quick restarts

        if self.server_config.tls_enabled:
            # validate the TLS configuration and create a context
            try:
                self.context = get_ssl_context(self.server_config.tls, 'server')
                if not self.platform.is_windows:
                    verify_certificate(self.server_config.tls)
                # log_object_attr(logging.DEBUG, self.socket, "self.socket")
            except Exception as ex:
                logger.error("Error setting up SSL Context (%s)", ex)
                raise
        else:
            logger.warning("NRPE server running with TLS disabled. This is not recommended.")

        # Bind Host Address and Port together
        # Look closely! The bind() function takes a tuple as its argument
        logger.debug("Binding socket to (%s, %s)", self.server_config.bind_address, self.server_config.port)
        self._socket.bind((self.server_config.bind_address, self.server_config.port))

        # Set socket backlog
        # (the number of unaccepted connections that the system will allow before refusing new connections)
        logger.info(
            "Listening (max queued clients: %i, max active clients: %i)",
            self.server_config.max_queued_connections, self.server_config.max_active_connections)

        self._reset_connections()
        self._socket.listen(self.server_config.max_queued_connections)

        # initialise cache for hostname lookups
        self._hostname_cache: dict[str, str] = {}
        spawn(self._gproxy, self.housekeeping, self.server_config.housekeeping_interval)

    def _reset_connections(self):
        """Reset the accepted connections and connection lock"""
        if self._connected_sockets:
            logger.warning("Force closing active connections")
            for conn, conn_greenlet in self._connected_sockets.values():
                kill(conn_greenlet)
                conn.close()
            self._connected_sockets = {}
        # limit the number of concurrent connections
        logger.debug("Creating concurrent connection lock of size %i", self.server_config.max_active_connections)
        self._lock = Semaphore(value=self.server_config.max_active_connections)

    def command_listener(self):
        """Listen for incoming NRPE requests"""
        logger.debug("Starting NRPEListener.command_listener()")
        self._running = True

        while self.is_running():
            # The number of concurrent requests being processed is controlled by the semaphore
            if not self._lock.acquire(timeout=self.server_config.max_request_time):
                logger.debug("Failed to acquire lock")
                logger.error("Requests are taking too long to receive / process")
                self._reset_connections()
                continue
            logger.debug("Acquired lock")

            # Block waiting for inbound connection
            conn, host = self.accept_connection()
            if not conn:
                logger.warning("Releasing lock (connection rejected)")
                self._lock.release()
                continue

            # Check the client name
            try:
                peername = conn.getpeername()
            except OSError as ex:
                logger.warning("Invalid peer connection: %s", ex)
                self._lock.release()
                conn.close()
                continue

            # Handle the request
            try:
                self._connected_sockets[peername] = (
                    conn,
                    spawn(self.connection_handler, conn, host, peername)
                )
            except Exception as ex:
                # Catch-all to make sure we close the connection if something bad happens
                logger.error("Error while spawning command: %s", ex)
                conn.close()

    def accept_connection(self) -> tuple[Union[socket.socket, SSLSocket], str]:
        """Accept and validate a connection"""

        def _reject_connection(conn: socket.socket, reason: str):
            """Close the connection"""
            logger.warning(reason)
            if conn:
                conn.close()
            return (None, None)

        conn: Union[socket.socket, SSLSocket] = None
        client_cert: dict = None
        host: str = '<unknown>'
        try:
            conn, address = self._socket.accept()  # accept new connection
            host = address[0]

            if self.server_config.tls_enabled:
                conn.settimeout(self.server_config.tls_handshake_timeout)
                conn = self.context.wrap_socket(conn, server_side=True)
                client_cert = conn.getpeercert()
                if client_cert:
                    host = self.get_certificate_names(client_cert)

                logger.debug("Client certificate: %s", client_cert)
                logger.debug("TLS version: %s", conn.version())
                logger.debug("Cipher: %s", conn.cipher())
        except socket.timeout as ex:
            return _reject_connection(conn, f"Connection from {host}: SSL Handshake timeout ({ex})")
        except ssl.SSLError as ex:
            return _reject_connection(conn, f"Connection from {host}: SSL Handshake error ({ex})")
        except OSError as ex:
            return _reject_connection(conn, f"Connection from {host}: Socket error ({ex})")

        if self._host_filtering:
            # check that the client is allowed to use the service
            if client_cert:
                remote = self.is_host_allowed_cert(client_cert)
            else:
                remote = self.is_host_allowed_no_cert(host)
                host = remote or host
            if remote is None:
                return _reject_connection(conn, f"Connection rejected: host '{host}' is not in allowed_hosts")

        logger.debug("Connection accepted from: '%s'", host)
        return conn, host

    def is_host_allowed_cert(self, client_cert: dict) -> Optional[str]:
        """Certificate host name validation against allowed_hosts list"""
        for hostname in self.server_config.allowed_hosts:
            try:
                ssl.match_hostname(client_cert, hostname)
                logger.debug("Host '%s' allowed", hostname)
                return hostname
            except ssl.CertificateError:
                pass
        return None

    @staticmethod
    def get_certificate_names(cert: dict) -> str:
        """Extract CN and SAN from the certificate"""
        cn = [val[0][1] for val in cert.get('subject', []) if val[0][0] == 'commonName']
        san = [val[1] for val in cert.get('subjectAltName', []) if val[0] == 'DNS' and val[1] not in cn]
        return ', '.join(cn + san)

    def is_host_allowed_no_cert(self, remote: str) -> str:
        """
        Validate the hostname or alias against allowed_hosts list
        Results are cached to avoid multiple reverse DNS lookups
        """
        def _add_to_cache(remote: str, name: Union[str, None]):
            """add to hostname cache"""
            self._hostname_cache[remote] = name
            logger.debug("Adding host '%s' to cache as '%s'", remote, name)
            return name

        # Check the cache
        try:
            name = self._hostname_cache[remote]
            logger.debug("Cached host '%s' (%s)", self._hostname_cache[remote], remote)
            return name
        except KeyError:
            pass

        # Check the allow list
        if is_host_in_net_list(remote, self.server_config.allowed_hosts):
            logger.debug("Host '%s' allowed", remote)
            return remote

        # Attempt a lookup
        try:
            host = socket.gethostbyaddr(remote)
        except socket.herror:
            return _add_to_cache(remote, None)

        logger.debug("Looked up '%s': %s", remote, host)
        if is_host_in_net_list(host[0], self.server_config.allowed_hosts):
            return _add_to_cache(remote, host[0])

        # Check the aliases
        for alias in host[1]:
            if is_host_in_net_list(alias, self.server_config.allowed_hosts):
                return _add_to_cache(remote, f'{remote} ({alias})')

        return _add_to_cache(remote, None)

    @staticmethod
    def get_packet_class(_: bytes) -> Type[AbstractPacket]:
        """
        Return Python class matching to type of packet received
        """
        return NRPEPacketV2

    def connection_handler(self, conn: 'socket._socket', host: str, peername: tuple):
        """
        Receive the NRPE request
        Clients are expected to send the request as soon as the
        connection has been established
        """
        command_uuid = uuid4()
        display_uuid = str(command_uuid)[:6]
        error = False
        try:
            logger.debug("[%s %s] connection_handler started", display_uuid, host)
            data = b''
            start = time.time()
            conn.settimeout(0.1)
            while len(data) < self.MAX_PACKET_SIZE:  # receive whole request packet
                try:
                    buff = conn.recv(self.SOCKET_BUFFER_SIZE)
                    if not buff:
                        break
                    data += buff
                except socket.timeout:
                    pass
                if time.time() - start > self.server_config.receive_data_timeout:
                    raise NRPETimeout(self.server_config.receive_data_timeout)

            if not len(data):
                raise NRPEPacketException("No data received")

            packet_class = self.get_packet_class(data)
            request_packet = packet_class.from_bytes(data)

            logger.debug("[%s %s] Preparing to execute packet %s", display_uuid, host, request_packet)

            self.send_result(
                command_uuid=command_uuid,
                host=host,
                connection=conn,
                result=self.execute_command(
                    command_uuid=command_uuid,
                    host=host,
                    command=request_packet.check_name,
                    arguments=request_packet.check_arguments
                ),
                packet_class=packet_class,
                allow_multi_packet_response=self.server_config.allow_multi_packet_response,
            )
        except ConnectionResetError:
            error = True
            logger.warning("Connection has been reset by client %s", peername)
        except Exception as ex:
            error = True
            logger.error("[%s %s] Request error: %s\n%s", display_uuid, host, ex, traceback.format_exc())
        finally:
            logger.debug("[%s %s] Closing connection", display_uuid, host)
            self._connected_sockets.pop(peername, None)
            conn.close()
            logger.debug("[%s %s] Releasing lock (%s path)", display_uuid, host, 'error' if error else 'success')
            self._lock.release()

    def execute_command(self, command_uuid: UUID, host: str, command: str, arguments: list[str]) -> Result:
        """Execute the requested command via the script runner"""
        display_uuid = str(command_uuid)[:6]

        exit_code, response_stdout, response_stderr, early_timeout = self.script_runner.run_script(command, arguments)
        logger.debug(
            "[%s %s] %s, %s, %s, %s",
            display_uuid, host, exit_code, response_stdout, response_stderr, early_timeout)
        # Combine stdout and stderr
        if response_stderr:
            if response_stdout:
                response_stdout += '\n' + response_stderr
            else:
                response_stdout = response_stderr
        return Result(command_uuid, exit_code, response_stdout)

    @staticmethod
    def send_result(command_uuid: UUID, host: str, connection: socket.socket,
                    result: Result, packet_class: Type[AbstractPacket], allow_multi_packet_response: bool):
        """Generate the NRPE response and forward it to the client"""
        display_uuid = str(command_uuid)[:6]
        logger.debug("len(result.stdout) = %d", len(result.stdout))

        # Send packet(s) and close client connection
        for packet in packet_class.create_packets_from_result(result, allow_multi_packet_response):
            logger.debug("[%s %s] Sending %s", display_uuid, host, packet)
            connection.sendall(packet.to_bytes())

    def housekeeping(self, interval: int):
        """Tidy up resources"""
        logger.debug("Housekeeping spawned (NRPEServer)")
        while self.is_running():
            sleep(interval)
            # Clear the hostname cache
            self._hostname_cache = {}

    def is_running(self) -> bool:
        return self._running

    def _gproxy(self, func, *args):
        """Proxies the greenlet function allowing any exceptions to kill the process."""
        try:
            func(*args)
        except Exception as ex:
            logger.error('Error thrown for %s (%s)', func.__name__, ex)
            raise
