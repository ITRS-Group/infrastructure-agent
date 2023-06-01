"""
Infrastructure Agent: Unit tests for nrpe server
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

import socket
import ssl
import uuid

import mock
import pytest

from agent.config import ConfigurationError
from nrpe.packet import NRPEPacketV2
from nrpe.server import NRPEListener


class SocketTimeout(Exception):
    pass


@pytest.fixture
def server(agent_config, platform_linux, mocker) -> NRPEListener:
    mocker.patch('nrpe.server.Semaphore')
    mocker.patch('nrpe.server.socket', timeout=SocketTimeout, herror=Exception)
    mocker.patch('nrpe.server.spawn')
    mocker.patch('nrpe.server.get_ssl_context')
    mocker.patch('nrpe.server.verify_certificate')
    svr = NRPEListener(platform_linux, agent_config.server, mocker.Mock())
    yield svr


@pytest.mark.parametrize(
    'allowed_hosts, tls, check_client_cert, context, windows, filtering, exception, logexp', [
        pytest.param(
            None, False, False, None, False, False, ConfigurationError,
            ["'allowed_hosts' has not been configured"],
            id="allowed_hosts_not_configured"),
        pytest.param(
            [], False, None, False, False, False, None,
            ['NRPE server allows connections from any host. This is not recommended'],
            id="filtering_disabled"),
        pytest.param(
            ['ok-host'], False, False, None, False, True, None,
            ['NRPE server allows connections from: ok-host'],
            id="filtering_one_host_no_tls_no_check_client_cert"),
        pytest.param(
            ['ok-host', '10.0.1.42', 'opsview.com'], False, False, None, False, True, None,
            [],
            id="filtering_many_hosts_no_tls_no_check_client_cert"),
        pytest.param(
            ['ok-host'], False, True, None, False, True, None,
            ['NRPE server allows connections from: ok-host'],
            id="filtering_one_host_no_tls_yes_check_client_cert"),
        pytest.param(
            ['ok-host', '10.0.1.42', 'opsview.com'], False, True, None, False, True, None,
            [],
            id="filtering_many_hosts_no_tls_yes_check_client_cert"),
        pytest.param(
            ['ok-host'], True, True, None, False, True, None,
            ['NRPE server allows connections from: ok-host', ],
            id="filtering_one_host_yes_tls_yes_check_client_cert"),
        pytest.param(
            ['ok-host', '10.0.1.42', '10.0.1.43', 'opsview.com'], True, True, None, False, True, None,
            ["'check_client_cert' is enabled. Any IP addresses configured in 'allowed_hosts' will be ignored."],
            id="filtering_many_hosts_yes_tls_yes_check_client_cert"),
        pytest.param(
            [], False, False, None, False, False, None,
            ['NRPE server running with TLS disabled. This is not recommended'],
            id="no_tls"),
        pytest.param([], True, False, [mock.Mock()], False, False, None, ['with TLS'], id="tls_linux"),
        pytest.param([], True, False, [mock.Mock()], True, False, None, ['with TLS'], id="tls_windows"),
        pytest.param(
            [], True, False, False, True, False, Exception, ['with TLS', 'Error setting up SSL Context'],
            id="context_error"),
    ])
def test_nrpe_server_post_init(
        allowed_hosts, tls, check_client_cert, context, windows, filtering,
        exception, logexp, mocker, server, platform_win, caplog):
    server.server_config.allowed_hosts = allowed_hosts
    server.server_config.tls_enabled = tls
    server.server_config.tls.check_client_cert = check_client_cert
    mocker.patch('nrpe.server.get_ssl_context', side_effect=context)
    if windows:
        server.platform = platform_win
    if not exception:
        server.__post_init__()
    else:
        with pytest.raises(exception):
            server.__post_init__()
    assert server._host_filtering == filtering
    for text in logexp:
        assert text in caplog.text


@pytest.mark.parametrize(
    'lock, accept_connection, spawn, exception, logexp', [
        pytest.param(
            [False], None, None, StopIteration,
            [
                'Starting NRPEListener.command_listener()',
                'Failed to acquire lock',
            ],
            id="lock_fail"),
        pytest.param(
            [False, False, False], None, None, None,
            [
                'Starting NRPEListener.command_listener()',
                'Failed to acquire lock',
            ],
            id="server_stopped"),
        pytest.param(
            [True], (None, None), None, StopIteration,
            [
                'Starting NRPEListener.command_listener()',
                'Releasing lock (connection rejected)',
            ],
            id="connection_rejected"),
        pytest.param(
            [True], (mock.Mock(), 'host'), Exception('bar'), Exception,
            [
                'Starting NRPEListener.command_listener()',
                'Error while spawning command: bar',
            ],
            id="spawn_error"),
        pytest.param(
            [True], (mock.Mock(), 'host'), None, StopIteration,
            [
                'Starting NRPEListener.command_listener()',
            ],
            id="success"),
        pytest.param(
            [True], (mock.Mock(getpeername=mock.Mock(side_effect=OSError)), ''), None, StopIteration,
            [
                'Invalid peer connection',
            ],
            id="invalid_peer"),
    ])
def test_nrpe_server_command_listener(
        lock, accept_connection, spawn, exception, logexp,
        mocker, server, caplog):
    server.is_running = mocker.Mock(side_effect=[True, True, False])
    server._lock.acquire = mocker.Mock(side_effect=lock + [StopIteration])
    server.accept_connection = mocker.Mock(return_value=accept_connection)
    mocker.patch('nrpe.server.spawn', side_effect=[spawn])
    if not exception:
        server.command_listener()
    else:
        with pytest.raises(exception):
            server.command_listener()
    for text in logexp:
        assert text in caplog.text


def test_nrpe_server_force_close_active_connections(mocker, server, caplog):
    server.is_running = mocker.Mock(side_effect=[True, True, False])
    conn_mock = mocker.Mock()
    server.accept_connection = mocker.Mock(return_value=(conn_mock, 'h1'))
    server._lock.acquire = mocker.Mock(side_effect=[True, False])
    server.command_listener()
    assert conn_mock.close.called
    assert 'Force closing active connections' in caplog.text


@pytest.mark.parametrize(
    'tls, accept, wrap, cert, hostfilter, match_hostname, expected, logexp', [
        pytest.param(
            True, ssl.SSLError, None, None, None, None, (None, None),
            [
                'SSL Handshake error',
            ],
            id="ssl_error"),
        pytest.param(
            True, socket.error, None, None, None, None, (None, None),
            [
                'Socket error',
            ],
            id="socket_error"),
        pytest.param(
            True, socket.gaierror, None, None, None, None, (None, None),
            [
                'Socket error',
            ],
            id="socket_gaierror"),
        pytest.param(
            True, ('knownhost', 42), SocketTimeout, None, None, None, (None, None),
            [
                'SSL Handshake timeout',
            ],
            id="ssl_handshake_timeout"),
        pytest.param(
            False, ('knownhost', 42), None, None, True, None, (True, 'knownhost'),
            [
                "Host 'knownhost' allowed",
                "Connection accepted from: 'knownhost'",
            ],
            id="success_no_tls"),
        pytest.param(
            True, ('knownhost', 42), None, {'subject': ((('commonName', 'knownhost.foo'),),)},
            True, None, (True, 'knownhost.foo'),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Host 'knownhost' allowed",
                "Connection accepted from: 'knownhost.foo'",
            ],
            id="success_tls"),
        pytest.param(
            True, ('knownhost', 42), None, None, True, None, (True, 'knownhost'),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Host 'knownhost' allowed",
                "Connection accepted from: 'knownhost'",
            ],
            id="success_tls_no_certificate"),
        pytest.param(
            False, ('unknown', 42), None, None, True, None, (None, None),
            [
                "Connection rejected: host 'unknown' is not in allowed_hosts",
            ],
            id="fail_host_filtering_no_tls"),
        pytest.param(
            True, ('unknown', 42), None, {'subject': ((('commonName', 'unknown.foo'),),)},
            True, ssl.CertificateError, (None, None),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Connection rejected: host 'unknown.foo' is not in allowed_hosts",
            ],
            id="fail_host_filtering_tls"),
        pytest.param(
            False, ('unknown', 42), None, None, False, None, (True, 'unknown'),
            [
                "Connection accepted from: 'unknown'",
            ],
            id="success_no_host_filtering_no_tls"),
        pytest.param(
            True, ('unknown', 42), None, {'subject': ((('commonName', 'unknown.foo'),),)},
            False, None, (True, 'unknown.foo'),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Connection accepted from: 'unknown.foo'",
            ],
            id="success_no_host_filtering_tls"),
    ])
def test_nrpe_server_accept_connection(
        tls, accept, wrap, cert, hostfilter, match_hostname, expected, logexp, mocker, server, caplog):
    mock_conn = mocker.Mock()
    server._socket.accept = mocker.Mock(side_effect=[(mock_conn, accept) if isinstance(accept, tuple) else accept])
    server._host_filtering = hostfilter
    server.server_config.allowed_hosts.append('knownhost')
    server.server_config.tls_enabled = tls
    if tls:
        server.context.wrap_socket.side_effect = [wrap or mock_conn]
        mock_conn.getpeercert.return_value = cert
        mocker.patch('nrpe.server.ssl.match_hostname', side_effect=[match_hostname])

    (conn, host) = server.accept_connection()

    assert (conn is None) == (expected[0] is None)
    assert host == expected[1]
    for text in logexp:
        assert text in caplog.text


@pytest.mark.parametrize(
    'cert, expected', [
        pytest.param('knownhost', 'knownhost', id="valid"),
        pytest.param('unknown', None, id="invalid"),
    ])
def test_nrpe_is_host_allowed_cert(cert, expected, mocker, server):
    def _host_match(cert, hostname):
        if cert != hostname:
            raise ssl.CertificateError

    server.server_config.allowed_hosts.append('knownhost')
    mocker.patch('nrpe.server.ssl.match_hostname', side_effect=_host_match)
    assert server.is_host_allowed_cert(cert) == expected


@pytest.mark.parametrize(
    'remote, gethostbyaddr, expected', [
        pytest.param('knownhost', None, 'knownhost', id="valid"),
        pytest.param('unknown', ('unknown', ['still_unknown'], []), None, id="unknown"),
        pytest.param('unknown', socket.herror, None, id="lookup_failed"),
        pytest.param('unknown', ('knownhost', [], []), 'knownhost', id="known_addr"),
        pytest.param('unknown', ('unknown', ['knownhost'], []), 'unknown (knownhost)', id="known_alias"),
    ])
def test_nrpe_is_host_allowed_no_cert(remote, gethostbyaddr, expected, mocker, server):
    mocker.patch('nrpe.server.socket.gethostbyaddr', side_effect=[gethostbyaddr])
    server.server_config.allowed_hosts.append('knownhost')
    assert server.is_host_allowed_no_cert(remote) == expected
    assert server.is_host_allowed_no_cert(remote) == expected


@pytest.mark.parametrize(
    'cert, expected', [
        pytest.param({}, '', id="empty"),
        pytest.param({'subject': ()}, '', id="empty_subject"),
        pytest.param({'subject': ((('countryName', 'GB'),),)}, '', id="almost_empty_subject"),
        pytest.param({'subject': ((('commonName', 'knownhost'),),)}, 'knownhost', id="known_host_CN"),
        pytest.param({'subjectAltName': ()}, '', id="empty_SAN"),
        pytest.param({'subjectAltName': (('DNS', 'knownhost'),)}, 'knownhost', id="known_host_SAN"),
        pytest.param(
            {
                'OCSP': ('http://ocsp.sectigo.com',),
                'caIssuers': ('http://crt.sectigo.com/SectigoRSADomainValidationSecureServerCA.crt',),
                'issuer': ((('countryName', 'GB'),),
                           (('stateOrProvinceName', 'Greater Manchester'),),
                           (('localityName', 'Salford'),),
                           (('organizationName', 'Sectigo Limited'),),
                           (('commonName', 'Sectigo RSA Domain Validation Secure Server CA'),)),
                'notBefore': 'Mar 14 00:00:00 2022 GMT',
                'notAfter': 'Apr  8 23:59:59 2023 GMT',
                'serialNumber': '447DF9B0AD5CE5C53AD321177A04386C',
                'subject': ((('commonName', '*.itrsgroup.com'),),),
                'version': 3,
                'subjectAltName': (('DNS', '*.itrsgroup.com'), ('DNS', 'itrsgroup.com')),
            },
            '*.itrsgroup.com, itrsgroup.com',
            id="known_host_CN_SAN_itrs"),
        pytest.param(
            {
                'OCSP': ('http://r3.o.lencr.org',),
                'caIssuers': ('http://r3.i.lencr.org/',),
                'issuer': ((('countryName', 'US'),),
                           (('organizationName', "Let's Encrypt"),),
                           (('commonName', 'R3'),)),
                'version': 3,
                'serialNumber': '0438574CD328C56895F413F351823B2C624F',
                'notBefore': 'Jul 19 20:45:21 2022 GMT',
                'notAfter': 'Oct 17 20:45:20 2022 GMT',
                'subject': ((('commonName', 'www.opsview.com'),),),
                'subjectAltName': (('DNS', 'opsview.com'), ('DNS', 'www.opsview.com')),
            },
            'www.opsview.com, opsview.com',
            id="known_host_CN_SAN_opsview"),
    ])
def test_nrpe_get_certificate_names(cert, expected, server):
    assert server.get_certificate_names(cert) == expected


def test_nrpe_server_get_packet_class(server):
    assert server.get_packet_class(None) == NRPEPacketV2


@pytest.mark.parametrize(
    'data, time, logexp', [
        pytest.param(
            [b'', None],
            [0] * 100,
            [' client] connection_handler started', ' client] Request error: No data received'],
            id="no_data"),
        pytest.param(
            [b'foo', None],
            [0] * 100,
            [' client] connection_handler started', ' client] Preparing to execute packet '],
            id="not_much_data"),
        pytest.param(
            [b'f' * 1024, b'o' * 42, None],
            [0] * 100,
            [' client] connection_handler started', ' client] Preparing to execute packet '],
            id="plenty_of_data"),
        pytest.param(
            [SocketTimeout, b'f' * 1024, b'o' * 42, None],
            [0] * 100,
            [' client] connection_handler started', ' client] Preparing to execute packet '],
            id="slow_request"),
        pytest.param(
            Exception,
            [0] * 100,
            [' client] connection_handler started', ' client] Request error: ', ' client] Releasing lock (error path)'],
            id="data_error"),
        pytest.param(
            [b'f' * 1024, Exception('boom')],
            [0] * 100,
            [
                ' client] connection_handler started',
                ' client] Request error: boom',
                ' client] Releasing lock (error path)',
            ],
            id="more_data_error"),
        pytest.param(
            [b'f' * 1024, b'o' * 42, None],
            [0, 10, 20, 30, 40, 50, 60, 70],
            [
                ' client] connection_handler started',
                ' client] Request error: Timed out waiting for client data',
                ' client] Releasing lock (error path)',
            ],
            id="timeout"),
        pytest.param(
            ConnectionResetError,
            [0] * 100,
            ['Connection has been reset by client'],
            id="peer_reset"),

    ])
def test_nrpe_connection_handler(server, time, data, logexp, mocker, caplog):
    mock_connection = mocker.Mock()
    mock_connection.recv.side_effect = data
    mocker.patch('nrpe.server.NRPEPacketV2')
    mocker.patch('nrpe.server.time.time', side_effect=time)
    server.script_runner.run_script.return_value = (0, 'foo', 'bar', False)
    server.connection_handler(mock_connection, 'client', ('127.0.0.1', 12345))
    for text in logexp:
        assert text in caplog.text


@pytest.mark.parametrize('stdout, stderr, exp_log', [
    pytest.param('', '', '[uuid client] 0, , , False', id="no output"),
    pytest.param('foo', '', '[uuid client] 0, foo, , False', id="stdout only"),
    pytest.param('', 'bar', '[uuid client] 0, , bar, False', id="stderr only"),
    pytest.param('foo', 'bar', '[uuid client] 0, foo, bar, False', id="stdout + stderr"),
])
def test_nrpe_server_execute_command(stdout, stderr, exp_log, server, caplog):
    server.script_runner.run_script.return_value = (0, stdout, stderr, False)
    server.execute_command('uuid', 'client', 'cmd', ['arg1', 'arg2'])
    assert str(exp_log) in caplog.text


def test_nrpe_server_send_result(server, mocker, caplog):
    mock_result = mocker.Mock()
    mock_result.rc = 42
    mock_result.stdout = 'fubar'
    mock_connection = mocker.Mock()
    server.send_result(
        command_uuid=uuid.UUID('af11f2bb-2b70-4c61-8fb5-abf7e97c5a5c'), host='client', connection=mock_connection,
        result=mock_result, packet_class=NRPEPacketV2, allow_multi_packet_response=True
    )
    assert mock_connection.sendall.called
    assert '[af11f2 client] Sending NRPEPacketV2' in caplog.text


def test_nrpe_housekeeping(server, mocker):
    mocker.patch('nrpe.server.sleep')
    server.is_running = mocker.Mock(side_effect=[True, True, True, True, False, False])
    server._hostname_cache['foo'] = 'bar'
    server.housekeeping(42)
    assert server._hostname_cache == {}


@pytest.mark.parametrize(
    'running', [
        pytest.param(False, id="stopped"),
        pytest.param(True, id="running"),
    ])
def test_nrpe_is_running(running, server):
    server._running = running
    assert server.is_running() == running


@pytest.mark.parametrize(
    'func, error, expected', [
        pytest.param('foo', False, '', id="success"),
        pytest.param(Exception('bar'), True, 'Error thrown for mock_func (bar)', id="error"),
    ])
def test_nrpe_gproxy(func, error, expected, server, mocker, caplog):
    mock_func = mocker.Mock(side_effect=[func], __name__='mock_func')
    if not error:
        server._gproxy(mock_func)
    else:
        with pytest.raises(Exception):
            server._gproxy(mock_func)
    assert mock_func.called
    assert expected in caplog.text
