"""
Infrastructure Agent: Unit tests for nrpe server
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

import socket
import ssl
import uuid

import mock
import pytest

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
    'allowed_hosts, tls, check_client_cert, context, windows, filtering, exception, logexp',
    [
        pytest.param(
            None,
            False,
            False,
            None,
            False,
            True,
            None,
            ["'allowed_hosts' is currently null, which blocks any host from connecting"],
            id="allowed_hosts_not_configured",
        ),
        pytest.param(
            [],
            False,
            None,
            False,
            False,
            False,
            None,
            ['NRPE server allows connections from any host. This is not recommended'],
            id="filtering_disabled",
        ),
        pytest.param(
            ['ok-host'],
            False,
            False,
            None,
            False,
            True,
            None,
            ['NRPE server allows connections from: ok-host'],
            id="filtering_one_host_no_tls_no_check_client_cert",
        ),
        pytest.param(
            ['ok-host', '10.0.1.42', 'opsview.com'],
            False,
            False,
            None,
            False,
            True,
            None,
            [],
            id="filtering_many_hosts_no_tls_no_check_client_cert",
        ),
        pytest.param(
            ['ok-host'],
            False,
            True,
            None,
            False,
            True,
            None,
            ['NRPE server allows connections from: ok-host'],
            id="filtering_one_host_no_tls_yes_check_client_cert",
        ),
        pytest.param(
            ['ok-host', '10.0.1.42', 'opsview.com'],
            False,
            True,
            None,
            False,
            True,
            None,
            [],
            id="filtering_many_hosts_no_tls_yes_check_client_cert",
        ),
        pytest.param(
            ['ok-host'],
            True,
            True,
            None,
            False,
            True,
            None,
            [
                'NRPE server allows connections from: ok-host',
            ],
            id="filtering_one_host_yes_tls_yes_check_client_cert",
        ),
        pytest.param(
            ['ok-host', '10.0.1.42', '10.0.1.43', 'opsview.com'],
            True,
            True,
            None,
            False,
            True,
            None,
            ["'check_client_cert' is enabled. Any IP addresses configured in 'allowed_hosts' will be ignored."],
            id="filtering_many_hosts_yes_tls_yes_check_client_cert",
        ),
        pytest.param(
            [],
            False,
            False,
            None,
            False,
            False,
            None,
            ['NRPE server running with TLS disabled. This is not recommended'],
            id="no_tls",
        ),
        pytest.param([], True, False, [mock.Mock()], False, False, None, ['with TLS'], id="tls_linux"),
        pytest.param([], True, False, [mock.Mock()], True, False, None, ['with TLS'], id="tls_windows"),
        pytest.param(
            [],
            True,
            False,
            False,
            True,
            False,
            Exception,
            ['with TLS', 'Error setting up SSL Context'],
            id="context_error",
        ),
    ],
)
def test_nrpe_server_post_init(
    allowed_hosts,
    tls,
    check_client_cert,
    context,
    windows,
    filtering,
    exception,
    logexp,
    mocker,
    server,
    platform_win,
    caplog,
):
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
    'lock, accept_connection, spawn, exception, logexp',
    [
        pytest.param(
            [False],
            None,
            None,
            StopIteration,
            [
                'Starting NRPEListener.command_listener()',
                'Failed to acquire lock',
            ],
            id="lock_fail",
        ),
        pytest.param(
            [False, False, False],
            None,
            None,
            None,
            [
                'Starting NRPEListener.command_listener()',
                'Failed to acquire lock',
            ],
            id="server_stopped",
        ),
        pytest.param(
            [True],
            (None, None),
            None,
            StopIteration,
            [
                'Starting NRPEListener.command_listener()',
                'Releasing lock (connection rejected)',
            ],
            id="connection_rejected",
        ),
        pytest.param(
            [True],
            (mock.Mock(), 'host'),
            Exception('bar'),
            Exception,
            [
                'Starting NRPEListener.command_listener()',
                'Error while spawning command: bar',
            ],
            id="spawn_error",
        ),
        pytest.param(
            [True],
            (mock.Mock(), 'host'),
            None,
            StopIteration,
            [
                'Starting NRPEListener.command_listener()',
            ],
            id="success",
        ),
        pytest.param(
            [True],
            (mock.Mock(getpeername=mock.Mock(side_effect=OSError)), ''),
            None,
            StopIteration,
            [
                'Invalid peer connection',
            ],
            id="invalid_peer",
        ),
    ],
)
def test_nrpe_server_command_listener(lock, accept_connection, spawn, exception, logexp, mocker, server, caplog):
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
    'tls, accept, wrap, cert, hostfilter, allowed_hosts, expected, logexp',
    [
        pytest.param(
            True,
            ssl.SSLError,
            None,
            None,
            None,
            ['knownhost.foo'],
            (None, None),
            [
                'SSL Handshake error',
            ],
            id="ssl_error",
        ),
        pytest.param(
            True,
            socket.error,
            None,
            None,
            None,
            ['knownhost.foo'],
            (None, None),
            [
                'Socket error',
            ],
            id="socket_error",
        ),
        pytest.param(
            True,
            socket.gaierror,
            None,
            None,
            None,
            ['knownhost.foo'],
            (None, None),
            [
                'Socket error',
            ],
            id="socket_gaierror",
        ),
        pytest.param(
            True,
            ('knownhost', 42),
            SocketTimeout,
            None,
            None,
            ['knownhost.foo'],
            (None, None),
            [
                'SSL Handshake timeout',
            ],
            id="ssl_handshake_timeout",
        ),
        pytest.param(
            False,
            ('knownhost.foo', 42),
            None,
            None,
            True,
            ['knownhost.foo'],
            (True, 'knownhost.foo'),
            [
                "Host 'knownhost.foo' allowed",
                "Connection accepted from: 'knownhost.foo'",
            ],
            id="success_no_tls",
        ),
        pytest.param(
            True,
            ('knownhost.foo', 42),
            None,
            {
                'subject': [
                    (('commonName', 'known.foo'),),
                    (
                        ('foo', 'bar'),
                        ('commonName', 'knownhost.foo'),
                        ('foo', 'bar'),
                    ),
                ]
            },
            True,
            ['knownhost.foo'],
            (True, 'known.foo'),
            [
                'Client certificate: ',
                'TLS version: ',
                'Cipher: ',
                "Host 'knownhost.foo' allowed",
                "Connection accepted from: 'known.foo'",
            ],
            id="success_tls",
        ),
        pytest.param(
            True,
            ('knownhost.foo', 42),
            None,
            {'subjectAltName': (('DNS', '*.*.foo'),)},
            True,
            None,
            (None, None),
            [
                "Connection rejected: host 'knownhost.foo', as currently blocking all hosts",
            ],
            id="block_all_hosts",
        ),
        pytest.param(
            True,
            ('knownhost.foo', 42),
            None,
            {'subjectAltName': (('DNS', ''), ('DNS', '*.foo'), ('IP Address', '192.168.0.1'))},
            True,
            ['knownhost.foo'],
            (True, ', *.foo'),
            [
                'Client certificate: ',
                'TLS version: ',
                'Cipher: ',
                "Host 'knownhost.foo' allowed",
                "Connection accepted from: ', *.foo'",
            ],
            id="success_tls_wildcard",
        ),
        pytest.param(
            True,
            ('knownhost.foo', 42),
            None,
            {'subjectAltName': (('DNS', '*.*.foo'),)},
            True,
            ['knownhost.foo'],
            (None, None),
            [
                "Connection rejected: host '*.*.foo' is not in allowed_hosts",
            ],
            id="fail_tls_wildcard_too_many",
        ),
        pytest.param(
            True,
            ('knownhost.foo', 42),
            None,
            {'subjectAltName': (('DNS', 'bar.*.foo'),)},
            True,
            ['knownhost.foo'],
            (None, None),
            [
                "Connection rejected: host 'bar.*.foo' is not in allowed_hosts",
            ],
            id="fail_tls_wildcard_not_start",
        ),
        pytest.param(
            True,
            ('knownhost.foo', 42),
            None,
            {'subjectAltName': (('DNS', '*'),)},
            True,
            ['knownhost.foo'],
            (None, None),
            [
                "Connection rejected: host '*' is not in allowed_hosts",
            ],
            id="fail_tls_wildcard_no_sep",
        ),
        pytest.param(
            True,
            ('knownhost.foo', 42),
            None,
            {'subjectAltName': (('DNS', 'bad*.foo'),)},
            True,
            ['knownhost.foo'],
            (None, None),
            [
                "Connection rejected: host 'bad*.foo' is not in allowed_hosts",
            ],
            id="fail_tls_wildcard_bad",
        ),
        pytest.param(
            True,
            ('.foo', 42),
            None,
            {'subjectAltName': (('foo', 'bar'), ('DNS', '*.foo'))},
            True,
            ['.foo'],
            (None, None),
            [
                "Connection rejected: host '*.foo' is not in allowed_hosts",
            ],
            id="fail_tls_wildcard_bad_hostname",
        ),
        pytest.param(
            True,
            ('192.168.0.1', 42),
            None,
            {'subjectAltName': (('IP Address', 'f800::1'), ('IP Address', '192.168.0.1'), ('DNS', 'knownhost.foo'))},
            True,
            ['192.168.0.1'],
            (True, 'knownhost.foo', [socket.gaierror], ['192.168.0.1']),
            [
                'Client certificate: ',
                'TLS version: ',
                'Cipher: ',
                "Host '192.168.0.1' allowed",
                "Connection accepted from: 'knownhost.foo'",
            ],
            id="success_tls_ip",
        ),
        pytest.param(
            True,
            ('192.168.0.1', 42),
            None,
            {'subjectAltName': (('IP Address', 'f800::1'), ('IP Address', '192.168.0.2'), ('DNS', 'knownhost.foo'))},
            True,
            ['192.168.0.1'],
            (None, None, [socket.gaierror], ['192.168.0.1']),
            [
                'Client certificate: ',
                'TLS version: ',
                'Cipher: ',
                "Connection rejected: host 'knownhost.foo' is not in allowed_hosts"
            ],
            id="fail_tls_ip",
        ),
        pytest.param(
            True,
            ('knownhost.foo', 42),
            None,
            {'empty': ()},
            True,
            ['knownhost.foo'],
            (None, None),
            [
                "Connection rejected: host '' is not in allowed_hosts",
            ],
            id="fail_empty_cert",
        ),
        pytest.param(
            True,
            ('knownhost.foo', 42),
            None,
            None,
            True,
            ['knownhost.foo'],
            (True, 'knownhost.foo'),
            [
                'Client certificate: ',
                'TLS version: ',
                'Cipher: ',
                "Host 'knownhost.foo' allowed",
                "Connection accepted from: 'knownhost.foo'",
            ],
            id="success_tls_no_certificate",
        ),
        pytest.param(
            False,
            ('unknown', 42),
            None,
            None,
            True,
            ['knownhost.foo'],
            (None, None),
            [
                "Connection rejected: host 'unknown' is not in allowed_hosts",
            ],
            id="fail_host_filtering_no_tls",
        ),
        pytest.param(
            True,
            ('unknown', 42),
            None,
            {'subject': ((('commonName', 'unknown.foo'),),)},
            True,
            ['knownhost.foo'],
            (None, None),
            [
                'Client certificate: ',
                'TLS version: ',
                'Cipher: ',
                "Connection rejected: host 'unknown.foo' is not in allowed_hosts",
            ],
            id="fail_host_filtering_tls",
        ),
        pytest.param(
            True,
            ('unknown', 42),
            None,
            {'subject': ((('commonName', 'unknown.foo'),), (('commonName', 'foo.bar'),))},
            True,
            ['knownhost.foo'],
            (None, None),
            [
                'Client certificate: ',
                'TLS version: ',
                'Cipher: ',
                "Connection rejected: host 'unknown.foo, foo.bar' is not in allowed_hosts",
            ],
            id="fail_host_filtering_tls_multi",
        ),
        pytest.param(
            False,
            ('unknown', 42),
            None,
            None,
            False,
            ['knownhost.foo'],
            (True, 'unknown'),
            [
                "Connection accepted from: 'unknown'",
            ],
            id="success_no_host_filtering_no_tls",
        ),
        pytest.param(
            True,
            ('unknown', 42),
            None,
            {'subject': ((('commonName', 'unknown.foo'),),)},
            False,
            ['knownhost.foo'],
            (True, 'unknown.foo'),
            [
                'Client certificate: ',
                'TLS version: ',
                'Cipher: ',
                "Connection accepted from: 'unknown.foo'",
            ],
            id="success_no_host_filtering_tls",
        ),
        pytest.param(
            True,
            ('this', 42),
            None,
            {'subjectAltName': (('IP Address', 'f800::1'), ('IP Address', '192.168.0.1'), ('DNS', 'knownhost.foo'))},
            True,
            [
                'this.is.a.very.long.hostname.just.to.test.that.the.code.for.detecting.long.hostnames.actually.works.as'
                '.expected.I.think.Im.going.to.need.to.repeat.this.as.it.is.not.long.enough.even.now.this.is.a.very'
                '.long.hostname.just.to.test.that.the.code.for.detecting.long.hostnames.works'
            ],
            (None, None),
            [
                'Client certificate: ',
                'TLS version: ',
                'Cipher: ',
                "Connection rejected: host 'knownhost.foo' is not in allowed_hosts",
            ],
            id="fail_long_hostname_tls",
        ),
        pytest.param(
            True,
            ('this', 42),
            None,
            {'subjectAltName': (('IP Address', 'f800::1'), ('IP Address', '192.168.0.1'), ('DNS', 'knownhost.foo'))},
            True,
            ['this_is_invalid.foo'],
            (None, None),
            [
                'Client certificate: ',
                'TLS version: ',
                'Cipher: ',
                "Connection rejected: host 'knownhost.foo' is not in allowed_hosts",
            ],
            id="fail_invalid_hostname_tls",
        ),
        pytest.param(
            True,
            ('this', 42),
            None,
            {'subjectAltName': (('IP Address', 'f800::1'), ('IP Address', '192.168.0.1'), ('DNS', 'knownhost.foo'))},
            True,
            ['this-is-invalid-.foo'],
            (None, None),
            [
                'Client certificate: ',
                'TLS version: ',
                'Cipher: ',
                "Connection rejected: host 'knownhost.foo' is not in allowed_hosts",
            ],
            id="fail_dash_hostname_tls",
        ),
    ],
)
def test_nrpe_server_accept_connection(
    tls, accept, wrap, cert, hostfilter, allowed_hosts, expected, logexp, mocker, server, caplog
):
    if len(expected) == 2:
        getaddrinfo = [socket.gaierror]
        ip_address = [ValueError, ValueError]
    else:
        getaddrinfo = expected[2]
        ip_address = expected[3]
    mocker.patch('nrpe.server.socket.getaddrinfo', side_effect=getaddrinfo)
    mocker.patch('nrpe.server.ipaddress.ip_address', side_effect=ip_address)
    mock_conn = mocker.Mock()
    server._socket.accept = mocker.Mock(side_effect=[(mock_conn, accept) if isinstance(accept, tuple) else accept])
    server._host_filtering = hostfilter
    server._block_all_hosts = allowed_hosts is None
    if allowed_hosts:
        server.server_config.allowed_hosts.extend(allowed_hosts)
    server.server_config.tls_enabled = tls
    if tls:
        server.context.wrap_socket.side_effect = [wrap or mock_conn]
        mock_conn.getpeercert.return_value = cert

    (conn, host) = server.accept_connection()

    assert (conn is None) == (expected[0] is None)
    assert host == expected[1]
    for text in logexp:
        assert text in caplog.text


@pytest.mark.parametrize(
    'cert, expected',
    [
        pytest.param({'subject': [(('commonName', 'knownhost'),)]}, 'knownhost', id="valid"),
        pytest.param({'subject': [(('commonName', 'unknown'),)]}, None, id="invalid"),
    ],
)
def test_nrpe_is_host_allowed_cert(cert, expected, mocker, server):
    server.server_config.allowed_hosts.append('knownhost')
    assert server.is_host_allowed_cert(cert) == expected


@pytest.mark.parametrize(
    'remote, gethostbyaddr, expected',
    [
        pytest.param('knownhost', None, 'knownhost', id="valid"),
        pytest.param('unknown', ('unknown', ['still_unknown'], []), None, id="unknown"),
        pytest.param('unknown', socket.herror, None, id="lookup_failed"),
        pytest.param('unknown', ('knownhost', [], []), 'knownhost', id="known_addr"),
        pytest.param('unknown', ('unknown', ['knownhost'], []), 'unknown (knownhost)', id="known_alias"),
    ],
)
def test_nrpe_is_host_allowed_no_cert(remote, gethostbyaddr, expected, mocker, server):
    mocker.patch('nrpe.server.socket.gethostbyaddr', side_effect=[gethostbyaddr])
    server.server_config.allowed_hosts.append('knownhost')
    assert server.is_host_allowed_no_cert(remote) == expected
    assert server.is_host_allowed_no_cert(remote) == expected


@pytest.mark.parametrize(
    'cert, expected',
    [
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
                'issuer': (
                    (('countryName', 'GB'),),
                    (('stateOrProvinceName', 'Greater Manchester'),),
                    (('localityName', 'Salford'),),
                    (('organizationName', 'Sectigo Limited'),),
                    (('commonName', 'Sectigo RSA Domain Validation Secure Server CA'),),
                ),
                'notBefore': 'Mar 14 00:00:00 2022 GMT',
                'notAfter': 'Apr  8 23:59:59 2023 GMT',
                'serialNumber': '447DF9B0AD5CE5C53AD321177A04386C',
                'subject': ((('commonName', '*.itrsgroup.com'),),),
                'version': 3,
                'subjectAltName': (('DNS', '*.itrsgroup.com'), ('DNS', 'itrsgroup.com')),
            },
            '*.itrsgroup.com, itrsgroup.com',
            id="known_host_CN_SAN_itrs",
        ),
        pytest.param(
            {
                'OCSP': ('http://r3.o.lencr.org',),
                'caIssuers': ('http://r3.i.lencr.org/',),
                'issuer': ((('countryName', 'US'),), (('organizationName', "Let's Encrypt"),), (('commonName', 'R3'),)),
                'version': 3,
                'serialNumber': '0438574CD328C56895F413F351823B2C624F',
                'notBefore': 'Jul 19 20:45:21 2022 GMT',
                'notAfter': 'Oct 17 20:45:20 2022 GMT',
                'subject': ((('commonName', 'www.opsview.com'),),),
                'subjectAltName': (('DNS', 'opsview.com'), ('DNS', 'www.opsview.com')),
            },
            'www.opsview.com, opsview.com',
            id="known_host_CN_SAN_opsview",
        ),
    ],
)
def test_nrpe_get_certificate_names(cert, expected, server):
    assert server.get_certificate_names(cert) == expected


def test_nrpe_server_get_packet_class(server):
    assert server.get_packet_class(None) == NRPEPacketV2


@pytest.mark.parametrize(
    'data, time, logexp',
    [
        pytest.param(
            [b'', None],
            [0] * 100,
            [' client] connection_handler started', ' client] Request error: No data received'],
            id="no_data",
        ),
        pytest.param(
            [b'foo', None],
            [0] * 100,
            [' client] connection_handler started', ' client] Preparing to execute packet '],
            id="not_much_data",
        ),
        pytest.param(
            [b'f' * 1024, b'o' * 42, None],
            [0] * 100,
            [' client] connection_handler started', ' client] Preparing to execute packet '],
            id="plenty_of_data",
        ),
        pytest.param(
            [SocketTimeout, b'f' * 1024, b'o' * 42, None],
            [0] * 100,
            [' client] connection_handler started', ' client] Preparing to execute packet '],
            id="slow_request",
        ),
        pytest.param(
            Exception,
            [0] * 100,
            [' client] connection_handler started', ' client] Request error: ', ' client] Releasing lock (error path)'],
            id="data_error",
        ),
        pytest.param(
            [b'f' * 1024, Exception('boom')],
            [0] * 100,
            [
                ' client] connection_handler started',
                ' client] Request error: boom',
                ' client] Releasing lock (error path)',
            ],
            id="more_data_error",
        ),
        pytest.param(
            [b'f' * 1024, b'o' * 42, None],
            [0, 10, 20, 30, 40, 50, 60, 70],
            [
                ' client] connection_handler started',
                ' client] Request error: Timed out waiting for client data',
                ' client] Releasing lock (error path)',
            ],
            id="timeout",
        ),
        pytest.param(ConnectionResetError, [0] * 100, ['Connection has been reset by client'], id="peer_reset"),
    ],
)
def test_nrpe_connection_handler(server, time, data, logexp, mocker, caplog):
    mock_connection = mocker.Mock()
    mock_connection.recv.side_effect = data
    mocker.patch('nrpe.server.NRPEPacketV2')
    mocker.patch('nrpe.server.time.time', side_effect=time)
    server.script_runner.run_script.return_value = (0, 'foo', 'bar', False)
    server.connection_handler(mock_connection, 'client', ('127.0.0.1', 12345))
    for text in logexp:
        assert text in caplog.text


@pytest.mark.parametrize(
    'stdout, stderr, exp_log',
    [
        pytest.param('', '', '[uuid client] 0, , , False', id="no output"),
        pytest.param('foo', '', '[uuid client] 0, foo, , False', id="stdout only"),
        pytest.param('', 'bar', '[uuid client] 0, , bar, False', id="stderr only"),
        pytest.param('foo', 'bar', '[uuid client] 0, foo, bar, False', id="stdout + stderr"),
    ],
)
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
        command_uuid=uuid.UUID('af11f2bb-2b70-4c61-8fb5-abf7e97c5a5c'),
        host='client',
        connection=mock_connection,
        result=mock_result,
        packet_class=NRPEPacketV2,
        allow_multi_packet_response=True,
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
    'running',
    [
        pytest.param(False, id="stopped"),
        pytest.param(True, id="running"),
    ],
)
def test_nrpe_is_running(running, server):
    server._running = running
    assert server.is_running() == running


@pytest.mark.parametrize(
    'func, error, expected',
    [
        pytest.param('foo', False, '', id="success"),
        pytest.param(Exception('bar'), True, 'Error thrown for mock_func (bar)', id="error"),
    ],
)
def test_nrpe_gproxy(func, error, expected, server, mocker, caplog):
    mock_func = mocker.Mock(side_effect=[func], __name__='mock_func')
    if not error:
        server._gproxy(mock_func)
    else:
        with pytest.raises(Exception):
            server._gproxy(mock_func)
    assert mock_func.called
    assert expected in caplog.text
