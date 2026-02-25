"""
Infrastructure Agent: Unit tests for nrpe server
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

import socket
import ssl
import uuid

import mock
import pytest

from nrpe.packet import NRPEPacketV2
from nrpe.server import NRPEListener, is_valid_hostname, _match_hostname


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


@pytest.mark.parametrize('hostname, expected', [
    pytest.param('foo', True, id="bare_hostname"),
    pytest.param('foo.bar', True, id="FQDN"),
    pytest.param('opsview@foo.bar', False, id="email_address"),
    pytest.param('-99.red.balloons', False, id="leading_hyphen"),
    pytest.param('99-.red.balloons', False, id="trailing_hyphen_hostname"),
    pytest.param('99.red.balloons-', False, id="trailing_hyphen_domain"),
    pytest.param('a123456789SixtyThreeCharacters0123456789012345678901234567890xy.foo', True, id="63_char_hostname"),
    pytest.param('a123456789SixtyFourCharacters90123456789012345678901234567890xyz.foo', False, id="64_char_hostname"),
    pytest.param(
        'this.is.a.very.long.hostname.just.to.test.that.the.code.for.detecting.long.hostnames.actually.works.as'
        '.expected.I.think.Im.going.to.need.to.repeat.this.as.it.is.not.long.enough.even.now.this.is.a.very'
        '.long.hostname.just.to.test.that.the.code.for.detecting', True, id="255_char_FQDN",
        # actually there is an implied trailing . so this is really a 256 char FQDN
    ),
    pytest.param(
        'this.is.a.very.long.hostname.just.to.test.that.the.code.for.detecting.long.hostnames.actually.works.as'
        '.expected.I.think.Im.going.to.need.to.repeat.this.as.it.is.not.long.enough.even.now.this.is.a.very'
        '.long.hostname.just.to.test.that.the.code.for.detecting0', False, id="256_char_FQDN"),
])
def test_is_valid_hostname(hostname, expected):
    assert is_valid_hostname(hostname) == expected


@pytest.mark.parametrize('cert, hostname, resolved_ips, expected', [
    pytest.param(
        {'subject': ((('commonName', 'hostname.match'),),), 'subjectAltName': (('DNS', 'fred.foo'),)},
        'hostname.match', [], True, id="CN_match"),
    pytest.param(
        {'subject': ((('commonName', '1.2.3.4'),),), 'subjectAltName': (('DNS', 'fred.foo'),)},
        '1.2.3.4', [], True, id="CN_match_IP"),
    pytest.param(
        {'subject': ((('commonName', 'fred'),),), 'subjectAltName': (('DNS', 'hostname.match'),)},
        'hostname.match', [], True, id="SAN_DNS_match"),
    pytest.param(
        {'subject': ((('commonName', 'fred'),),), 'subjectAltName': (('IP Address', '1.2.3.4'),)},
        '1.2.3.4', [], True, id="SAN_IP_address_match"),
    pytest.param(
        {'subject': ((('commonName', 'fred'),),), 'subjectAltName': (('IP Address', '9.8.7.6'),)},
        '1.2.3.4', ['9.8.7.6'], True, id="SAN_IP_address_match_resolved_address"),
    pytest.param(
        {'subject': ((('commonName', 'fred'),),), 'subjectAltName': (('DNS', '9.8.7.6'),)},
        '1.2.3.4', ['9.8.7.6'], False, id="SAN_DNS_resolved_address"),
    pytest.param(
        {'subject': ((('commonName', '9.8.7.6'),),), 'subjectAltName': (('IP Address', '5.6.7.8'),)},
        '1.2.3.4', ['9.8.7.6'], False, id="CN_resolved_address"),
    pytest.param(
        {'subject': ((('commonName', '*.hostname.match'),),), 'subjectAltName': (('DNS', 'fred.foo'),)},
        'foo.hostname.match', [], True, id="CN_wildcard_match"),
    pytest.param(
        {'subject': ((('commonName', 'fred'),),), 'subjectAltName': (('DNS', '*.hostname.match'),)},
        'foo.hostname.match', [], True, id="SAN_DNS_wildcard_match"),
    pytest.param(
        {'subject': ((('commonName', 'fred'),),), 'subjectAltName': (('DNS', '*.hostname.match'),)},
        'foo.match.hostname', [], False, id="SAN_DNS_no_wildcard_match"),
])
def test_match_hostname(cert, hostname, resolved_ips, expected):
    assert _match_hostname(cert, hostname, resolved_ips) == expected


@pytest.mark.parametrize(
    'allowed_hosts, tls, check_client_cert, context, windows, filtering, exception, logexp',
    [
        pytest.param(
            None, False, False, None, False, True, None,
            ["'allowed_hosts' is currently null, which blocks any host from connecting"],
            id="allowed_hosts_not_configured",
        ),
        pytest.param(
            [], False, None, False, False, False, None,
            ['NRPE server allows connections from any host. This is not recommended'],
            id="filtering_disabled",
        ),
        pytest.param(
            ['ok-host'], False, False, None, False, True, None,
            ['NRPE server allows connections from: ok-host'],
            id="filtering_one_host_no_tls_no_check_client_cert",
        ),
        pytest.param(
            ['ok-host', '10.0.1.42', 'opsview.com'], False, False, None, False, True, None,
            [],
            id="filtering_many_hosts_no_tls_no_check_client_cert",
        ),
        pytest.param(
            ['ok-host'], False, True, None, False, True, None,
            ['NRPE server allows connections from: ok-host'],
            id="filtering_one_host_no_tls_yes_check_client_cert",
        ),
        pytest.param(
            ['ok-host', '10.0.1.42', 'opsview.com'], False, True, None, False, True, None,
            [],
            id="filtering_many_hosts_no_tls_yes_check_client_cert",
        ),
        pytest.param(
            ['ok-host'], True, True, None, False, True, None,
            ['NRPE server allows connections from: ok-host'],
            id="filtering_one_host_yes_tls_yes_check_client_cert",
        ),
        pytest.param(
            ['ok-host', '10.0.1.42', '10.0.1.43', 'opsview.com'], True, True, None, False, True, None,
            ["'check_client_cert' is enabled. Any IP addresses configured in 'allowed_hosts' will be ignored."],
            id="filtering_many_hosts_yes_tls_yes_check_client_cert",
        ),
        pytest.param(
            [], False, False, None, False, False, None,
            ['NRPE server running with TLS disabled. This is not recommended'],
            id="no_tls",
        ),
        pytest.param([], True, False, [mock.Mock()], False, False, None, ['with TLS'], id="tls_linux"),
        pytest.param([], True, False, [mock.Mock()], True, False, None, ['with TLS'], id="tls_windows"),
        pytest.param(
            [], True, False, False, True, False, Exception,
            ['with TLS', 'Error setting up SSL Context'],
            id="context_error",
        ),
        pytest.param(
            [
                'this.is.a.very.long.hostname.just.to.test.that.the.code.for.detecting.long.hostnames.actually.works.as'
                '.expected.I.think.Im.going.to.need.to.repeat.this.as.it.is.not.long.enough.even.now.this.is.a.very'
                '.long.hostname.just.to.test.that.the.code.for.detecting.long.hostnames.works'
            ],
            True, False, None, True, True, None,
            [],
            id="very_long_allowed_host_name",
        ),
    ],
)
def test_nrpe_server_post_init(
        allowed_hosts, tls, check_client_cert, context, windows, filtering, exception,
        logexp, mocker, server, platform_win, caplog,
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


@pytest.mark.parametrize('tls, check_cert, allowed_hosts, getaddr, expected, logexp', [
    pytest.param(False, False, [], None, {}, '', id="no_allowed_hosts"),
    pytest.param(True, True, [], None, {}, '', id="no_allowed_hosts"),
    pytest.param(True, True, ['host.foo'], socket.gaierror, {'host.foo': []}, '', id="addr_lookup_fail"),
    pytest.param(
        True, True, ['opsera.com'], [[
            (2, 1, 6, '', ('23.253.127.84', 0)),
            (2, 2, 17, '', ('23.253.127.84', 0)),
            (2, 3, 0, '', ('23.253.127.84', 0))]],
        {'opsera.com': ['23.253.127.84']},
        'NRPE server allows connections from: opsera.com',
        id="many_duplicate_ips"),
    pytest.param(
        True, True, ['opsera.com'], [[
            (2, 1, 6, '', ('23.253.127.84', 0)),
            (2, 2, 17, '', ('23.253.127.85', 0)),
            (2, 3, 0, '', ('23.253.127.84', 0))]],
        {'opsera.com': ['23.253.127.84', '23.253.127.85']},
        'NRPE server allows connections from: opsera.com',
        id="some_duplicate_ips"),
    pytest.param(
        True, True, ['opsera.com', '1.2.3.4'], [[
            (2, 1, 6, '', ('23.253.127.84', 0)),
            (2, 2, 17, '', ('23.253.127.85', 0)),
            (2, 3, 0, '', ('23.253.127.84', 0))]],
        {'opsera.com': ['23.253.127.84', '23.253.127.85']},
        [
            "Ignoring '1.2.3.4' from allowed_hosts",
            'NRPE server allows connections from: opsera.com',
            "Any IP addresses configured in 'allowed_hosts' will be ignored.",
        ],
        id="IPs_in_allowed_hosts_ignored"),
    pytest.param(
        True, False, ['opsera.com', '1.2.3.4'], [[
            (2, 1, 6, '', ('23.253.127.84', 0)),
            (2, 2, 17, '', ('23.253.127.85', 0)),
            (2, 3, 0, '', ('23.253.127.84', 0))]],
        {'opsera.com': ['23.253.127.84', '23.253.127.85'], '1.2.3.4': ['1.2.3.4']},
        [
            'NRPE server allows connections from: opsera.com',
            'NRPE server allows connections from: 1.2.3.4',
        ],
        id="IPs_in_allowed_hosts_allowed"),
])
def test_nrpe_server_initialise_allowed_hosts(
        tls, check_cert, allowed_hosts, getaddr,
        expected, logexp,
        mocker, server, caplog,
):
    server.server_config.tls_enabled = tls
    server.server_config.tls.check_client_cert = check_cert
    server.server_config.allowed_hosts = allowed_hosts
    mocker.patch('nrpe.server.socket.getaddrinfo', side_effect=getaddr)
    server._initialise_allowed_hosts()
    assert len(server._allowed_hosts) == len(expected)
    for key, value in expected.items():
        assert key in server._allowed_hosts
        server._allowed_hosts[key].sort()
        assert server._allowed_hosts[key] == expected[key]
    if isinstance(logexp, list):
        for logentry in logexp:
            assert logentry in caplog.text
    else:
        assert logexp in caplog.text


@pytest.mark.parametrize('lock, accept_connection, spawn, exception, logexp', [
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
    'tls, accept, wrap, cert, hostfilter, check_client_cert, allowed_hosts, expected, logexp',
    [
        pytest.param(
            True, ssl.SSLError, None, None, None, None, {'knownhost.foo': []},
            (None, None), ['SSL Handshake error'],
            id="ssl_error"),
        pytest.param(
            True, socket.error, None, None, None, None, {'knownhost.foo': []},
            (None, None), ['Socket error'],
            id="socket_error"),
        pytest.param(
            True, socket.gaierror, None, None, None, None, {'knownhost.foo': []},
            (None, None), ['Socket error'],
            id="socket_gaierror"),
        pytest.param(
            True, ('knownhost', 42), SocketTimeout, None, None, None, {'knownhost.foo': []},
            (None, None), ['SSL Handshake timeout'],
            id="ssl_handshake_timeout"),
        pytest.param(
            False, ('knownhost.foo', 42), None, None, True, False, {'knownhost.foo': []},
            (True, 'knownhost.foo'),
            [
                "Host 'knownhost.foo' allowed",
                "Connection accepted from: 'knownhost.foo'",
            ],
            id="success_no_tls"),
        pytest.param(
            True, ('knownhost.foo', 42), None,
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
            True, False, {'knownhost.foo': []},
            (True, 'known.foo'),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Host 'knownhost.foo' allowed", "Connection accepted from: 'known.foo'",
            ],
            id="success_tls"),
        pytest.param(
            True, ('knownhost.foo', 42), None,
            {
                'subject': [
                    (('commonName', 'opsview@known.foo'),),
                    (
                        ('foo', 'bar'),
                        ('commonName', 'opsview@knownhost.foo'),
                        ('foo', 'bar'),
                    ),
                ]
            },
            True, False, {'opsview@knownhost.foo': []},
            (True, 'opsview@known.foo'),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Host 'opsview@knownhost.foo' allowed", "Connection accepted from: 'opsview@known.foo'",
            ],
            id="success_tls_not_a_hostname"),
        pytest.param(
            True, ('knownhost.foo', 42), None, {'subjectAltName': (('DNS', '*.*.foo'),)}, True, False, None,
            (None, None), ["Connection rejected: host 'knownhost.foo', as currently blocking all hosts"],
            id="block_all_hosts"),
        pytest.param(
            True, ('knownhost.foo', 42), None,
            {'subjectAltName': (('DNS', ''), ('DNS', '*.foo'), ('IP Address', '192.168.0.1'))},
            True, False, {'knownhost.foo': []},
            (True, ', *.foo'),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Host 'knownhost.foo' allowed", "Connection accepted from: ', *.foo'",
            ],
            id="success_tls_wildcard"),
        pytest.param(
            True, ('knownhost.foo', 42), None, {'subjectAltName': (('DNS', '*.*.foo'),)}, True, False,
            {'knownhost.foo': []},
            (None, None), ["Connection rejected: host '*.*.foo' is not in allowed_hosts"],
            id="fail_tls_wildcard_too_many"),
        pytest.param(
            True, ('knownhost.foo', 42), None, {'subjectAltName': (('DNS', 'bar.*.foo'),)}, True, True,
            {'knownhost.foo': []},
            (None, None), ["Connection rejected: host 'bar.*.foo' is not in allowed_hosts"],
            id="fail_tls_wildcard_not_start"),
        pytest.param(
            True, ('knownhost.foo', 42), None, {'subjectAltName': (('DNS', '*'),)}, True, False, {'knownhost.foo': []},
            (None, None), ["Connection rejected: host '*' is not in allowed_hosts"],
            id="fail_tls_wildcard_no_sep"),
        pytest.param(
            True, ('knownhost.foo', 42), None, {'subjectAltName': (('DNS', 'bad*.foo'),)}, True, False,
            {'knownhost.foo': []},
            (None, None), ["Connection rejected: host 'bad*.foo' is not in allowed_hosts"],
            id="fail_tls_wildcard_bad"),
        pytest.param(
            True, ('192.168.0.1', 42), None,
            {'subjectAltName': (('IP Address', 'f800::1'), ('IP Address', '192.168.0.1'), ('DNS', 'knownhost.foo'))},
            True, True, {'another.name': ['192.168.0.1']},
            (True, 'knownhost.foo', [socket.gaierror], ['192.168.0.1']),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Host 'another.name' allowed", "Connection accepted from: 'knownhost.foo'",
            ],
            id="success_tls_ip"),
        pytest.param(
            True, ('192.168.0.1', 42), None,
            {'subjectAltName': (('IP Address', 'f800::1'), ('IP Address', '192.168.0.2'), ('DNS', 'knownhost.foo'))},
            True, False, {'192.168.0.1': ['192.168.0.1']},
            (None, None, [socket.gaierror], ['192.168.0.1']),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Connection rejected: host 'knownhost.foo' is not in allowed_hosts"
            ],
            id="fail_tls_ip"),
        pytest.param(
            True, ('knownhost.foo', 42), None, {'empty': ()}, True, False, {'knownhost.foo': []},
            (None, None), ["Connection rejected: host '' is not in allowed_hosts"],
            id="fail_empty_cert"),
        pytest.param(
            True, ('knownhost.foo', 42), None, None, True, False, {'knownhost.foo': []},
            (True, 'knownhost.foo'),
            [
                "Host 'knownhost.foo' allowed", "Connection accepted from: 'knownhost.foo'",
            ],
            id="success_tls_no_certificate"),
        pytest.param(
            True, ('knownhost.foo', 42), None, None, True, True, {'knownhost.foo': []},
            (None, None), ['Connection from knownhost.foo: no client certificate received'],
            id="fail_tls_no_certificate_but_client_cert_reqd"),
        pytest.param(
            False, ('unknown', 42), None, None, True, False, {'knownhost.foo': []},
            (None, None), ["Connection rejected: host 'unknown' is not in allowed_hosts"],
            id="fail_host_filtering_no_tls"),
        pytest.param(
            True, ('unknown', 42), None, {'subject': ((('commonName', 'unknown.foo'),),)}, True, False,
            {'knownhost.foo': []},
            (None, None),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Connection rejected: host 'unknown.foo' is not in allowed_hosts",
            ],
            id="fail_host_filtering_tls"),
        pytest.param(
            True, ('unknown', 42), None,
            {'subject': ((('commonName', 'unknown.foo'),), (('commonName', 'foo.bar'),))},
            True, False, {'knownhost.foo': []},
            (None, None),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Connection rejected: host 'unknown.foo, foo.bar' is not in allowed_hosts",
            ],
            id="fail_host_filtering_tls_multi"),
        pytest.param(
            False, ('unknown', 42), None, None, False, False, {'knownhost.foo': []},
            (True, 'unknown'), ["Connection accepted from: 'unknown'"],
            id="success_no_host_filtering_no_tls"),
        pytest.param(
            True, ('unknown', 42), None, {'subject': ((('commonName', 'unknown.foo'),),)}, False, False,
            {'knownhost.foo': []},
            (True, 'unknown.foo'),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Connection accepted from: 'unknown.foo'",
            ],
            id="success_no_host_filtering_tls"),
        pytest.param(
            True, ('this', 42), None,
            {'subjectAltName': (('IP Address', 'f800::1'), ('IP Address', '192.168.0.1'), ('DNS', 'knownhost.foo'))},
            True, False, {'this_is_invalid.foo': []},
            (None, None),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Connection rejected: host 'knownhost.foo' is not in allowed_hosts",
            ],
            id="fail_invalid_hostname_tls"),
        pytest.param(
            True, ('this', 42), None,
            {'subjectAltName': (('IP Address', 'f800::1'), ('IP Address', '192.168.0.1'), ('DNS', 'knownhost.foo'))},
            True, False, {'this-is-invalid-.foo': []},
            (None, None),
            [
                'Client certificate: ', 'TLS version: ', 'Cipher: ',
                "Connection rejected: host 'knownhost.foo' is not in allowed_hosts",
            ],
            id="fail_dash_hostname_tls"),
    ],
)
def test_nrpe_server_accept_connection(
        tls, accept, wrap, cert, hostfilter, check_client_cert, allowed_hosts,
        expected, logexp,
        mocker, server, caplog,
):
    mock_conn = mocker.Mock()
    server._socket.accept = mocker.Mock(side_effect=[(mock_conn, accept) if isinstance(accept, tuple) else accept])
    server._host_filtering = hostfilter
    server.server_config.tls.check_client_cert = check_client_cert
    server._block_all_hosts = allowed_hosts is None
    if allowed_hosts:
        server.server_config.allowed_hosts.extend([host for host in allowed_hosts.keys()])
        server._allowed_hosts = allowed_hosts
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
    server._allowed_hosts['knownhost'] = []
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
