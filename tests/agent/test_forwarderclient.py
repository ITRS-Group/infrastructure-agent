"""
Infrastructure Agent: Unit tests for forwarderclient
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

import base64
import pytest

from agent.config import ForwarderClientConfig
from agent.forwarderclient import ForwarderClient
from gevent.queue import Empty

PATCH_PREFIX = 'agent.forwarderclient.'


@pytest.fixture
def client(agent_config, mocker) -> ForwarderClient:
    config = ForwarderClientConfig(
        host='Host', port=1234, tls_enabled=False)
    client_fix = ForwarderClient('TestClient', config)
    yield client_fix


@pytest.mark.parametrize(
    'user, password, tls_enabled, idle_timeout, expected_headers, expected_idle_nospawn_secs', [
        pytest.param(
            None, None, False, ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS,
            {'Content-Type': 'application/json'},
            ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS // ForwarderClient.NOSPAWN_IDLE_DIVISOR,
            id="tcp"),
        pytest.param(
            None, None, True, ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS,
            {'Content-Type': 'application/json'},
            ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS // ForwarderClient.NOSPAWN_IDLE_DIVISOR,
            id="tls_no_credentials"),
        pytest.param(
            'User', None, True, ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS,
            {'Content-Type': 'application/json'},
            ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS // ForwarderClient.NOSPAWN_IDLE_DIVISOR,
            id="tls_no_password"),
        pytest.param(
            None, 'TopSecret', True, ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS,
            {'Content-Type': 'application/json'},
            ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS // ForwarderClient.NOSPAWN_IDLE_DIVISOR,
            id="tls_no_username"),
        pytest.param(
            'User', 'TopSecret', True, ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS,
            {
                'Content-Type': 'application/json',
                'Authorization': 'Basic ' +
                    base64.encodebytes('User:TopSecret'.encode('utf-8')).decode('utf-8').strip(),
            }, ForwarderClientConfig.MIN_IDLE_TIMEOUT_SECS // ForwarderClient.NOSPAWN_IDLE_DIVISOR,
            id="tls"),
        pytest.param(
            None, None, False, ForwarderClient.MAX_IDLE_NOSPAWN_SECS - 1,
            {'Content-Type': 'application/json'},
            (ForwarderClient.MAX_IDLE_NOSPAWN_SECS - 1) // ForwarderClient.NOSPAWN_IDLE_DIVISOR,
            id="idle_less_than_max"),
        pytest.param(
            None, None, False, (ForwarderClient.MAX_IDLE_NOSPAWN_SECS * ForwarderClient.NOSPAWN_IDLE_DIVISOR) - 1,
            {'Content-Type': 'application/json'},
            ForwarderClient.MAX_IDLE_NOSPAWN_SECS - 1,
            id="idle_less_than_max"),
        pytest.param(
            None, None, False, (ForwarderClient.MAX_IDLE_NOSPAWN_SECS * ForwarderClient.NOSPAWN_IDLE_DIVISOR) + 1,
            {'Content-Type': 'application/json'},
            ForwarderClient.MAX_IDLE_NOSPAWN_SECS,
            id="idle_more_than_max"),
    ])
def test_forwarderclient_init(
        user, password, tls_enabled, idle_timeout,
        expected_headers, expected_idle_nospawn_secs, agent_config,
):
    config = ForwarderClientConfig(
        host='Host', port=1234, user=user, password=password, tls_enabled=tls_enabled, idle_timeout=idle_timeout)
    client = ForwarderClient('TestClient', config)
    assert client._headers == expected_headers
    assert client._idle_nospawn_secs == expected_idle_nospawn_secs


def test_forwarderclient_queue_result(client, mocker, caplog):
    mocker.patch.object(client, '_send_queue')
    client.queue_result('host', 'service', 2, 'output', 42)
    assert \
        "ForwarderClient: Queuing result for host='host', service='service'," \
        " status=2, output='output', result_time=42" \
        in caplog.text


@pytest.mark.parametrize('send_result_batch, logexp', [
    pytest.param([None], '', id="success"),
    pytest.param(Exception, 'ForwarderClient: Error sending batch to forwarder', id="batch_exception"),
    pytest.param(BaseException, 'ForwarderClient: Unexpected error sending batch to forwarder', id="batch_error"),
])
def test_forwarderclient_queue_puller(send_result_batch, logexp, mocker, client, caplog):
    mocker.patch.object(client, '_send_result_batch', side_effect=send_result_batch)
    mocker.patch(PATCH_PREFIX + 'gevent.sleep')
    mock_queue = mocker.patch.object(client, '_send_queue')
    mock_queue.get.side_effect = [1, StopIteration]
    mock_queue.get_nowait.side_effect = [1, Empty]
    with pytest.raises(StopIteration):
        client._queue_puller()
    assert logexp in caplog.text


@pytest.mark.parametrize('connected, resp_code, resp_data, logexp', [
    pytest.param(False, 200, None, 'ForwarderClient: Sending results batch (size=1) ', id="connect_success"),
    pytest.param(True, 200, None, 'ForwarderClient: Sending results batch (size=1) ', id="connected_success"),
    pytest.param(True, 500, b'[data]', 'ForwarderClient: Response from forwarder: 500 [data]', id="error_json"),
    pytest.param(True, 500, b'foo-bar', 'ForwarderClient: Response from forwarder: 500 foo-bar', id="error_text"),
])
def test_forwarderclient_send_result_batch(connected, resp_code, resp_data, logexp, mocker, client, caplog):
    mock_resp = mocker.Mock()
    mock_resp.status_code = resp_code
    mock_resp.read.return_value = resp_data
    mock_conn = mocker.Mock()
    mock_conn.request.return_value = mock_resp
    if connected:
        client._client = mock_conn
    else:
        mocker.patch.object(client, '_connect', return_value=mock_conn)
    mocker.patch.object(client, '_reset_idle_timer')
    client._send_result_batch([mocker.Mock(host='host', service='serv', status=0, output='out', result_time=99)])
    assert logexp in caplog.text


@pytest.mark.parametrize('idle_timer, now, created, nospawn, expected, logexp', [
    pytest.param(False, 100, 99, 50, 99, '', id="no_action"),
    pytest.param(False, 100, 40, 50, 100, 'ForwarderClient: Resetting idle timeout to 42 seconds', id="created"),
    pytest.param(True, 100, 40, 50, 100, 'ForwarderClient: Resetting idle timeout to 42 seconds', id="kill"),
])
def test_forwarderclient_reset_idle_timer(
        idle_timer, now, created, nospawn, expected, logexp, mocker, client, caplog
):
    mocker.patch(PATCH_PREFIX + 'time.time', return_value=now)
    mocker.patch(PATCH_PREFIX + 'gevent.spawn_later')
    if idle_timer:
        client._idle_timer = mocker.Mock()
    client._idle_timer_created = created
    client._idle_nospawn_secs = nospawn
    client._idle_timeout = 42
    client._reset_idle_timer()
    assert logexp in caplog.text
    assert client._idle_timer_created == expected


def test_forwarderclient_on_idle_timeout(mocker, client, caplog):
    mock_close = mocker.patch.object(client, '_close_connection')
    client._on_idle_timeout()
    assert 'ForwarderClient: Idle timeout occurred, closing client' in caplog.text
    mock_close.assert_called()


def test_forwarderclient_connect(mocker, client, caplog):
    mock_httpclient = mocker.Mock()
    mocker.patch(PATCH_PREFIX + 'HTTPClient', return_value=mock_httpclient)
    assert client._connect() == mock_httpclient
    assert 'ForwarderClient: Connecting to forwarder' in caplog.text


@pytest.mark.parametrize('puller, idle_timer', [
    (False, False),
    (False, True),
    (True, False),
    (True, True),
])
def test_forwarderclient_close(puller, idle_timer, mocker, client):
    mock_puller = mocker.Mock() if puller else None
    client._puller = mock_puller
    mock_idle_timer = mocker.Mock() if idle_timer else None
    client._idle_timer = mock_idle_timer
    mock_close_conn = mocker.patch.object(client, '_close_connection')
    client.close()
    if puller:
        mock_puller.kill.assert_called()
    if idle_timer:
        mock_idle_timer.kill.assert_called()
    assert client._puller is None
    assert client._idle_timer is None
    mock_close_conn.assert_called()


@pytest.mark.parametrize('client_conn, logexp', [
    (False, ''),
    (True, 'ForwarderClient: Closing connection to forwarder'),
])
def test_forwarderclient_close_connection(client_conn, logexp, mocker, client, caplog):
    mock_conn = mocker.Mock()
    if client_conn:
        client._client = mock_conn
    client._close_connection()
    assert mock_conn.close.called == client_conn
    assert client._client is None
    assert logexp in caplog.text
