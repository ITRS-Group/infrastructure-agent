"""
Infrastructure Agent: Unit tests for cachemanager
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

import pytest
from mock import call

from agent.cachemanager import Cache
from cache.exceptions import ClientApiError, ServerApiError


@pytest.fixture
def cache(agent_config, mocker) -> Cache:
    mock_encoder = mocker.Mock()
    cache_fix = Cache(agent_config.cachemanager, mock_encoder)
    yield cache_fix


def test_cachemanager_init(cachemanager):
    assert cachemanager._config.port == 8183


def test_cachemanager_get_env(cachemanager, mocker):
    mocker.patch('agent.cachemanager.time.time', return_value=42.123)
    assert cachemanager.get_env('foo') == {
        'OPSVIEW_CACHE_MANAGER_NAMESPACE': b'ENC: namespace=PLUGIN#foo&timestamp=42',
        'OPSVIEW_CACHE_MANAGER_HOST': '127.0.0.1',
        'OPSVIEW_CACHE_MANAGER_PORT': '8183',
    }


def test_cachemanager_get_cache(cachemanager):
    assert cachemanager.get_cache() == cachemanager._cache


@pytest.mark.parametrize(
    'tls_enabled, get_context, exception', [
        pytest.param(False, None, None, id="no_tls"),
        pytest.param(True, [None], None, id="tls"),
        pytest.param(True, Exception, Exception, id="tls_error"),
    ])
def test_cachemanager_run(tls_enabled, get_context, exception, cachemanager, mocker):
    mock_gevent = mocker.patch('agent.cachemanager.gevent')
    mocker.patch('agent.cachemanager.WSGIServer')
    mocker.patch('agent.cachemanager.get_ssl_context', side_effect=get_context)
    cachemanager._config.tls_enabled = tls_enabled
    if not exception:
        cachemanager.run()
        assert mock_gevent.spawn.called
    else:
        with pytest.raises(exception):
            cachemanager.run()


@pytest.mark.parametrize(
    'agent', [
        pytest.param(False, id="no_agent"),
        pytest.param(True, id="agent"),
    ])
def test_cachemanager_shutdown(agent, cachemanager, mocker):
    if agent:
        cachemanager.agent = mocker.Mock()
    cachemanager._shutdown()
    if agent:
        assert cachemanager.agent.stop.called


@pytest.mark.parametrize(
    'environ, raw_data, rsp_exp, start_exp', [
        pytest.param(
            {'REQUEST_METHOD': 'GET', 'PATH_INFO': '/'}, b'"bar"',
            [b'ITRS Group Cache Manager API'],
            [call('200 OK', [('Content-Type', 'text/text')])],
            id="get_webroot"),
        pytest.param(
            {'REQUEST_METHOD': 'GET', 'PATH_INFO': '/status'}, b'"bar"',
            [
                b'{"ref": "42", "uptime": 2, "peers": [],'
                b' "cache_items": 0, "cache_size": 0, "cache_percent": 0.0, "max_item_size": 0}'
            ],
            [call('200 OK', [('Content-Type', 'application/json')])],
            id="get_status"),
        pytest.param(
            {'REQUEST_METHOD': 'POST', 'PATH_INFO': '/'}, b'"bar"',
            [b'ITRS Group Cache Manager API'],
            [call('200 OK', [('Content-Type', 'text/text')])],
            id="post_webroot"),
        pytest.param(
            {'REQUEST_METHOD': 'POST', 'PATH_INFO': '/get_data'}, b'"bar"',
            [b'{"data": "foo", "lock": "bar", "expiry": 42}'],
            [],
            id="post_get_data"),
        pytest.param(
            {'REQUEST_METHOD': 'POST', 'PATH_INFO': '/set_data'}, b'"bar"',
            [b'"ok"'],
            [call('200 OK', [('Content-Type', 'application/json')])],
            id="post_set_data"),
        pytest.param({'REQUEST_METHOD': 'GET', 'PATH_INFO': '/foo'}, None, [], None, id="get_invalid_request"),
        pytest.param({'REQUEST_METHOD': 'POST', 'PATH_INFO': '/foo'}, b'"bar"', [], None, id="post_invalid_request"),
        pytest.param({'REQUEST_METHOD': 'PUT', 'PATH_INFO': '/'}, None, [], None, id="put_invalid_request"),
    ])
def test_cachemanager_handler(environ, raw_data, rsp_exp, start_exp, cachemanager, mocker):
    cachemanager._time_start = 42.0
    mocker.patch('agent.cachemanager.time.time', return_value=44.123)
    environ['wsgi.input'] = mocker.Mock()
    environ['wsgi.input'].read = mocker.Mock(return_value=raw_data)
    cachemanager._cache.get_data = mocker.Mock(return_value=('foo', 'bar', 42))
    cachemanager._cache.set_data = mocker.Mock(return_value='fubar')
    mock_start = mocker.Mock()
    rsp = cachemanager._handler(environ, mock_start)
    assert rsp == rsp_exp
    if start_exp:
        assert mock_start.call_args_list == start_exp


def test_cachemanager_json_response(cachemanager, mocker):
    mock_start = mocker.Mock()
    rsp = cachemanager.json_response(mock_start, 'foo')
    assert mock_start.call_count == 1
    assert mock_start.call_args_list == [call('200 OK', [('Content-Type', 'application/json')])]
    assert rsp == [b'"foo"']


def test_cachemanager_error_response(cachemanager, mocker):
    mock_start = mocker.Mock()
    rsp = cachemanager.error_response(mock_start, '500 Server Error')
    assert mock_start.call_count == 1
    assert mock_start.call_args_list == [call('500 Server Error', [('Content-Type', 'text/text')])]
    assert rsp == []


def test_cachemanager_handle_webroot(cachemanager, mocker):
    mock_start = mocker.Mock()
    rsp = cachemanager.handle_webroot(mock_start)
    assert mock_start.call_count == 1
    assert mock_start.call_args_list == [call('200 OK', [('Content-Type', 'text/text')])]
    assert rsp == [b'ITRS Group Cache Manager API']


@pytest.mark.parametrize(
    'get_data, expected', [
        pytest.param(('foo', 'bar', 42), [b'{"data": "foo", "lock": "bar", "expiry": 42}'], id="success"),
        pytest.param(
            ServerApiError('foo'), [call('500 Server Error', [('Content-Type', 'text/text')])],
            id="server_api_error"),
        pytest.param(Exception(), [call('400 Invalid Request', [('Content-Type', 'text/text')])], id="other_error"),
    ])
def test_cachemanager_handle_get_data(get_data, expected, cachemanager, mocker):
    cachemanager._cache.get_data = mocker.Mock(side_effect=[get_data])
    mock_start = mocker.Mock()
    rsp = cachemanager.handle_get_data(mock_start, 'wibble')
    if isinstance(get_data, Exception):
        assert mock_start.call_args_list == expected
    else:
        assert rsp == expected


@pytest.mark.parametrize(
    'set_data, expected', [
        pytest.param('foo', [b'"ok"'], id="success"),
        pytest.param(
            ServerApiError('foo'), [call('500 Server Error', [('Content-Type', 'text/text')])],
            id="server_api_error"),
        pytest.param(Exception(), [call('400 Invalid Request', [('Content-Type', 'text/text')])], id="other_error"),
    ])
def test_cachemanager_handle_set_data(set_data, expected, cachemanager, mocker):
    cachemanager._cache.set_data = mocker.Mock(side_effect=[set_data])
    mock_start = mocker.Mock()
    rsp = cachemanager.handle_set_data(mock_start, 'wibble')
    if isinstance(set_data, Exception):
        assert mock_start.call_args_list == expected
    else:
        assert rsp == expected


def test_cachemanager_handle_status(cachemanager, mocker):
    cachemanager._time_start = 42.0
    mocker.patch('agent.cachemanager.time.time', return_value=44.123)
    mock_start = mocker.Mock()
    rsp = cachemanager.handle_status(mock_start)
    assert rsp == [
        b'{"ref": "42", "uptime": 2, "peers": [],'
        b' "cache_items": 0, "cache_size": 0, "cache_percent": 0.0, "max_item_size": 0}'
    ]


def test_cachemanager_housekeeping(cachemanager, mocker):
    def _stop_cm(_sleep):
        cachemanager._running = False

    mock_cache = mocker.Mock()
    cachemanager._cache = mock_cache
    cachemanager._running = True
    mock_sleep = mocker.patch('agent.cachemanager.gevent.sleep', side_effect=_stop_cm)
    cachemanager.housekeeping(42)
    mock_sleep.assert_called_with(42)
    assert mock_cache.housekeeping.called


@pytest.mark.parametrize(
    'func, error', [
        pytest.param('foo', False, id="success"),
        pytest.param(Exception('bar'), True, id="error"),
    ])
def test_cachemanager_gproxy(func, error, cachemanager, mocker):
    mock_func = mocker.Mock(side_effect=[func], __name__='mock_func')
    cachemanager._shutdown = mocker.Mock()
    cachemanager._gproxy(mock_func)
    assert cachemanager._shutdown.called == error


def test_cache_get_locking_cache(cache):
    assert cache.get_locking_cache() == cache._cache


@pytest.mark.parametrize(
    'params, exception', [
        pytest.param({'namespace': 'NS', 'key': 'KY'}, False, id="success"),
        pytest.param({'key': 'KY'}, True, id="missing_namespace"),
        pytest.param({'namespace': 'NS'}, True, id="missing_key"),
    ])
def test_cache_get_data(params, exception, cache, mocker):
    mocker.patch('agent.cachemanager.decode_namespace', return_value='DNS')
    mock_response = mocker.Mock(data='data', lock='lock', expiry='expiry')
    mock_get_data = mocker.Mock(return_value=mock_response)
    cache._cache.get_data = mock_get_data
    if not exception:
        assert cache.get_data(params) == ('data', 'lock', 'expiry')
    else:
        with pytest.raises(ClientApiError):
            cache.get_data(params)


@pytest.mark.parametrize(
    'params, exception', [
        pytest.param({'namespace': 'NS', 'key': 'KY', 'data': 'DATA', 'ttl': 1}, False, id="success"),
        pytest.param({'key': 'KY', 'data': 'DATA', 'ttl': 1}, True, id="missing_namespace"),
        pytest.param({'namespace': 'NS', 'data': 'DATA', 'ttl': 1}, True, id="missing_key"),
        pytest.param({'namespace': 'NS', 'key': 'KY', 'ttl': 1}, True, id="missing_data"),
        pytest.param({'namespace': 'NS', 'key': 'KY', 'data': 'DATA'}, True, id="missing_ttl"),
        pytest.param({'namespace': 'NS', 'key': 'KY', 'data': 2112, 'ttl': 1}, True, id="invalid_data"),
        pytest.param({'namespace': 'NS', 'key': 'KY', 'data': 'DATA', 'ttl': []}, True, id="invalid_ttl"),
    ])
def test_cache_set_data(params, exception, cache, mocker):
    mocker.patch('agent.cachemanager.decode_namespace', return_value='DNS')
    if not exception:
        assert cache.set_data(params) == '"ok"'
    else:
        with pytest.raises(ClientApiError):
            cache.set_data(params)


@pytest.mark.parametrize(
    'count, logexp', [
        pytest.param(0, '', id="none"),
        pytest.param(1, 'Cache purged 1 expired item.', id="one"),
        pytest.param(2, 'Cache purged 2 expired items.', id="many"),
    ])
def test_cache_housekeeping(count, logexp, cache, mocker, caplog):
    cache._cache.cleanup_expired_data = mocker.Mock(return_value=count)
    cache.housekeeping()
    assert logexp in caplog.text
