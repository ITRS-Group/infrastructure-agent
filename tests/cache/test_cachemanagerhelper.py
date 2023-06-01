"""
Infrastructure Agent: Unit tests for cache manager helper
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

import mock
import pytest
import time

from cache.aesencoder import AesEncoder
from cache.cachemanagerhelper import decode_namespace
from cache.exceptions import ClientApiError, UnicodeKeyError

NS1 = 'namespace1'
NSANY = 'anything'


def test_decode_namespace_no_encoder():
    actual = decode_namespace(NS1, None, 0)
    assert actual == NS1


@pytest.mark.parametrize(
    'namespace, encoder, exception, expected', [
        pytest.param(
            NS1, AesEncoder('VGVyYSB0aGUgQ2F0'),
            ClientApiError,
            'Failed to decode namespace: Incorrect padding',
            id="invalid_format"),
        pytest.param(
            NS1, mock.Mock(decode=mock.Mock(return_value='timestamp=1234')),
            ClientApiError,
            "Missing encoded parameter 'namespace'",
            id="missing_namespace"),
        pytest.param(
            NSANY, mock.Mock(decode=mock.Mock(return_value=f'namespace={NS1}')),
            ClientApiError,
            "Missing encoded parameter 'timestamp'",
            id="missing_timestamp"),
        pytest.param(
            NSANY, mock.Mock(decode=mock.Mock(return_value=f'namespace={NS1}&ts=99'.encode('utf-16'))),
            UnicodeKeyError,
            'Namespace and Key must be ASCII',
            id="non_ascii"),
    ])
def test_decode_namespace_errors(encoder, namespace, exception, expected):
    with pytest.raises(exception) as error_ctxt:
        decode_namespace(namespace, encoder, 10)
    assert error_ctxt.value.args[0] == expected


def test_decode_namespace_no_time_margin(mocker):
    encoder = mocker.Mock()
    encoder.decode.return_value = f'namespace={NS1}'
    decoded = decode_namespace(NSANY, encoder, 0)
    assert decoded == NS1


def test_decode_namespace_out_of_date(mocker):
    encoder = mocker.Mock()
    now = time.time()
    time_margin = 30
    for ts in [now - time_margin - 1, now + time_margin + 1]:
        encoder.decode.return_value = f'namespace={NS1}&timestamp={ts}'
        with pytest.raises(ClientApiError) as error_ctxt:
            decode_namespace(NSANY, encoder, time_margin)
        assert error_ctxt.value.args[0] == "Invalid encoded parameter 'timestamp'"


def test_decode_namespace_within_time_margin(mocker):
    encoder = mocker.Mock()
    now = time.time()
    time_margin = 30
    for ts in [now - time_margin + 1, now + time_margin - 1]:
        encoder.decode.return_value = f'namespace={NS1}&timestamp={ts}'
        decoded = decode_namespace(NSANY, encoder, time_margin)
        assert decoded == NS1
