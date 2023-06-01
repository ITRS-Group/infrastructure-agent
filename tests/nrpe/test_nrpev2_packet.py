"""
Infrastructure Agent: Unit tests for nrpe packet
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

from pathlib import Path
from uuid import UUID

import pytest

from agent.objects import Result
from nrpe.packet import NRPEPacketV2, NRPEPacketException

RELATIVE_RESOURCES_PATH = '../resources'
BASE_PATH = Path(__file__).parent
RESOURCES_PATH = (BASE_PATH / RELATIVE_RESOURCES_PATH).resolve()

RESULT_UUID = UUID('12345678-1234-5678-1234-567812345678')


def read_binary_file(path):
    with open(path, 'rb') as f:
        return f.read()


nrpe_check_valid_packet = read_binary_file(f'{RESOURCES_PATH}/packets/nrpev2/nrpe_check_valid.bin')
nrpe_check_invalid_crc = read_binary_file(f'{RESOURCES_PATH}/packets/nrpev2/nrpe_check_invalid_crc.bin')
nrpe_check_negative_checksum = read_binary_file(f'{RESOURCES_PATH}/packets/nrpev2/nrpe_check_negative_checksum.bin')


@pytest.mark.parametrize(
    'packet, expected, exception, exception_msg', [
        pytest.param(
            nrpe_check_valid_packet,
            NRPEPacketV2(
                packet_version=2, packet_type=NRPEPacketV2.NRPE_REQUEST_TYPE,
                crc32_value=259656801, result_code=30049, buffer=b'_NRPE_CHECK!a b c', _padding=18801
            ),
            None,
            None,
            id="nrpe_check-valid-checksum"
        ),
        pytest.param(nrpe_check_invalid_crc, None, NRPEPacketException, 'checksum error', id="invalid-checksum-error"),
        pytest.param(b'', None, NRPEPacketException, '', id="empty-packet-error"),
    ])
def test_nrpev2_packet_from_bytes(packet, expected, exception, exception_msg):
    if not exception:
        packet_object = NRPEPacketV2.from_bytes(packet)
        assert packet_object == expected
    else:
        with pytest.raises(exception) as e:
            NRPEPacketV2.from_bytes(packet)
        if exception_msg:
            assert exception_msg in str(e)


@pytest.mark.parametrize(
    'nrpe_object, expected_crc32', [
        pytest.param(
            NRPEPacketV2(
                packet_version=2, packet_type=NRPEPacketV2.NRPE_REQUEST_TYPE,
                crc32_value=0, result_code=30049, buffer=b'_NRPE_CHECK!a b c', _padding=18801
            ),
            259656801,
            id="nrpe_check-request"),
        pytest.param(
            NRPEPacketV2(
                packet_version=2, packet_type=NRPEPacketV2.NRPE_RESPONSE_TYPE,
                crc32_value=0, result_code=3, buffer=b'boom! bam! it went wrong!'
            ),
            3664613340,
            id="nrpe_check-request"),
    ])
def test_nrpev2_packet_calc_crc32_value(nrpe_object: NRPEPacketV2, expected_crc32):
    assert nrpe_object.calc_crc32_value() == expected_crc32


@pytest.mark.parametrize('packet_object, packet_bytes', [
    pytest.param(
        NRPEPacketV2(
            packet_version=2, packet_type=NRPEPacketV2.NRPE_REQUEST_TYPE,
            crc32_value=0, result_code=30049, buffer=b'_NRPE_CHECK!a b c', _padding=18801
        ),
        nrpe_check_valid_packet,
        id="check_nrpe_packet_calc_crc"
    ),
    pytest.param(
        NRPEPacketV2(
            packet_version=2, packet_type=NRPEPacketV2.NRPE_REQUEST_TYPE,
            crc32_value=259656801, result_code=30049, buffer=b'_NRPE_CHECK!a b c', _padding=18801
        ),
        nrpe_check_valid_packet,
        id="check_nrpe_packet_no_calc_crc"
    ),
    pytest.param(
        NRPEPacketV2(
            packet_version=2, packet_type=NRPEPacketV2.NRPE_RESPONSE_TYPE,
            crc32_value=259656801, result_code=-11, buffer=b'segfault oh no!!! boom!!',
        ),
        nrpe_check_negative_checksum,
        id="check_nrpe_packet_negative_rc"
    )
])
def test_nrpev2_packet_to_bytes(packet_object: NRPEPacketV2, packet_bytes: bytes):
    assert packet_object.to_bytes() == packet_bytes


@pytest.mark.parametrize('result, allow_multi_packet_response, expected', [
    pytest.param(
        Result(RESULT_UUID, 0, 'J' * 10),
        True,
        [
            NRPEPacketV2(packet_version=2, packet_type=2, crc32_value=0, result_code=0, buffer=b'J' * 10, _padding=0)
        ],
        id="10char-stdout-result-allow-multi"
    ),

    pytest.param(
        Result(RESULT_UUID, 0, 'J' * 1023),
        True,
        [
            NRPEPacketV2(packet_version=2, packet_type=2, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0)
        ],
        id="1023char-stdout-result-allow-multi"
    ),

    pytest.param(
        Result(RESULT_UUID, 0, 'J' * 1024),
        True,
        [
            NRPEPacketV2(packet_version=2, packet_type=3, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0),
            NRPEPacketV2(packet_version=2, packet_type=2, crc32_value=0, result_code=0, buffer=b'J' * 1, _padding=0)
        ],
        id="1024char-stdout-result-allow-multi"
    ),

    pytest.param(
        Result(RESULT_UUID, 0, 'J' * 7777),
        True,
        [
            NRPEPacketV2(packet_version=2, packet_type=3, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0),
            NRPEPacketV2(packet_version=2, packet_type=3, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0),
            NRPEPacketV2(packet_version=2, packet_type=3, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0),
            NRPEPacketV2(packet_version=2, packet_type=3, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0),
            NRPEPacketV2(packet_version=2, packet_type=3, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0),
            NRPEPacketV2(packet_version=2, packet_type=3, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0),
            NRPEPacketV2(packet_version=2, packet_type=3, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0),
            NRPEPacketV2(packet_version=2, packet_type=2, crc32_value=0, result_code=0, buffer=b'J' * 616, _padding=0),
        ],
        id="7777char-stdout-result-allow-multi"
    ),

    pytest.param(
        Result(RESULT_UUID, 0, 'J' * 10),
        False,
        [
            NRPEPacketV2(packet_version=2, packet_type=2, crc32_value=0, result_code=0, buffer=b'J' * 10, _padding=0)
        ],
        id="10char-stdout-result-no-allow-multi"
    ),

    pytest.param(
        Result(RESULT_UUID, 0, 'J' * 1023),
        False,
        [
            NRPEPacketV2(packet_version=2, packet_type=2, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0),
        ],
        id="1023char-stdout-result-no-allow-multi"
    ),

    pytest.param(
        Result(RESULT_UUID, 0, 'J' * 1024),
        False,
        [
            NRPEPacketV2(packet_version=2, packet_type=2, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0),
        ],
        id="1024char-stdout-result-no-allow-multi"
    ),

    pytest.param(
        Result(RESULT_UUID, 0, 'J' * 7777),
        False,
        [
            NRPEPacketV2(packet_version=2, packet_type=2, crc32_value=0, result_code=0, buffer=b'J' * 1023, _padding=0),
        ],
        id="7777char-stdout-result-no-allow-multi"
    ),

])
def test_nrpev2_packet_create_packets_from_result(
        result: Result, allow_multi_packet_response: bool, expected: list[NRPEPacketV2]):
    assert NRPEPacketV2.create_packets_from_result(result, allow_multi_packet_response) == expected
