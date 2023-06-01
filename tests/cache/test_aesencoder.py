"""
Infrastructure Agent: Unit tests for AES decoder
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

import pytest

from cache.aesencoder import AesEncoder

# 128-Bit Keys
KEY_ONE = b'SmFtaWVMdWNrZXR0Q29vbA=='
KEY_TWO = b'T3Bzdmlld0ZyZWVDb2tlcw=='

# 256-Bit Keys
KEY_THREE = b'QmVzdEJpdE9mVGVzdGluZ0lzSGlkaW5nTWVzc2FnZXM='


@pytest.mark.parametrize(
    'mindata, maxdata, enckey, deckey, exception', [
        pytest.param(1, 256, KEY_ONE, KEY_ONE, None, id="128_bit_key"),
        pytest.param(1, 256, KEY_ONE, KEY_ONE + b',' + KEY_TWO, None, id="128_bit_keys_1st"),
        pytest.param(1, 256, KEY_TWO, KEY_ONE + b',' + KEY_TWO, None, id="128_bit_keys_2nd"),
        pytest.param(1, 256, KEY_THREE, KEY_THREE, None, id="256_bit_key"),
        pytest.param(1, 256, KEY_THREE, KEY_ONE + b',' + KEY_THREE, None, id="256_bit_key"),
        pytest.param(1, 256, KEY_ONE, KEY_TWO, ValueError, id="Undecodable_128"),
        pytest.param(1, 256, KEY_THREE, KEY_TWO, ValueError, id="Undecodable_256_128"),
        pytest.param(1, 256, KEY_ONE, KEY_THREE, ValueError, id="Undecodable_128_256"),
    ])
def test_encode_decode(mindata: int, maxdata: int, enckey: bytes, deckey: bytes, exception):
    for i in range(mindata, maxdata):
        for string in (True, False):
            original_message = ''.join([chr(c) for c in range(i)])
            if not string:
                original_message = original_message.encode('utf-8')

            encoder = AesEncoder(enckey)
            encoded_message = encoder.encode(original_message)

            decoder = AesEncoder(deckey)
            if not exception:
                if string:
                    assert decoder.decode(encoded_message).decode('utf-8') == original_message
                else:
                    assert decoder.decode(encoded_message) == original_message
            else:
                with pytest.raises(exception):
                    decoder.decode(encoded_message)
