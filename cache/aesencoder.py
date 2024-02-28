"""
Infrastructure Agent: AES encoder
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import base64
import os

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional, Union


class AesEncoder:

    AES_BLOCK_SIZE = 16  # 128 bits
    SIG_SIZE = SHA256.digest_size

    def __init__(self, base64_key: Optional[bytes] = None):
        # Create a list of the decoded values of all keys in base64_key
        if base64_key is None:
            self.keys = [os.urandom(AesEncoder.AES_BLOCK_SIZE)]
        else:
            if not isinstance(base64_key, bytes):
                base64_key = base64_key.encode('UTF-8')
            self.keys = [base64.b64decode(key) for key in base64_key.split(b',')]
        self.primary_key = self.keys[0]

    def encode(self, message: Union[bytes, str]) -> bytes:
        """Encode a message"""
        if not isinstance(message, bytes):
            message = message.encode('UTF-8')
        return self._encrypt(message)

    def decode(self, message: Union[bytes, str]) -> bytes:
        """Decode a message"""
        if not isinstance(message, bytes):
            message = message.encode('UTF-8')
        return self._decrypt(message)

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data"""

        def _pkcs7(data: bytes):
            length = self.AES_BLOCK_SIZE - (len(data) % self.AES_BLOCK_SIZE)
            return data + chr(length).encode('utf-8') * length

        data = _pkcs7(data)
        salt = os.urandom(self.AES_BLOCK_SIZE)
        encryptor = AES.new(self.primary_key, AES.MODE_CBC, salt)
        cipher_text = encryptor.encrypt(data)
        sig = HMAC.new(self.primary_key, salt + cipher_text, SHA256).digest()
        return base64.encodebytes(salt + cipher_text + sig).replace(b'\n', b'')

    def _decrypt(self, data: bytes) -> bytes:
        """Decrypt data"""
        data = base64.decodebytes(data)
        data, sig = self._split(data, -self.SIG_SIZE)
        for key in self.keys:
            # If there are multiple keys, try them all until one fits
            if HMAC.new(key, data, SHA256).digest() == sig:
                break
        else:
            # We're locked out, no key works!
            raise ValueError("Cannot verify HMAC signature!")

        salt, data = self._split(data, self.AES_BLOCK_SIZE)
        decryptor = AES.new(key, AES.MODE_CBC, salt)
        decrypted = decryptor.decrypt(data)
        return decrypted[:-decrypted[-1]]

    @staticmethod
    def _split(data: bytes, index: int) -> (bytes, bytes):
        """Split the data at the requested index"""
        return data[:index], data[index:]
