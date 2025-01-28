"""
Infrastructure Agent: Utility function to decode a cachemanager namespace
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import time

from .aesencoder import AesEncoder
from .exceptions import ClientApiError, UnicodeKeyError
from .stringtodict import string_to_dict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union


def decode_namespace(orig_namespace: Union[bytes, str], ns_encoder: AesEncoder, timestamp_error_margin: int) -> str:
    """
    Decodes and validates the encoded namespace parameter.

    If an encoder is specified (via config), the namespace itself is encoded with the format:
        namespace=<namespace>&timestamp=<epoch-timestamp>
        Where:
            'namespace' is always required.
            'timestamp' is required if timestamp_error_margin config value is non-zero.
    """

    if ns_encoder:
        try:
            ns_text: Union[bytes, str] = ns_encoder.decode(orig_namespace)
            if not isinstance(ns_text, str):
                ns_text = ns_text.decode('ascii')
        except (UnicodeEncodeError, UnicodeDecodeError):
            raise UnicodeKeyError("Namespace and Key must be ASCII")
        except Exception as e:
            raise ClientApiError(f"Failed to decode namespace: {e}")
        ns_param_dict: dict = string_to_dict(ns_text, item_delim='&', value_delim='=')
        namespace: str = ns_param_dict.get('namespace')
        if not namespace:
            raise ClientApiError("Missing encoded parameter 'namespace'")
        error_margin: int = timestamp_error_margin
        if error_margin:
            timestamp: float = ns_param_dict.get('timestamp')
            if not timestamp:
                raise ClientApiError("Missing encoded parameter 'timestamp'")
            now: float = time.time()
            if (timestamp < (now - error_margin)) or (timestamp > (now + error_margin)):
                raise ClientApiError("Invalid encoded parameter 'timestamp'")
    else:
        namespace: str = orig_namespace
    return namespace
