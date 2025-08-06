"""
Infrastructure Agent: Helper functions
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union


# Parsing integer units
RE_BYTES = re.compile(r'^(\d+) ?([KMG]?B)?$')
UNIT_MULTIPLIER = {'B': 1, 'KB': 1024, 'MB': 1048576, 'GB': 1073741824}


logger = logging.getLogger(__name__)


def merge_dictionary(original: dict, updates: dict, merge_lists: tuple[str] = ()):
    """Updates a dict with values from another"""
    if updates:
        for key, value in updates.items():
            if isinstance(value, dict) and key in original:
                # recursion
                merge_dictionary(original[key], value, merge_lists)
            elif (
                    isinstance(value, list) and
                    key in original and
                    key in merge_lists and
                    type(original[key]) == type(value)
            ):
                # add to existing value
                original[key] += value
            else:
                # overwrite previous value
                original[key] = value


def parse_byte_string(text: Union[str, int]) -> int:
    """
    Parses a byte size such as '11', '11B' '11 B', '67 KB', '100MB' '10GB'.
    Also handles integers (implies bytes).
    """
    if isinstance(text, int):
        return text
    m = RE_BYTES.match(str(text))
    if not m:
        raise ValueError(f"Cannot parse bytes from '{text}'")
    size, unit = int(m.group(1)), m.group(2)
    return size * UNIT_MULTIPLIER[unit or 'B']


def is_host_in_net_list(host: str, valid_net_list: list[str]) -> bool:
    """Tries to determine if the name (host/ip) is in a list of valid nets/names."""
    # Try a simple name lookup first
    if host in valid_net_list:
        return True
    try:
        ipa = ipaddress.ip_address(host)
        for valid_net in valid_net_list:
            subnet = ipaddress.ip_network(valid_net)
            if ipa in subnet:
                return True
    except ValueError:
        pass  # Not IP addresses
    return False


def basic_auth(user: str, password: str) -> str:
    """Formats a basic authorisation HTTP header"""
    try:
        token = f'{user}:{password}'.encode('utf-8')
        auth_str = base64.encodebytes(token).decode('utf-8').strip()
    except (UnicodeDecodeError, UnicodeEncodeError):
        logger.warning('Failed to encode user/password')
        auth_str = ''
    return f'Basic {auth_str}'
