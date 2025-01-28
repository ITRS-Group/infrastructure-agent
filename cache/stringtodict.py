"""
Infrastructure Agent: Utility function to convert a string to a dictionary
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union


def string_to_dict(string: str, item_delim: str = ';', value_delim: str = '=') -> dict:
    """Converts a delimited string to a dictionary."""
    result = {}
    items = string.split(item_delim)
    for item in items:
        k, _, v = item.partition(value_delim)
        result[k.strip()] = num_or_string(v)
    return result


def num_or_string(value) -> Union[int, float, str]:
    """Return the respective int or float for a value or the original value string if unable."""
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value
