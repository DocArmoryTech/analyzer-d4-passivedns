# pdns/rrtypes.py
from .default.helpers import get_config
from enum import Enum
from typing import List
from .exceptions import InvalidConfigError

# Load and validate rrtypes
rrtypes_config = get_config("rrtypes", default=[])
if not rrtypes_config or not isinstance(rrtypes_config, list):
    raise InvalidConfigError("rrtypes.json is missing or invalid")

RRType = Enum(
    "RRType",
    {entry["type"].upper(): entry["value"] for entry in rrtypes_config if "type" in entry and "value" in entry},
    type=str,
)

# Load and validate supported types
supported_types = get_config("generic", "rrset_supported", default=[])
if not supported_types or not isinstance(supported_types, list):
    raise InvalidConfigError("generic.rrset_supported is missing or invalid")

def create_supported_enum(supported: List[str]) -> Enum:
    """
    Create an enum for supported RR types based on config.

    Args:
        supported: List of supported RR type names or values.

    Returns:
        Enum of supported RR types.
    """
    enum_dict = {}
    rrset = {entry["type"].upper(): entry["value"] for entry in rrtypes_config}
    for t in supported:
        t_upper = t.upper()
        if t_upper in rrset:
            enum_dict[t_upper] = rrset[t_upper]
        elif t in rrset.values():
            name = next((k for k, v in rrset.items() if v == t), None)
            if name:
                enum_dict[name] = t
        else:
            logger.warning(f"Invalid supported RR type in generic.rrset_supported: {t}")
    if not enum_dict:
        raise InvalidConfigError("No valid supported RR types found in generic.rrset_supported")
    return Enum("SupportedRRType", enum_dict, type=str)

SupportedRRType = create_supported_enum(supported_types)

__all__ = ["RRType", "SupportedRRType"]