from .default.helpers import get_config
from enum import Enum
from typing import List

# Load rrtypes from config/rrtypes.json
rrtypes_config = get_config("rrtypes")  # List of dicts from rrtypes.json

# Create RRTypeFull enum for all RR types
RRType = Enum(
    "RRType",
    {entry["type"].upper(): entry["value"] for entry in rrtypes_config},
    type=str,
)

# Load supported types from config
supported_types = get_config(
    "generic", "rrset_supported"
)  # e.g., ["1", "2"] or ["A", "AAAA"]


# Create RRTypeSupported enum for supported types
def create_supported_enum(supported: list[str]) -> Enum:
    enum_dict = {}
    rrset = {
        entry["type"].upper(): entry["value"] for entry in rrtypes_config
    }  # Temp mapping for lookup
    for t in supported:
        t_upper = t.upper()
        if t_upper in rrset:  # Specified by name (e.g., "A")
            enum_dict[t_upper] = rrset[t_upper]
        elif t in rrset.values():  # Specified by value (e.g., "1")
            # Find the corresponding name
            name = next((k for k, v in rrset.items() if v == t), None)
            if name:
                enum_dict[name] = rrset[name]
        # Ignore invalid entries silently
    return Enum("SupportedRRType", enum_dict, type=str)


RRTypeSupported = create_supported_enum(supported_types)

__all__ = ["RRType", "SupportedRRType"]
