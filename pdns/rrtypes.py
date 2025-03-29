# pdns/rrtypes.py
from .default.helpers import get_config
from enum import Enum

# Load rrset from config/rrtypes.json and convert to a dictionary
rrtypes_config = get_config("rrtypes")  # List of dicts from rrtypes.json
rrset = {entry["type"]: entry["value"] for entry in rrtypes_config}  # e.g., {"A": "1", "NS": "2", ...}

# Optional: Keep full rrtypes data if needed elsewhere
rrtypes_full = {entry["type"]: entry for entry in rrtypes_config}  # e.g., {"A": {"type": "A", "value": "1", ...}}

# Dynamically create RRType enum for supported types
def create_rrtype_enum():
    supported_types = get_config("generic", "rrset_supported")  # e.g., ["1", "2"] or ["A", "AAAA"]
    enum_dict = {}
    
    for t in supported_types:
        t_upper = t.upper()
        if t_upper in rrset:  # Specified by name (e.g., "A")
            enum_dict[t_upper] = t_upper
        elif t in rrset.values():  # Specified by value (e.g., "1")
            # Find the corresponding name
            name = next(k for k, v in rrset.items() if v == t)
            enum_dict[name] = name
        # Ignore invalid entries silently
    
    return Enum("RRType", enum_dict, type=str)

RRType = create_rrtype_enum()

# Compute rrset_supported as a list of numeric values
rrset_supported = [
    rrset[name] for name in RRType.__members__ if name in rrset
]

__all__ = ["rrset", "rrset_supported", "RRType", "rrtypes_full"]