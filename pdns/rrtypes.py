# pdns/rrtypes.py
from .default.helpers import get_config


# Load rrset from config/rrtypes.json
rrset = get_config("rrtypes")


rrset_supported = set()
for t in  get_config("generic", "rrset_supported"):
    if t in rrset:  # If specified by name (e.g., "A")
        rrset_supported.add(rrset[t])
    elif t in rrset.values():  # If specified by value (e.g., "1")
        rrset_supported.add(t)
    # Ignore invalid entries silently

# Convert to list for compatibility
rrset_supported = list(rrset_supported)