# pdns/rrtypes.py
from .default.helpers import get_config

# Load rrset from config/records-type.json
rrset = get_config("records-type")

# Define supported RR types (can be updated dynamically if needed)
rrset_supported = ['1', '2', '5', '15', '16', '28', '33', '46']  # A, NS, CNAME, MX, TXT, AAAA, SRV, CAA
## validate against rrset