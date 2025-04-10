from pypdns import PDNSRecord
from ..default.helpers import logger
from ..default.exceptions import DNSParseError
from ..rrtypes import SupportedRRType


def parse_line(line: str) -> PDNSRecord | None:
    """Parse a passivedns-formatted line into a PDNSRecord."""
    vkey = ["timestamp", "ip-src", "ip-dst", "class", "q", "type", "v", "ttl", "count"]
    if not line or line == "":
        return None
    v = line.split("||")
    if len(v) != len(vkey):
        raise DNSParseError(f"Invalid number of fields in record: {line}")
    record = dict(zip(vkey, v))

    try:
        record_dict = {
            "time_first": int(record["timestamp"]),
            "time_last": int(record["timestamp"]),
            "rrname": record["q"],
            "rrtype": record["type"],
            "rdata": [record["v"]],
            "count": int(record["count"]),
        }
        return PDNSRecord(**record_dict)
    except (ValueError, TypeError) as e:
        raise DNSParseError(f"Failed to parse record: {line} - {e}")


__all__ = ["parse_line"]
