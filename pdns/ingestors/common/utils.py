from pypdns import PDNSRecord
from ...default.exceptions import DNSParseError

def parse_line(line: str) -> PDNSRecord | None:
    """Parse a passivedns-formatted line into a PDNSRecord."""
    if not line or line == "":
        return None
    v = line.split("||")
    if len(v) != 9:
        raise DNSParseError(f"Invalid number of fields in record: {line}")
    
    # ["timestamp", "ip-src", "ip-dst", "class", "q", "type", "v", "ttl", "count"]
    try:
        timestamp = int(v[0])    # Position 0: timestamp
        rrname = v[4]           # Position 4: q (query name)
        rrtype = v[5]           # Position 5: type
        rdata = [v[6]]          # Position 6: v (value/response data)
        count = int(v[8])       # Position 8: count
        
        record_dict = {
            "time_first": timestamp,
            "time_last": timestamp,
            "rrname": rrname,
            "rrtype": rrtype,
            "rdata": rdata,
            "count": count,
        }
        return PDNSRecord(**record_dict)
    except (ValueError, TypeError) as e:
        raise DNSParseError(f"Failed to parse record: {line} - {e}")

__all__ = ["parse_line"]