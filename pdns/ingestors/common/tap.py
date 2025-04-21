from typing import List
from google.protobuf.message import DecodeError
from dnstap_pb2 import Dnstap
from pypdns import PDNSRecord
from ...default.helpers import logger
import dnspython.dns.message

async def parse_dnstap_message(dnstap_data: bytes) -> List[PDNSRecord]:
    """Parse a DNSTap message into a list of PDNSRecord objects."""
    records = []
    try:
        dnstap = Dnstap()
        dnstap.ParseFromString(dnstap_data)
        if dnstap.type != Dnstap.MESSAGE or not dnstap.message.HasField("response_message"):
            return records
        dns_msg = dnspython.dns.message.from_wire(dnstap.message.response_message)
        timestamp = int(dnstap.message.response_time_sec)
        for rrset in dns_msg.answer:
            for rr in rrset:
                records.append(PDNSRecord(
                    rrname=rrset.name.to_text(),
                    rrtype=rrset.rdtype,
                    rdata=[rr.to_text()],
                    time_first=timestamp,
                    time_last=timestamp,
                    count=1
                ))
        return records
    except (DecodeError, dnspython.dns.exception.DNSException) as e:
        logger.debug({"event": "dnstap_parse_error", "error": str(e)})
        return records