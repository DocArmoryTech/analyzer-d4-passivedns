import asyncio
import struct
from typing import List
from google.protobuf.message import DecodeError
from dnstap_pb2 import Dnstap
from pypdns import PDNSRecord
from ...default.helpers import logger
from ...db.manager import DatabaseManager
from ...ingestors.base import FrameIngestor
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

class DNSTapFileIngestor(FrameIngestor):
    """Ingestor for DNSTap files containing framed binary data."""
    type = "dnstapfile"

    async def ingest(self) -> None:
        """Ingest DNSTap records from a file by reading framed messages."""
        self.running = True
        logger.info({"event": "ingestor_start", "file": self.file_path})
        try:
            with open(self.file_path, "rb") as f:
                while self.running:
                    length_bytes = f.read(4)
                    if not length_bytes or len(length_bytes) < 4:
                        break
                    frame_length = struct.unpack(">I", length_bytes)[0]
                    frame_data = f.read(frame_length)
                    if len(frame_data) < frame_length:
                        break
                    records = await parse_dnstap_message(frame_data)
                    for rdns in records:
                        await self.db_manager.store_record(rdns)
                        logger.debug({"event": "ingest_record", "record": rdns.raw})
                    await asyncio.sleep(0)
            logger.info({"event": "ingestor_complete", "file": self.file_path})
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
        finally:
            self.running = False