import asyncio
from typing import Optional
from google.protobuf.message import DecodeError
from dnstap_pb2 import Dnstap
from pypdns import PDNSRecord
from ...default.helpers import logger
from ...db.manager import DatabaseManager
from ...ingestors.base import StreamIngestor
import dnspython.dns.message
import fstrm

async def parse_dnstap_message(dnstap_data: bytes) -> list[PDNSRecord]:
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

class DNSTapSocketIngestor(StreamIngestor):
    """Ingestor for live DNSTap streams over Unix socket or TCP."""
    type = "dnstapsocket"

    def __init__(self, db_manager: DatabaseManager, config: dict) -> None:
        super().__init__(db_manager, config)
        self.connection_type: str = config.get("connection_type", "").lower()
        self.address: str = config.get("address", "")
        self.port: Optional[int] = config.get("port")
        if not self.connection_type or not self.address:
            raise ValueError("Missing required config parameters: connection_type, address")
        if self.connection_type == "tcp" and self.port is None:
            raise ValueError("Port required for TCP connection")

    async def ingest(self) -> None:
        """Continuously ingest DNSTap records from a socket connection."""
        self.running = True
        conn_str = f"{self.connection_type}://{self.address}" + (f":{self.port}" if self.port else "")
        logger.info({"event": "ingestor_start", "connection": conn_str})
        retry_delay = 1
        max_retry_delay = 60
        while self.running:
            try:
                if self.connection_type == "unix":
                    reader = await fstrm.unix_connect(self.address)
                elif self.connection_type == "tcp":
                    reader = await fstrm.tcp_connect((self.address, self.port))
                else:
                    raise ValueError(f"Unsupported connection type: {self.connection_type}")
                retry_delay = 1
                async for frame_data in reader:
                    if not self.running:
                        break
                    records = await parse_dnstap_message(frame_data)
                    for rdns in records:
                        await self.db_manager.store_record(rdns)
                        logger.debug({"event": "ingest_record", "record": rdns.raw})
                    await asyncio.sleep(0)
            except Exception as e:
                logger.error({"event": "ingest_error", "error": str(e)})
                if not self.running:
                    break
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)
        logger.info({"event": "ingestor_complete", "connection": conn_str})