import asyncio
import struct
import socket
import dnspython.dns.message
from typing import List, Optional
from google.protobuf.message import DecodeError
from dnstap_pb2 import Dnstap
from pypdns import PDNSRecord
from pdns.default.helpers import logger
from pdns.db.manager import DatabaseManager
from pdns.ingestors.base import Ingestor, DaemonIngestor
import fstrm

# Utility function to parse DNSTap messages
async def parse_dnstap_message(dnstap_data: bytes) -> List[PDNSRecord]:
    """Parse a DNSTap message into a list of PDNSRecord objects."""
    records = []
    try:
        dnstap = Dnstap()
        dnstap.ParseFromString(dnstap_data)
        if dnstap.type != Dnstap.MESSAGE or not dnstap.message.HasField("response_message"):
            return records
        
        # Parse the DNS response message
        dns_msg = dnspython.dns.message.from_wire(dnstap.message.response_message)
        timestamp = int(dnstap.message.response_time_sec)
        
        # Extract ANSWER section RRs
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

class DNSTapFileIngestor(Ingestor):
    """Ingestor for DNSTap files containing framed binary data."""
    
    def __init__(self, db_manager: DatabaseManager, file_path: str) -> None:
        super().__init__(db_manager)
        self.file_path = file_path
    
    async def ingest(self) -> None:
        """Ingest DNSTap records from a file by reading framed messages."""
        self.running = True
        logger.info({"event": "ingestor_start", "file": self.file_path})
        try:
            with open(self.file_path, "rb") as f:
                while self.running:
                    # Read frame length (4-byte big-endian)
                    length_bytes = f.read(4)
                    if not length_bytes or len(length_bytes) < 4:
                        break
                    frame_length = struct.unpack(">I", length_bytes)[0]
                    
                    # Read frame data
                    frame_data = f.read(frame_length)
                    if len(frame_data) < frame_length:
                        break
                    
                    # Parse DNSTap message and store records
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

class DNSTapSocketIngestor(DaemonIngestor):
    """Ingestor for live DNSTap streams over Unix socket or TCP."""
    
    type = "dnstap_socket"
    
    def __init__(self, db_manager: DatabaseManager, connection_type: str, address: str, port: Optional[int] = None) -> None:
        super().__init__(db_manager)
        self.connection_type = connection_type.lower()
        self.address = address
        self.port = port if connection_type == "tcp" else None
    
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
                    if not self.port:
                        raise ValueError("Port required for TCP connection")
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