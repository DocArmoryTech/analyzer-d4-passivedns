import os
import asyncio
from typing import Dict, List
from scapy.all import PcapReader, DNS, DNSRR, IP
from pypdns import PDNSRecord
from ...default.helpers import logger
from ...db.manager import DatabaseManager
from ...ingestors.base import FrameIngestor
from ...ingestors.common.utils import parse_line

async def parse_pcap_packet(packet) -> List[PDNSRecord]:
    """Parse a Scapy packet into a list of PDNSRecord objects."""
    records = []
    try:
        # Check for DNS response and IP layer
        if not (packet.haslayer(DNS) and packet[DNS].qr == 1 and packet.haslayer(IP)):
            return records
        ip = packet[IP]
        dns = packet[DNS]
        # Ensure there are answers and a question section
        if dns.ancount == 0 or not dns.qd:
            return records
        # Extract query details from the first question
        query = dns.qd[0]
        query_name = query.qname.decode().rstrip(".")
        query_type = query.qtype
        # Extract IP addresses and timestamp
        src_ip = ip.src
        dst_ip = ip.dst
        timestamp = int(packet.time)
        # Process each answer record
        for rr in dns.an:
            records.append(PDNSRecord(
                src_ip=src_ip,
                dst_ip=dst_ip,
                query_name=query_name,
                query_type=query_type,
                rrname=rr.rrname.decode().rstrip("."),
                rrtype=rr.type,
                rdata=[rr.rdata.decode() if isinstance(rr.rdata, bytes) else str(rr.rdata)],
                time_first=timestamp,
                time_last=timestamp,
                count=1
            ))
        return records
    except Exception as e:
        logger.debug({"event": "pcap_parse_error", "error": str(e)})
        return records

class PCAPFileIngestor(FrameIngestor):
    """Ingestor for PCAP files containing DNS packets."""
    type = "file_pcap"

    def __init__(self, db_manager: DatabaseManager, config: Dict) -> None:
        super().__init__(db_manager, config)
        self.passivedns_binary = config.get("passivedns", "")

    async def ingest(self) -> None:
        """Ingest a PCAP file and store DNS records in the database."""
        self.running = True
        logger.info({"event": "ingestor_start", "file": self.file_path})
        try:
            if self.passivedns_binary and os.path.exists(self.passivedns_binary) and os.access(self.passivedns_binary, os.X_OK):
                logger.info({"event": "using_passivedns", "binary": self.passivedns_binary})
                await self.ingest_with_passivedns(self.passivedns_binary)
            else:
                logger.info({"event": "using_default_parsing"})
                await self.ingest_with_scapy()
            logger.info({"event": "ingestor_complete", "file": self.file_path})
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
        finally:
            self.running = False

    async def ingest_with_passivedns(self, passivedns_binary: str) -> None:
        """Parse PCAP file using the passivedns binary."""
        proc = await asyncio.create_subprocess_exec(
            passivedns_binary, "-i", "-r", self.file_path,
            stdout=asyncio.subprocess.PIPE
        )
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            line_str = line.decode().strip()
            record = parse_line(line_str)
            if record:
                await self.db_manager.store_record(record)
                logger.debug({"event": "ingest_record", "record": record.raw})
            else:
                logger.debug({"event": "passivedns_parse_error", "error": "Invalid line", "line": line_str})
        await proc.wait()
        if proc.returncode != 0:
            logger.error({"event": "passivedns_error", "returncode": proc.returncode})

    async def ingest_with_scapy(self) -> None:
        """Parse PCAP file using Scapy (default method)."""
        self.running = True
        logger.info({"event": "scapy_parsing_start", "file": self.file_path})
        try:
            with PcapReader(self.file_path) as pcap_reader:
                for packet in pcap_reader:
                    if not self.running:
                        break
                    records = await parse_pcap_packet(packet)
                    for rdns in records:
                        await self.db_manager.store_record(rdns)
                        logger.debug({"event": "ingest_record", "record": rdns.raw})
                    await asyncio.sleep(0)
        except Exception as e:
            logger.error({"event": "scapy_parsing_error", "error": str(e)})
        finally:
            self.running = False