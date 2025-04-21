import asyncio
from typing import List
from scapy.all import rdpcap, DNS, DNSRR
from pypdns import PDNSRecord
from ...default.helpers import logger
from ...db.manager import DatabaseManager
from ...ingestors.base import FrameIngestor

async def parse_pcap_packet(packet) -> List[PDNSRecord]:
    """Parse a Scapy packet into a list of PDNSRecord objects."""
    records = []
    try:
        if not (packet.haslayer(DNS) and packet[DNS].qr == 1):
            return records
        dns = packet[DNS]
        timestamp = int(packet.time)
        for rr in dns.an if dns.ancount > 0 else []:
            records.append(PDNSRecord(
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
    type = "frame_pcap"

    async def ingest(self) -> None:
        """Ingest DNS records from a PCAP file."""
        self.running = True
        logger.info({"event": "ingestor_start", "file": self.file_path})
        try:
            packets = rdpcap(self.file_path)
            for packet in packets:
                if not self.running:
                    break
                records = await parse_pcap_packet(packet)
                for rdns in records:
                    await self.db_manager.store_record(rdns)
                    logger.debug({"event": "ingest_record", "record": rdns.raw})
                await asyncio.sleep(0)
            logger.info({"event": "ingestor_complete", "file": self.file_path})
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
        finally:
            self.running = False