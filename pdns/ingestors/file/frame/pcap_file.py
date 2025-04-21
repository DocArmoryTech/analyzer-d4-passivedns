import asyncio
from typing import List
from scapy.all import rdpcap, DNS, DNSRR, IP
from pypdns import PDNSRecord
from ...default.helpers import logger
from ...db.manager import DatabaseManager
from ...ingestors.base import FrameIngestor

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
        # Extract query details from the first question (typically one per packet)
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
    def __init__(self, file_path: str, db_manager, config: dict):
        super().__init__(db_manager, config)
        self.passivedns_binary = self.config.get("passivedns")
        
    async def ingest(self) -> None:
        """Ingest a PCAP file and store DNS records in the database."""
        self.running = True
        logger.info({"event": "ingestor_start", "file": self.file_path})
        try:    
            if passivedns_binary and os.path.exists(passivedns_binary) and os.access(passivedns_binary, os.X_OK):
                logger.info({"event": "using_passivedns", "binary": passivedns_binary})
                await self.ingest_with_passivedns(passivedns_binary)
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
        proc = await asyncio.subprocess.create_subprocess_exec(
            passivedns_binary, "-I", "-r", self.file_path,
            stdout=asyncio.subprocess.PIPE
        )
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            record = self.parse_passivedns_output(line.decode())
            if record:
                await self.db_manager.store_record(record)
                logger.debug({"event": "ingest_record", "record": record.raw})
        await proc.wait()
        if proc.returncode != 0:
            logger.error({"event": "passivedns_error", "returncode": proc.returncode})

    async def ingest_with_scapy(self) -> None:
        """Parse PCAP file using Scapy (default method)."""
        packets = rdpcap(self.file_path)
        for packet in packets:
            if not self.running:
                break
            records = await parse_pcap_packet(packet)
            for rdns in records:
                await self.db_manager.store_record(rdns)
                logger.debug({"event": "ingest_record", "record": rdns.raw})
            await asyncio.sleep(0)

    def parse_passivedns_output(self, line: str) -> Optional[PDNSRecord]:
        """Parse a line of passivedns output into a PDNSRecord."""
        try:
            fields = line.strip().split("||")
            if len(fields) != 10:
                logger.debug({"event": "passivedns_parse_error", "error": "incorrect field count", "line": line})
                return None
            first_seen_str, last_seen_str, count_str, query, query_type, answer, answer_type, ttl, client_ip, server_ip = fields

            # Convert timestamps to epoch integers
            first_seen = int(datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S").timestamp())
            last_seen = int(datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S").timestamp())
            count = int(count_str)

            # Create PDNSRecord
            record = PDNSRecord(
                time_first=first_seen,
                time_last=last_seen,
                count=count,
                query_name=query,
                query_type=query_type,
                rrname=query,
                rrtype=answer_type,
                rdata=[answer],
                src_ip=server_ip,  # DNS server IP
                dst_ip=client_ip   # Client IP
            )
            return record
        except Exception as e:
            logger.debug({"event": "passivedns_parse_error", "error": str(e), "line": line})
            return None
