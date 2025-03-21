# pdns/ingestors/d4_file.py
import asyncio
from ..default.helpers import logger
from ..default.exceptions import DNSParseError
from ..db.manager import DatabaseManager
from ..schemas import DNSRecord
from .base import Ingestor

class PDNSIngestor(Ingestor):
    def __init__(self, db_manager: DatabaseManager, file_path: str):
        super().__init__(db_manager)
        self.file_path = file_path

    def parse_line(self, line: str) -> DNSRecord | None:
        vkey = ['timestamp', 'ip-src', 'ip-dst', 'class', 'q', 'type', 'v', 'ttl', 'count']
        if not line or line == '':
            return None
        v = line.split("||")
        if len(v) != len(vkey):
            raise DNSParseError(f"Invalid number of fields in record: {line}")
        record = dict(zip(vkey, v))
        
        try:
            return DNSRecord(
                time_first=int(record['timestamp']),
                time_last=int(record['timestamp']),
                rrname=record['q'],
                rrtype=record['type'],
                rdata=[record['v']],
                count=int(record['count'])
            )
        except (ValueError, TypeError) as e:
            raise DNSParseError(f"Failed to parse record: {line} - {e}")

    async def ingest(self) -> None:
        self.running = True
        logger.info({"event": "ingestor_start", "file": self.file_path})
        
        try:
            with open(self.file_path, "r") as f:
                for line in f:
                    if not self.running:
                        break
                    l = line.strip()
                    if not l:
                        continue
                    try:
                        rdns = self.parse_line(l)
                        if rdns:
                            await self.db_manager.store_record(rdns)
                            logger.debug({"event": "ingest_record", "record": rdns.dict()})
                    except DNSParseError as e:
                        logger.debug({"event": "ingest_error", "error": str(e), "line": l})
                    await asyncio.sleep(0)
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
            self.running = False