# pdns/ingestors/redis_queue.py
import asyncio
from ..default.helpers import logger
from ..default.exceptions import DNSParseError
from ..db.base import Database
from ..schemas import DNSRecord
from .base import Ingestor

class RedisQueueIngestor(Ingestor):
    def __init__(self, db: Database, queue_name: str, dnstype: dict, excludesubstrings: list, expirations: dict):
        super().__init__(db)
        self.queue_name = queue_name
        self.dnstype = dnstype
        self.excludesubstrings = excludesubstrings
        self.expirations = expirations

    def parse_line(self, line: str) -> DNSRecord | None:
        vkey = ['timestamp', 'ip-src', 'ip-dst', 'class', 'q', 'type', 'v', 'ttl', 'count']
        if not line or line == '':
            return None
        v = line.split("||")
        if len(v) != len(vkey):
            raise DNSParseError(f"Invalid number of fields in record: {line}")
        record = dict(zip(vkey, v))
        
        try:
            rrtype = next(t for t, val in self.dnstype.items() if val == record['type'])
            return DNSRecord(
                time_first=record['timestamp'],
                time_last=record['timestamp'],
                rrname=record['q'],
                rrtype=rrtype,  # Validated by DNSRecord
                rdata=record['v'],
                count=record['count']
            )
        except (KeyError, ValueError, StopIteration) as e:
            raise DNSParseError(f"Failed to parse record: {line} - {e}")

    async def ingest(self) -> None:
        self.running = True
        logger.info({"event": "ingestor_start", "queue": self.queue_name})
        
        try:
            client = await self.db.connect()
            while self.running:
                record_line = await client.rpop(self.queue_name)
                if record_line is None:
                    await asyncio.sleep(1)
                    continue
                l = record_line.decode().strip()
                try:
                    rdns = self.parse_line(l)
                    if rdns:
                        await self.db.process_record(rdns, self.dnstype, self.excludesubstrings, self.expirations)
                        logger.debug({"event": "ingest_record", "record": rdns.dict()})
                except (DNSParseError, ValueError) as e:
                    logger.debug({"event": "ingest_error", "error": str(e), "line": l})
                await asyncio.sleep(0)
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})