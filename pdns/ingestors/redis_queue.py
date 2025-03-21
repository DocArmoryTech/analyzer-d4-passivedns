# pdns/ingestors/redis_queue.py
import asyncio
from ..default.helpers import logger
from ..default.exceptions import DNSParseError
from ..db.manager import DatabaseManager
from ..schemas import DNSRecord
from .base import Ingestor

class RedisQueueIngestor(Ingestor):
    def __init__(self, db_manager: DatabaseManager, queue_name: str):
        super().__init__(db_manager)
        self.queue_name = queue_name

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
                        await self.db_manager.store_record(rdns)
                        logger.debug({"event": "ingest_record", "record": rdns.dict()})
                except DNSParseError as e:
                    logger.debug({"event": "ingest_error", "error": str(e), "line": l})
                await asyncio.sleep(0)
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
            self.running = False