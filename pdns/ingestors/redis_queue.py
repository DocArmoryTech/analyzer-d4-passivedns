# pdns/ingestors/redis_queue.py
import asyncio
from ..default.helpers import logger
from ..default.exceptions import DNSParseError
from ..db.manager import DatabaseManager
from pypdns import PDNSRecord  # Import PDNSRecord from pypdns
from .base import Ingestor
from .utils import parse_line

class RedisQueueIngestor(Ingestor):
    def __init__(self, db_manager: DatabaseManager, queue_name: str):
        super().__init__(db_manager)
        self.queue_name = queue_name

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
                    rdns = parse_line(l)
                    if rdns:
                        await self.db_manager.store_record(rdns)
                        logger.debug({"event": "ingest_record", "record": rdns.raw})
                except DNSParseError as e:
                    logger.debug({"event": "ingest_error", "error": str(e), "line": l})
                await asyncio.sleep(0)
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
            self.running = False