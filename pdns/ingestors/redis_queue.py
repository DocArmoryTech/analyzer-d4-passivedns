# pdns/ingestors/redis_queue.py
import asyncio
import aioredis
from ..default.helpers import logger
from ..default.exceptions import DNSParseError
from ..db.manager import DatabaseManager
from pypdns import PDNSRecord
from .base import Ingestor
from .utils import parse_line

class RedisQueueIngestor(Ingestor):
    def __init__(self, db_manager: DatabaseManager, queue_name: str):
        """
        Initialize the RedisQueueIngestor.

        Args:
            db_manager: The DatabaseManager instance for storing records.
            queue_name: A Redis connection string (e.g., 'redis://host:port/db' or '/path/to/socket:queue_name').
        """
        super().__init__(db_manager)
        self.queue_name = queue_name
        self.redis_client = None

    async def connect_redis(self) -> aioredis.Redis:
        """Establish a connection to the Redis queue instance."""
        try:
            # Parse queue_name as a connection string
            if self.queue_name.startswith("redis://"):
                # Handle redis://host:port/db?queue=queue_name format
                uri = self.queue_name
                redis = await aioredis.create_redis_pool(uri, encoding="utf-8")
                logger.info({"event": "redis_queue_connect", "uri": uri})
            elif ":" in self.queue_name:
                # Handle host:port:queue_name format
                host, port, queue = self.queue_name.split(":", 2)
                redis = await aioredis.create_redis_pool(
                    (host, int(port)),
                    encoding="utf-8",
                    minsize=1,
                    maxsize=10
                )
                self.queue_key = queue
                logger.info({"event": "redis_queue_connect", "host": host, "port": port, "queue": queue})
            else:
                # Assume Unix socket path:queue_name
                socket, queue = self.queue_name.rsplit(":", 1)
                redis = await aioredis.create_redis_pool(
                    socket,
                    encoding="utf-8",
                    minsize=1,
                    maxsize=10
                )
                self.queue_key = queue
                logger.info({"event": "redis_queue_connect", "socket": socket, "queue": queue})
            return redis
        except Exception as e:
            logger.error({"event": "redis_queue_connect_error", "queue_name": self.queue_name, "error": str(e)})
            raise

    async def ingest(self) -> None:
        """Ingest records from a Redis queue and store them via DatabaseManager."""
        self.running = True
        logger.info({"event": "ingestor_start", "queue_name": self.queue_name})

        try:
            self.redis_client = await self.connect_redis()
            queue_key = getattr(self, "queue_key", self.queue_name)  # Use parsed queue name or full string

            while self.running:
                record_line = await self.redis_client.rpop(queue_key)
                if record_line is None:
                    await asyncio.sleep(1)  # Wait briefly if queue is empty
                    continue
                l = record_line.decode("utf-8").strip()
                try:
                    rdns = parse_line(l)
                    if rdns:
                        await self.db_manager.store_record(rdns)
                        logger.debug({"event": "ingest_record", "record": rdns.raw})
                except DNSParseError as e:
                    logger.debug({"event": "ingest_error", "error": str(e), "line": l})
                await asyncio.sleep(0)  # Yield control to event loop
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
        finally:
            if self.redis_client:
                self.redis_client.close()
                await self.redis_client.wait_closed()
                logger.info({"event": "redis_queue_disconnect", "queue_name": self.queue_name})
            self.running = False