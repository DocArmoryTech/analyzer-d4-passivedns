import asyncio
import aioredis
from typing import Optional
from ..default.helpers import logger
from ..default.exceptions import DNSParseError
from ..db.manager import DatabaseManager
from pypdns import PDNSRecord
from .base import StreamIngestor
from .utils import parse_line


class RedisQueueIngestor(StreamIngestor):
    """Ingestor for DNS records from a Redis queue.

    Pulls messages from a Redis queue, parses them, and stores them in the database.
    """

    type = "d4redis"  # Identifier for this ingestor type

    def __init__(self, db_manager: DatabaseManager, config: dict) -> None:
        super().__init__(db_manager, config)
        self.redis_uri: str = config.get("redis_uri", "")
        if not self.redis_uri:
            raise ValueError("Missing required config parameter: redis_uri")

    async def connect_redis(self) -> aioredis.Redis:
        """Connect to the Redis server based on the provided URI.

        Returns:
            aioredis.Redis: The Redis client connection.
        """
        try:
            if self.redis_uri.startswith("redis://"):
                uri = self.redis_uri
                redis = await aioredis.create_redis_pool(uri, encoding="utf-8")
                logger.info({"event": "redis_queue_connect", "uri": uri})
            elif ":" in self.redis_uri:
                host, port, queue = self.redis_uri.split(":", 2)
                redis = await aioredis.create_redis_pool(
                    (host, int(port)), encoding="utf-8", minsize=1, maxsize=10
                )
                self.queue_key = queue
                logger.info(
                    {
                        "event": "redis_queue_connect",
                        "host": host,
                        "port": port,
                        "queue": queue,
                    }
                )
            else:
                socket, queue = self.redis_uri.rsplit(":", 1)
                redis = await aioredis.create_redis_pool(
                    socket, encoding="utf-8", minsize=1, maxsize=10
                )
                self.queue_key = queue
                logger.info(
                    {"event": "redis_queue_connect", "socket": socket, "queue": queue}
                )
            return redis
        except Exception as e:
            logger.error(
                {
                    "event": "redis_queue_connect_error",
                    "queue_name": self.redis_uri,
                    "error": str(e),
                }
            )
            raise

    async def ingest(self) -> None:
        """Continuously ingest records from the Redis queue.

        Reconnects with exponential backoff on failure.
        """
        self.running = True
        logger.info({"event": "ingestor_start", "queue_name": self.redis_uri})
        retry_delay = 1
        max_retry_delay = 60
        while self.running:
            try:
                self.redis_client = await self.connect_redis()
                queue_key = getattr(self, "queue_key", self.redis_uri)
                retry_delay = 1  # Reset on success
                while self.running:
                    record_line = await self.redis_client.rpop(queue_key)
                    if record_line is None:
                        await asyncio.sleep(1)
                        continue
                    l = record_line.decode("utf-8").strip()
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
                if self.redis_client:
                    self.redis_client.close()
                    await self.redis_client.wait_closed()
                if not self.running:
                    break
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)
        logger.info({"event": "ingestor_complete", "queue_name": self.redis_uri})