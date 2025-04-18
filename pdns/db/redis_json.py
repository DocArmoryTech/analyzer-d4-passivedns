# pdns/db/redis_json.py
from .base import Database
from ..default.helpers import logger
from ..default.exceptions import DBConnectionError
from pypdns import PDNSRecord
import aioredis
from typing import Tuple, List, Optional, AsyncGenerator
from collections import deque

class RedisJSONDatabase(Database):
    """Redis implementation using JSON hashes for Passive DNS storage."""
    def __init__(self, **kwargs):
        """Initialize Redis connection with provided configuration."""
        self.config = kwargs or {"host": "127.0.0.1", "port": 6379, "db": 0}
        self.db_number = self.config.get("db", 0)
        if "socket" not in self.config and not ("host" in self.config and "port" in self.config):
            raise ValueError("Redis config must specify 'socket' or 'host' and 'port'")
        self.redis_pool = None
        self.queue = deque()

    async def connect(self) -> None:
        """Establish a connection pool to Redis."""
        try:
            if "socket" in self.config:
                self.redis_pool = await aioredis.create_redis_pool(
                    self.config["socket"],
                    db=self.db_number,
                    decode_responses=True,
                    encoding="utf-8",
                    minsize=1,
                    maxsize=10,
                )
                logger.info({"event": "redis_init", "type": "unix", "socket": self.config["socket"], "db": self.db_number})
            else:
                self.redis_pool = await aioredis.create_redis_pool(
                    (self.config["host"], self.config["port"]),
                    db=self.db_number,
                    decode_responses=True,
                    encoding="utf-8",
                    minsize=1,
                    maxsize=10,
                )
                logger.info({"event": "redis_init", "type": "tcp", "host": self.config["host"], "port": self.config["port"], "db": self.db_number})
            while self.queue:
                record, expiration = self.queue.popleft()
                await self.store_record(record, expiration)
        except aioredis.RedisError as e:
            logger.error({"event": "redis_connect_error", "error": str(e)})
            raise DBConnectionError(f"Failed to connect to Redis: {e}")

    async def disconnect(self) -> None:
        """Close the Redis connection pool."""
        if self.redis_pool:
            self.redis_pool.close()
            await self.redis_pool.wait_closed()
            self.redis_pool = None
            logger.info({"event": "redis_disconnect"})

    async def store_record(self, record: PDNSRecord, expiration: Optional[int] = None) -> None:
        """Store a Passive DNS record in Redis with optional expiration."""
        if not self.redis_pool:
            self.queue.append((record, expiration))
            logger.debug({"event": "record_queued", "rrname": record.rrname})
            return

        rrtype = str(record.rrtype).upper()
        rrname = record.rrname.lower().rstrip(".")
        rdata = record.rdata if isinstance(record.rdata, list) else [record.rdata]

        async with self.redis_pool.acquire() as redis:
            async with redis.pipeline() as pipe:
                for rd in rdata:
                    record_key = f"record:{rrname}:{rrtype}:{rd}"
                    record_data = {
                        "rrname": rrname,
                        "rrtype": rrtype,
                        "rdata": rd,
                        "time_first": record.time_first,
                        "time_last": record.time_last,
                        "count": record.count or 1,
                        "sensor_id": record.sensor_id,
                    }
                    pipe.hset(record_key, mapping=record_data)
                    if expiration:
                        pipe.expire(record_key, expiration)

                    query_key = f"r:{rrname}:{rrtype}"
                    value_key = f"v:{rd}:{rrtype}"
                    pipe.sadd(query_key, rd)
                    pipe.sadd(value_key, rrname)
                    if expiration:
                        pipe.expire(query_key, expiration)
                        pipe.expire(value_key, expiration)

                pipe.hincrby("stats:types", rrtype, 1)
                pipe.incrby("stats:processed", 1)
                if record.sensor_id:
                    pipe.hincrby(f"sensor:{record.sensor_id}", "count", record.count or 1)

                await pipe.execute()

        logger.debug({"event": "record_stored", "rrname": rrname, "rrtype": rrtype})

    async def get_record(self, rrname: str, cursor: Optional[str], limit: int, rrtype: Optional[str] = None) -> Tuple[List[PDNSRecord], Optional[str], int]:
        """Fetch records for a given rrname with pagination."""
        if not self.redis_pool:
            await self.connect()

        async with self.redis_pool.acquire() as redis:
            try:
                rrname = rrname.lower().rstrip(".")
                query_key = f"r:{rrname}:{rrtype}" if rrtype else f"r:{rrname}:*"
                cursor = cursor or "0"
                records = []

                rdata_list = []
                total = 0
                while True:
                    cursor, rdata = await redis.sscan(query_key, cursor, count=limit)
                    rdata_list.extend(rdata)
                    total += len(rdata)
                    if cursor == "0":
                        break
                    if len(rdata_list) >= limit:
                        break

                next_cursor = cursor if cursor != "0" and len(rdata_list) >= limit else None

                for rd in rdata_list[:limit]:
                    record_key = f"record:{rrname}:{rrtype}:{rd}"
                    data = await redis.hgetall(record_key)
                    if data:
                        records.append(
                            PDNSRecord(
                                rrname=data["rrname"],
                                rrtype=data["rrtype"],
                                rdata=data["rdata"],
                                time_first=int(data["time_first"]),
                                time_last=int(data["time_last"]),
                                count=int(data["count"]),
                                sensor_id=data.get("sensor_id"),
                            )
                        )

                return records, next_cursor, total
            except aioredis.RedisError as e:
                logger.error({"event": "redis_get_record_failed", "rrname": rrname, "error": str(e)})
                return [], None, 0

    async def stream_records(self, q: str, chunk_size: int = 100) -> AsyncGenerator[PDNSRecord, None]:
        """Stream records for a given rrname in chunks."""
        if not self.redis_pool:
            await self.connect()

        async with self.redis_pool.acquire() as redis:
            cursor = "0"
            q = q.lower().rstrip(".")
            while True:
                cursor, keys = await redis.scan(cursor, match=f"record:{q}:*:*", count=chunk_size)
                for key in keys:
                    data = await redis.hgetall(key)
                    if data:
                        yield PDNSRecord(
                            rrname=data["rrname"],
                            rrtype=data["rrtype"],
                            rdata=data["rdata"],
                            time_first=int(data["time_first"]),
                            time_last=int(data["time_last"]),
                            count=int(data["count"]),
                            sensor_id=data.get("sensor_id"),
                        )
                if cursor == "0":
                    break

    async def get_stats(self) -> dict:
        """Retrieve database statistics."""
        if not self.redis_pool:
            await self.connect()

        async with self.redis_pool.acquire() as redis:
            try:
                processed = await redis.get("stats:processed") or "0"
                types = await redis.hgetall("stats:types")
                return {"records_processed": int(processed), "types": {k: int(v) for k, v in types.items()}}
            except aioredis.RedisError as e:
                logger.error({"event": "redis_get_stats_failed", "error": str(e)})
                return {"records_processed": 0, "types": {}}

    async def get_sensors(self) -> List[Tuple[str, int]]:
        """Retrieve sensor statistics."""
        if not self.redis_pool:
            await self.connect()

        async with self.redis_pool.acquire() as redis:
            try:
                cursor = "0"
                sensors = []
                while True:
                    cursor, keys = await redis.scan(cursor, match="sensor:*", count=100)
                    for key in keys:
                        count = await redis.hget(key, "count") or "0"
                        sensors.append((key.split(":")[1], int(count)))
                    if cursor == "0":
                        break
                return sensors
            except aioredis.RedisError as e:
                logger.error({"event": "redis_get_sensors_failed", "error": str(e)})
                return []

    async def get_associated_records(self, q: str) -> List[str]:
        """Get associated rrnames for a given rdata."""
        if not self.redis_pool:
            await self.connect()

        async with self.redis_pool.acquire() as redis:
            try:
                associated = []
                cursor = "0"
                while True:
                    cursor, keys = await redis.scan(cursor, match=f"v:{q}:*", count=100)
                    for key in keys:
                        rrnames = await redis.smembers(key)
                        associated.extend(rrnames)
                    if cursor == "0":
                        break
                return list(set(associated))
            except aioredis.RedisError as e:
                logger.error({"event": "redis_get_associated_records_failed", "query": q, "error": str(e)})
                return []