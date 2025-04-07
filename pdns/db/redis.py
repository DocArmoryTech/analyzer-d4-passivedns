# pdns/db/redis.py
from .base import Database
from ..default.helpers import logger, get_config
from pypdns import PDNSRecord
import aioredis
import json
from typing import Tuple, List, Optional, AsyncGenerator

class RedisDatabase(Database):
    """Redis implementation of the Database interface for Passive DNS storage."""

    def __init__(self):
        """Initialize Redis connection based on database.json config."""
        # Load Redis configuration with defaults
        self.config = get_config("redis", default={"host": "127.0.0.1", "port": 6379, "db": 0})
        self.db_number = self.config.get("db", 0)
        self.redis_pool = None
        # Load expiration settings for records
        self.expirations = get_config("generic", "expiration", quiet=True) or {}

    async def connect(self) -> None:
        """Establish a connection pool to Redis."""
        try:
            if "socket" in self.config:
                # Unix socket connection
                self.redis_pool = await aioredis.create_redis_pool(
                    self.config["socket"],
                    db=self.db_number,
                    decode_responses=True,
                    encoding="utf-8",
                    minsize=1,
                    maxsize=10
                )
                logger.info({
                    "event": "redis_init",
                    "type": "unix",
                    "socket": self.config["socket"],
                    "db": self.db_number
                })
            elif "host" in self.config and "port" in self.config:
                # TCP connection
                self.redis_pool = await aioredis.create_redis_pool(
                    (self.config["host"], self.config["port"]),
                    db=self.db_number,
                    decode_responses=True,
                    encoding="utf-8",
                    minsize=1,
                    maxsize=10
                )
                logger.info({
                    "event": "redis_init",
                    "type": "tcp",
                    "host": self.config["host"],
                    "port": self.config["port"],
                    "db": self.db_number
                })
            else:
                raise ValueError("Invalid Redis config: must specify 'socket' or 'host' and 'port'")
        except Exception as e:
            logger.error({"event": "redis_connect_error", "error": str(e)})
            raise

    async def disconnect(self) -> None:
        """Close the Redis connection pool."""
        if self.redis_pool:
            self.redis_pool.close()
            await self.redis_pool.wait_closed()
            logger.info({"event": "redis_disconnect"})

    async def store_record(self, record: PDNSRecord) -> None:
        """Store a Passive DNS record in Redis, associating with sensor-id."""
        if not self.redis_pool:
            await self.connect()

        # Normalize record attributes
        rrtype = str(record.rrtype) if record.rrtype.isdigit() else str(record.rrtype)
        rrname = record.rrname.lower().rstrip(".")
        rdata = record.rdata if isinstance(record.rdata, list) else [record.rdata]
        expiration = self.expirations.get(rrtype)

        # Use connection from pool and pipeline for batch operations
        async with self.redis_pool.acquire() as redis:
            async with redis.pipeline() as pipe:
                for rd in rdata:
                    # Define keys for storing relationships and metadata
                    query_key = f"r:{rrname}:{rrtype}"
                    value_key = f"v:{rd}:{rrtype}"
                    firstseen_key = f"s:{rrname}:{rd}:{rrtype}"
                    lastseen_key = f"l:{rrname}:{rd}:{rrtype}"
                    occ_key = f"o:{rrname}:{rd}:{rrtype}"
                    sensor_key = f"sensor:{rrname}:{rd}:{rrtype}"

                    # Store relationships
                    pipe.sadd(query_key, rd)
                    pipe.sadd(value_key, rrname)
                    if expiration:
                        pipe.expire(query_key, expiration)
                        pipe.expire(value_key, expiration)

                    # Store timestamps and occurrence count
                    if not await redis.exists(firstseen_key):
                        pipe.set(firstseen_key, str(record.time_first))
                    current_lastseen = await redis.get(lastseen_key)
                    if current_lastseen is None or int(record.time_last) > int(current_lastseen):
                        pipe.set(lastseen_key, str(record.time_last))
                    pipe.incrby(occ_key, record.count or 1)

                    # Store sensor ID if provided
                    if record.sensor_id:
                        pipe.set(sensor_key, record.sensor_id)

                # Update statistics
                pipe.hincrby("dist:type", rrtype, 1)
                pipe.incrby("stats:processed", 1)
                if record.sensor_id:
                    pipe.hincrby(f"sensor:{record.sensor_id}", "count", record.count or 1)

                # Execute pipeline
                await pipe.execute()

        logger.debug({"event": "record_stored", "rrname": rrname, "rrtype": rrtype, "rdata": rdata})

    async def get_record(self, rrname: str, cursor: Optional[str] = None, limit: int = 200, rrtype: Optional[str] = None) -> Tuple[List[PDNSRecord], Optional[str], int]:
        """Fetch records for a given rrname with optional rrtype filter and pagination."""
        if not self.redis_pool:
            await self.connect()

        async with self.redis_pool.acquire() as redis:
            try:
                rrname = rrname.lower().rstrip(".")
                query_key = f"r:{rrname}:{rrtype}" if rrtype else None

                if query_key:
                    # Fetch rdata for specific rrtype
                    rdata_set = await redis.smembers(query_key)
                else:
                    # Scan for all rrtypes if not specified
                    cursor_scan = 0
                    rdata_set = set()
                    while True:
                        cursor_scan, keys = await redis.scan(cursor_scan, match=f"r:{rrname}:*", count=100)
                        for key in keys:
                            rdata_set.update(await redis.smembers(key))
                        if cursor_scan == 0:
                            break

                if not rdata_set:
                    return [], None, 0

                # Pagination
                rdata_list = sorted(rdata_set)  # Sort for consistent ordering
                start = int(cursor) if cursor else 0
                end = min(start + limit, len(rdata_list))
                total = len(rdata_list)
                paginated_rdata = rdata_list[start:end]
                next_cursor = str(end) if end < total else None

                # Reconstruct PDNSRecord objects
                records = []
                rrtypes = [rrtype] if rrtype else [k.split(":")[-1] for k in keys] if not query_key else []
                for rd in paginated_rdata:
                    for rrt in rrtypes or [rrtype]:
                        firstseen_key = f"s:{rrname}:{rd}:{rrt}"
                        lastseen_key = f"l:{rrname}:{rd}:{rrt}"
                        occ_key = f"o:{rrname}:{rd}:{rrt}"
                        sensor_key = f"sensor:{rrname}:{rd}:{rrt}"

                        time_first = await redis.get(firstseen_key) or 0
                        time_last = await redis.get(lastseen_key) or 0
                        count = await redis.get(occ_key) or 1
                        sensor_id = await redis.get(sensor_key)

                        records.append(PDNSRecord(
                            rrname=rrname,
                            rrtype=rrt,
                            rdata=rd,
                            time_first=int(time_first),
                            time_last=int(time_last),
                            count=int(count),
                            sensor_id=sensor_id
                        ))

                return records, next_cursor, total
            except Exception as e:
                logger.error({"event": "redis_get_record_failed", "rrname": rrname, "error": str(e)})
                return [], None, 0

    async def stream_records(self, q: str, chunk_size: int = 100) -> AsyncGenerator[PDNSRecord, None]:
        """Stream records for a given query in chunks."""
        if not self.redis_pool:
            await self.connect()

        async with self.redis_pool.acquire() as redis:
            cursor = 0
            while True:
                cursor, keys = await redis.scan(cursor, match=f"pdns:{q}:*", count=chunk_size)
                for key in keys:
                    value = await redis.get(key)
                    if value:
                        data = json.loads(value)
                        yield PDNSRecord(**data)
                if cursor == 0:
                    break

    async def get_stats(self) -> dict:
        """Retrieve database statistics."""
        if not self.redis_pool:
            await self.connect()

        async with self.redis_pool.acquire() as redis:
            try:
                info = await redis.info()
                return {"records": info.get("keys", 0)}
            except Exception as e:
                logger.error({"event": "redis_get_stats_failed", "error": str(e)})
                return {"records": 0}

    async def get_sensors(self) -> List[Tuple[str, int]]:
        """Retrieve sensor statistics."""
        if not self.redis_pool:
            await self.connect()

        async with self.redis_pool.acquire() as redis:
            try:
                sensor_keys = await redis.keys("sensor:*")
                sensors = []
                for key in sensor_keys:
                    count = await redis.hget(key, "count")
                    if count:
                        sensors.append((key.split(":")[1], int(count)))
                return sensors
            except Exception as e:
                logger.error({"event": "redis_get_sensors_failed", "error": str(e)})
                return []

    async def get_associated_records(self, q: str) -> List[str]:
        """Get associated rrnames for a given rdata."""
        if not self.redis_pool:
            await self.connect()

        async with self.redis_pool.acquire() as redis:
            try:
                associated = []
                cursor = 0
                while True:
                    cursor, keys = await redis.scan(cursor, match=f"v:{q}:*", count=100)
                    for key in keys:
                        rrnames = await redis.smembers(key)
                        associated.extend(rrnames)
                    if cursor == 0:
                        break
                return list(set(associated))  # Remove duplicates
            except Exception as e:
                logger.error({"event": "redis_get_associated_records_failed", "query": q, "error": str(e)})
                return []