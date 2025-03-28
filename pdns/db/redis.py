# pdns/db/redis.py
from .base import Database
from ..default.helpers import logger, get_config
from pypdns import PDNSRecord
import aioredis
import json
from typing import Tuple, List, Optional, AsyncGenerator

class RedisDatabase(Database):
    """Redis implementation of the Database interface."""

    def __init__(self, host: str = "127.0.0.1", port: int = 6400, db: int = 0):
        self.redis_pool = None
        self.expirations: Dict[str, int] = get_config("generic", "expiration", quiet=True) or {}


    def __init__(self):
        """Initialize Redis connection based on database.json config."""
        self.config = get_config("redis", default={})  # Load redis config from database.json or fallback
        self.db_number = self.config.get("db", 0)  # Default to DB 0 if not specified

        
    async def connect(self) -> None:
        """Establish a connection pool to Redis."""
        try:
            if "socket" in self.config:
                # Unix socket connection
                self.redis_pool = await aioredis.create_redis_pool(
                    unix_socket_path=self.config["socket"],
                    db=self.db_number,
                    decode_responses=True,
                    encoding="utf-8",
                    minsize=1,
                    maxsize=10
                )
                logger.info({"event": "redis_init", "type": "unix", "socket": self.config["socket"], "db": self.db_number})
            elif "ip" in self.config and "port" in self.config:
                # TCP connection
                self.redis_pool = await aioredis.create_redis_pool(
                    host=self.config["ip"],
                    port=self.config["port"],
                    db=self.db_number,
                    decode_responses=True,
                    encoding="utf-8",
                    minsize=1,
                    maxsize=10
                )
                logger.info({"event": "redis_init", "type": "tcp", "ip": self.config["ip"], "port": self.config["port"], "db": self.db_number})
            else:
                raise ValueError("Invalid Redis config: must specify either 'socket' or 'ip' and 'port'")
        except Exception as e:
            logger.error({"event": "redis_connect_error", "error": str(e)})
            raise RedisConnectionError(f"Failed to connect to Redis: {e}")

    async def disconnect(self) -> None:
        """Close the Redis connection pool."""
        if self.redis_pool:
            self.redis_pool.close()
            await self.redis_pool.wait_closed()
            logger.info({"event": "redis_disconnect"})

    async def store_record(self, record: PDNSRecord) -> None:
        """Store a Passive DNS record in Redis, associating with sensor-id."""
        if not self.client:
            await self.connect()

        rrtype = record.rrtype if record.rrtype.isdigit() else str(rrset.get(record.rrtype.upper(), record.rrtype))
        rrname = record.rrname.lower().rstrip(".")
        rdata = record.rdata if isinstance(record.rdata, list) else [record.rdata]
        expiration = self.expirations.get(rrtype)

        async with self.client.pipeline() as pipe:
            for rd in rdata:
                query_key = f"r:{rrname}:{rrtype}"
                value_key = f"v:{rd}:{rrtype}"
                firstseen_key = f"s:{rrname}:{rd}:{rrtype}"
                lastseen_key = f"l:{rrname}:{rd}:{rrtype}"
                occ_key = f"o:{rrname}:{rd}:{rrtype}"
                sensor_key = f"sensor:{rrname}:{rd}:{rrtype}"  # New key for sensor-id

                pipe.sadd(query_key, rd)
                pipe.sadd(value_key, rrname)
                if expiration:
                    pipe.expire(query_key, expiration)
                    pipe.expire(value_key, expiration)

                if not await self.client.exists(firstseen_key):
                    pipe.set(firstseen_key, str(record.time_first))
                current_lastseen = await self.client.get(lastseen_key)
                if current_lastseen is None or int(record.time_last) > int(current_lastseen):
                    pipe.set(lastseen_key, str(record.time_last))
                pipe.incrby(occ_key, record.count or 1)

                # Store sensor-id if present
                if record.sensor_id:
                    pipe.set(sensor_key, record.sensor_id)

            # Stats outside the rdata loop
            pipe.hincrby("dist:type", rrtype, 1)
            pipe.incrby("stats:processed", 1)
            if record.sensor_id:
                pipe.hincrby(f"sensor:{record.sensor_id}", "count", record.count or 1)

            await pipe.execute()

        logger.debug({"event": "record_stored", "rrname": rrname, "rrtype": rrtype, "rdata": rdata, "sensor_id": record.sensor_id})
            
    async def get_record(self, key: str, cursor: Optional[str] = None, limit: int = 200, rrtype: Optional[str] = None) -> Tuple[List[PDNSRecord], Optional[str], int]:
        """Fetch records for a given key with pagination."""
        try:
            start = int(cursor) if cursor else 0
            end = start + limit - 1
            total = await self.redis.zcard(key)
            records = await self.redis.zrange(key, start, end)
            
            result = []
            for record in records:
                data = json.loads(record)
                pdns_record = PDNSRecord(
                    rrname=data["rrname"],
                    rrtype=data["rrtype"],
                    rdata=data["rdata"],
                    time_first=data["time_first"],
                    time_last=data["time_last"],
                    count=data["count"],
                    sensor_id=data.get("sensor_id")
                )
                if rrtype is None or pdns_record.rrtype == rrtype:
                    result.append(pdns_record)
            
            next_cursor = str(end + 1) if end < total - 1 else None
            return result, next_cursor, total
        except Exception as e:
            logger.error({"event": "redis_get_record_failed", "key": key, "error": str(e)})
            return [], None, 0

    async def stream_records(self, key: str, chunk_size: int = 100) -> AsyncGenerator[PDNSRecord, None]:
        """Stream records for a given key in chunks."""
        try:
            cursor = 0
            while True:
                records = await self.redis.zrange(key, cursor, cursor + chunk_size - 1)
                if not records:
                    break
                for record in records:
                    data = json.loads(record)
                    yield PDNSRecord(
                        rrname=data["rrname"],
                        rrtype=data["rrtype"],
                        rdata=data["rdata"],
                        time_first=data["time_first"],
                        time_last=data["time_last"],
                        count=data["count"],
                        sensor_id=data.get("sensor_id")
                    )
                cursor += chunk_size
        except Exception as e:
            logger.error({"event": "redis_stream_records_failed", "key": key, "error": str(e)})

    async def get_stats(self) -> dict:
        """Return database statistics."""
        try:
            info = await self.redis.info()
            return {"records": info.get("keys", 0)}
        except Exception as e:
            logger.error({"event": "redis_get_stats_failed", "error": str(e)})
            return {"records": 0}

    async def get_sensors(self) -> List[dict]:
        """Return sensor information."""
        # Placeholder; extend with actual sensor tracking if needed
        return [{"sensor_id": "unknown", "count": await self.redis.dbsize()}]