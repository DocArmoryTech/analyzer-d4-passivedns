# pdns/databases/redis.py
import asyncio
from typing import Optional, List, Tuple
from ..db.base import Database
from ..default.helpers import logger
from ..schemas import DNSRecord
import redis.asyncio as redis
from ..rrtypes import rrset
import json

class RedisDatabase(Database):
    def __init__(self, host: str = "127.0.0.1", port: int = 6400, db: int = 0):
        super().__init__()
        self.host = host
        self.port = port
        self.db = db
        self.pool = None

    async def connect(self, pool_size: int = 10):
        """Connect to Redis with a connection pool."""
        if not self.pool:
            self.pool = redis.ConnectionPool(
                host=self.host,
                port=self.port,
                db=self.db,
                max_connections=pool_size,
                decode_responses=True
            )
            self.client = redis.Redis(connection_pool=self.pool)
        return self.client

    async def disconnect(self):
        """Disconnect from Redis and close the pool."""
        if self.pool:
            await self.pool.disconnect()
            self.pool = None
            self.client = None

    async def store_record(self, record: DNSRecord) -> None:
        """Store a DNS record in Redis."""
        if not self.client:
            await self.connect()
        rrtype = record.rrtype if record.rrtype.isdigit() else str(next(v for k, v in rrset.items() if k == record.rrtype))
        rdata = record.rdata[0]
        key = f"dns:{record.rrname}:{rrtype}:{rdata}"
        name_key = f"dnsname:{record.rrname}"
        data_key = f"dnsdata:{rdata}"

        record_json = record.to_json()
        async with self.client.pipeline() as pipe:
            expiration = self.expirations.get(record.rrtype)
            if expiration is not None:
                pipe.setex(key, expiration, record_json)
            else:
                pipe.set(key, record_json)

            pipe.sadd(name_key, f"{rrtype}||{rdata}")
            pipe.sadd(data_key, f"{record.rrname}||{rrtype}")
            pipe.hincrby("stat", "dns", 1)
            pipe.hincrby("stat", "dnsname", 1 if await self.client.scard(name_key) == 1 else 0)
            pipe.hincrby("stat", "dnsdata", 1 if await self.client.scard(data_key) == 1 else 0)
            if record.sensor_id:
                pipe.hincrby(f"sensor:{record.sensor_id}", "count", record.count)
            await pipe.execute()

        logger.debug({"event": "record_stored", "key": key})

    async def get_record(self, q: str, cursor: str, limit: int, rrtype: str = None) -> Tuple[List[dict], Optional[str], int]:
        if not self.client:
            await self.connect()
        name_key = f"dnsname:{q}"
        members = await self.client.smembers(name_key)
        records = []
        total = len(members)

        start = int(cursor) if cursor else 0
        end = min(start + limit, total) if total > 0 else 0
        next_cursor = str(end) if end < total else None

        for member in sorted(members)[start:end]:
            rtype, rdata = member.split("||")
            if rrtype and rtype != rrtype:
                continue
            key = f"dns:{q}:{rtype}:{rdata}"
            record_json = await self.client.get(key)
            if record_json:
                records.append(json.loads(record_json))

        return records, next_cursor, total

    async def get_associated_records(self, q: str) -> List[str]:
        if not self.client:
            await self.connect()
        if "." in q and not q.startswith("dns"):
            key = f"dnsdata:{q}"
            members = await self.client.smembers(key)
            return [m.split("||")[0] for m in members]
        return [q]

    async def stream_records(self, q: str, chunk_size: int) -> str:
        if not self.client:
            await self.connect()
        name_key = f"dnsname:{q}"
        members = await self.client.smembers(name_key)
        for i in range(0, len(members), chunk_size):
            chunk = sorted(members)[i:i + chunk_size]
            for member in chunk:
                rtype, rdata = member.split("||")
                key = f"dns:{q}:{rtype}:{rdata}"
                record_json = await self.client.get(key)
                if record_json:
                    yield json.loads(record_json)["rrname"] + "||" + rtype + "||" + rdata + "||" + \
                          str(json.loads(record_json)["time_first"]) + "||" + str(json.loads(record_json)["time_last"]) + "||" + \
                          str(json.loads(record_json)["count"]) + "\n"
            await asyncio.sleep(0)

    async def get_stats(self) -> dict:
        if not self.client:
            await self.connect()
        stats = await self.client.hgetall("stat")
        return {k: int(v) for k, v in stats.items()}

    async def get_sensors(self) -> List[Tuple[str, int]]:
        if not self.client:
            await self.connect()
        sensor_keys = await self.client.keys("sensor:*")
        sensors = []
        for key in sensor_keys:
            sensor_id = key.split(":", 1)[1]
            count = await self.client.hget(key, "count")
            sensors.append((sensor_id, int(count or 0)))
        return sensors