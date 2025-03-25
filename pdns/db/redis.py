# pdns/databases/redis.py
import asyncio
from typing import Optional, List, Tuple, AsyncGenerator
from ..db.base import Database
from ..default.helpers import logger
from pypdns import PDNSRecord  # Import from pypdns
import redis.asyncio as redis
from ..rrtypes import rrset, rrset_supported
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

    async def store_record(self, record: PDNSRecord) -> None:
        """Store a Passive DNS record in Redis, handling multiple rdata entries."""
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
                pipe.incrby(occ_key, record.count or 1)  # Default to 1 if count is None

            # Stats outside the rdata loop
            pipe.hincrby("dist:type", rrtype, 1)
            pipe.incrby("stats:processed", 1)
            if record.sensor_id:
                pipe.hincrby(f"sensor:{record.sensor_id}", "count", record.count or 1)

            await pipe.execute()

        logger.debug({"event": "record_stored", "rrname": rrname, "rrtype": rrtype, "rdata": rdata})

    async def get_record(self, q: str, cursor: str, limit: int, rrtype: str = None) -> Tuple[List[PDNSRecord], Optional[str], int]:
        """Retrieve Passive DNS records for a given query name, pipelining supported rrtypes."""
        if not self.client:
            await self.connect()

        rrtypes = [rrtype] if rrtype else rrset_supported
        if rrtype and not rrtype.isdigit():
            rrtypes = [str(rrset.get(rrtype.upper(), rrtype))]

        rdata_by_type = {}
        total = 0

        async with self.client.pipeline() as pipe:
            for rtype in rrtypes:
                query_key = f"r:{q}:{rtype}"
                pipe.smembers(query_key)
            results = await pipe.execute()

            for rtype, rdata_set in zip(rrtypes, results):
                if rdata_set:
                    rdata_by_type[rtype] = rdata_set
                    total += len(rdata_set)

        if not rdata_by_type:
            return [], None, 0

        records = []
        for rtype, rdata_set in rdata_by_type.items():
            async with self.client.pipeline() as pipe:
                for rdata in rdata_set:
                    firstseen_key = f"s:{q}:{rdata}:{rtype}"
                    lastseen_key = f"l:{q}:{rdata}:{rtype}"
                    occ_key = f"o:{q}:{rdata}:{rtype}"
                    pipe.get(firstseen_key)
                    pipe.get(lastseen_key)
                    pipe.get(occ_key)
                results = await pipe.execute()

                metadata = {}
                for i, rdata in enumerate(rdata_set):
                    firstseen, lastseen, count = results[i * 3:(i + 1) * 3]
                    if firstseen and lastseen and count:
                        metadata[rdata] = (int(firstseen), int(lastseen), int(count))

                if metadata:
                    record_dict = {
                        "rrname": q,
                        "rrtype": rtype,
                        "rdata": list(rdata_set),
                        "time_first": min(t[0] for t in metadata.values()),
                        "time_last": max(t[1] for t in metadata.values()),
                        "count": sum(t[2] for t in metadata.values()),
                        "sensor_id": None,  # Add logic if stored elsewhere
                        "origin": None  # Add logic if stored elsewhere
                    }
                    records.append(PDNSRecord(record_dict))

        sorted_records = sorted(records, key=lambda r: (r.rrtype, r.rdata[0] if isinstance(r.rdata, list) else r.rdata))
        start = int(cursor) if cursor else 0
        end = min(start + limit, len(sorted_records)) if sorted_records else 0
        next_cursor = str(end) if end < len(sorted_records) else None

        return sorted_records[start:end], next_cursor, len(sorted_records)

    async def get_associated_records(self, q: str) -> List[str]:
        """Get associated rrnames for a given rdata, pipelining supported rrtypes."""
        if not self.client:
            await self.connect()
        if "." not in q or q.startswith("r:"):
            return [q]

        rrnames = set()
        async with self.client.pipeline() as pipe:
            for rtype in rrset_supported:
                value_key = f"v:{q}:{rtype}"
                pipe.smembers(value_key)
            results = await pipe.execute()

            for rrname_set in results:
                rrnames.update(rrname_set)

        return list(rrnames)

    async def stream_records(self, q: str, chunk_size: int) -> AsyncGenerator[PDNSRecord, None]:
        """Stream Passive DNS records as PDNSRecord objects, pipelining supported rrtypes."""
        if not self.client:
            await self.connect()

        rdata_by_type = {}
        async with self.client.pipeline() as pipe:
            for rtype in rrset_supported:
                query_key = f"r:{q}:{rtype}"
                pipe.smembers(query_key)
            results = await pipe.execute()

            for rtype, rdata_set in zip(rrset_supported, results):
                if rdata_set:
                    rdata_by_type[rtype] = rdata_set

        if not rdata_by_type:
            return

        records_by_type = {}
        for rtype, rdata_set in rdata_by_type.items():
            async with self.client.pipeline() as pipe:
                for rdata in rdata_set:
                    firstseen_key = f"s:{q}:{rdata}:{rtype}"
                    lastseen_key = f"l:{q}:{rdata}:{rtype}"
                    occ_key = f"o:{q}:{rdata}:{rtype}"
                    pipe.get(firstseen_key)
                    pipe.get(lastseen_key)
                    pipe.get(occ_key)
                results = await pipe.execute()

                metadata = {}
                for i, rdata in enumerate(rdata_set):
                    firstseen, lastseen, count = results[i * 3:(i + 1) * 3]
                    if firstseen and lastseen and count:
                        metadata[rdata] = (int(firstseen), int(lastseen), int(count))

                if metadata:
                    record_dict = {
                        "rrname": q,
                        "rrtype": rtype,
                        "rdata": list(rdata_set),
                        "time_first": min(t[0] for t in metadata.values()),
                        "time_last": max(t[1] for t in metadata.values()),
                        "count": sum(t[2] for t in metadata.values()),
                        "sensor_id": None,  # Add logic if stored elsewhere
                        "origin": None  # Add logic if stored elsewhere
                    }
                    records_by_type[rtype] = PDNSRecord(record_dict)

        sorted_items = sorted(records_by_type.items(), key=lambda x: x[0])
        for i in range(0, len(sorted_items), chunk_size):
            chunk = sorted_items[i:i + chunk_size]
            for _, record in chunk:
                yield record
            await asyncio.sleep(0)

    async def get_stats(self) -> dict:
        """Retrieve database statistics."""
        if not self.client:
            await self.connect()
        stats = {}
        stats["processed"] = int(await self.client.get("stats:processed") or 0)
        stats["ttl"] = {k: int(v) for k, v in (await self.client.hgetall("dist:ttl") or {}).items()}
        stats["class"] = {k: int(v) for k, v in (await self.client.hgetall("dist:class") or {}).items()}
        stats["type"] = {k: int(v) for k, v in (await self.client.hgetall("dist:type") or {}).items()}
        return stats

    async def get_sensors(self) -> List[Tuple[str, int]]:
        """Retrieve sensor statistics."""
        if not self.client:
            await self.connect()
        sensor_keys = await self.client.keys("sensor:*")
        sensors = []
        for key in sensor_keys:
            sensor_id = key.split(":", 1)[1]
            count = await self.client.hget(key, "count")
            sensors.append((sensor_id, int(count or 0)))
        return sensors