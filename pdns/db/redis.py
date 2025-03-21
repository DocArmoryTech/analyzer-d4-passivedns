# pdns/databases/redis.py
import redis.asyncio as redis
from ..schemas import DNSRecord
from ..rrtypes import rrset  
from ..default.exceptions import DNSParseError
from .base import Database
from typing import List, Optional, Tuple, AsyncGenerator

class RedisDatabase(Database):
    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0):
        self.host = host
        self.port = port
        self.db = db
        self.client = None

    async def connect(self):
        if not self.client:
            self.client = redis.Redis(host=self.host, port=self.port, db=self.db)
        return self.client

    async def disconnect(self):
        if self.client:
            await self.client.close()
            self.client = None

    async def get_stats(self) -> int:
        client = await self.connect()
        stats = await client.get('stats:processed')
        return int(stats or 0)

    async def get_sensors(self) -> List[Tuple[str, float]]:
        client = await self.connect()
        sensors = await client.zrange('stats:sensors', 0, -1, withscores=True)
        return [(s.decode(), float(c)) for s, c in sensors]

    async def get_timestamps_and_count(self, t1: str, t2: str, rr_values: List[str]) -> Tuple[Optional[int], Optional[int], Optional[int]]:
        client = await self.connect()
        first = await client.get(f"s:{t1}:{t2}:{rr_values[0]}")
        last = await client.get(f"l:{t1}:{t2}:{rr_values[0]}")
        count = await client.get(f"o:{t1}:{t2}:{rr_values[0]}")
        return (
            int(first) if first else None,
            int(last) if last else None,
            int(count) if count else None
        )

    async def get_record(self, t: str, cursor: Optional[str], limit: int, rrtype: Optional[str]) -> Tuple[List[dict], Optional[str], int]:
        client = await self.connect()
        pattern = f"r:{t.lower()}:*" if not rrtype else f"r:{t.lower()}:{rrtype}"
        keys = await client.keys(pattern)
        records = []
        for key in keys[:limit]:
            rdata = await client.smembers(key.decode())
            for rd in rdata:
                rd = rd.decode()
                type_val = key.decode().split(':')[-1]
                first, last, count = await self.get_timestamps_and_count(t, rd, [type_val])
                records.append({
                    "rrname": t,
                    "rrtype": type_val,  # Numeric for now; mapped in routes
                    "rdata": rd,
                    "time_first": first,
                    "time_last": last,
                    "count": count or 1
                })
        next_cursor = "more" if len(keys) > limit else None
        return records, next_cursor, len(records)

    async def store_record(self, record: DNSRecord, expiration: Optional[int] = None) -> None:
        client = await self.connect()
        rrname = record.rrname
        rdata = record.rdata
        rrtype_value = rrset[record.rrtype]  # Use rrset directly
        
        query_key = f"r:{rrname}:{rrtype_value}"
        await client.sadd(query_key, rdata)
        if expiration:
            await client.expire(query_key, expiration)
        
        reverse_key = f"v:{rdata}:{rrtype_value}"
        await client.sadd(reverse_key, rrname)
        if expiration:
            await client.expire(reverse_key, expiration)
        
        firstseen_key = f"s:{rrname}:{rdata}:{rrtype_value}"
        lastseen_key = f"l:{rrname}:{rdata}:{rrtype_value}"
        count_key = f"o:{rrname}:{rdata}:{rrtype_value}"
        
        if not await client.exists(firstseen_key):
            await client.set(firstseen_key, record.time_first)
        if expiration:
            await client.expire(firstseen_key, expiration)
        
        last = await client.get(lastseen_key)
        if last is None or int(last) < record.time_last:
            await client.set(lastseen_key, record.time_last)
        if expiration:
            await client.expire(lastseen_key, expiration)
        
        await client.incrby(count_key, record.count)
        if expiration:
            await client.expire(count_key, expiration)
        
        await client.incrby('stats:processed', 1)
        if record.sensor_id:
            await client.sadd('sensors:seen', record.sensor_id)
            await client.zincrby('stats:sensors', 1, record.sensor_id)

    async def get_associated_records(self, rdata: str) -> List[str]:
        client = await self.connect()
        keys = await client.keys(f"v:{rdata}:*")
        rrnames = []
        for key in keys:
            rrnames.extend([r.decode() for r in await client.smembers(key)])
        return rrnames

    async def stream_records(self, t: str, chunk_size: int) -> AsyncGenerator[str, None]:
        client = await self.connect()
        keys = await client.keys(f"r:{t.lower()}:*")
        for key in keys:
            rdata = await client.smembers(key.decode())
            for rd in rdata:
                rd = rd.decode()
                type_val = key.decode().split(':')[-1]
                first, last, count = await self.get_timestamps_and_count(t, rd, [type_val])
                yield f"{t}||{type_val}||{rd}||{first}||{last}||{count}"