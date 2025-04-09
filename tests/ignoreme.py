# tests/test_db.py
import pytest
import asyncio
from pdns.db.manager import DatabaseManager
from pdns.db.redis import RedisDatabase
from pypdns import PDNSRecord

@pytest.mark.asyncio
async def test_store_record_with_expiration():
    db = RedisDatabase()
    manager = DatabaseManager(db)
    manager.expirations = {"16": 24000}  # Mock config
    await manager.initialize()

    record = PDNSRecord(rrname="example.com", rrtype="16", rdata="1.2.3.4", time_first=1600000000, time_last=1600000000)
    await manager.store_record(record)

    async with db.redis_pool.acquire() as redis:
        ttl = await redis.ttl("r:example.com:16")
        assert 23000 <= ttl <= 24000  # Allow some timing variance

    await manager.shutdown()