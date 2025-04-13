import pytest
from pdns.ingestors.redisqueue import RedisQueueIngestor
from pdns.db.manager import DatabaseManager
from pypdns import PDNSRecord
from unittest.mock import AsyncMock, patch
import asyncio

@pytest.mark.asyncio
async def test_parse_line_valid():
    ingestor = RedisQueueIngestor(AsyncMock(spec=DatabaseManager), "redis://localhost")
    line = "1234567890||1.1.1.1||2.2.2.2||IN||example.com||A||1.2.3.4||3600||1"
    record = await ingestor.parse_line(line)
    assert isinstance(record, PDNSRecord)
    assert record.rrname == "example.com"
    assert record.rdata == ["1.2.3.4"]

@pytest.mark.asyncio
async def test_ingest_redis_queue():
    db_manager = AsyncMock(spec=DatabaseManager)
    with patch("aioredis.create_redis_pool", new_callable=AsyncMock) as mock_redis_pool:
        mock_redis = mock_redis_pool.return_value
        mock_redis.rpop.side_effect = [
            b"1234567890||1.1.1.1||2.2.2.2||IN||example.com||A||1.2.3.4||3600||1",
            b"1234567891||1.1.1.1||2.2.2.2||IN||test.com||AAAA||2600::||3600||1",
            None,  # Empty queue
        ]
        ingestor = RedisQueueIngestor(db_manager, "redis://localhost")
        task = asyncio.create_task(ingestor.ingest())
        await asyncio.sleep(0.1)
        ingestor.stop()
        await task
        assert db_manager.store_record.call_count == 2
        calls = db_manager.store_record.call_args_list
        assert calls[0][0][0].rrname == "example.com"
        assert calls[1][0][0].rrname == "test.com"

@pytest.mark.asyncio
async def test_redis_connection_failure():
    db_manager = AsyncMock(spec=DatabaseManager)
    with patch("aioredis.create_redis_pool", side_effect=Exception("Connection failed")):
        ingestor = RedisQueueIngestor(db_manager, "redis://localhost")
        task = asyncio.create_task(ingestor.ingest())
        await asyncio.sleep(0.1)
        ingestor.stop()
        await task
        assert db_manager.store_record.call_count == 0

@pytest.mark.asyncio
async def test_redis_invalid_data():
    db_manager = AsyncMock(spec=DatabaseManager)
    with patch("aioredis.create_redis_pool", new_callable=AsyncMock) as mock_redis_pool:
        mock_redis = mock_redis_pool.return_value
        mock_redis.rpop.side_effect = [
            b"invalid||data",
            None,
        ]
        ingestor = RedisQueueIngestor(db_manager, "redis://localhost")
        task = asyncio.create_task(ingestor.ingest())
        await asyncio.sleep(0.1)
        ingestor.stop()
        await task
        assert db_manager.store_record.call_count == 0