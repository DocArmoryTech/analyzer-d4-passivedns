import pytest
from pdns.ingestors.zeek import ZeekIngestor
from pdns.db.manager import DatabaseManager
from pypdns import PDNSRecord
from unittest.mock import AsyncMock
import json

@pytest.mark.asyncio
async def test_parse_line_valid():
    ingestor = ZeekIngestor(AsyncMock(spec=DatabaseManager), "dummy_path")
    line = json.dumps({
        "ts": "1234567890.123",
        "query": "example.com",
        "qtype_name": "A",
        "answers": ["1.2.3.4"]
    })
    record = await ingestor.parse_line(line)
    assert isinstance(record, PDNSRecord)
    assert record.rrname == "example.com"
    assert record.rrtype == "A"
    assert record.rdata == ["1.2.3.4"]
    assert record.time_first == int(float("1234567890.123"))

@pytest.mark.asyncio
async def test_parse_line_missing_fields():
    ingestor = ZeekIngestor(AsyncMock(spec=DatabaseManager), "dummy_path")
    line = json.dumps({"ts": "1234567890.123"})
    record = await ingestor.parse_line(line)
    assert record is None

@pytest.mark.asyncio
async def test_parse_line_invalid_json():
    ingestor = ZeekIngestor(AsyncMock(spec=DatabaseManager), "dummy_path")
    line = "invalid json"
    with pytest.raises(Exception):
        await ingestor.parse_line(line)

@pytest.mark.asyncio
async def test_ingest_file(tmp_path):
    db_manager = AsyncMock(spec=DatabaseManager)
    file = tmp_path / "test_zeek.jsonl"
    content = (
        json.dumps({"ts": "1234567890.123", "query": "example.com", "qtype_name": "A", "answers": ["1.2.3.4"]}) + "\n"
        + json.dumps({"ts": "1234567891.123", "query": "test.com", "qtype_name": "AAAA", "answers": ["2600::"]}) + "\n"
        + "invalid json\n"
    )
    file.write_text(content)
    ingestor = ZeekIngestor(db_manager, str(file))
    await ingestor.ingest()
    assert db_manager.store_record.call_count == 2
    calls = db_manager.store_record.call_args_list
    assert calls[0][0][0].rrname == "example.com"
    assert calls[1][0][0].rrname == "test.com"

@pytest.mark.asyncio
async def test_ingest_empty_file(tmp_path):
    db_manager = AsyncMock(spec=DatabaseManager)
    file = tmp_path / "empty.jsonl"
    file.write_text("")
    ingestor = ZeekIngestor(db_manager, str(file))
    await ingestor.ingest()
    assert db_manager.store_record.call_count == 0