import pytest
from pdns.ingestors.ndjson import NDJSONFileIngestor
from pdns.db.manager import DatabaseManager
from pypdns import PDNSRecord
from unittest.mock import AsyncMock
import json

@pytest.mark.asyncio
async def test_parse_line_valid():
    ingestor = NDJSONFileIngestor(AsyncMock(spec=DatabaseManager), "dummy_path")
    line = json.dumps({"rrname": "example.com", "rrtype": "A", "rdata": ["1.2.3.4"], "time_first": 1234567890})
    record = await ingestor.parse_line(line)
    assert isinstance(record, PDNSRecord)
    assert record.rrname == "example.com"
    assert record.rrtype == "A"
    assert record.rdata == ["1.2.3.4"]
    assert record.time_first == 1234567890

@pytest.mark.asyncio
async def test_parse_line_invalid_json():
    ingestor = NDJSONFileIngestor(AsyncMock(spec=DatabaseManager), "dummy_path")
    line = "not json"
    with pytest.raises(Exception):
        await ingestor.parse_line(line)

@pytest.mark.asyncio
async def test_parse_line_missing_fields():
    ingestor = NDJSONFileIngestor(AsyncMock(spec=DatabaseManager), "dummy_path")
    line = json.dumps({"rrname": "example.com"})
    record = await ingestor.parse_line(line)
    assert record is None

@pytest.mark.asyncio
async def test_ingest_file(tmp_path):
    db_manager = AsyncMock(spec=DatabaseManager)
    file = tmp_path / "test.ndjson"
    content = (
        json.dumps({"rrname": "example.com", "rrtype": "A", "rdata": ["1.2.3.4"]}) + "\n"
        + json.dumps({"rrname": "test.com", "rrtype": "AAAA", "rdata": ["2600::"]}) + "\n"
        + "invalid json\n"
    )
    file.write_text(content)
    ingestor = NDJSONFileIngestor(db_manager, str(file))
    await ingestor.ingest()
    assert db_manager.store_record.call_count == 2
    calls = db_manager.store_record.call_args_list
    assert calls[0][0][0].rrname == "example.com"
    assert calls[1][0][0].rrname == "test.com"

@pytest.mark.asyncio
async def test_ingest_empty_file(tmp_path):
    db_manager = AsyncMock(spec=DatabaseManager)
    file = tmp_path / "empty.ndjson"
    file.write_text("")
    ingestor = NDJSONFileIngestor(db_manager, str(file))
    await ingestor.ingest()
    assert db_manager.store_record.call_count == 0