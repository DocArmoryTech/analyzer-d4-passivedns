import pytest
from pdns.ingestors.json import JSONFileIngestor
from pdns.db.manager import DatabaseManager
from pypdns import PDNSRecord
from unittest.mock import AsyncMock
import json

@pytest.mark.asyncio
async def test_ingest_valid_json(tmp_path):
    db_manager = AsyncMock(spec=DatabaseManager)
    file = tmp_path / "test.json"
    data = [
        {"rrname": "example.com", "rrtype": "A", "rdata": ["1.2.3.4"], "time_first": 1234567890},
        {"rrname": "test.com", "rrtype": "AAAA", "rdata": ["2600::"], "time_first": 1234567891},
    ]
    file.write_text(json.dumps(data))
    ingestor = JSONFileIngestor(db_manager, str(file))
    await ingestor.ingest()
    assert db_manager.store_record.call_count == 2
    calls = db_manager.store_record.call_args_list
    assert calls[0][0][0].rrname == "example.com"
    assert calls[1][0][0].rrname == "test.com"

@pytest.mark.asyncio
async def test_ingest_invalid_json(tmp_path):
    db_manager = AsyncMock(spec=DatabaseManager)
    file = tmp_path / "test.json"
    file.write_text("not a json list")
    ingestor = JSONFileIngestor(db_manager, str(file))
    await ingestor.ingest()
    assert db_manager.store_record.call_count == 0

@pytest.mark.asyncio
async def test_ingest_non_list_json(tmp_path):
    db_manager = AsyncMock(spec=DatabaseManager)
    file = tmp_path / "test.json"
    file.write_text(json.dumps({"rrname": "example.com"}))
    ingestor = JSONFileIngestor(db_manager, str(file))
    await ingestor.ingest()
    assert db_manager.store_record.call_count == 0

@pytest.mark.asyncio
async def test_ingest_empty_list(tmp_path):
    db_manager = AsyncMock(spec=DatabaseManager)
    file = tmp_path / "test.json"
    file.write_text(json.dumps([]))
    ingestor = JSONFileIngestor(db_manager, str(file))
    await ingestor.ingest()
    assert db_manager.store_record.call_count == 0

@pytest.mark.asyncio
async def test_ingest_partial_invalid(tmp_path):
    db_manager = AsyncMock(spec=DatabaseManager)
    file = tmp_path / "test.json"
    data = [
        {"rrname": "example.com", "rrtype": "A", "rdata": ["1.2.3.4"]},
        {"rrtype": "missing_name"},
    ]
    file.write_text(json.dumps(data))
    ingestor = JSONFileIngestor(db_manager, str(file))
    await ingestor.ingest()
    assert db_manager.store_record.call_count == 1
    assert db_manager.store_record.call_args[0][0].rrname == "example.com"