import pytest
from pdns.ingestors.passivedns import PDNSIngestor
from pdns.db.manager import DatabaseManager
from pypdns import PDNSRecord
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_parse_line_valid():
    ingestor = PDNSIngestor(AsyncMock(spec=DatabaseManager), "dummy_path")
    line = "1234567890||1.1.1.1||2.2.2.2||IN||example.com||A||1.2.3.4||3600||1"
    record = await ingestor.parse_line(line)
    assert isinstance(record, PDNSRecord)
    assert record.time_first == 1234567890
    assert record.rrname == "example.com"
    assert record.rrtype == "A"
    assert record.rdata == ["1.2.3.4"]

@pytest.mark.asyncio
async def test_parse_line_invalid_format():
    ingestor = PDNSIngestor(AsyncMock(spec=DatabaseManager), "dummy_path")
    line = "invalid||data"
    with pytest.raises(Exception):
        await ingestor.parse_line(line)

@pytest.mark.asyncio
async def test_parse_line_empty():
    ingestor = PDNSIngestor(AsyncMock(spec=DatabaseManager), "dummy_path")
    line = ""
    record = await ingestor.parse_line(line)
    assert record is None

@pytest.mark.asyncio
async def test_ingest_file(tmp_path):
    db_manager = AsyncMock(spec=DatabaseManager)
    file = tmp_path / "test_pdns.txt"
    content = (
        "1234567890||1.1.1.1||2.2.2.2||IN||example.com||A||1.2.3.4||3600||1\n"
        "1234567891||1.1.1.1||2.2.2.2||IN||test.com||AAAA||2600::||3600||1\n"
        "invalid||line\n"
    )
    file.write_text(content)
    ingestor = PDNSIngestor(db_manager, str(file))
    await ingestor.ingest()
    assert db_manager.store_record.call_count == 2
    calls = db_manager.store_record.call_args_list
    assert calls[0][0][0].rrname == "example.com"
    assert calls[1][0][0].rrname == "test.com"

@pytest.mark.asyncio
async def test_ingest_empty_file(tmp_path):
    db_manager = AsyncMock(spec=DatabaseManager)
    file = tmp_path / "empty.txt"
    file.write_text("")
    ingestor = PDNSIngestor(db_manager, str(file))
    await ingestor.ingest()
    assert db_manager.store_record.call_count == 0