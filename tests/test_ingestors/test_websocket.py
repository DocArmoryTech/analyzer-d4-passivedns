import pytest
from pdns.ingestors.websocket import WebSocketIngestor
from pdns.db.manager import DatabaseManager
from pypdns import PDNSRecord
from unittest.mock import AsyncMock, patch
import asyncio
import json

@pytest.mark.asyncio
async def test_parse_line_valid():
    ingestor = WebSocketIngestor(AsyncMock(spec=DatabaseManager), "ws://test")
    line = json.dumps({"rrname": "example.com", "rrtype": "A", "rdata": ["1.2.3.4"], "time_first": 1234567890})
    record = await ingestor.parse_line(line)
    assert isinstance(record, PDNSRecord)
    assert record.rrname == "example.com"
    assert record.rdata == ["1.2.3.4"]

@pytest.mark.asyncio
async def test_ingest_websocket():
    db_manager = AsyncMock(spec=DatabaseManager)
    with patch("websockets.connect", new_callable=AsyncMock) as mock_connect:
        mock_ws = mock_connect.return_value
        mock_ws.recv.side_effect = [
            json.dumps({"rrname": "example.com", "rrtype": "A", "rdata": ["1.2.3.4"]}),
            json.dumps({"rrname": "test.com", "rrtype": "AAAA", "rdata": ["2600::"]}),
            asyncio.CancelledError,  # Simulate connection close
        ]
        ingestor = WebSocketIngestor(db_manager, "ws://test")
        task = asyncio.create_task(ingestor.ingest())
        await asyncio.sleep(0.1)
        ingestor.stop()
        await task
        assert db_manager.store_record.call_count == 2
        calls = db_manager.store_record.call_args_list
        assert calls[0][0][0].rrname == "example.com"
        assert calls[1][0][0].rrname == "test.com"

@pytest.mark.asyncio
async def test_websocket_connection_failure():
    db_manager = AsyncMock(spec=DatabaseManager)
    with patch("websockets.connect", side_effect=Exception("Connection failed")):
        ingestor = WebSocketIngestor(db_manager, "ws://test")
        task = asyncio.create_task(ingestor.ingest())
        await asyncio.sleep(0.1)
        ingestor.stop()
        await task
        assert db_manager.store_record.call_count == 0

@pytest.mark.asyncio
async def test_websocket_invalid_data():
    db_manager = AsyncMock(spec=DatabaseManager)
    with patch("websockets.connect", new_callable=AsyncMock) as mock_connect:
        mock_ws = mock_connect.return_value
        mock_ws.recv.side_effect = [
            "invalid json",
            asyncio.CancelledError,
        ]
        ingestor = WebSocketIngestor(db_manager, "ws://test")
        task = asyncio.create_task(ingestor.ingest())
        await asyncio.sleep(0.1)
        ingestor.stop()
        await task
        assert db_manager.store_record.call_count == 0