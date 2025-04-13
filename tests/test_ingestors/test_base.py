import pytest
from pdns.ingestors.base import Ingestor, DaemonIngestor, FileIngestor
from pdns.db.manager import DatabaseManager
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_ingestor_initialization():
    db_manager = AsyncMock(spec=DatabaseManager)
    ingestor = Ingestor(db_manager)
    assert ingestor.db_manager == db_manager
    assert ingestor.running is False

@pytest.mark.asyncio
async def test_ingestor_start_stop():
    db_manager = AsyncMock(spec=DatabaseManager)
    ingestor = Ingestor(db_manager)
    ingestor.start()
    assert ingestor.running is True
    ingestor.stop()
    assert ingestor.running is False

@pytest.mark.asyncio
async def test_daemon_ingestor_type():
    class TestDaemon(DaemonIngestor):
        type = "test_daemon"
    db_manager = AsyncMock(spec=DatabaseManager)
    ingestor = TestDaemon(db_manager)
    assert ingestor.type == "test_daemon"

@pytest.mark.asyncio
async def test_file_ingestor_path():
    db_manager = AsyncMock(spec=DatabaseManager)
    ingestor = FileIngestor(db_manager, "/path/to/file")
    assert ingestor.path == "/path/to/file"