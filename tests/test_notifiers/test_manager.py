# tests/test_notifiers/test_manager.py
import pytest
from pdns.notifiers.manager import NotificationManager
from pdns.notifiers.log.notifier import LogNotifier
from pdns.notifiers.mail.notifier import MailNotifier
from pdns.notifiers.filters.string import StringFilter
from pdns.notifiers.filters.dnsbl import DNSBLFilter
from pdns.notifiers.filters.composite import CompositeFilter
from pypdns import PDNSRecord
from unittest.mock import AsyncMock, patch, MagicMock


@pytest.mark.asyncio
async def test_notification_manager_load_notifiers():
    """Test loading multiple notifiers from config."""
    config = [
        {
            "type": "log",
            "config": {"level": "info"},
            "filter": {"type": "string", "condition": {"rrtype": "A"}},
        },
        {
            "type": "mail",
            "config": {
                "smtp_host": "smtp.example.com",
                "smtp_port": 587,
                "sender": "alerts@example.com",
                "recipient": "admin@example.com",
            },
            "filter": {
                "type": "composite",
                "operator": "not",
                "filters": [{"type": "string", "condition": {"rrtype": "MX"}}],
            },
        },
    ]
    with patch("pdns.default.helpers.get_config", return_value=config):
        manager = NotificationManager()
        assert len(manager.notifiers) == 2
        assert isinstance(manager.notifiers[0], LogNotifier)
        assert isinstance(manager.notifiers[1], MailNotifier)
        assert isinstance(manager.notifiers[0].filter, StringFilter)
        assert isinstance(manager.notifiers[1].filter, CompositeFilter)


@pytest.mark.asyncio
async def test_notification_manager_invalid_config():
    """Test handling of invalid notifier config."""
    config = [
        {"type": "log"},  # Missing config
        {"type": "invalid", "config": {}},  # Unknown type
    ]
    with patch("pdns.default.helpers.get_config", return_value=config):
        with patch("pdns.default.helpers.logger.error") as mock_log:
            manager = NotificationManager()
            assert len(manager.notifiers) == 0
            assert mock_log.call_count == 2


@pytest.mark.asyncio
async def test_notification_manager_check_record():
    """Test processing a record with multiple notifiers."""
    config = [
        {
            "type": "log",
            "config": {"level": "info"},
            "filter": {"type": "string", "condition": {"rrtype": "A"}},
        },
        {
            "type": "log",
            "config": {"level": "debug"},
            "filter": {"type": "string", "condition": {"rrtype": "MX"}},
        },
    ]
    with patch("pdns.default.helpers.get_config", return_value=config):
        manager = NotificationManager()
        record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
        with patch.object(LogNotifier, "handle", new_callable=AsyncMock) as mock_handle:
            await manager.check_record(record)
            assert mock_handle.call_count == 1  # Only the first notifier matches


@pytest.mark.asyncio
async def test_notification_manager_nested_filter():
    """Test loading and evaluating nested composite filters."""
    config = [
        {
            "type": "log",
            "config": {"level": "info"},
            "filter": {
                "type": "composite",
                "operator": "or",
                "filters": [
                    {
                        "type": "composite",
                        "operator": "and",
                        "filters": [
                            {"type": "string", "condition": {"rrtype": "A"}},
                            {"type": "string", "condition": {"rrname": "example.com"}},
                        ],
                    },
                    {
                        "type": "composite",
                        "operator": "not",
                        "filters": [{"type": "string", "condition": {"rrtype": "MX"}}],
                    },
                ],
            },
        },
    ]
    with patch("pdns.default.helpers.get_config", return_value=config):
        manager = NotificationManager()
        assert len(manager.notifiers) == 1
        record = PDNSRecord(rrtype="TXT", rrname="example.com", rdata=["text"])
        with patch.object(LogNotifier, "handle", new_callable=AsyncMock) as mock_handle:
            await manager.check_record(record)
            mock_handle.assert_called_once()  # Matches 'not MX'


@pytest.mark.asyncio
async def test_notification_manager_async_filter():
    """Test handling async filters like DNSBLFilter."""
    config = [
        {
            "type": "log",
            "config": {"level": "info"},
            "filter": {"type": "dnsbl", "dnsbl_domain": "zen.spamhaus.org"},
        },
    ]
    with patch("pdns.default.helpers.get_config", return_value=config):
        manager = NotificationManager()
        record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
        with patch("dns.asyncresolver.resolve", new_callable=AsyncMock, return_value=["127.0.0.2"]):
            with patch.object(LogNotifier, "handle", new_callable=AsyncMock) as mock_handle:
                await manager.check_record(record)
                mock_handle.assert_called_once()


@pytest.mark.asyncio
async def test_notification_manager_shutdown():
    """Test shutdown cleans up notifier resources."""
    config = [
        {
            "type": "matrix",
            "config": {
                "homeserver_url": "https://matrix.example.com",
                "access_token": "token",
                "room_id": "!room:example.com",
            },
            "filter": {"type": "string", "condition": {"rrtype": "A"}},
        },
    ]
    with patch("pdns.default.helpers.get_config", return_value=config):
        manager = NotificationManager()
        with patch("aiohttp.ClientSession.close", new_callable=AsyncMock) as mock_close:
            await manager.shutdown()
            mock_close.assert_called_once()


@pytest.mark.asyncio
async def test_notification_manager_debug_records():
    """Test debug logging of triggered records."""
    config = [
        {
            "type": "log",
            "config": {"level": "info"},
            "filter": {"type": "string", "condition": {"rrtype": "A"}},
        },
    ]
    with patch("pdns.default.helpers.get_config", return_value=config):
        with patch("pdns.default.helpers.get_config", side_effect=lambda k, **kw: True if k == "notifiers_debug_records" else config):
            manager = NotificationManager()
            record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
            with patch("pdns.default.helpers.logger.debug") as mock_log:
                await manager.check_record(record)
                mock_log.assert_called_once()
                assert mock_log.call_args[0][0]["event"] == "notification_triggered"


@pytest.mark.asyncio
async def test_notification_manager_performance():
    """Test performance with multiple notifiers."""
    config = [
        {
            "type": "log",
            "config": {"level": "info"},
            "filter": {"type": "string", "condition": {"rrtype": "A"}},
        },
        {
            "type": "log",
            "config": {"level": "debug"},
            "filter": {
                "type": "composite",
                "operator": "not",
                "filters": [{"type": "string", "condition": {"rrtype": "MX"}}],
            },
        },
    ]
    with patch("pdns.default.helpers.get_config", return_value=config):
        manager = NotificationManager()
        records = [
            PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
            for _ in range(1000)
        ]
        start = time.time()
        for record in records:
            await manager.check_record(record)
        duration = time.time() - start
        assert duration < 1.0  # Process 1000 records in under 1 second