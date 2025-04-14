# tests/test_notifiers/test_rocketchat.py
import pytest
from pdns.notifiers.rocket.notifier import RocketChatNotifier
from pdns.notifiers.filters.string import StringFilter
from pypdns import PDNSRecord
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_rocketchat_notifier_success():
    """Test successful Rocket.Chat notification."""
    config = {"webhook_url": "https://rocket.example.com/webhook"}
    filter = StringFilter({"rrtype": "A"})
    notifier = RocketChatNotifier(config, filter, "pdns/notifiers/rocket")
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    with patch("aiohttp.ClientSession.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value.__aenter__.return_value.status = 200
        await notifier.handle(record)
        mock_post.assert_called_once()
        assert mock_post.call_args[1]["json"]["text"]