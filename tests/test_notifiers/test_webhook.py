# tests/test_notifiers/test_webhook.py
import pytest
from pdns.notifiers.webhook import WebhookNotifier
from pdns.notifiers.filters.string import StringFilter
from pypdns import PDNSRecord
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_webhook_notifier_success():
    """Test successful webhook notification."""
    config = {"webhook_url": "https://example.com/webhook"}
    filter = StringFilter({"rrtype": "A"})
    notifier = WebhookNotifier(config, filter, "pdns/notifiers/webhook")
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    with patch("aiohttp.ClientSession.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value.__aenter__.return_value.status = 200
        await notifier.handle(record)
        mock_post.assert_called_once()
        assert mock_post.call_args[1]["json"]["text"]


@pytest.mark.asyncio
async def test_webhook_notifier_failure():
    """Test webhook failure logs error."""
    config = {"webhook_url": "https://example.com/webhook"}
    filter = StringFilter({"rrtype": "A"})
    notifier = WebhookNotifier(config, filter, "pdns/notifiers/webhook")
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    with patch("aiohttp.ClientSession.post", side_effect=Exception("Network error")) as mock_post:
        with patch("pdns.default.helpers.logger.error") as mock_log:
            await notifier.handle(record)
            mock_log.assert_called_once()
            assert mock_log.call_args[0][0]["event"] == "webhook_failed"


def test_webhook_notifier_invalid_config():
    """Test validation of webhook_url."""
    config = {"webhook_url": "ftp://invalid.com"}
    filter = StringFilter({"rrtype": "A"})
    with pytest.raises(ValueError):
        WebhookNotifier(config, filter, "pdns/notifiers/webhook")