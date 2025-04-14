# tests/test_notifiers/test_matrix.py
import pytest
from pdns.notifiers.matrix.notifier import MatrixNotifier
from pdns.notifiers.filters.string import StringFilter
from pypdns import PDNSRecord
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_matrix_notifier_success():
    """Test successful Matrix message sending."""
    config = {
        "homeserver_url": "https://matrix.example.com",
        "access_token": "token",
        "room_id": "!room:example.com",
    }
    filter = StringFilter({"rrtype": "A"})
    notifier = MatrixNotifier(config, filter, "pdns/notifiers/matrix")
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    with patch("aiohttp.ClientSession.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value.__aenter__.return_value.status = 200
        await notifier.handle(record)
        mock_post.assert_called_once()
        call_args = mock_post.call_args[1]
        assert call_args["json"]["msgtype"] == "m.text"


@pytest.mark.asyncio
async def test_matrix_notifier_failure():
    """Test Matrix failure logs error."""
    config = {
        "homeserver_url": "https://matrix.example.com",
        "access_token": "token",
        "room_id": "!room:example.com",
    }
    filter = StringFilter({"rrtype": "A"})
    notifier = MatrixNotifier(config, filter, "pdns/notifiers/matrix")
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    with patch("aiohttp.ClientSession.post", side_effect=Exception("Network error")) as mock_post:
        with patch("pdns.default.helpers.logger.error") as mock_log:
            await notifier.handle(record)
            mock_log.assert_called_once()
            assert mock_log.call_args[0][0]["event"] == "matrix_failed"


def test_matrix_notifier_invalid_config():
    """Test validation of required config."""
    config = {"homeserver_url": "invalid://matrix.example.com"}
    filter = StringFilter({"rrtype": "A"})
    with pytest.raises(ValueError):
        MatrixNotifier(config, filter, "pdns/notifiers/matrix")