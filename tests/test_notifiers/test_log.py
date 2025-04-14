# tests/test_notifiers/test_log.py
import pytest
from pdns.notifiers.log.notifier import LogNotifier
from pdns.notifiers.filters.string import StringFilter
from pypdns import PDNSRecord
from unittest.mock import patch


@pytest.mark.asyncio
async def test_log_notifier_info():
    """Test logging at info level."""
    config = {"level": "info"}
    filter = StringFilter({"rrtype": "A"})
    notifier = LogNotifier(config, filter, "pdns/notifiers/log")
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    with patch("pdns.default.helpers.logger.info") as mock_log:
        await notifier.handle(record)
        mock_log.assert_called_once()
        call_args = mock_log.call_args[0][0]
        assert call_args["event"] == "alert_triggered"
        assert call_args["notifier"] == "unnamed_notifier"


@pytest.mark.asyncio
async def test_log_notifier_invalid_level():
    """Test validation of log level."""
    config = {"level": "invalid"}
    filter = StringFilter({"rrtype": "A"})
    with pytest.raises(ValueError):
        LogNotifier(config, filter, "pdns/notifiers/log")