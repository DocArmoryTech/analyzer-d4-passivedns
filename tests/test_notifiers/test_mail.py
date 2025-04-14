# tests/test_notifiers/test_mail.py
import pytest
from pdns.notifiers.mail.notifier import MailNotifier
from pdns.notifiers.filters.string import StringFilter
from pypdns import PDNSRecord
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_mail_notifier_success():
    """Test successful email sending."""
    config = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "sender": "alerts@example.com",
        "recipient": "admin@example.com",
        "username": "alerts",
        "password": "secret",
    }
    filter = StringFilter({"rrtype": "A"})
    notifier = MailNotifier(config, filter, "pdns/notifiers/mail")
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    with patch("aiosmtplib.send", new_callable=AsyncMock) as mock_send:
        await notifier.handle(record)
        mock_send.assert_called_once()
        call_kwargs = mock_send.call_args[1]
        assert call_kwargs["username"] == "alerts"
        assert call_kwargs["use_tls"] is True


@pytest.mark.asyncio
async def test_mail_notifier_failure():
    """Test email failure logs error."""
    config = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "sender": "alerts@example.com",
        "recipient": "admin@example.com",
    }
    filter = StringFilter({"rrtype": "A"})
    notifier = MailNotifier(config, filter, "pdns/notifiers/mail")
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    with patch("aiosmtplib.send", side_effect=Exception("SMTP error")) as mock_send:
        with patch("pdns.default.helpers.logger.error") as mock_log:
            await notifier.handle(record)
            mock_log.assert_called_once()
            assert mock_log.call_args[0][0]["event"] == "email_failed"


def test_mail_notifier_missing_config():
    """Test validation of required config."""
    config = {"smtp_host": "smtp.example.com"}
    filter = StringFilter({"rrtype": "A"})
    with pytest.raises(ValueError):
        MailNotifier(config, filter, "pdns/notifiers/mail")