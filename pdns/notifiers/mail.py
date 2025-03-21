# pdns/notifiers/mail.py
from .base import Notifier
from ..default.helpers import logger
import aiosmtplib
from email.message import EmailMessage

class MailNotifier(Notifier):
    def __init__(self, name: str, condition: dict, smtp_host: str, smtp_port: int, sender: str, recipient: str):
        super().__init__(name, condition)
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.recipient = recipient

    async def notify(self, record: DNSRecord) -> None:
        msg = EmailMessage()
        msg["Subject"] = f"Alert: {self.name}"
        msg["From"] = self.sender
        msg["To"] = self.recipient
        msg.set_content(f"Alert triggered: {self.name}\nRecord: {record.dict()}")

        try:
            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
            )
            logger.debug({"event": "email_sent", "alert_name": self.name, "recipient": self.recipient})
        except Exception as e:
            logger.error({"event": "email_failed", "alert_name": self.name, "error": str(e)})