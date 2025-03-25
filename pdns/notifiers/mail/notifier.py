from ..base import Notifier
from ...default.helpers import logger
import aiosmtplib
from email.message import EmailMessage
from pypdns import PDNSRecord

class MailNotifier(Notifier):
    def __init__(self, config: dict, template_dir: str):
        super().__init__(config, template_dir)
        self.smtp_host = config["smtp_host"]
        self.smtp_port = config["smtp_port"]
        self.sender = config["sender"]
        self.recipient = config["recipient"]

    async def notify(self, record: PDNSRecord) -> None:
        message = self.render_template(record)
        msg = EmailMessage()
        msg["Subject"] = f"Alert: {self.name}"
        msg["From"] = self.sender
        msg["To"] = self.recipient
        msg.set_content(message)

        try:
            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
            )
            logger.debug({"event": "email_sent", "notifier": self.name, "recipient": self.recipient})
        except Exception as e:
            logger.error({"event": "email_failed", "notifier": self.name, "error": str(e)})