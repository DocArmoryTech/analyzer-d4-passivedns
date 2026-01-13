# pdns/notifiers/mail/notifier.py
from ..base import Notifier
from ...default.helpers import logger
from ..filters.base import NotificationFilter
import aiosmtplib
from email.message import EmailMessage


class MailNotifier(Notifier):
    """Notifier that sends alerts via email using SMTP."""

    type = 'mail'

    def __init__(
        self,
        config: dict,
        filter_instance: NotificationFilter,
        template_dir: str,
    ):
        """Initialize the mail notifier.

        Args:
            config (dict): Configuration with 'smtp_host', 'smtp_port', 'sender',
                          'recipient', and optional 'username', 'password'.
            filter_instance (NotificationFilter): Filter to evaluate records.
            template_dir (str): Directory for default templates.

        Raises:
            ValueError: If required config fields are missing.
        """
        super().__init__(config, filter_instance, template_dir)
        self.smtp_host = config.get("smtp_host")
        self.smtp_port = config.get("smtp_port")
        self.sender = config.get("sender")
        self.recipient = config.get("recipient")
        self.username = config.get("username")
        self.password = config.get("password")
        if not all([self.smtp_host, self.smtp_port, self.sender, self.recipient]):
            raise ValueError("Missing required config: smtp_host, smtp_port, sender, or recipient")

    def default_template(self) -> str:
        """Return the default template file name."""
        return "template.jinja"

    async def handle(self, record: 'PDNSRecord') -> None:
        """Send an email notification for the given record.

        Args:
            record (PDNSRecord): The DNS record to process.
        """
        message = self.render_template(record)
        msg = EmailMessage()
        msg["Subject"] = f"Alert: {record.rrname} ({self.name})"
        msg["From"] = self.sender
        msg["To"] = self.recipient
        msg.set_content(message)
        try:
            kwargs = {"hostname": self.smtp_host, "port": self.smtp_port}
            if self.username and self.password:
                kwargs.update({"username": self.username, "password": self.password, "use_tls": True})
            await aiosmtplib.send(msg, **kwargs)
            logger.debug(
                {"event": "email_sent", "notifier": self.name, "recipient": self.recipient}
            )
        except Exception as e:
            logger.error(
                {"event": "email_failed", "notifier": self.name, "error": str(e)}
            )