# pdns/notifiers/manager.py
from ..default.helpers import get_config, logger
from ..schemas import DNSRecord
from .log import LogNotifier
from .webhook import WebhookNotifier
from .mail import MailNotifier

class NotificationManager:
    """Manages loading and triggering of notification handlers."""

    def __init__(self):
        """Load notifiers from config."""
        try:
            alerts_config = get_config("alerts")
            self.notifiers = []
            for alert in alerts_config.get("alerts", []):
                method = alert.get("method")
                if method == "log":
                    self.notifiers.append(LogNotifier(
                        name=alert["name"],
                        condition=alert["condition"],
                        level=alert.get("level", "info")
                    ))
                elif method == "webhook":
                    self.notifiers.append(WebhookNotifier(
                        name=alert["name"],
                        condition=alert["condition"],
                        url=alert["url"]
                    ))
                elif method == "mail":
                    self.notifiers.append(MailNotifier(
                        name=alert["name"],
                        condition=alert["condition"],
                        smtp_host=alert["smtp_host"],
                        smtp_port=alert["smtp_port"],
                        sender=alert["sender"],
                        recipient=alert["recipient"]
                    ))
        except Exception as e:
            logger.error(f"Failed to load alerts config: {str(e)}, using empty list")
            self.notifiers = []

    async def trigger(self, record: DNSRecord) -> None:
        """Trigger notifications for matching notifiers."""
        for notifier in self.notifiers:
            if notifier.matches(record):
                await notifier.notify(record)