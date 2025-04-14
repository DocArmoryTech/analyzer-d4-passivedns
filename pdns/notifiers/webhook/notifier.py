# pdns/notifiers/webhook.py
from ..base import Notifier
from ..default.helpers import logger
from .filters.base import NotificationFilter
import aiohttp


class WebhookNotifier(Notifier):
    """Base notifier for sending alerts via HTTP webhooks."""

    type = 'webhook'

    def __init__(
        self,
        config: dict,
        filter_instance: NotificationFilter,
        template_dir: str,
    ):
        """Initialize the webhook notifier.

        Args:
            config (dict): Configuration with 'webhook_url'.
            filter_instance (NotificationFilter): Filter to evaluate records.
            template_dir (str): Directory for default templates.

        Raises:
            ValueError: If 'webhook_url' is missing or invalid.
        """
        super().__init__(config, filter_instance, template_dir)
        self.webhook_url = config.get("webhook_url")
        if not self.webhook_url:
            raise ValueError("Missing required config: webhook_url")
        if not self.webhook_url.startswith(("http://", "https://")):
            raise ValueError("webhook_url must start with http:// or https://")
        self.session = None

    def default_template(self) -> str:
        """Return the default template file name."""
        return "template.jinja"

    async def handle(self, record: 'PDNSRecord') -> None:
        """Send a webhook notification for the given record.

        Args:
            record (PDNSRecord): The DNS record to process.
        """
        if not self.session:
            self.session = aiohttp.ClientSession()
        message = self.render_template(record)
        payload = {"text": message}
        try:
            async with self.session.post(self.webhook_url, json=payload) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}: {await resp.text()}")
                logger.debug(
                    {"event": f"{self.type}_sent", "notifier": self.name, "url": self.webhook_url}
                )
        except Exception as e:
            logger.error(
                {"event": f"{self.type}_failed", "notifier": self.name, "error": str(e)}
            )

    async def shutdown(self):
        """Close the HTTP session."""
        if self.session:
            await self.session.close()