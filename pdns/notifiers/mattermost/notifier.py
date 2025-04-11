# pdns/notifiers/mattermost/notifier.py
from ..base import Notifier
from ...default.helpers import logger
import aiohttp
from .filters.base import NotificationFilter

class MattermostNotifier(Notifier):
    def __init__(
        self, config: dict, filter_instance: NotificationFilter, template_dir: str
    ):
        super().__init__(config, filter_instance, template_dir)
        self.webhook_url = config["webhook_url"]

    def default_template(self) -> str:
        return "template.jinja"  # Default template in pdns/notifiers/mattermost/

    async def handle(self, record: 'PDNSRecord') -> None:
        message = self.render_template(record)
        payload = {"text": message}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(self.webhook_url, json=payload) as resp:
                    if resp.status != 200:
                        raise Exception(f"HTTP {resp.status}: {await resp.text()}")
                logger.debug(
                    {"event": "mattermost_sent", "notifier": self.name, "url": self.webhook_url}
                )
            except Exception as e:
                logger.error(
                    {"event": "mattermost_failed", "notifier": self.name, "error": str(e)}
                )