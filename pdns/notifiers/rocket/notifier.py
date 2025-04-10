# pdns/notifiers/rocket/notifier.py
from ..base import Notifier
from ...default.helpers import logger
import aiohttp
from .filters.base import NotificationFilter


class RocketChatNotifier(Notifier):
    def __init__(
        self, config: dict, filter_instance: NotificationFilter, template_dir: str
    ):
        super().__init__(config, filter_instance, template_dir)
        self.webhook_url = config["webhook_url"]

    async def notify(self, message: str) -> None:
        payload = {"text": message}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(self.webhook_url, json=payload) as resp:
                    if resp.status != 200:
                        raise Exception(f"HTTP {resp.status}: {await resp.text()}")
                logger.debug(
                    {
                        "event": "rocketchat_sent",
                        "notifier": self.name,
                        "url": self.webhook_url,
                    }
                )
            except Exception as e:
                logger.error(
                    {
                        "event": "rocketchat_failed",
                        "notifier": self.name,
                        "error": str(e),
                    }
                )
