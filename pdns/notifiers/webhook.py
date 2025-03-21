# pdns/notifiers/webhook.py
from .base import Notifier
from ..default.helpers import logger
import aiohttp

class WebhookNotifier(Notifier):
    def __init__(self, name: str, condition: dict, url: str):
        super().__init__(name, condition)
        self.url = url

    async def notify(self, record: DNSRecord) -> None:
        async with aiohttp.ClientSession() as session:
            try:
                await session.post(self.url, json={"alert": self.name, "record": record.dict()})
                logger.debug({"event": "webhook_sent", "alert_name": self.name, "url": self.url})
            except Exception as e:
                logger.error({"event": "webhook_failed", "alert_name": self.name, "error": str(e)})