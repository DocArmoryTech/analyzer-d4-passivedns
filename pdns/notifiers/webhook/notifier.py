from ..base import Notifier
from ...default.helpers import logger
import aiohttp
from pypdns import PDNSRecord

class WebhookNotifier(Notifier):
    def __init__(self, config: dict, template_dir: str):
        super().__init__(config, template_dir)
        self.url = config["url"]

    async def notify(self, record: PDNSRecord) -> None:
        message = self.render_template(record)
        payload = {"alert": self.name, "message": message}
        async with aiohttp.ClientSession() as session:
            try:
                await session.post(self.url, json=payload)
                logger.debug({"event": "webhook_sent", "notifier": self.name, "url": self.url})
            except Exception as e:
                logger.error({"event": "webhook_failed", "notifier": self.name, "error": str(e)})