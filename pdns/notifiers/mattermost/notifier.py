from ..base import Notifier
from ...default.helpers import logger
import aiohttp
from pypdns import PDNSRecord

class MattermostNotifier(Notifier):
    def __init__(self, config: dict, template_dir: str):
        super().__init__(config, template_dir)
        self.webhook_url = config["webhook_url"]

    async def notify(self, record: PDNSRecord) -> None:
        message = self.render_template(record)
        payload = {"text": message}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(self.webhook_url, json=payload) as resp:
                    if resp.status != 200:
                        raise Exception(f"HTTP {resp.status}: {await resp.text()}")
                logger.debug({"event": "mattermost_sent", "notifier": self.name, "url": self.webhook_url})
            except Exception as e:
                logger.error({"event": "mattermost_failed", "notifier": self.name, "error": str(e)})