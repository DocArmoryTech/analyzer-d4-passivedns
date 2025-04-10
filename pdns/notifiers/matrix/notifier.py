# pdns/notifiers/matrix/notifier.py
from ..base import Notifier
from ...default.helpers import logger
import aiohttp
from .filters.base import NotificationFilter


class MatrixNotifier(Notifier):
    def __init__(
        self, config: dict, filter_instance: NotificationFilter, template_dir: str
    ):
        super().__init__(config, filter_instance, template_dir)
        self.homeserver_url = config["homeserver_url"].rstrip("/")
        self.access_token = config["access_token"]
        self.room_id = config["room_id"]
        self.endpoint = f"{self.homeserver_url}/_matrix/client/v3/rooms/{self.room_id}/send/m.room.message"

    async def notify(self, message: str) -> None:
        payload = {
            "msgtype": "m.text",
            "body": message,
            "format": "org.matrix.custom.html",
            "formatted_body": message.replace("\n", "<br>")
            .replace("**", "<b>")
            .replace("**", "</b>"),
        }
        headers = {"Authorization": f"Bearer {self.access_token}"}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    self.endpoint, json=payload, headers=headers
                ) as resp:
                    if resp.status != 200:
                        raise Exception(f"HTTP {resp.status}: {await resp.text()}")
                logger.debug(
                    {
                        "event": "matrix_sent",
                        "notifier": self.name,
                        "room_id": self.room_id,
                    }
                )
            except Exception as e:
                logger.error(
                    {"event": "matrix_failed", "notifier": self.name, "error": str(e)}
                )
