# pdns/notifiers/log/notifier.py
from ..base import Notifier
from ...default.helpers import logger
from .filters.base import NotificationFilter

class LogNotifier(Notifier):
    def __init__(self, config: dict, filter_instance: NotificationFilter, template_dir: str):
        super().__init__(config, filter_instance, template_dir)
        self.level = config.get("level", "info").lower()
        if self.level not in ["debug", "info", "warning", "error", "critical"]:
            self.level = "info"

    async def notify(self, message: str) -> None:
        getattr(logger, self.level)(
            {"event": "alert_triggered", "notifier": self.name, "message": message}
        )