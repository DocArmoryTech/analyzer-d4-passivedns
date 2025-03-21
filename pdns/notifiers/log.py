# pdns/notifiers/log.py
from .base import Notifier
from ..default.helpers import logger

class LogNotifier(Notifier):
    def __init__(self, name: str, condition: dict, level: str = "info"):
        super().__init__(name, condition)
        self.level = level.lower()
        if self.level not in ["debug", "info", "warning", "error", "critical"]:
            self.level = "info"

    async def notify(self, record: DNSRecord) -> None:
        getattr(logger, self.level)(
            {"event": "alert_triggered", "alert_name": self.name, "record": record.dict()}
        )