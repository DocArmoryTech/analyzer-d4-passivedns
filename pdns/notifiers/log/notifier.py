from ..base import Notifier
from ...default.helpers import logger, get_config
from pypdns import PDNSRecord

class LogNotifier(Notifier):
    def __init__(self, config: dict, template_dir: str):
        # Use get_config instead of passed config
        log_config = get_config("notifiers", {}).get("log", {})
        super().__init__(log_config, template_dir)
        self.level = log_config.get("level", "info").lower()
        if self.level not in ["debug", "info", "warning", "error", "critical"]:
            self.level = "info"

    async def notify(self, record: PDNSRecord) -> None:
        message = self.render_template(record)
        getattr(logger, self.level)(
            {"event": "alert_triggered", "notifier": self.name, "message": message}
        )