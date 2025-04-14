# pdns/notifiers/log/notifier.py
from ..base import Notifier
from ..default.helpers import logger
from .filters.base import NotificationFilter


class LogNotifier(Notifier):
    """Notifier that logs alerts to the configured logging system."""

    type = 'log'

    def __init__(
        self,
        config: dict,
        filter_instance: NotificationFilter,
        template_dir: str,
    ):
        """Initialize the log notifier.

        Args:
            config (dict): Configuration with optional 'level' (e.g., 'info').
            filter_instance (NotificationFilter): Filter to evaluate records.
            template_dir (str): Directory for default templates.

        Raises:
            ValueError: If 'level' is invalid.
        """
        super().__init__(config, filter_instance, template_dir)
        self.level = config.get("level", "info").lower()
        if self.level not in ["debug", "info", "warning", "error", "critical"]:
            raise ValueError(f"Invalid log level: {self.level}")

    def default_template(self) -> str:
        """Return the default template file name."""
        return "template.jinja"

    async def handle(self, record: 'PDNSRecord') -> None:
        """Log the notification for the given record.

        Args:
            record (PDNSRecord): The DNS record to log.
        """
        message = self.render_template(record)
        getattr(logger, self.level)(
            {"event": "alert_triggered", "notifier": self.name, "message": message}
        )