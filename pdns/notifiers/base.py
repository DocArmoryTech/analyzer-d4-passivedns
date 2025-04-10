# pdns/notifiers/base.py
from abc import ABC, abstractmethod
from pypdns import PDNSRecord
from jinja2 import Environment, FileSystemLoader, TemplateError
from ..default.helpers import logger
from .filters.base import NotificationFilter


class Notifier(ABC):
    """Abstract base class for alert notification handlers."""

    def __init__(
        self,
        config: dict,
        filter_instance: NotificationFilter,
        template_dir: str = "templates",
    ):
        self.name = config.get("name", "unnamed_notifier")
        self.filter = filter_instance
        self.jinja_env = Environment(
            loader=FileSystemLoader(template_dir), autoescape=True
        )
        self.template_file = config.get("template", "default.jinja")

    def render_template(self, record: PDNSRecord) -> str:
        try:
            template = self.jinja_env.get_template(self.template_file)
            record_dict = (
                record.raw
                if record.raw
                else {
                    "rrname": record.rrname,
                    "rrtype": record.rrtype,
                    "rdata": record.rdata,
                    "time_first": record.time_first,
                    "time_last": record.time_last,
                    "count": record.count,
                    "sensor_id": record.sensor_id,
                }
            )
            return template.render(record=record_dict)
        except TemplateError as e:
            logger.error(
                {
                    "event": "template_render_failed",
                    "notifier": self.name,
                    "error": str(e),
                }
            )
            return f"Error rendering template: {str(e)}"

    @abstractmethod
    async def notify(self, message: str) -> None:
        """Send the notification with pre-rendered message."""
        pass
