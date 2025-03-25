# pdns/notifiers/base.py
from abc import ABC, abstractmethod
from pypdns import PDNSRecord
from jinja2 import Environment, FileSystemLoader, TemplateError
from ..default.helpers import logger

class Notifier(ABC):
    """Abstract base class for alert notification handlers with Jinja2 templating."""

    def __init__(self, config: dict, template_dir: str):
        self.name = config.get("name")
        self.condition = config.get("condition", {})
        self.template_file = config.get("template", "template.jinja")
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)

    def render_template(self, record: PDNSRecord) -> str:
        """Render the Jinja2 template from the file with the record data."""
        try:
            template = self.jinja_env.get_template(self.template_file)
            record_dict = record.raw if record.raw else {
                "rrname": record.rrname,
                "rrtype": record.rrtype,
                "rdata": record.rdata,
                "time_first": record.time_first,
                "time_last": record.time_last,
                "count": record.count,
                "sensor_id": record.sensor_id
            }
            return template.render(record=record_dict)
        except TemplateError as e:
            logger.error({"event": "template_render_failed", "notifier": self.name, "error": str(e)})
            return f"Error rendering template: {str(e)}"

    @abstractmethod
    async def notify(self, record: PDNSRecord) -> None:
        """Send the alert notification for the record."""
        pass