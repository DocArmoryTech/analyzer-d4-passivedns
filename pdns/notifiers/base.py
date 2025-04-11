# pdns/notifiers/base.py
from abc import ABC, abstractmethod
from pypdns import PDNSRecord
from jinja2 import Environment, FileSystemLoader, TemplateError
from ..default.helpers import logger
from .filters.base import NotificationFilter
import os

class Notifier(ABC):
    """Abstract base class for alert notification handlers."""
    type: str  # Required class variable for notifier subclasses

    def __init__(
        self,
        config: dict,
        filter_instance: NotificationFilter,
        default_template_dir: str = "templates",
    ):
        self.name = config.get("name", "unnamed_notifier")
        self.filter = filter_instance
        self.template_path = config.get("template", None)  # Optional custom template path
        self.default_template_dir = default_template_dir
        self.jinja_env = self._setup_jinja_env()

    def _setup_jinja_env(self) -> Environment:
        """Set up the Jinja2 environment with the appropriate template directory."""
        if self.template_path:
            # Use the directory of the custom template path from config
            template_dir = os.path.dirname(self.template_path)
        else:
            # Use the default template directory (e.g., pdns/notifiers/log)
            template_dir = self.default_template_dir
        return Environment(loader=FileSystemLoader(template_dir), autoescape=True)

    def get_template(self):
        """Get the Jinja2 template based on the configuration or defaults."""
        if self.template_path:
            # Use the custom template specified in config
            template_file = os.path.basename(self.template_path)
            return self.jinja_env.get_template(template_file)
        else:
            # Try the notifier-specific default template
            default_template = self.default_template()
            if default_template:
                return self.jinja_env.get_template(default_template)
            # Fall back to a base default template
            return self.jinja_env.get_template("default.jinja")

    def default_template(self) -> str | None:
        """Return the default template file name for this notifier. Subclasses can override."""
        return None  # No default template unless overridden

    def render_template(self, record: PDNSRecord) -> str:
        """Render the template with the given PDNSRecord."""
        try:
            template = self.get_template()
            record_dict = {
                "rrname": record.rrname,
                "rrtype": record.rrtype,
                "rdata": record.rdata,
                "time_first": record.time_first,
                "time_last": record.time_last,
                "count": record.count,
                "sensor_id": record.sensor_id,
            }
            return template.render(record=record_dict)
        except TemplateError as e:
            logger.error({
                "event": "template_render_failed",
                "notifier": self.name,
                "error": str(e),
            })
            return f"Error rendering template: {str(e)}"

    @abstractmethod
    async def handle(self, record: PDNSRecord) -> None:
        """Handle the notification for the given record."""
        pass