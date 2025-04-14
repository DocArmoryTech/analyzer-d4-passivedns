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
        """Initialize the notifier with configuration and filter.

        Args:
            config (dict): Configuration dictionary for the notifier.
            filter_instance (NotificationFilter): Filter to evaluate records.
            default_template_dir (str): Directory for default templates.
        """
        self.name = config.get("name", "unnamed_notifier")
        self.filter = filter_instance
        self.template_path = config.get("template")  # Optional custom template path
        self.default_template_dir = default_template_dir
        self.jinja_env = self._setup_jinja_env()

    def _setup_jinja_env(self) -> Environment:
        """Set up the Jinja2 environment with the appropriate template directory."""
        if self.template_path:
            template_dir = os.path.dirname(self.template_path)
        else:
            template_dir = self.default_template_dir
        return Environment(loader=FileSystemLoader(template_dir), autoescape=True)

    def get_template(self):
        """Get the Jinja2 template based on configuration or defaults."""
        if self.template_path:
            template_file = os.path.basename(self.template_path)
            return self.jinja_env.get_template(template_file)
        else:
            default_template = self.default_template()
            if default_template:
                return self.jinja_env.get_template(default_template)
            return self.jinja_env.get_template("default.jinja")

    def default_template(self) -> str | None:
        """Return the default template file name for this notifier.

        Returns:
            str | None: The default template name, or None if no default exists.
        """
        return None

    def render_template(self, record: PDNSRecord) -> str:
        """Render the template with the given PDNSRecord.

        Args:
            record (PDNSRecord): The DNS record to render.

        Returns:
            str: The rendered template string or an error message.
        """
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
        """Handle the notification for the given record.

        Args:
            record (PDNSRecord): The DNS record to process.
        """
        pass