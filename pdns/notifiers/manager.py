# pdns/notifiers/manager.py
from ..default.helpers import logger, get_config
from pypdns import PDNSRecord
from .base import Notifier
from .filters.base import NotificationFilter
from .filters.string import StringFilter
from .filters.dnsbl import DNSBLFilter
from typing import List
import asyncio
import importlib


class NotificationManager:
    def __init__(self) -> None:
        self.notifiers: List[Notifier] = []
        self._lock = asyncio.Lock()
        self._load_notifiers()

    def _load_notifiers(self) -> None:
        # Fetch notifiers config using get_config
        notifiers_config = get_config("notifiers", default=[])
        if not isinstance(notifiers_config, list):
            logger.error("Notifiers config must be a list; no notifiers loaded")
            return

        for config in notifiers_config:
            try:
                notifier_type = config["type"]
                module = importlib.import_module(
                    f"pdns.notifiers.{notifier_type}.notifier"
                )
                notifier_class = getattr(
                    module, f"{notifier_type.capitalize()}Notifier"
                )
                filter_instance = self._create_filter(config.get("filter", {}))
                template_dir = f"pdns/notifiers/{notifier_type}"
                notifier = notifier_class(config, filter_instance, template_dir)
                self.notifiers.append(notifier)
                logger.debug({"event": "notifier_loaded", "name": config.get("name")})
            except KeyError as e:
                logger.error(f"Missing required field in notifier config: {str(e)}")
            except ImportError as e:
                logger.error(
                    f"Failed to import notifier module {notifier_type}: {str(e)}"
                )
            except Exception as e:
                logger.error(f"Failed to load notifier {notifier_type}: {str(e)}")

    def _create_filter(self, filter_config: dict) -> NotificationFilter:
        filter_type = filter_config.get("type", "string")
        if filter_type == "string":
            return StringFilter(filter_config.get("condition", {}))
        elif filter_type == "dnsbl":
            return DNSBLFilter(filter_config.get("dnsbl_domain", "zen.spamhaus.org"))
        else:
            raise ValueError(f"Unknown filter type: {filter_type}")

    async def check_record(self, record: PDNSRecord) -> None:
        async with self._lock:
            for notifier in self.notifiers:
                if notifier.filter.evaluate(record):
                    message = notifier.render_template(record)
                    await notifier.notify(message)

    async def initialize(self) -> None:
        logger.info({"event": "notification_manager_initialized"})

    async def shutdown(self) -> None:
        logger.info({"event": "notification_manager_shutdown"})
