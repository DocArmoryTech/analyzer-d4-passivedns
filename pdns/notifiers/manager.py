# pdns/notifiers/manager.py
from ..default.helpers import logger, get_config
from pypdns import PDNSRecord
from .base import Notifier
from .filters.base import NotificationFilter
from typing import List
import asyncio
import importlib
import inspect

class NotificationManager:
    """Manages a collection of notifiers for processing DNS records."""

    def __init__(self) -> None:
        self.notifiers: List[Notifier] = []
        self._lock = asyncio.Lock()
        self._load_notifiers()

    def _load_notifiers(self) -> None:
        """Load notifiers from the generic config dynamically."""
        notifiers_config = await get_config("notifiers", quiet=True) or []
        if not isinstance(notifiers_config, list):
            logger.error("Notifiers config must be a list; no notifiers loaded")
            return

        # Dynamically load all Notifier subclasses from the notifiers module
        notifier_module = importlib.import_module(".notifiers", package="pdns")
        notifier_classes = {
            cls.type: cls
            for name, cls in inspect.getmembers(notifier_module, inspect.isclass)
            if hasattr(cls, "type") and issubclass(cls, Notifier) and cls != Notifier
        }

        for idx, config in enumerate(notifiers_config):
            try:
                notifier_type = config.get("type")
                if not notifier_type:
                    raise ValueError("Missing 'type' field in notifier config")

                notifier_class = notifier_classes.get(notifier_type)
                if not notifier_class:
                    raise ValueError(f"Unknown notifier type: {notifier_type}")

                # Create filter and instantiate notifier
                filter_instance = self._create_filter(config.get("filter", {}))
                default_template_dir = f"pdns/notifiers/{notifier_type}"
                notifier = notifier_class(config, filter_instance, default_template_dir)
                self.notifiers.append(notifier)
                logger.debug({
                    "event": "notifier_loaded",
                    "index": idx,
                    "type": notifier_type,
                    "name": config.get("name"),
                })
            except Exception as e:
                logger.error({
                    "event": "notifier_load_failed",
                    "index": idx,
                    "error": str(e),
                })

    def _create_filter(self, filter_config: dict) -> NotificationFilter:
        """Dynamically create a filter instance based on config."""
        filter_module = importlib.import_module(".notifiers.filters", package="pdns")
        filter_classes = {
            cls.type: cls
            for name, cls in inspect.getmembers(filter_module, inspect.isclass)
            if hasattr(cls, "type") and issubclass(cls, NotificationFilter) and cls != NotificationFilter
        }

        filter_type = filter_config.get("type", "string")  # Default to "string"
        filter_class = filter_classes.get(filter_type)
        if not filter_class:
            raise ValueError(f"Unknown filter type: {filter_type}")

        filter_params = {k: v for k, v in filter_config.items() if k != "type"}
        return filter_class(**filter_params)

    async def check_record(self, record: PDNSRecord) -> None:
        """Check a record against all notifiers and trigger notifications."""
        async with self._lock:
            for notifier in self.notifiers:
                if notifier.filter.evaluate(record):
                    await notifier.handle(record)

    async def initialize(self) -> None:
        logger.info({"event": "notification_manager_initialized"})

    async def shutdown(self) -> None:
        logger.info({"event": "notification_manager_shutdown"})