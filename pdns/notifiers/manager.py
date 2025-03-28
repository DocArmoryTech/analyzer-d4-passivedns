# pdns/notifiers/manager.py
from ..default.helpers import logger, get_config
from pypdns import PDNSRecord
from .base import Notifier
from .filters.base import NotificationFilter
from .filters.string import StringFilter
from .filters.dnsbl import DNSBLFilter
import asyncio
import os
import json
import importlib
import ipaddress

class NotificationManager:
    """Manages loading and triggering of notification handlers from notifier directories."""

    def __init__(self):
        """Load notifiers from subdirectories in pdns/notifiers."""
        self.notifiers: list[Notifier] = []
        notifiers_dir = "pdns/notifiers"
        self._lock = asyncio.Lock()
        self._load_notifiers()
    
    def _create_filter(self, config: dict) -> NotificationFilter:
        """Factory method to create appropriate filter based on config."""
        filter_type = config.get("filter_type", "string")
        if filter_type == "string":
            return StringFilter(config.get("condition", {}))
        elif filter_type == "dnsbl":
            return DNSBLFilter(config.get("dnsbl_domain", "zen.spamhaus.org"))
        else:
            raise ValueError(f"Unknown filter type: {filter_type}")
        
    def _load_notifiers(self):
        notifiers_dir = "pdns/notifiers"
        if not os.path.exists(notifiers_dir):
            logger.warning(f"Notifiers directory {notifiers_dir} does not exist")
            return

        for notifier_name in os.listdir(notifiers_dir):
            notifier_path = os.path.join(notifier_path, notifier_name)
            if not os.path.isdir(notifier_path) or notifier_name.startswith("__"):
                continue

            config_path = os.path.join(notifier_path, "config.json")
            if not os.path.exists(config_path):
                logger.warning(f"No config.json in {notifier_name}")
                continue

            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
                
                if notifier_name == "log":
                    config = get_config("notifiers", {}).get("log", {})
                
                module = importlib.import_module(f"pdns.notifiers.{notifier_name}")
                notifier_class = getattr(module, f"{notifier_name.capitalize()}Notifier")
                notifier = notifier_class(config, notifier_path)
                filter_instance = self._create_filter(config)
                self.notifiers.append((notifier, filter_instance))
                logger.debug({"event": "notifier_loaded", "name": config.get("name")})
            except Exception as e:
                logger.error(f"Failed to load notifier {notifier_name}: {str(e)}")

                
    def matches(self, record: PDNSRecord, condition: dict) -> bool:
        """Check if the record matches the given condition (exact match or IP network)."""
        for key, value in condition.items():
            record_value = getattr(record, key, None) if key != "rdata" else record.rdata[0] if isinstance(record.rdata, list) else record.rdata
            if not record_value:
                return False
            if value.startswith("in:"):
                try:
                    network = ipaddress.ip_network(value[len("in:"):], strict=False)
                    if key == "rdata" and ipaddress.ip_address(record_value) not in network:
                        return False
                except ValueError:
                    return False
            elif str(record_value) != value:
                return False
        return True

    async def trigger(self, record: PDNSRecord) -> None:
        """Trigger notifications for matching notifiers."""
        for notifier in self.notifiers:
            if self.matches(record, notifier.condition):
                await notifier.notify(record)