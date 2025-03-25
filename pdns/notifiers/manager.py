# pdns/notifiers/manager.py
from ..default.helpers import logger, get_config
from pypdns import PDNSRecord
from .base import Notifier
import os
import json
import importlib
import re
import ipaddress

class NotificationManager:
    """Manages loading and triggering of notification handlers from notifier directories."""

    def __init__(self):
        """Load notifiers from subdirectories in pdns/notifiers."""
        self.notifiers: list[Notifier] = []
        notifiers_dir = "pdns/notifiers"

        if not os.path.exists(notifiers_dir):
            logger.warning(f"Notifiers directory {notifiers_dir} does not exist, no notifiers loaded")
            return

        for notifier_name in os.listdir(notifiers_dir):
            notifier_path = os.path.join(notifiers_dir, notifier_name)
            if not os.path.isdir(notifier_path) or notifier_name.startswith("__"):
                continue

            config_path = os.path.join(notifier_path, "config.json")
            if not os.path.exists(config_path):
                logger.warning(f"No config.json found in {notifier_name}, skipping")
                continue

            try:
                with open(config_path, "r") as f:
                    config = json.load(f)

                # Use get_config for LogNotifier
                if notifier_name == "log":
                    config = get_config("notifiers", {}).get("log", {})

                # Dynamically import the notifier class
                module = importlib.import_module(f"pdns.notifiers.{notifier_name}")
                notifier_class = getattr(module, f"{notifier_name.capitalize()}Notifier")
                self.notifiers.append(notifier_class(config, notifier_path))
                logger.debug({"event": "notifier_loaded", "name": config.get("name"), "type": notifier_name})
            except Exception as e:
                logger.error(f"Failed to load notifier {notifier_name}: {str(e)}")

    def matches(self, record: PDNSRecord, condition: dict) -> bool:
        """Check if the record matches the given condition."""
        regex_conditions = {}
        for key, value in condition.items():
            if value.startswith("regex:"):
                pattern = value[len("regex:"):]
                regex_conditions[key] = re.compile(pattern)

        for key, value in condition.items():
            record_value = getattr(record, key, None) if key != "rdata" else record.rdata[0] if isinstance(record.rdata, list) else record.rdata
            if not record_value:
                return False
            if key in regex_conditions:
                if not regex_conditions[key].match(str(record_value)):
                    return False
            elif value.startswith("in:"):
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