# pdns/notifiers/base.py
from abc import ABC, abstractmethod
from ..schemas import DNSRecord
import re
import ipaddress

class Notifier(ABC):
    """Abstract base class for alert notification handlers."""

    def __init__(self, name: str, condition: dict):
        self.name = name
        self.condition = condition
        # Precompile regex patterns
        self.regex_conditions = {}
        for key, value in condition.items():
            if value.startswith("regex:"):
                pattern = value[len("regex:"):]
                self.regex_conditions[key] = re.compile(pattern)

    def matches(self, record: DNSRecord) -> bool:
        """Check if the record matches the notifier's conditions."""
        for key, value in self.condition.items():
            record_value = getattr(record, key, None) if key != "rdata" else record.rdata[0]
            if not record_value:
                return False
            if key in self.regex_conditions:
                if not self.regex_conditions[key].match(record_value):
                    return False
            elif value.startswith("in:"):
                try:
                    network = ipaddress.ip_network(value[len("in:"):], strict=False)
                    if key == "rdata" and ipaddress.ip_address(record_value) not in network:
                        return False
                except ValueError:
                    return False
            elif record_value != value:
                return False
        return True

    @abstractmethod
    async def notify(self, record: DNSRecord) -> None:
        """Send the alert notification for the record."""
        pass