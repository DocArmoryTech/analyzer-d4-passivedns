# pdns/notifiers/filters/string.py
from .base import NotificationFilter
from pypdns import PDNSRecord


class StringFilter(NotificationFilter):
    """Filter based on case-insensitive string matching of record attributes."""

    type = 'string'

    def __init__(self, condition: dict):
        """Initialize with a dictionary of attribute-value pairs to match.

        Args:
            condition (dict): Key-value pairs where keys are record attributes
                             (e.g., 'rrtype', 'rrname') and values are strings to match
                             case-insensitively.
        """
        self.condition = condition

    def evaluate(self, record: PDNSRecord) -> bool:
        """Evaluate if the record matches all conditions case-insensitively.

        Args:
            record (PDNSRecord): The DNS record to check.

        Returns:
            bool: True if all conditions match (case-insensitive), False otherwise.
        """
        for key, value in self.condition.items():
            record_value = (
                getattr(record, key, None)
                if key != "rdata"
                else (record.rdata[0] if isinstance(record.rdata, list) else record.rdata)
            )
            if not record_value or str(record_value).lower() != str(value).lower():
                return False
        return True