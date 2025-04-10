from .base import NotificationFilter
from pypdns import PDNSRecord


class StringFilter(NotificationFilter):
    """Filter based on exact string matching of record attributes."""

    type = 'string'

    def __init__(self, condition: dict):
        self.condition = condition

    def evaluate(self, record: PDNSRecord) -> bool:
        for key, value in self.condition.items():
            record_value = (
                getattr(record, key, None)
                if key != "rdata"
                else (
                    record.rdata[0] if isinstance(record.rdata, list) else record.rdata
                )
            )
            if not record_value or str(record_value) != value:
                return False
        return True
