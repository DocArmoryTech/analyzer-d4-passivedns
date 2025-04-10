# pdns/notifiers/filters/composite.py
from .base import NotificationFilter
from pypdns import PDNSRecord
from typing import List


class CompositeFilter(NotificationFilter):
    def __init__(self, filters: List[NotificationFilter], operator: str = "and"):
        self.filters = filters
        self.operator = operator.lower()
        if self.operator not in ["and", "or"]:
            raise ValueError("Operator must be 'and' or 'or'")

    def evaluate(self, record: PDNSRecord) -> bool:
        if self.operator == "and":
            return all(f.evaluate(record) for f in self.filters)
        elif self.operator == "or":
            return any(f.evaluate(record) for f in self.filters)
        return False
