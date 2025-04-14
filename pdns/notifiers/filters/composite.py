# pdns/notifiers/filters/composite.py
from .base import NotificationFilter
from pypdns import PDNSRecord
from typing import List


class CompositeFilter(NotificationFilter):
    """Filter combining multiple filters with 'and', 'or', or 'not' operators."""

    type = 'composite'

    def __init__(self, filters: List[NotificationFilter] = None, operator: str = "and"):
        """Initialize with a list of filters and an operator.

        Args:
            filters (List[NotificationFilter], optional): Filters to combine.
            operator (str): 'and', 'or', or 'not' (default: 'and').

        Raises:
            ValueError: If operator is invalid or filters are missing/invalid for the operator.
        """
        self.operator = operator.lower()
        if self.operator not in ["and", "or", "not"]:
            raise ValueError("Operator must be 'and', 'or', or 'not'")
        if self.operator == "not" and (not filters or len(filters) != 1):
            raise ValueError("'not' operator requires exactly one filter")
        if self.operator in ["and", "or"] and not filters:
            raise ValueError("'and' or 'or' operator requires at least one filter")
        self.filters = filters or []

    def evaluate(self, record: PDNSRecord) -> bool:
        """Evaluate the record against the combined filters.

        Args:
            record (PDNSRecord): The DNS record to check.

        Returns:
            bool: True if the filter criteria are met, False otherwise.
        """
        if self.operator == "and":
            return all(f.evaluate(record) for f in self.filters)
        elif self.operator == "or":
            return any(f.evaluate(record) for f in self.filters)
        elif self.operator == "not":
            return not self.filters[0].evaluate(record)
        return False