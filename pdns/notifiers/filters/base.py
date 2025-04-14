# pdns/notifiers/filters/base.py
from abc import ABC, abstractmethod
from pypdns import PDNSRecord


class NotificationFilter(ABC):
    """Abstract base class for notification filtering strategies.

    Subclasses must define a 'type' class variable and implement the 'evaluate' method.
    """

    type: str  # Required class variable

    @abstractmethod
    def evaluate(self, record: PDNSRecord) -> bool:
        """Determine if the record meets the filter criteria.

        Args:
            record (PDNSRecord): The DNS record to evaluate.

        Returns:
            bool: True if the record matches the filter, False otherwise.
        """
        pass