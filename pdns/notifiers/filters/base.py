from abc import ABC, abstractmethod
from pypdns import PDNSRecord


class NotificationFilter(ABC):
    """Abstract base class for notification filtering strategies."""

    @abstractmethod
    def evaluate(self, record: PDNSRecord) -> bool:
        """Determine if the record meets the filter criteria."""
        pass
