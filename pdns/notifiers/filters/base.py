from abc import ABC, abstractmethod
from pypdns import PDNSRecord


class NotificationFilter(ABC):
    """Abstract base class for notification filtering strategies."""

    type: str  # Required class variable 

    @abstractmethod
    def evaluate(self, record: PDNSRecord) -> bool:
        """Determine if the record meets the filter criteria."""
        pass
