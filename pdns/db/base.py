from abc import ABC, abstractmethod
from typing import Optional, List, Tuple, AsyncGenerator
from pypdns import PDNSRecord

class Database(ABC):
    """Abstract base class defining the database interface."""

    @abstractmethod
    async def connect(self) -> None:
        """Establish a connection to the database."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close the database connection."""
        pass

    @abstractmethod
    async def store_record(self, record: PDNSRecord) -> None:
        """Store a Passive DNS record in the database."""
        pass

    @abstractmethod
    async def get_record(
        self, q: str, cursor: Optional[str], limit: int, rrtype: Optional[str] = None
    ) -> Tuple[List[PDNSRecord], Optional[str], int]:
        """Retrieve Passive DNS records for a given query name with pagination."""
        pass

    @abstractmethod
    async def get_associated_records(self, q: str) -> List[str]:
        """Get associated rrnames for a given rdata."""
        pass

    @abstractmethod
    async def stream_records(self, q: str, chunk_size: int) -> AsyncGenerator[PDNSRecord, None]:
        """Stream Passive DNS records as PDNSRecord objects."""
        pass

    @abstractmethod
    async def get_stats(self) -> dict:
        """Retrieve database statistics."""
        pass

    @abstractmethod
    async def get_sensors(self) -> List[Tuple[str, int]]:
        """Retrieve sensor statistics."""
        pass