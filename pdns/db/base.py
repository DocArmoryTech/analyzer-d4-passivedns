# pdns/databases/base.py
from abc import ABC, abstractmethod
from ..default.helpers import get_config, logger
from ..schemas import DNSRecord

class Database(ABC):
    """Abstract base class for database implementations."""

    def __init__(self):
        # Load expirations
        try:
            self.expirations = get_config("expirations")
            if not isinstance(self.expirations, dict):
                raise ValueError("expirations config must be a dictionary")
        except Exception as e:
            logger.error(f"Failed to load expirations config: {str(e)}, using empty dict")
            self.expirations = {}

    @abstractmethod
    async def connect(self):
        pass

    @abstractmethod
    async def disconnect(self):
        pass

    @abstractmethod
    async def store_record(self, record: DNSRecord) -> None:
        """Store a DNS record in the database."""
        pass

    @abstractmethod
    async def get_record(self, q: str, cursor: str, limit: int, rrtype: str = None) -> tuple[list[dict], str | None, int]:
        pass

    @abstractmethod
    async def get_associated_records(self, q: str) -> list[str]:
        pass

    @abstractmethod
    async def stream_records(self, q: str, chunk_size: int) -> str:
        pass

    @abstractmethod
    async def get_stats(self) -> dict:
        pass

    @abstractmethod
    async def get_sensors(self) -> list[tuple[str, int]]:
        pass