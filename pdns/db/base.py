# pdns/databases/base.py
from abc import ABC, abstractmethod
from ..default.helpers import get_config, logger
from ..schemas import DNSRecord
from ..notifiers.manager import NotificationManager

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
        
        # Load excludesubstrings
        try:
            self.excludesubstrings = get_config("generic", "excludesubstrings")
            if not isinstance(self.excludesubstrings, list):
                raise ValueError("excludesubstrings in generic config must be a list")
        except Exception as e:
            logger.error(f"Failed to load excludesubstrings config: {str(e)}, using empty list")
            self.excludesubstrings = []

        # Instantiate NotificationManager
        self.notification_manager = NotificationManager()

    def _is_excluded(self, record: DNSRecord) -> bool:
        """Check if a record is excluded based on substring rules."""
        if any(substr in record.rrname for substr in self.excludesubstrings):
            logger.debug({"event": "record_excluded", "rrname": record.rrname})
            return True
        return False

    @abstractmethod
    async def connect(self):
        pass

    @abstractmethod
    async def disconnect(self):
        pass

    async def store_record(self, record: DNSRecord) -> None:
        """Store a DNS record in the database, checking exclusions and triggering alerts."""
        if self._is_excluded(record):
            return
        await self.notification_manager.trigger(record)  # Trigger alerts
        await self._store_record_impl(record)

    @abstractmethod
    async def _store_record_impl(self, record: DNSRecord) -> None:
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