# pdns/databases/manager.py
from ..default.helpers import get_config, logger
from ..schemas import DNSRecord
from .base import Database
from ..notifiers.manager import NotificationManager

class DatabaseManager:
    """Manages record storage, exclusions, notifications, and database connections."""

    def __init__(self, database: Database, pool_size: int = 10):
        self.database = database
        self.pool_size = pool_size
        
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

    async def initialize(self):
        """Initialize the database connection pool."""
        await self.database.connect(pool_size=self.pool_size)

    async def shutdown(self):
        """Shutdown the database connection pool."""
        await self.database.disconnect()

    def _is_excluded(self, record: DNSRecord) -> bool:
        """Check if a record is excluded based on substring rules."""
        if any(substr in record.rrname for substr in self.excludesubstrings):
            logger.debug({"event": "record_excluded", "rrname": record.rrname})
            return True
        return False

    async def store_record(self, record: DNSRecord) -> None:
        """Store a DNS record, checking exclusions and triggering alerts."""
        if self._is_excluded(record):
            return
        await self.notification_manager.trigger(record)
        await self.database.store_record(record)