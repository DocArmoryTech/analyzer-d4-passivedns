# pdns/databases/manager.py
from ..default.helpers import get_config, logger
from ..schemas import DNSRecord
from .base import Database
from ..notifiers.manager import NotificationManager

class DatabaseManager:
    """Manages record storage, exclusions, notifications, and database connections."""

    def __init__(self, database: Database, excludesubstrings: list[str] = None):
        self.database = database
        
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
        await self.database.connect()
        await alert_manager.initialize()
        logger.info({"event": "db_manager_init"})
        
    
    async def shutdown(self):
        await alert_manager.shutdown()
        await self.database.disconnect()
        logger.info({"event": "db_manager_shutdown"})

    def _is_excluded(self, record: DNSRecord) -> bool:
        """Check if a record is excluded based on substring rules."""
        if any(substr in record.rrname for substr in self.excludesubstrings):
            logger.debug({"event": "record_excluded", "rrname": record.rrname})
            return True
        return False
    
    async def store_record(self, record):
        if any(s in record.rrname for s in self.excludesubstrings):
            logger.debug({"event": "record_excluded", "rrname": record.rrname})
            return
        await self.database.store_record(record)
        dns_record = DNSRecord.from_pdns(record)
        await alert_manager.check_record(dns_record)

    # Proxy other methods
    async def get_record(self, rrname, cursor, limit, rrtype):
        return await self.database.get_record(rrname, cursor, limit, rrtype)

    async def get_stats(self):
        return await self.database.get_stats()

    async def get_sensors(self):
        return await self.database.get_sensors()

    async def get_associated_records(self, query):
        return await self.database.get_associated_records(query)

    async def stream_records(self, rrname, chunk_size):
        async for record in self.database.stream_records(rrname, chunk_size):
            yield record


    