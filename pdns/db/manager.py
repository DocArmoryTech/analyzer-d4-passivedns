from ..default.helpers import get_config, logger
from ..schemas import DNSRecord
from .base import Database
from ..notifiers.manager import NotificationManager
from typing import Optional, List, Tuple, AsyncGenerator
from pypdns import PDNSRecord

class DatabaseManager:
    """Manages record storage, exclusions, notifications, and database connections."""

    def __init__(self, database: Database):
        self.database = database
        try:
            self.excludesubstrings = get_config("generic", "excludesubstrings")
            if not isinstance(self.excludesubstrings, list):
                raise ValueError("excludesubstrings in generic config must be a list")
        except Exception as e:
            logger.error(f"Failed to load excludesubstrings config: {str(e)}, using empty list")
            self.excludesubstrings = []
        self.notification_manager = NotificationManager()

    async def initialize(self) -> None:
        await self.database.connect()
        await self.notification_manager.initialize()  # Fixed typo
        logger.info({"event": "db_manager_init"})

    async def shutdown(self) -> None:
        await self.notification_manager.shutdown()  # Fixed typo
        await self.database.disconnect()
        logger.info({"event": "db_manager_shutdown"})

    async def store_record(self, record: PDNSRecord) -> None:
        if any(s in record.rrname for s in self.excludesubstrings):
            logger.debug({"event": "record_excluded", "rrname": record.rrname})
            return
        await self.database.store_record(record)
        dns_record = DNSRecord.from_pdns(record)
        await self.notification_manager.check_record(dns_record)

    async def get_record(
        self, rrname: str, cursor: Optional[str], limit: int, rrtype: Optional[str] = None
    ) -> Tuple[List[PDNSRecord], Optional[str], int]:
        return await self.database.get_record(rrname, cursor, limit, rrtype)

    async def get_stats(self) -> dict:
        return await self.database.get_stats()

    async def get_sensors(self) -> List[Tuple[str, int]]:
        return await self.database.get_sensors()

    async def get_associated_records(self, query: str) -> List[str]:
        return await self.database.get_associated_records(query)

    async def stream_records(self, rrname: str, chunk_size: int) -> AsyncGenerator[PDNSRecord, None]:
        async for record in self.database.stream_records(rrname, chunk_size):
            yield record