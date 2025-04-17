# pdns/db/manager.py
from ..default.helpers import get_config, logger
from ..schemas import DNSRecord
from .base import Database
from ..notifiers.manager import NotificationManager
from typing import Optional, List, Tuple, AsyncGenerator, Dict
from pypdns import PDNSRecord


class DatabaseManager:
    """Manages record storage, exclusions, notifications, expiration, and database connections."""

    def __init__(self, database: Database) -> None:
        """
        Initialize the DatabaseManager with a database backend and configuration.

        Args:
            database: The underlying Database implementation (e.g., RedisDatabase).
        """
        self.database = database

        # Load exclusion substrings from config
        try:
            excludes = await get_config("generic", "excludesubstrings")
            if not isinstance(excludes, list):
                raise ValueError("excludesubstrings in generic config must be a list")
            self.excludesubstrings: List[str] = excludes
        except Exception as e:
            logger.error(
                f"Failed to load excludesubstrings config: {str(e)}, using empty list"
            )
            self.excludesubstrings = []

        # Load expiration settings from config
        try:
            expirations = await get_config("generic", "expiration")
            if not isinstance(expirations, dict):
                raise ValueError("expiration in generic config must be a dictionary")
            # Convert keys to strings if they aren't already
            self.expirations: Dict[str, int] = {
                str(k): v for k, v in expirations.items()
            }
        except Exception as e:
            logger.error(
                f"Failed to load expiration config: {str(e)}, using empty dict"
            )
            self.expirations = {}

        # Initialize notification manager
        self.notification_manager = NotificationManager()

    async def initialize(self) -> None:
        """Initialize the database connection and notification manager."""
        await self.database.connect()
        await self.notification_manager.initialize()
        logger.info({"event": "db_manager_init"})

    async def shutdown(self) -> None:
        """Shutdown the notification manager and database connection."""
        await self.notification_manager.shutdown()
        await self.database.disconnect()
        logger.info({"event": "db_manager_shutdown"})

    async def store_record(self, record: PDNSRecord) -> None:
        """
        Store a Passive DNS record with expiration handling.

        Args:
            record: The PDNSRecord to store.
        """
        # Check exclusions
        if any(s in record.rrname for s in self.excludesubstrings):
            logger.debug({"event": "record_excluded", "rrname": record.rrname})
            return

        # Determine expiration based on RR type
        rrtype_str = str(record.rrtype)  # Normalize to string to match config
        expiration = self.expirations.get(rrtype_str)

        # Store the record with expiration
        await self.database.store_record(record, expiration=expiration)

        # Handle notifications
        dns_record = DNSRecord.from_pdns(record)
        await self.notification_manager.check_record(dns_record)

    async def get_record(
        self,
        rrname: str,
        cursor: Optional[str],
        limit: int,
        rrtype: Optional[str] = None,
    ) -> Tuple[List[PDNSRecord], Optional[str], int]:
        """
        Retrieve DNS records for a given rrname.

        Args:
            rrname: The resource record name to query.
            cursor: Pagination cursor (if any).
            limit: Maximum number of records to return.
            rrtype: Optional RR type filter.

        Returns:
            Tuple of (records, next_cursor, total_count).
        """
        return await self.database.get_record(rrname, cursor, limit, rrtype)

    async def get_stats(self) -> dict:
        """Retrieve database statistics."""
        return await self.database.get_stats()

    async def get_sensors(self) -> List[Tuple[str, int]]:
        """Retrieve sensor statistics."""
        return await self.database.get_sensors()

    async def get_associated_records(self, query: str) -> List[str]:
        """
        Get associated rrnames for a given rdata.

        Args:
            query: The rdata to query for associated rrnames.

        Returns:
            List of associated rrnames.
        """
        return await self.database.get_associated_records(query)

    async def stream_records(
        self, rrname: str, chunk_size: int
    ) -> AsyncGenerator[PDNSRecord, None]:
        """
        Stream DNS records for a given rrname in chunks.

        Args:
            rrname: The resource record name to stream.
            chunk_size: Number of records per chunk.

        Yields:
            PDNSRecord objects.
        """
        async for record in self.database.stream_records(rrname, chunk_size):
            yield record
