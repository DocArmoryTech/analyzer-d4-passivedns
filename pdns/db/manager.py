# pdns/db/manager.py
from ..default.helpers import get_config, logger
from ..default.exceptions import DBConnectionError, InvalidConfigError
from ..schemas import DNSRecord
from .base import Database
from .redis import RedisDatabase
from .redis_json import RedisJSONDatabase
from ..notifiers.manager import NotificationManager
from typing import Optional, List, Tuple, AsyncGenerator, Dict
from pypdns import PDNSRecord

class DatabaseManager:
    """Manages record storage, exclusions, notifications, expiration, and database connections."""
    def __init__(self) -> None:
        """Initialize the DatabaseManager with a database backend and configuration."""
        # Load database configuration from generic.json
        db_config = get_config("generic", "database", default={"type": "redis", "config": {"host": "127.0.0.1", "port": 6379, "db": 0}})
        if not isinstance(db_config, dict) or "type" not in db_config:
            raise InvalidConfigError("generic.database must be a dict with 'type' field")

        db_type = db_config.get("type")
        db_config_params = db_config.get("config", {"host": "127.0.0.1", "port": 6379, "db": 0})

        # Select backend based on type
        if db_type == "redis":
            self.database = RedisDatabase(**db_config_params)
        elif db_type == "redis_json":
            self.database = RedisJSONDatabase(**db_config_params)
        else:
            raise InvalidConfigError(f"Unknown database type: {db_type}")

        # Load exclusion substrings
        excludes = get_config("generic", "excludesubstrings", default=[])
        if not isinstance(excludes, list) or not all(isinstance(s, str) for s in excludes):
            raise InvalidConfigError("excludesubstrings in generic config must be a list of strings")
        self.excludesubstrings: List[str] = excludes

        # Load expiration settings
        expirations = get_config("generic", "expiration", default={})
        if not isinstance(expirations, dict) or not all(isinstance(k, str) and isinstance(v, int) for k, v in expirations.items()):
            raise InvalidConfigError("expiration in generic config must be a dictionary of string keys and integer values")
        self.expirations: Dict[str, int] = expirations

        self.notification_manager = NotificationManager()

    async def initialize(self) -> None:
        """Initialize the database connection and notification manager."""
        try:
            await self.database.connect()
            await self.notification_manager.initialize()
            logger.info({"event": "db_manager_init"})
        except DBConnectionError as e:
            logger.error({"event": "db_manager_init_failed", "error": str(e)})
            raise

    async def shutdown(self) -> None:
        """Shutdown the notification manager and database connection."""
        await self.notification_manager.shutdown()
        await self.database.disconnect()
        logger.info({"event": "db_manager_shutdown"})

    async def store_record(self, record: PDNSRecord) -> None:
        """Store a Passive DNS record with expiration handling."""
        if any(s in record.rrname for s in self.excludesubstrings):
            logger.debug({"event": "record_excluded", "rrname": record.rrname})
            return

        rrtype_str = str(record.rrtype).upper()
        expiration = self.expirations.get(rrtype_str)
        await self.database.store_record(record, expiration=expiration)
        dns_record = DNSRecord.from_pdns(record)
        await self.notification_manager.check_record(dns_record)

    async def get_record(self, rrname: str, cursor: Optional[str], limit: int, rrtype: Optional[str] = None) -> Tuple[List[PDNSRecord], Optional[str], int]:
        """Retrieve DNS records for a given rrname."""
        return await self.database.get_record(rrname, cursor, limit, rrtype)

    async def get_stats(self) -> dict:
        """Retrieve database statistics."""
        return await self.database.get_stats()

    async def get_sensors(self) -> List[Tuple[str, int]]:
        """Retrieve sensor statistics."""
        return await self.database.get_sensors()

    async def get_associated_records(self, query: str) -> List[str]:
        """Get associated rrnames for a given rdata."""
        return await self.database.get_associated_records(query)

    async def stream_records(self, rrname: str, chunk_size: int) -> AsyncGenerator[PDNSRecord, None]:
        """Stream DNS records for a given rrname in chunks."""
        async for record in self.database.stream_records(rrname, chunk_size):
            yield record