# pdns/db/manager.py
from ..default.helpers import get_config, logger
from ..rrtypes import RRType
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
        expirations_cfg = get_config("generic", "expiration", default={})
        if not isinstance(expirations_cfg, dict) or not all(isinstance(k, str) and isinstance(v, int) for k, v in expirations_cfg.items()):
            raise InvalidConfigError("expiration in generic config must be a dictionary of string keys and integer values")

        # Normalize expiration keys so configs can use either RR names (e.g., "A")
        # or numeric codes as strings (e.g., "1"). Internally we store
        # everything keyed by the numeric string from RRType.
        normalized_expirations: Dict[str, int] = {}
        for key, value in expirations_cfg.items():
            upper_key = key.upper()
            if upper_key in RRType.__members__:
                code = str(RRType[upper_key].value)
                normalized_expirations[code] = value
            else:
                normalized_expirations[upper_key] = value

        self.expirations: Dict[str, int] = normalized_expirations

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

        rrtype_raw = str(record.rrtype).upper()

        # Allow PDNSRecord.rrtype to be either a name (e.g., "A") or
        # a numeric code. Normalize to the numeric string used internally.
        if rrtype_raw in RRType.__members__:
            rrtype_key = str(RRType[rrtype_raw].value)
        else:
            rrtype_key = rrtype_raw

        expiration = self.expirations.get(rrtype_key)
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