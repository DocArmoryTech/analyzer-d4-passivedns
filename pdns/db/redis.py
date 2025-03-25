# pdns/db/redis.py
from .base import Database
from ..default.helpers import logger, get_config
from pypdns import PDNSRecord
import aioredis
import json
from typing import Tuple, List, Optional, AsyncGenerator

class RedisDatabase(Database):
    """Redis implementation of the Database interface."""

    def __init__(self):
        """Initialize Redis connection based on database.json config."""
        config = get_config("redis", default={})  # Load redis config from database.json or fallback
        self.db_number = config.get("db", 0)  # Default to DB 0 if not specified

        if "socket" in config:
            # Unix socket connection
            self.redis = aioredis.Redis(
                unix_socket_path=config["socket"],
                db=self.db_number,
                decode_responses=True
            )
            logger.info({"event": "redis_init", "type": "unix", "socket": config["socket"], "db": self.db_number})
        elif "ip" in config and "port" in config:
            # TCP connection
            self.redis = aioredis.Redis(
                host=config["ip"],
                port=config["port"],
                db=self.db_number,
                decode_responses=True
            )
            logger.info({"event": "redis_init", "type": "tcp", "ip": config["ip"], "port": config["port"], "db": self.db_number})
        else:
            raise ValueError("Invalid Redis config: must specify either 'socket' or 'ip' and 'port'")

    async def get_record(self, key: str, cursor: Optional[str] = None, limit: int = 200, rrtype: Optional[str] = None) -> Tuple[List[PDNSRecord], Optional[str], int]:
        """Fetch records for a given key with pagination."""
        try:
            start = int(cursor) if cursor else 0
            end = start + limit - 1
            total = await self.redis.zcard(key)
            records = await self.redis.zrange(key, start, end)
            
            result = []
            for record in records:
                data = json.loads(record)
                pdns_record = PDNSRecord(
                    rrname=data["rrname"],
                    rrtype=data["rrtype"],
                    rdata=data["rdata"],
                    time_first=data["time_first"],
                    time_last=data["time_last"],
                    count=data["count"],
                    sensor_id=data.get("sensor_id")
                )
                if rrtype is None or pdns_record.rrtype == rrtype:
                    result.append(pdns_record)
            
            next_cursor = str(end + 1) if end < total - 1 else None
            return result, next_cursor, total
        except Exception as e:
            logger.error({"event": "redis_get_record_failed", "key": key, "error": str(e)})
            return [], None, 0

    async def stream_records(self, key: str, chunk_size: int = 100) -> AsyncGenerator[PDNSRecord, None]:
        """Stream records for a given key in chunks."""
        try:
            cursor = 0
            while True:
                records = await self.redis.zrange(key, cursor, cursor + chunk_size - 1)
                if not records:
                    break
                for record in records:
                    data = json.loads(record)
                    yield PDNSRecord(
                        rrname=data["rrname"],
                        rrtype=data["rrtype"],
                        rdata=data["rdata"],
                        time_first=data["time_first"],
                        time_last=data["time_last"],
                        count=data["count"],
                        sensor_id=data.get("sensor_id")
                    )
                cursor += chunk_size
        except Exception as e:
            logger.error({"event": "redis_stream_records_failed", "key": key, "error": str(e)})

    async def get_stats(self) -> dict:
        """Return database statistics."""
        try:
            info = await self.redis.info()
            return {"records": info.get("keys", 0)}
        except Exception as e:
            logger.error({"event": "redis_get_stats_failed", "error": str(e)})
            return {"records": 0}

    async def get_sensors(self) -> List[dict]:
        """Return sensor information."""
        # Placeholder; extend with actual sensor tracking if needed
        return [{"sensor_id": "unknown", "count": await self.redis.dbsize()}]