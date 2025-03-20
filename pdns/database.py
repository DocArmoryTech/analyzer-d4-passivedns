# pdns/database.py
import redis.asyncio as redis
from fastapi import HTTPException
from .default.helpers import logger

REDIS_HOST = "127.0.0.1"  # Could be moved to config later
REDIS_PORT = 6400
redis_pool = redis.ConnectionPool.from_url(f"redis://{REDIS_HOST}:{REDIS_PORT}/0")

async def get_redis_client():
    client = redis.Redis.from_pool(redis_pool)
    try:
        await client.ping()
        yield client
    except redis.exceptions.BusyLoadingError:
        raise HTTPException(status_code=503, detail="Loading dataset...", headers={"Retry-After": "10"})
    except redis.ConnectionError:
        raise HTTPException(status_code=503, detail="Dataset unavailable", headers={"Retry-After": "5"})
    except Exception as e:
        logger.error({"event": "redis_error", "error": str(e)})
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        await client.aclose()