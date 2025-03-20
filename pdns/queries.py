# pdns/queries.py
from typing import List, Tuple, Optional, AsyncGenerator
from .db.base import Database

async def get_timestamps_and_count(db: Database, t1: str, t2: str, rr_values: List[str]) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    return await db.get_timestamps_and_count(t1, t2, rr_values)

async def get_record(db: Database, t: str, cursor: Optional[str] = None, limit: int = 200, rrtype: Optional[str] = None) -> Tuple[List[dict], Optional[str], int]:
    return await db.get_record(t, cursor, limit, rrtype)

async def get_associated_records(db: Database, rdata: str) -> List[str]:
    return await db.get_associated_records(rdata)

async def stream_records(db: Database, t: str, chunk_size: int) -> AsyncGenerator[str, None]:
    async for record in db.stream_records(t, chunk_size):
        yield record