from fastapi import APIRouter, Request, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from typing import Optional
from ..main import limiter, get_database, optional_auth
from ..queries import get_associated_records, stream_records
from ..default.helpers import logger, get_remote_address
from ..rrtypes import rrset, RRType  # Updated import
from ..schemas import DNSRecord, TimeFormat
from ..db.base import Database
import iptools
import json

router = APIRouter(prefix="/stream", tags=["stream"])

@router.get("/{q}")
@limiter.limit("20/minute")
async def stream(
    request: Request,
    q: str,
    chunk_size: int = Query(default=100, ge=10, le=1000, description="Number of records per chunk"),
    rrtype: Optional[RRType] = Query(default=None, description="Filter by RR type (e.g., A, AAAA)"),  # Use RRType
    time_format: TimeFormat = Query(default=TimeFormat.unix, description="Timestamp format: unix (int) or iso (string)"),
    db: Database = Depends(get_database),
    auth=Depends(optional_auth)
):
    rrtype_value = rrtype.value if rrtype else None  # Access enum value
    
    async def event_stream():
        record_count = 0
        try:
            if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
                associated = await get_associated_records(db, q)
                if not associated:
                    yield "\n"
                    return
                for x in associated:
                    async for entry in stream_records(db, x, chunk_size, rrtype=rrtype_value):
                        record = DNSRecord.from_pdns(entry)
                        yield record.to_ndjson(time_format) + "\n"
                        record_count += 1
            else:
                found = False
                async for entry in stream_records(db, q.strip(), chunk_size, rrtype=rrtype_value):
                    found = True
                    record = DNSRecord.from_pdns(entry)
                    yield record.to_ndjson(time_format) + "\n"
                    record_count += 1
                if not found:
                    yield "\n"
        except ValueError as e:
            logger.error({"endpoint": "/stream", "query": q, "client_ip": get_remote_address(request), "error": str(e)})
            yield f"{json.dumps({'error': f'Invalid data: {str(e)}'})}\n"
        except Exception as e:
            logger.error({"endpoint": "/stream", "query": q, "client_ip": get_remote_address(request), "error": str(e)})
            yield f"{json.dumps({'error': f'Database error: {str(e)}'})}\n"
        finally:
            logger.info({
                "endpoint": "/stream",
                "query": q,
                "client_ip": get_remote_address(request),
                "status": 200,
                "record_count": record_count
            })
    
    return StreamingResponse(event_stream(), media_type="application/x-ndjson")