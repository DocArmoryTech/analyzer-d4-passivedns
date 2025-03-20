# pdns/routes/stream.py
from fastapi import APIRouter, Request, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from typing import Optional  # Add this for Optional type hint
from ..main import limiter, get_database
from ..queries import get_associated_records, stream_records
from ..default.helpers import logger, format_record, get_remote_address
from ..rrtypes import rrset, rrset_supported
from ..databases.base import Database
import json
import iptools

router = APIRouter(prefix="/stream", tags=["stream"])

@router.get("/{q}")
@limiter.limit("20/minute")
async def stream(
    request: Request,
    q: str,
    chunk_size: int = Query(default=100, ge=10, le=1000, description="Number of records per chunk"),
    rrtype: Optional[str] = Query(default=None, description="Filter by RR type (e.g., A, AAAA)"),
    time_format: str = Query(default="unix", pattern="^(unix|iso)$", description="Timestamp format: unix (int) or iso (string)"),
    db: Database = Depends(get_database),
    auth=Depends(optional_auth)
):
    # Validate rrtype query parameter against rrset filtered by rrset_supported
    valid_rrtypes = [k for k, v in rrset.items() if v in rrset_supported]
    if rrtype and rrtype.upper() not in valid_rrtypes:
        raise HTTPException(400, detail=f"Invalid rrtype: {rrtype}. Supported types: {', '.join(valid_rrtypes)}")
    
    async def event_stream():
        try:
            if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
                associated = await get_associated_records(db, q)
                if not associated:
                    yield "[]\n"
                    return
                for x in associated:
                    async for record in stream_records(db, x, chunk_size):
                        # Parse the ||-separated string from stream_records
                        r = record.strip().split("||")
                        parsed = {
                            "rrname": r[0],
                            "rrtype": next(k for k, v in rrset.items() if v == r[1]),  # Map numeric to name
                            "rdata": r[2],
                            "time_first": r[3],
                            "time_last": r[4],
                            "count": r[5]
                        }
                        yield f"{json.dumps(format_record(parsed, time_format))}\n"
            else:
                found = False
                # Convert rrtype to numeric for filtering if provided
                rrtype_value = rrset.get(rrtype.upper()) if rrtype else None
                async for record in stream_records(db, q.strip(), chunk_size):
                    # Parse the ||-separated string
                    r = record.strip().split("||")
                    parsed = {
                        "rrname": r[0],
                        "rrtype": r[1],  # Numeric initially
                        "rdata": r[2],
                        "time_first": r[3],
                        "time_last": r[4],
                        "count": r[5]
                    }
                    # Filter by rrtype if specified (compare numeric values)
                    if rrtype_value is None or parsed["rrtype"] == rrtype_value:
                        found = True
                        parsed["rrtype"] = next(k for k, v in rrset.items() if v == parsed["rrtype"])  # Map to name
                        yield f"{json.dumps(format_record(parsed, time_format))}\n"
                if not found:
                    yield "[]\n"
        except Exception as e:
            logger.error({"endpoint": "/stream", "query": q, "client_ip": get_remote_address(request), "error": str(e)})
            yield f"{json.dumps({'error': f'Database error: {str(e)}'})}\n"
    
    logger.info({"endpoint": "/stream", "query": q, "client_ip": get_remote_address(request), "status": 200})
    return StreamingResponse(event_stream(), media_type="application/x-ndjson")