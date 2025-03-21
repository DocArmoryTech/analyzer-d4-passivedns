# pdns/routes/query.py
from fastapi import APIRouter, Request, Response, Depends, Query, HTTPException
from typing import Optional
from ..main import limiter, get_database
from ..queries import get_record
from ..default.helpers import logger, get_remote_address
from ..rrtypes import rrset, rrset_supported
from ..schemas import DNSRecord
from ..db.base import Database
import json

router = APIRouter(prefix="/query", tags=["query"])

@router.get("/{q}")
@limiter.limit("50/minute")
async def query(
    request: Request,
    q: str,
    cursor: Optional[str] = Query(default=None, description="Cursor for pagination, required if > limit"),
    limit: int = Query(default=200, ge=10, le=1000, description="Max records per page or total without cursor"),
    rrtype: Optional[str] = Query(default=None, description="Filter by RR type (e.g., A, AAAA)"),
    metadata: bool = Query(default=False, description="Wrap results in metadata object"),
    time_format: str = Query(default="unix", pattern="^(unix|iso)$", description="Timestamp format: unix (int) or iso (string)"),
    format: str = Query(default="ndjson", pattern="^(ndjson|json)$", description="Response format: ndjson or json"),
    db: Database = Depends(get_database),
    auth=Depends(optional_auth)
):
    valid_rrtypes = [k for k, v in rrset.items() if v in rrset_supported]
    if rrtype and rrtype.upper() not in valid_rrtypes:
        raise HTTPException(400, detail=f"Invalid rrtype: {rrtype}. Supported types: {', '.join(valid_rrtypes)}")

    rrtype_value = rrset.get(rrtype.upper()) if rrtype else None
    records, next_cursor, total = await get_record(db, q.strip(), cursor, limit, rrtype_value)
    
    headers = {"X-Total-Count": str(total)}
    if total > limit:
        if cursor is None:
            records = records[:limit]
            headers["X-Next-Cursor"] = str(limit)
            headers["X-Pagination-Required"] = "true"
            logger.warning({"endpoint": "/query", "query": q, "client_ip": get_remote_address(request), "total": total, "limit": limit, "message": "Partial results returned"})
        elif next_cursor:
            headers["X-Next-Cursor"] = next_cursor
    
    formatted_records = []
    for r in records:
        dns_record = DNSRecord(
            rrname=r["rrname"],
            rrtype=next(k for k, v in rrset.items() if v == r["rrtype"]),
            rdata=[r["rdata"]],  # Single value from db, wrapped as list
            time_first=r["time_first"],
            time_last=r["time_last"],
            count=r["count"]
        )
        if format == "ndjson":
            formatted_records.append(dns_record.to_ndjson(time_format))
        else:
            formatted_records.append(json.loads(dns_record.to_json(time_format)))
    
    if format == "ndjson":
        response_content = "".join(formatted_records)
        media_type = "application/x-ndjson"
    else:
        response_content = json.dumps(
            formatted_records if not metadata else {"data": formatted_records, "total": total, "next_cursor": next_cursor}
        )
        media_type = "application/json"
    
    logger.info({"endpoint": "/query", "query": q, "client_ip": get_remote_address(request), "status": 200, "record_count": len(records)})
    return Response(content=response_content, media_type=media_type, headers=headers)