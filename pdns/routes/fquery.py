# pdns/routes/fquery.py
from fastapi import APIRouter, Request, Response, Depends, Query, HTTPException
from typing import Optional
from ..main import limiter, get_database
from ..queries import get_record, get_associated_records
from ..default.helpers import logger, get_remote_address
from ..rrtypes import rrset, rrset_supported
from ..schemas import PDNSRecord, MetadataResponse
from ..db.base import Database
import json
import iptools

router = APIRouter(prefix="/fquery", tags=["fquery"])

@router.get("/{q}")
@limiter.limit("50/minute")
async def full_query(
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
    
    result = []
    total = 0
    next_cursor = None
    
    rrtype_value = rrtype.upper() if rrtype else None
    
    if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
        associated = await get_associated_records(db, q)
        for x in associated:
            records, nc, tc = await get_record(db, x, cursor, limit, rrtype_value)
            result.extend([r for r in records if rrtype_value is None or r.rrtype == rrtype_value])
            total += tc
            if (cursor is not None or total > limit) and nc:
                next_cursor = nc
                break
    else:
        associated = await get_associated_records(db, q)
        for x in associated:
            records, nc, tc = await get_record(db, x.strip(), cursor, limit, rrtype_value)
            result.extend([r for r in records if rrtype_value is None or r.rrtype == rrtype_value])
            total += tc
            if (cursor is not None or total > limit) and nc:
                next_cursor = nc
                break
    
    headers = {"X-Total-Count": str(total)}
    if total > limit:
        if cursor is None:
            result = result[:limit]
            headers["X-Next-Cursor"] = str(limit)
            headers["X-Pagination-Required"] = "true"
            logger.warning({"endpoint": "/fquery", "query": q, "client_ip": get_remote_address(request), "total": total, "limit": limit, "message": "Partial results returned"})
        elif next_cursor:
            headers["X-Next-Cursor"] = next_cursor
    
    formatted_records = []
    for r in result:
        record = PDNSRecord.from_pdns(r)
        if format == "ndjson":
            formatted_records.append(record.to_ndjson(time_format))
        else:
            formatted_records.append(record.dict() if time_format == "unix" else json.loads(record.to_json(time_format)))
    
    if format == "ndjson":
        response_content = "\n".join(formatted_records)
        media_type = "application/x-ndjson"
    else:
        response_data = formatted_records if not metadata else MetadataResponse(
            data=[PDNSRecord.from_pdns(r) for r in result],
            total=total,
            next_cursor=next_cursor
        )
        response_content = json.dumps(response_data.dict() if isinstance(response_data, MetadataResponse) else response_data)
        media_type = "application/json"
    
    logger.info({"endpoint": "/fquery", "query": q, "client_ip": get_remote_address(request), "status": 200, "record_count": len(result)})
    return Response(content=response_content, media_type=media_type, headers=headers)