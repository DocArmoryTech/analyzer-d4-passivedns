from fastapi import APIRouter, Request, Response, Depends, Query, HTTPException
from typing import Optional
from ..main import limiter, get_database, optional_auth
from ..queries import get_record, get_associated_records
from ..default.helpers import logger, get_remote_address
from ..rrtypes import rrset, RRType  # Updated import
from ..schemas import DNSRecord, MetadataResponse, TimeFormat, ResponseFormat
from ..db.base import Database
import iptools

router = APIRouter(prefix="/fquery", tags=["fquery"])

@router.get("/{q}")
@limiter.limit("50/minute")
async def full_query(
    request: Request,
    q: str,
    cursor: Optional[str] = Query(default=None, description="Cursor for pagination, required if > limit"),
    limit: int = Query(default=200, ge=10, le=1000, description="Max records per page or total without cursor"),
    rrtype: Optional[RRType] = Query(default=None, description="Filter by RR type (e.g., A, AAAA)"),  # Use RRType
    metadata: bool = Query(default=False, description="Wrap results in metadata object"),
    time_format: TimeFormat = Query(default=TimeFormat.unix, description="Timestamp format: unix (int) or iso (string)"),
    format: ResponseFormat = Query(default=ResponseFormat.ndjson, description="Response format: ndjson or json"),
    db: Database = Depends(get_database),
    auth=Depends(optional_auth)
):
    rrtype_value = rrtype.value if rrtype else None  # Access enum value
    result = []
    total = 0
    next_cursor = None
    
    if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
        associated = await get_associated_records(db, q)
        for x in associated:
            records, nc, tc = await get_record(db, x, cursor, limit, rrtype_value)
            result.extend(records)
            total += tc
            if (cursor is not None or total > limit) and nc:
                next_cursor = nc
                break
    else:
        associated = await get_associated_records(db, q)
        for x in associated:
            records, nc, tc = await get_record(db, x.strip(), cursor, limit, rrtype_value)
            result.extend(records)
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
    
    if format == ResponseFormat.ndjson:
        formatted_records = [DNSRecord.from_pdns(r).to_ndjson(time_format) for r in result]
        response_content = "\n".join(formatted_records)
        logger.info({"endpoint": "/fquery", "query": q, "client_ip": get_remote_address(request), "status": 200, "record_count": len(result)})
        return Response(content=response_content, media_type="application/x-ndjson", headers=headers)
    else:
        formatted_records = []
        for r in result:
            record = DNSRecord.from_pdns(r)
            record_dict = record.dict()
            if time_format == TimeFormat.iso:
                record_dict["time_first"] = record.time_first_iso
                record_dict["time_last"] = record.time_last_iso
            formatted_records.append(record_dict)
        
        logger.info({"endpoint": "/fquery", "query": q, "client_ip": get_remote_address(request), "status": 200, "record_count": len(result)})
        if metadata:
            return MetadataResponse(
                data=[DNSRecord.from_pdns(r) for r in result],
                total=total,
                next_cursor=next_cursor
            ), headers
        return formatted_records, headers