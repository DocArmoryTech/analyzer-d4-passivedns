from fastapi import APIRouter, Request, Response, Depends, Query, HTTPException
from typing import Optional
from ..main import limiter, get_database, optional_auth
from ..queries import get_record
from ..default.helpers import logger, get_remote_address
from ..rrtypes import rrset, rrset_supported
from ..schemas import DNSRecord, MetadataResponse, TimeFormat, ResponseFormat  # Updated import

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
    time_format: TimeFormat = Query(default=TimeFormat.unix, description="Timestamp format: unix (int) or iso (string)"),
    format: ResponseFormat = Query(default=ResponseFormat.ndjson, description="Response format: ndjson or json"),
    db: Database = Depends(get_database),
    auth=Depends(optional_auth)
):
    valid_rrtypes = [k for k, v in rrset.items() if v in rrset_supported]
    if rrtype and rrtype.upper() not in valid_rrtypes:
        raise HTTPException(400, detail=f"Invalid rrtype: {rrtype}. Supported types: {', '.join(valid_rrtypes)}")

    rrtype_value = rrtype.upper() if rrtype else None
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
    
    if format == ResponseFormat.ndjson:
        formatted_records = [DNSRecord.from_pdns(r).to_ndjson(time_format) for r in records]
        response_content = "".join(formatted_records)
        logger.info({"endpoint": "/query", "query": q, "client_ip": get_remote_address(request), "status": 200, "record_count": len(records)})
        return Response(content=response_content, media_type="application/x-ndjson", headers=headers)
    else:
        formatted_records = []
        for r in records:
            record = DNSRecord.from_pdns(r)
            record_dict = record.dict()
            if time_format == TimeFormat.iso:
                record_dict["time_first"] = record.time_first_iso
                record_dict["time_last"] = record.time_last_iso
            formatted_records.append(record_dict)
        
        logger.info({"endpoint": "/query", "query": q, "client_ip": get_remote_address(request), "status": 200, "record_count": len(records)})
        if metadata:
            return MetadataResponse(
                data=[DNSRecord.from_pdns(r) for r in records],
                total=total,
                next_cursor=next_cursor
            ), headers
        return formatted_records, headers