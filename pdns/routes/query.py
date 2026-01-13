from fastapi import APIRouter, Request, Response, Depends, Query, HTTPException
from typing import Optional
from slowapi.util import get_remote_address
from ..main import limiter, get_database, optional_auth
from ..default.helpers import logger
from ..rrtypes import SupportedRRType
from ..schemas import DNSRecord, MetadataResponse, TimeFormat, ResponseFormat
from ..db.manager import DatabaseManager

router = APIRouter(prefix="/query", tags=["query"])


@router.get("/{q}")
@limiter.limit("50/minute")
async def query(
    request: Request,
    q: str,
    cursor: Optional[str] = Query(
        default=None,
        description="Cursor for pagination, use to fetch next page if total > limit",
    ),
    limit: int = Query(
        default=200,
        ge=1,
        le=1000,
        description="Max records per page or total without cursor",
    ),
    rrtype: Optional[SupportedRRType] = Query(
        default=None, description="Filter by supported RR type (e.g., A, AAAA)"
    ),
    metadata: bool = Query(
        default=False, description="Wrap results in metadata object"
    ),
    time_format: TimeFormat = Query(
        default=TimeFormat.unix,
        description="Timestamp format: unix (int) or iso (string)",
    ),
    format: ResponseFormat = Query(
        default=ResponseFormat.ndjson, description="Response format: ndjson or json"
    ),
    db: DatabaseManager = Depends(get_database),
    auth=Depends(optional_auth),
):
    rrtype_value = rrtype.value if rrtype else None
    try:
        records, next_cursor, total = await db.get_record(
            q.strip(), cursor, limit, rrtype_value
        )
    except Exception as e:
        logger.error(
            {
                "endpoint": "/query",
                "query": q,
                "client_ip": get_remote_address(request),
                "error": str(e),
            }
        )
        raise HTTPException(status_code=500, detail="Database error")

    headers = {"X-Total-Count": str(total)}
    if total > limit:
        if cursor is None:
            records = records[:limit]
            headers["X-Next-Cursor"] = str(limit)
            headers["X-Pagination-Required"] = "true"
            logger.warning(
                {
                    "endpoint": "/query",
                    "query": q,
                    "client_ip": get_remote_address(request),
                    "total": total,
                    "limit": limit,
                    "cursor": cursor,
                    "message": "Partial results returned",
                }
            )
        elif next_cursor:
            headers["X-Next-Cursor"] = next_cursor

    # Convert PDNSRecord objects to DNSRecord Pydantic models
    dns_records = [DNSRecord.from_pdns(r) for r in records]

    logger.info(
        {
            "endpoint": "/query",
            "query": q,
            "client_ip": get_remote_address(request),
            "status": 200,
            "record_count": len(dns_records),
        }
    )

    if format == ResponseFormat.ndjson:
        response_content = "\n".join(
            record.to_ndjson(time_format) for record in dns_records
        )
        return Response(
            content=response_content, media_type="application/x-ndjson", headers=headers
        )
    else:
        if time_format == TimeFormat.iso:
            for record in dns_records:
                record.time_first = record.time_first_iso
                record.time_last = record.time_last_iso
        if metadata:
            response_data = MetadataResponse(
                data=dns_records, total=total, next_cursor=next_cursor
            )
        else:
            response_data = [record.dict() for record in dns_records]
        return response_data, headers
