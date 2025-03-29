# pdns/schemas.py
from pydantic import BaseModel
from typing import List, Optional, Union
from pypdns import PDNSRecord
import json
from datetime import datetime

class TimeFormat(str, Enum):
    unix = "unix"
    iso = "iso"

class ResponseFormat(str, Enum):
    ndjson = "ndjson"
    json = "json"
    
class DNSRecord(BaseModel):
    rrname: str
    rrtype: str
    rdata: list[str]
    time_first: int
    time_last: int
    count: int
    sensor_id: str | None = None

    @classmethod
    def from_pdns(cls, record: PDNSRecord):
        return cls(
            rrname=record.rrname,
            rrtype=record.rrtype,
            rdata=record.rdata if isinstance(record.rdata, list) else [record.rdata],
            time_first=int(record.time_first.timestamp() if isinstance(record.time_first, datetime) else record.time_first),
            time_last=int(record.time_last.timestamp() if isinstance(record.time_last, datetime) else record.time_last),
            count=record.count,
            sensor_id=record.sensor_id
        )

    def to_ndjson(self, time_format: TimeFormat) -> str:  # Updated to use TimeFormat
        data = self.dict()
        if time_format == TimeFormat.iso:
            data["time_first"] = datetime.fromtimestamp(self.time_first).isoformat()
            data["time_last"] = datetime.fromtimestamp(self.time_last).isoformat()
        return json.dumps(data)

    @property
    def time_first_iso(self) -> str:
        return datetime.fromtimestamp(self.time_first).isoformat()

    @property
    def time_last_iso(self) -> str:
        return datetime.fromtimestamp(self.time_last).isoformat()

class MetadataResponse(BaseModel):
    data: list[DNSRecord]
    total: int
    next_cursor: str | None = None

__all__ = ["TimeFormat", "ResponseFormat", "DNSRecord", "MetadataResponse"]