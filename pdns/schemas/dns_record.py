# pdns/schemas.py
from pydantic import BaseModel
from typing import List, Optional, Union
from pypdns import PDNSRecord
import json
from datetime import datetime

class DNSRecord(BaseModel):
    rrname: str
    rrtype: str
    rdata: Union[str, List[str]]  # PDNSRecord.rdata can be str or list
    time_first: int
    time_last: int
    count: int
    sensor_id: Optional[str] = None

    class Config:
        # Allow population from PDNSRecord instances
        from_attributes = True

    @classmethod
    def from_pdns(cls, record: PDNSRecord) -> "PDNSRecord":
        return cls(
            rrname=record.rrname,
            rrtype=record.rrtype,
            rdata=record.rdata,
            time_first=record.time_first,
            time_last=record.time_last,
            count=record.count,
            sensor_id=record.sensor_id
        )

    def to_json(self, time_format: str = "unix") -> str:
        data = self.dict()
        if time_format == "iso":
            data["time_first"] = datetime.fromtimestamp(data["time_first"]).isoformat()
            data["time_last"] = datetime.fromtimestamp(data["time_last"]).isoformat()
        return json.dumps(data)

    def to_ndjson(self, time_format: str = "unix") -> str:
        return self.to_json(time_format) + "\n"
