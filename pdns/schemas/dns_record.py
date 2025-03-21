# pdns/schemas/dns_record.py
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Union
from ..rrtypes import rrset
import json

class DNSRecord(BaseModel):
    rrname: str = Field(..., description="Resource record name (domain)")
    rrtype: str = Field(..., description="Resource record type (e.g., A, AAAA)")
    rdata: List[str] = Field(..., description="Resource record data (list of values, e.g., IP addresses)")
    time_first: int = Field(..., description="First seen timestamp (epoch seconds)")
    time_last: int = Field(..., description="Last seen timestamp (epoch seconds)")
    count: int = Field(default=0, ge=0, description="Number of occurrences")
    sensor_id: Optional[str] = Field(None, description="Sensor identifier")
    origin: Optional[str] = Field(None, description="Resource origin URI")

    @validator('rrname', pre=True)
    def normalize_domain(cls, v):
        return v.lower()  # Keep trailing dot for COF compatibility

    @validator('rrtype', pre=True)
    def validate_rrtype(cls, v):
        v_str = str(v)
        if v_str in rrset:
            return v_str
        for name, num in rrset.items():
            if num == v_str:
                return name
        raise ValueError(f"Invalid rrtype '{v}'. Must be one of {list(rrset.keys())} or a supported numeric value")

    @validator('rdata', pre=True)
    def normalize_rdata(cls, v):
        if isinstance(v, str):
            return [v]
        if not isinstance(v, list):
            raise ValueError("rdata must be a string or list of strings")
        return v

    @validator('rdata', each_item=True, pre=False)
    def preprocess_txt(cls, v, values):
        rtype = rrset.get(values.get('rrtype'))
        if rtype == '16':
            return v.replace('"', '', 1)
        return v

    @validator('time_first', 'time_last', pre=True)
    def normalize_timestamp(cls, v):
        try:
            if isinstance(v, str) and ':' in v:
                from datetime import datetime
                return int(datetime.fromisoformat(v).timestamp())
            return int(float(v))
        except (ValueError, TypeError):
            raise ValueError("Timestamp must be a valid number or ISO string")

    @validator('count', pre=True)
    def ensure_non_negative(cls, v):
        return max(0, int(v))

    def to_json(self, time_format: str = "unix") -> str:
        """Return the record as a JSON string (COF-compliant)."""
        data = self.dict(exclude_none=True)
        if time_format == "iso":
            from datetime import datetime
            data["time_first"] = datetime.fromtimestamp(data["time_first"]).isoformat()
            data["time_last"] = datetime.fromtimestamp(data["time_last"]).isoformat()
        return json.dumps(data)

    def to_ndjson(self, time_format: str = "unix") -> str:
        """Return the record as an NDJSON string (JSON with newline)."""
        return self.to_json(time_format) + "\n"

    class Config:
        allow_population_by_field_name = True
        extra = "allow"  # Allow additional properties per COF
        json_encoders = {
            int: lambda v: v  # Keep as number for COF
        }