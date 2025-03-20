# pdns/schemas/dns_record.py
from pydantic import BaseModel, Field, validator
from typing import Optional, Union
from ..rrtypes import rrset

class DNSRecord(BaseModel):
    rrname: str = Field(..., description="Resource record name (domain)")
    rrtype: str = Field(..., description="Resource record type (e.g., A, AAAA)")
    rdata: str = Field(..., description="Resource record data (e.g., IP address)")
    time_first: Union[int, str] = Field(..., description="First seen timestamp (epoch seconds or ISO string)")
    time_last: Union[int, str] = Field(..., description="Last seen timestamp (epoch seconds or ISO string)")
    count: int = Field(default=1, ge=1, description="Number of occurrences")
    origin: Optional[str] = Field(None, alias="sensor_id", description="Origin or sensor identifier")

    @validator('rrname', 'rdata', pre=True)
    def normalize_domain(cls, v):
        return v.lower().strip('.')

    @validator('rrtype')
    def validate_rrtype(cls, v):
        if v not in rrset:
            raise ValueError(f"Invalid rrtype '{v}'.")
        return v

    @validator('rdata', pre=False)
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
    def ensure_positive(cls, v):
        return max(1, int(v))

    class Config:
        allow_population_by_field_name = True
        json_encoders = {
            int: lambda v: str(v)
        }
        json_schema_extra = {
            "example": {
                "rrname": "example.com",
                "rrtype": "A",
                "rdata": "93.184.216.34",
                "time_first": 1657878272,
                "time_last": 1657878272,
                "count": 1,
                "origin": "d4-sensor"
            }
        }