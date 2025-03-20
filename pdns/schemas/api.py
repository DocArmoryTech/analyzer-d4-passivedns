# pdns/schemas/api.py
from pydantic import BaseModel
from typing import List, Optional
from .dns_record import DNSRecord

class Sensor(BaseModel):
    sensor_id: str
    count: int

class InfoResponse(BaseModel):
    version: str
    software: str
    stats: int
    sensors: List[Sensor]

class MetadataResponse(BaseModel):
    data: List[DNSRecord]
    total: int
    next_cursor: Optional[str] = None