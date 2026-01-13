from typing import List, Optional

from pydantic import BaseModel

from .dnsrecord import DNSRecord


class Sensor(BaseModel):
    sensor_id: str
    count: int


class InfoResponse(BaseModel):
    version: str
    software: str
    stats: dict
    sensors: List[Sensor]


class MetadataResponse(BaseModel):
    data: List[DNSRecord]
    total: int
    next_cursor: Optional[str] = None
