# pdns/schemas.py
from pydantic import BaseModel
from typing import List, Optional, Union
from pypdns import PDNSRecord
import json
from datetime import datetime


class MetadataResponse(BaseModel):
    data: List[PDNSRecordSchema]
    total: int
    next_cursor: Optional[str] = None

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