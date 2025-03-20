# pdns/databases/base.py
from abc import ABC, abstractmethod
from ..default.helpers import logger
from ..default.exceptions import DNSParseError
from ..schemas import DNSRecord
from typing import List, Optional, Tuple, AsyncGenerator, Any

class Database(ABC):
    async def process_record(self, rdns: DNSRecord, excludesubstrings: List[str], expirations: dict) -> bool:
        """Process a DNS record before storing it in the database."""
        for exclude in excludesubstrings:
            if exclude in rdns.rrname:
                logger.debug(f"Excluded {rdns.rrname}")
                return False
        
        expiration = expirations.get(rrset[rdns.rrtype])
        if expiration is not None:
            expiration = int(expiration)
        
        await self.store_record(rdns, expiration=expiration)
        return True

    @abstractmethod
    async def connect(self) -> Any:
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        pass

    @abstractmethod
    async def get_stats(self) -> int:
        pass

    @abstractmethod
    async def get_sensors(self) -> List[Tuple[str, float]]:
        pass

    @abstractmethod
    async def get_timestamps_and_count(self, t1: str, t2: str, rr_values: List[str]) -> Tuple[Optional[int], Optional[int], Optional[int]]:
        pass

    @abstractmethod
    async def get_record(self, t: str, cursor: Optional[str], limit: int, rrtype: Optional[str]) -> Tuple[List[dict], Optional[str], int]:
        pass

    @abstractmethod
    async def store_record(self, record: DNSRecord, expiration: Optional[int] = None) -> None:
        pass

    @abstractmethod
    async def get_associated_records(self, rdata: str) -> List[str]:
        pass

    @abstractmethod
    async def stream_records(self, t: str, chunk_size: int) -> AsyncGenerator[str, None]:
        pass