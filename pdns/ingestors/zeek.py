# pdns/ingestors/zeek_dns.py
import aiofiles
import asyncio
import json
from ..default.helpers import logger
from ..db.manager import DatabaseManager
from pypdns import PDNSRecord
from .base import Ingestor

class ZeekDNSIngestor(Ingestor):
    def __init__(self, db_manager: DatabaseManager, file_path: str) -> None:
        super().__init__(db_manager)
        self.file_path: str = file_path

    async def ingest(self) -> None:
        self.running = True
        logger.info({"event": "ingestor_start", "file": self.file_path})
        
        try:
            async with aiofiles.open(self.file_path, "r") as f:
                async for line in f:
                    if not self.running:
                        break
                    l = line.strip()
                    if not l:
                        continue
                    try:
                        data = json.loads(l)
                        rdns = self._map_zeek_to_pdns(data)
                        if rdns:
                            await self.db_manager.store_record(rdns)
                            logger.debug({"event": "ingest_record", "record": rdns.raw})
                    except (json.JSONDecodeError, ValueError) as e:
                        logger.debug({"event": "ingest_error", "error": str(e), "line": l})
                    await asyncio.sleep(0)
            logger.info({"event": "ingestor_complete", "file": self.file_path})
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
        finally:
            self.running = False

    def _map_zeek_to_pdns(self, data: dict) -> PDNSRecord | None:
        """Map Zeek DNS log entry to PDNSRecord."""
        try:
            # Skip if no query or answers are missing/invalid
            if "query" not in data or data.get("answers", []) == []:
                return None
            
            timestamp = int(float(data["ts"]))  # Convert float timestamp to int
            rdata = data.get("answers", [])
            if isinstance(rdata, str):  # Handle rare case of single string
                rdata = [rdata]
            
            return PDNSRecord(
                rrname=data["query"],
                rrtype=data["qtype_name"],
                rdata=rdata,
                time_first=timestamp,
                time_last=timestamp,
                count=1  # Zeek logs each event once
            )
        except (KeyError, ValueError, TypeError) as e:
            raise ValueError(f"Failed to map Zeek DNS entry to PDNSRecord: {str(e)}")