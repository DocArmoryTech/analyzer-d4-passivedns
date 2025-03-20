# pdns/ingestors/ndjson_file.py
import asyncio
import json
from ..default.helpers import logger
from ..databases.base import Database
from ..schemas import DNSRecord
from .base import Ingestor

class NDJSONFileIngestor(Ingestor):
    def __init__(self, db: Database, file_path: str, dnstype: dict, excludesubstrings: list, expirations: dict):
        super().__init__(db)
        self.file_path = file_path
        self.dnstype = dnstype
        self.excludesubstrings = excludesubstrings
        self.expirations = expirations

    async def ingest(self) -> None:
        self.running = True
        logger.info({"event": "ingestor_start", "file": self.file_path})
        
        try:
            with open(self.file_path, "r") as f:
                for line in f:
                    if not self.running:
                        break
                    l = line.strip()
                    if not l:
                        continue
                    try:
                        data = json.loads(l)
                        rdns = DNSRecord(**data)  # Validates rrtype here
                        await self.db.process_record(rdns, self.dnstype, self.excludesubstrings, self.expirations)
                        logger.debug({"event": "ingest_record", "record": rdns.dict()})
                    except (json.JSONDecodeError, ValueError) as e:
                        logger.debug({"event": "ingest_error", "error": str(e), "line": l})
                    await asyncio.sleep(0)
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})