# pdns/ingestors/json_file.py
import json
from ..default.helpers import logger
from ..databases.base import Database
from ..schemas import DNSRecord
from .base import Ingestor

class JSONFileIngestor(Ingestor):
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
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        if not self.running:
                            break
                        try:
                            rdns = DNSRecord(**item)
                            await self.db.process_record(rdns, self.dnstype, self.excludesubstrings, self.expirations)
                            logger.debug({"event": "ingest_record", "record": rdns.dict()})
                        except Exception as e:
                            logger.debug({"event": "ingest_error", "error": str(e), "record": item})
                else:
                    logger.error({"event": "ingest_error", "error": "JSON file must contain a list of records"})
        except json.JSONDecodeError as e:
            logger.critical({"event": "ingest_error", "error": f"Invalid JSON in file {self.file_path}: {str(e)}"})
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})