# pdns/ingestors/json_file.py
import asyncio
from ..default.helpers import logger
from ..db.manager import DatabaseManager
from pypdns import PDNSRecord  # Import PDNSRecord from pypdns
from .base import Ingestor
import json

class JSONFileIngestor(Ingestor):
    def __init__(self, db_manager: DatabaseManager, file_path: str):
        super().__init__(db_manager)
        self.file_path = file_path

    async def ingest(self) -> None:
        self.running = True
        logger.info({"event": "ingestor_start", "file": self.file_path})
        
        try:
            with open(self.file_path, "r") as f:
                data = json.load(f)
                if not isinstance(data, list):
                    logger.error({"event": "ingest_error", "error": "JSON file must contain a list of records"})
                    return
                for item in data:
                    if not self.running:
                        break
                    try:
                        if "rdata" in item and isinstance(item["rdata"], str):
                            item["rdata"] = [item["rdata"]]
                        rdns = PDNSRecord(item)
                        await self.db_manager.store_record(rdns)
                        logger.debug({"event": "ingest_record", "record": rdns.raw})
                    except (ValueError, TypeError) as e:
                        logger.debug({"event": "ingest_error", "error": str(e), "record": item})
                    await asyncio.sleep(0)
        except json.JSONDecodeError as e:
            logger.critical({"event": "ingest_error", "error": f"Invalid JSON in file {self.file_path}: {str(e)}"})
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
            self.running = False