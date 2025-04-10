import asyncio
import json
import aiofiles
from ..default.helpers import logger
from ..db.manager import DatabaseManager
from pypdns import PDNSRecord
from .base import Ingestor


class JSONFileIngestor(Ingestor):
    def __init__(self, db_manager: DatabaseManager, file_path: str) -> None:
        super().__init__(db_manager)
        self.file_path: str = file_path

    async def ingest(self) -> None:
        self.running = True
        logger.info({"event": "ingestor_start", "file": self.file_path})

        try:
            async with aiofiles.open(self.file_path, "r") as f:
                content = await f.read()
                data = json.loads(content)
                if not isinstance(data, list):
                    logger.error(
                        {
                            "event": "ingest_error",
                            "error": "JSON file must contain a list of records",
                        }
                    )
                    return
                for entry in data:
                    if not self.running:
                        break
                    try:
                        if "rdata" in entry and isinstance(entry["rdata"], str):
                            entry["rdata"] = [entry["rdata"]]
                        rdns = PDNSRecord(**entry)
                        await self.db_manager.store_record(rdns)
                        logger.debug({"event": "ingest_record", "record": rdns.raw})
                    except (ValueError, TypeError) as e:
                        logger.debug(
                            {"event": "ingest_error", "error": str(e), "record": entry}
                        )
                    await asyncio.sleep(0)
            logger.info({"event": "ingestor_complete", "file": self.file_path})
        except json.JSONDecodeError as e:
            logger.critical(
                {
                    "event": "ingest_error",
                    "error": f"Invalid JSON in file {self.file_path}: {str(e)}",
                }
            )
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
        finally:
            self.running = False
