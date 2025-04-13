from abc import abstractmethod
import aiofiles
import asyncio
from ..default.helpers import logger
from .base import Ingestor
from ..db.manager import DatabaseManager
from pypdns import PDNSRecord

class FileIngestor(Ingestor):
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
                        rdns = await self.parse_line(l)
                        if rdns:
                            await self.db_manager.store_record(rdns)
                            logger.debug({"event": "ingest_record", "record": rdns.raw})
                    except Exception as e:
                        logger.debug({"event": "ingest_error", "error": str(e), "line": l})
                    await asyncio.sleep(0)
            logger.info({"event": "ingestor_complete", "file": self.file_path})
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
        finally:
            self.running = False

    @abstractmethod
    async def parse_line(self, line: str) -> PDNSRecord | None:
        """Parse a single line into a PDNSRecord."""
        pass