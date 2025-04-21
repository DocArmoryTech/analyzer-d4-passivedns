from abc import ABC, abstractmethod
import aiofiles
import asyncio
from ..default.helpers import logger
from ..db.manager import DatabaseManager
from pypdns import PDNSRecord


class Ingestor(ABC):
    """Abstract base class for all ingestors.

    Ingestors process data from various sources and store it in the database using
    the provided DatabaseManager.
    """

    def __init__(self, db_manager: DatabaseManager, config: Dict) -> None:
        self.db_manager: DatabaseManager = db_manager
        self.config: Dict = config
        self.running: bool = False

    @abstractmethod
    async def ingest(self) -> None:
        """Asynchronously ingest records and store them using the DatabaseManager."""
        pass

    def stop(self) -> None:
        """Stop the ingestor."""
        self.running = False


class StreamingIngestor(Ingestor, ABC):
    """Base class for ingestors that run continuously with the server.

    Must define a 'type' class variable to identify the ingestor type.
    """
    type: str


class LineIngestor(Ingestor):
    """Base class for ingestors that process files line-by-line.

    Subclasses must implement the `parse_line` method to convert each line into a PDNSRecord.
    """

    def __init__(self, db_manager: DatabaseManager, config: Dict) -> None:
        super().__init__(db_manager, config)
        self.file_path: str = config.get("file_path", "")
        if not self.file_path:
            raise ValueError("Missing required config parameter: file_path")


    async def ingest(self) -> None:
        """Ingest records from the file by reading it line-by-line.

        Each line is parsed using the subclass's `parse_line` method and stored in the database.
        """
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
        """Parse a single line from the file into a PDNSRecord.

        Args:
            line (str): The line to parse.

        Returns:
            PDNSRecord | None: The parsed record, or None if the line is invalid.

        Raises:
            Exception: If parsing fails.
        """
        pass

class FrameIngestor(Ingestor):
    """Base class for ingestors that process framed or binary file data."""
    def __init__(self, db_manager: DatabaseManager, config: Dict) -> None:
        super().__init__(db_manager, config)
        self.file_path: str = config.get("file_path", "")
        if not self.file_path:
            raise ValueError("Missing required config parameter: file_path")

    @abstractmethod
    async def ingest(self) -> None:
        """Ingest records from a framed or binary file."""
        pass