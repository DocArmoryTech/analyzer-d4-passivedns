from abc import ABC, abstractmethod
from ..db.manager import DatabaseManager


class Ingestor(ABC):
    """Abstract base class for ingestors."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager: DatabaseManager = db_manager
        self.running: bool = False

    @abstractmethod
    async def ingest(self) -> None:
        """Asynchronously ingest records and store them using the provided DatabaseManager."""
        pass

    def stop(self) -> None:
        """Stop the ingestor."""
        self.running = False


class DaemonIngestor(Ingestor, ABC):
    """Base class for ingestors that run continuously with the server."""

    type: str  # Required class variable for daemon ingestors
