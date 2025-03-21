# pdns/ingestors/base.py
from abc import ABC, abstractmethod
from ..db.manager import DatabaseManager

class Ingestor(ABC):
    """Abstract base class for ingestors."""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.running = False

    @abstractmethod
    async def ingest(self) -> None:
        """Ingest records using the DatabaseManager."""
        pass

    def stop(self) -> None:
        """Stop the ingestor."""
        self.running = False