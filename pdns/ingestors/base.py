# pdns/ingestors/base.py
from abc import ABC, abstractmethod
from ..db.base import Database

class Ingestor(ABC):
    """Abstract base class for ingestors."""

    def __init__(self, db: Database):
        self.db = db
        self.running = False

    @abstractmethod
    async def ingest(self) -> None:
        """Ingest records into the database."""
        pass

    def stop(self) -> None:
        """Stop the ingestor."""
        self.running = False