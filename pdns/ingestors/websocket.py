import asyncio
import websockets
import json
from ..default.helpers import logger
from ..db.manager import DatabaseManager
from pypdns import PDNSRecord
from .base import DaemonIngestor


class WebSocketIngestor(DaemonIngestor):
    """Ingestor for real-time DNS records via WebSocket.

    Connects to a WebSocket URL and processes incoming JSON messages into PDNSRecords.
    """

    type = "websocket"  # Identifier for this ingestor type

    def __init__(self, db_manager: DatabaseManager, ws_url: str) -> None:
        super().__init__(db_manager)
        self.ws_url: str = ws_url

    async def ingest(self) -> None:
        """Continuously ingest records from the WebSocket connection.

        Reconnects with exponential backoff on failure.
        """
        self.running = True
        logger.info({"event": "ingestor_start", "url": self.ws_url})
        retry_delay = 1  # Start with 1 second
        max_retry_delay = 60  # Cap at 1 minute
        while self.running:
            try:
                async with websockets.connect(self.ws_url) as websocket:
                    retry_delay = 1  # Reset on success
                    while self.running:
                        try:
                            message = await websocket.recv()
                            data = json.loads(message)
                            if "rdata" in data and isinstance(data["rdata"], str):
                                data["rdata"] = [data["rdata"]]
                            rdns = PDNSRecord(**data)
                            await self.db_manager.store_record(rdns)
                            logger.debug({"event": "ingest_record", "record": rdns.raw})
                        except (json.JSONDecodeError, ValueError) as e:
                            logger.debug({"event": "ingest_error", "error": str(e), "message": message})
                        except websockets.ConnectionClosed:
                            logger.info({"event": "websocket_connection_closed", "url": self.ws_url})
                            break
                        await asyncio.sleep(0)
            except Exception as e:
                logger.error({"event": "ingest_error", "error": str(e)})
                if not self.running:
                    break
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)
        logger.info({"event": "ingestor_complete", "url": self.ws_url})