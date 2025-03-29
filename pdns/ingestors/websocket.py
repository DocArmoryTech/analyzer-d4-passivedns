# pdns/ingestors/websocket.py
import asyncio
import websockets
from ..default.helpers import logger
from ..db.manager import DatabaseManager
from pypdns import PDNSRecord  # Import PDNSRecord from pypdns
from .base import Ingestor
import json

class WebSocketIngestor(Ingestor):
    def __init__(self, db_manager: DatabaseManager, ws_url: str):
        super().__init__(db_manager)
        self.ws_url = ws_url

    async def ingest(self) -> None:
        self.running = True
        logger.info({"event": "ingestor_start", "url": self.ws_url})
        
        try:
            async with websockets.connect(self.ws_url) as websocket:
                while self.running:
                    try:
                        message = await websocket.recv()
                        data = json.loads(message)
                        # Ensure rdata is a list if provided as a string
                        if "rdata" in data and isinstance(data["rdata"], str):
                            data["rdata"] = [data["rdata"]]
                        rdns = PDNSRecord(**data)  # PDNSRecord takes a dict
                        await self.db_manager.store_record(rdns)
                        logger.debug({"event": "ingest_record", "record": rdns.raw})  # Use .raw for logging
                    except (json.JSONDecodeError, ValueError) as e:
                        logger.debug({"event": "ingest_error", "error": str(e), "message": message})
                    await asyncio.sleep(0)
        except websockets.ConnectionClosed:
            logger.info({"event": "ingestor_stop", "reason": "WebSocket connection closed"})
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
            self.running = False