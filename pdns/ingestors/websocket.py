# pdns/ingestors/websocket.py
import asyncio
import websockets
from ..default.helpers import logger
from ..db.base import Database
from ..schemas import DNSRecord
from .base import Ingestor
import json

class WebSocketIngestor(Ingestor):
    def __init__(self, db: Database, ws_url: str):
        super().__init__(db)
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
                        if "rdata" in data and isinstance(data["rdata"], str):
                            data["rdata"] = [data["rdata"]]
                        rdns = DNSRecord(**data)
                        await self.db.store_record(rdns)  # Updated call
                        logger.debug({"event": "ingest_record", "record": rdns.dict()})
                    except (json.JSONDecodeError, ValueError) as e:
                        logger.debug({"event": "ingest_error", "error": str(e), "message": message})
                    await asyncio.sleep(0)
        except websockets.ConnectionClosed:
            logger.info({"event": "ingestor_stop", "reason": "WebSocket connection closed"})
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
            self.running = False