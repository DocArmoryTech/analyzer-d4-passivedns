import asyncio
import websockets
import json
from ..default.helpers import logger
from ..db.manager import DatabaseManager
from pypdns import PDNSRecord
from .base import DaemonIngestor

class WebSocketIngestor(Ingestor):
    type = "websocket"  # Class variable defining the ingestor type

    def __init__(self, db_manager: DatabaseManager, ws_url: str) -> None:
        super().__init__(db_manager)
        self.ws_url: str = ws_url

    async def ingest(self) -> None:
        self.running = True
        logger.info({"event": "ingestor_start", "url": self.ws_url})
        
        while self.running:
            try:
                async with websockets.connect(self.ws_url) as websocket:
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
                await asyncio.sleep(5)  # Wait before retrying
        logger.info({"event": "ingestor_complete", "url": self.ws_url})