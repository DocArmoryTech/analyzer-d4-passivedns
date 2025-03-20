# pdns/ingestors/websocket.py
import asyncio
import websockets
from ..default.helpers import logger
from ..databases.base import Database
from ..schemas import DNSRecord
from .base import Ingestor
import json

class WebSocketIngestor(Ingestor):
    def __init__(self, db: Database, ws_url: str, dnstype: dict, excludesubstrings: list, expirations: dict):
        super().__init__(db)
        self.ws_url = ws_url
        self.dnstype = dnstype
        self.excludesubstrings = excludesubstrings
        self.expirations = expirations

    async def ingest(self) -> None:
        self.running = True
        logger.info({"event": "ingestor_start", "url": self.ws_url})
        
        try:
            async with websockets.connect(self.ws_url) as websocket:
                while self.running:
                    try:
                        message = await websocket.recv()
                        data = json.loads(message)
                        rdns = DNSRecord(**data)  # Validates rrtype here
                        await self.db.process_record(rdns, self.dnstype, self.excludesubstrings, self.expirations)
                        logger.debug({"event": "ingest_record", "record": rdns.dict()})
                    except (json.JSONDecodeError, ValueError) as e:
                        logger.debug({"event": "ingest_error", "error": str(e), "message": message})
                    await asyncio.sleep(0)
        except websockets.ConnectionClosed:
            logger.info({"event": "ingestor_stop", "reason": "WebSocket connection closed"})
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})