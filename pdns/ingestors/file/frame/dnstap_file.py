import asyncio
import struct
from ...default.helpers import logger
from ...db.manager import DatabaseManager
from ...ingestors.base import FrameIngestor
from ...ingestors.common.frame_parser import parse_dnstap_message

class DNSTapFileIngestor(FrameIngestor):
    """Ingestor for DNSTap files containing framed binary data."""
    type = "file_dnstap"

    async def ingest(self) -> None:
        """Ingest DNSTap records from a file by reading framed messages."""
        self.running = True
        logger.info({"event": "ingestor_start", "file": self.file_path})
        try:
            with open(self.file_path, "rb") as f:
                while self.running:
                    length_bytes = f.read(4)
                    if not length_bytes or len(length_bytes) < 4:
                        break
                    frame_length = struct.unpack(">I", length_bytes)[0]
                    frame_data = f.read(frame_length)
                    if len(frame_data) < frame_length:
                        break
                    records = await parse_dnstap_message(frame_data)
                    for rdns in records:
                        await self.db_manager.store_record(rdns)
                        logger.debug({"event": "ingest_record", "record": rdns.raw})
                    await asyncio.sleep(0)
            logger.info({"event": "ingestor_complete", "file": self.file_path})
        except Exception as e:
            logger.error({"event": "ingest_error", "error": str(e)})
        finally:
            self.running = False