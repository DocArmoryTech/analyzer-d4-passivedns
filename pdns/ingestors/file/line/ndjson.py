import json
from ...base import LineIngestor
from pypdns import PDNSRecord


class NDJSONFileIngestor(LineIngestor):
    """Ingestor for newline-delimited JSON (NDJSON) files.

    Each line is expected to be a JSON object representing a DNS record.
    """

    type="ndjson"

    async def parse_line(self, line: str) -> PDNSRecord | None:
        """Parse a newline-delimited JSON line into a PDNSRecord.

        Args:
            line (str): The JSON line to parse.

        Returns:
            PDNSRecord | None: The parsed record, or None if invalid.

        Raises:
            Exception: If JSON decoding or record creation fails.
        """
        try:
            data = json.loads(line)
            if "rdata" in data and isinstance(data["rdata"], str):
                data["rdata"] = [data["rdata"]]
            return PDNSRecord(**data)
        except (json.JSONDecodeError, ValueError) as e:
            raise Exception(f"Failed to parse NDJSON line: {e}")