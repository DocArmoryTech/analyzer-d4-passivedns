import json
from ...base import LineIngestor
from pypdns import PDNSRecord


class ZeekIngestor(LineIngestor):
    """Ingestor for Zeek DNS log files.

    Each line is a JSON object representing a Zeek DNS log entry.
    """

    type="zeek"
    
    async def parse_line(self, line: str) -> PDNSRecord | None:
        """Parse a Zeek DNS log line (JSON) into a PDNSRecord.

        Args:
            line (str): The JSON line to parse.

        Returns:
            PDNSRecord | None: The parsed record, or None if invalid.

        Raises:
            Exception: If JSON decoding or mapping fails.
        """
        try:
            data = json.loads(line)
            return self._map_zeek_to_pdns(data)
        except (json.JSONDecodeError, ValueError) as e:
            raise Exception(f"Failed to parse Zeek line: {e}")

    def _map_zeek_to_pdns(self, data: dict) -> PDNSRecord | None:
        """Map Zeek DNS log entry to PDNSRecord.

        Args:
            data (dict): The parsed JSON data from the Zeek log.

        Returns:
            PDNSRecord | None: The mapped record, or None if mapping fails.
        """
        try:
            if "query" not in data or data.get("answers", []) == []:
                return None
            timestamp = int(float(data["ts"]))
            rdata = data.get("answers", [])
            if isinstance(rdata, str):
                rdata = [rdata]
            return PDNSRecord(
                rrname=data["query"],
                rrtype=data["qtype_name"],
                rdata=rdata,
                time_first=timestamp,
                time_last=timestamp,
                count=1,
            )
        except (KeyError, ValueError, TypeError) as e:
            raise ValueError(f"Failed to map Zeek DNS entry to PDNSRecord: {str(e)}")