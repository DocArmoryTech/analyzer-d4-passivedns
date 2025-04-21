from .base import LineIngestor
from .utils import parse_line
from pypdns import PDNSRecord


class PDNSIngestor(LineIngestor):
    """Ingestor for passivedns-formatted files.

    Each line is parsed using `parse_line` from `utils.py`.
    """

    type="pdns"
    
    async def parse_line(self, line: str) -> PDNSRecord | None:
        """Parse a passivedns-formatted line into a PDNSRecord.

        Args:
            line (str): The line to parse.

        Returns:
            PDNSRecord | None: The parsed record, or None if invalid.
        """
        return parse_line(line)