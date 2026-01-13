"""Package for shared utilities used by ingestor subclasses."""

from .utils import parse_line
from .tap import parse_dnstap_message

__all__ = ["parse_line", "parse_dnstap_message"]