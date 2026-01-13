# pdns/notifiers/filters/dnsbl.py
from .base import NotificationFilter
from pypdns import PDNSRecord
import dns.asyncresolver
from functools import lru_cache
from ...default.helpers import logger


class DNSBLFilter(NotificationFilter):
    """Filter based on DNS Blacklist (DNSBL) lookup for IP addresses in rdata."""

    type = 'dnsbl'

    def __init__(self, dnsbl_domain: str, cache_size: int = 1000):
        """Initialize with a DNSBL domain and optional cache size.

        Args:
            dnsbl_domain (str): The DNSBL domain (e.g., 'zen.spamhaus.org').
            cache_size (int): Maximum number of IPs to cache (default: 1000).
        """
        self.dnsbl_domain = dnsbl_domain
        self._check_dnsbl = lru_cache(maxsize=cache_size)(self._check_dnsbl)

    async def _check_dnsbl(self, ip: str) -> bool:
        """Check if an IP is listed in the DNSBL asynchronously.

        Args:
            ip (str): The IP address to check.

        Returns:
            bool: True if listed, False otherwise.
        """
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            query = f"{reversed_ip}.{self.dnsbl_domain}"
            await dns.asyncresolver.resolve(query, "A")
            logger.debug({"event": "dnsbl_hit", "ip": ip, "domain": self.dnsbl_domain})
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return False
        except Exception as e:
            logger.error({"event": "dnsbl_error", "ip": ip, "error": str(e)})
            return False

    async def evaluate(self, record: PDNSRecord) -> bool:
        """Evaluate if the record's rdata IP is listed in the DNSBL.

        Args:
            record (PDNSRecord): The DNS record to check.

        Returns:
            bool: True if the IP is blacklisted, False otherwise.
        """
        rdata = record.rdata[0] if isinstance(record.rdata, list) else record.rdata
        try:
            # Basic IP validation
            parts = rdata.split(".")
            if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                return False
            return await self._check_dnsbl(rdata)
        except (ValueError, AttributeError):
            logger.debug({"event": "dnsbl_invalid_ip", "rdata": rdata})
            return False