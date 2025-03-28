from .base import NotificationFilter
from pypdns import PDNSRecord
import dns.resolver
import asyncio

class DNSBLFilter(NotificationFilter):
    """Filter based on DNSBL (DNS Blacklist) lookup."""
    def __init__(self, dnsbl_domain: str):
        self.dnsbl_domain = dnsbl_domain

    async def _check_dnsbl(self, ip: str) -> bool:
        try:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            query = f"{reversed_ip}.{self.dnsbl_domain}"
            await dns.resolver.resolve(query, 'A')
            return True  # Listed in DNSBL
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False  # Not listed
        except Exception as e:
            # Log error if needed
            return False

    def evaluate(self, record: PDNSRecord) -> bool:
        # Assuming rdata contains an IP for DNSBL checking
        rdata = record.rdata[0] if isinstance(record.rdata, list) else record.rdata
        try:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(self._check_dnsbl(rdata))
        except ValueError:
            return False