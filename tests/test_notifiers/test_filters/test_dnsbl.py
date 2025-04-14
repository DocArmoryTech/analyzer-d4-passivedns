# tests/test_notifiers/test_filters/test_dnsbl.py
import pytest
from pdns.notifiers.filters.dnsbl import DNSBLFilter
from pypdns import PDNSRecord
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_dnsbl_filter_hit():
    filter = DNSBLFilter("zen.spamhaus.org")
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    with patch("dns.asyncresolver.resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = ["127.0.0.2"]
        assert await filter.evaluate(record) is True
        assert mock_resolve.called

@pytest.mark.asyncio
async def test_dnsbl_filter_miss():
    filter = DNSBLFilter("zen.spamhaus.org")
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    with patch("dns.asyncresolver.resolve", side_effect=dns.resolver.NXDOMAIN):
        assert await filter.evaluate(record) is False

@pytest.mark.asyncio
async def test_dnsbl_filter_invalid_ip():
    filter = DNSBLFilter("zen.spamhaus.org")
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["invalid"])
    assert await filter.evaluate(record) is False

@pytest.mark.asyncio
async def test_dnsbl_filter_cache():
    filter = DNSBLFilter("zen.spamhaus.org", cache_size=1)
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    with patch("dns.asyncresolver.resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = ["127.0.0.2"]
        assert await filter.evaluate(record) is True
        assert await filter.evaluate(record) is True
        assert mock_resolve.call_count == 1  # Cached