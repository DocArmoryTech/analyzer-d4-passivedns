# tests/test_notifiers/test_filters/test_performance.py
import pytest
from pdns.notifiers.filters.composite import CompositeFilter
from pdns.notifiers.filters.string import StringFilter
from pypdns import PDNSRecord
import time

@pytest.mark.asyncio
async def test_filter_performance():
    filter = CompositeFilter(
        filters=[
            CompositeFilter(
                filters=[
                    StringFilter({"rrtype": "A"}),
                    StringFilter({"rrname": "example.com"})
                ],
                operator="and"
            ),
            CompositeFilter(
                filters=[StringFilter({"rrtype": "MX"})],
                operator="not"
            )
        ],
        operator="or"
    )
    records = [
        PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
        for _ in range(1000)
    ]
    start = time.time()
    for record in records:
        filter.evaluate(record)
    duration = time.time() - start
    assert duration < 1.0  # Ensure it processes 1000 records in under 1 second