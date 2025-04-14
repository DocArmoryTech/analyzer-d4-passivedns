# tests/test_notifiers/test_filters/test_composite.py
import pytest
from pdns.notifiers.filters.composite import CompositeFilter
from pdns.notifiers.filters.string import StringFilter
from pdns.notifiers.filters.dnsbl import DNSBLFilter
from pypdns import PDNSRecord

def test_composite_filter_and():
    filter = CompositeFilter(
        filters=[
            StringFilter({"rrtype": "A"}),
            StringFilter({"rrname": "example.com"})
        ],
        operator="and"
    )
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    assert filter.evaluate(record) is True
    record2 = PDNSRecord(rrtype="A", rrname="test.com", rdata=["1.2.3.4"])
    assert filter.evaluate(record2) is False

def test_composite_filter_or():
    filter = CompositeFilter(
        filters=[
            StringFilter({"rrtype": "A"}),
            StringFilter({"rrtype": "MX"})
        ],
        operator="or"
    )
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    assert filter.evaluate(record) is True
    record2 = PDNSRecord(rrtype="TXT", rrname="example.com", rdata=["text"])
    assert filter.evaluate(record2) is False

def test_composite_filter_not():
    filter = CompositeFilter(
        filters=[StringFilter({"rrtype": "A"})],
        operator="not"
    )
    record = PDNSRecord(rrtype="MX", rrname="example.com", rdata=["1.2.3.4"])
    assert filter.evaluate(record) is True
    record2 = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    assert filter.evaluate(record2) is False

def test_composite_filter_nested():
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
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    assert filter.evaluate(record) is True
    record2 = PDNSRecord(rrtype="TXT", rrname="example.com", rdata=["text"])
    assert filter.evaluate(record2) is True
    record3 = PDNSRecord(rrtype="MX", rrname="example.com", rdata=["1.2.3.4"])
    assert filter.evaluate(record3) is False

def test_composite_filter_invalid_operator():
    with pytest.raises(ValueError):
        CompositeFilter(filters=[StringFilter({"rrtype": "A"})], operator="invalid")

def test_composite_filter_not_multiple_filters():
    with pytest.raises(ValueError):
        CompositeFilter(
            filters=[StringFilter({"rrtype": "A"}), StringFilter({"rrtype": "MX"})],
            operator="not"
        )