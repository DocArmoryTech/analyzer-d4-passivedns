# tests/test_notifiers/test_filters/test_string.py
import pytest
from pdns.notifiers.filters.string import StringFilter
from pypdns import PDNSRecord

def test_string_filter_case_insensitive():
    filter = StringFilter({"rrtype": "A", "rrname": "EXAMPLE.com"})
    record = PDNSRecord(rrtype="a", rrname="example.com", rdata=["1.2.3.4"])
    assert filter.evaluate(record) is True

def test_string_filter_no_match():
    filter = StringFilter({"rrtype": "A"})
    record = PDNSRecord(rrtype="MX", rrname="example.com", rdata=["1.2.3.4"])
    assert filter.evaluate(record) is False

def test_string_filter_empty_condition():
    filter = StringFilter({})
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    assert filter.evaluate(record) is True

def test_string_filter_missing_attribute():
    filter = StringFilter({"invalid_key": "value"})
    record = PDNSRecord(rrtype="A", rrname="example.com", rdata=["1.2.3.4"])
    assert filter.evaluate(record) is False