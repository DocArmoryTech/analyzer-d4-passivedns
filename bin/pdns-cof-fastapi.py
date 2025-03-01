#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# A Passive DNS COF compliant passive DNS server for the analyzer-d4-passivedns
#
# The output format is compliant with Passive DNS - Common Output Format
#
# https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof
#
# This software is part of the D4 project.
#
# The software is released under the GNU Affero General Public version 3.
#
# Copyright (c) 2013-2022 Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2019-2022 Computer Incident Response Center Luxembourg (CIRCL)

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import uvicorn
    
import iptools
import redis
import json
import os

rrset = [
    {
        "Reference": "[RFC1035]",
        "Type": "A",
        "Value": "1",
        "Meaning": "a host address",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "NS",
        "Value": "2",
        "Meaning": "an authoritative name server",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MD",
        "Value": "3",
        "Meaning": "a mail destination (OBSOLETE - use MX)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MF",
        "Value": "4",
        "Meaning": "a mail forwarder (OBSOLETE - use MX)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "CNAME",
        "Value": "5",
        "Meaning": "the canonical name for an alias",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "SOA",
        "Value": "6",
        "Meaning": "marks the start of a zone of authority",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MB",
        "Value": "7",
        "Meaning": "a mailbox domain name (EXPERIMENTAL)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MG",
        "Value": "8",
        "Meaning": "a mail group member (EXPERIMENTAL)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MR",
        "Value": "9",
        "Meaning": "a mail rename domain name (EXPERIMENTAL)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "NULL",
        "Value": "10",
        "Meaning": "a null RR (EXPERIMENTAL)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "WKS",
        "Value": "11",
        "Meaning": "a well known service description",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "PTR",
        "Value": "12",
        "Meaning": "a domain name pointer",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "HINFO",
        "Value": "13",
        "Meaning": "host information",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MINFO",
        "Value": "14",
        "Meaning": "mailbox or mail list information",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MX",
        "Value": "15",
        "Meaning": "mail exchange",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "TXT",
        "Value": "16",
        "Meaning": "text strings",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1183]",
        "Type": "RP",
        "Value": "17",
        "Meaning": "for Responsible Person",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1183][RFC5864]",
        "Type": "AFSDB",
        "Value": "18",
        "Meaning": "for AFS Data Base location",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1183]",
        "Type": "X25",
        "Value": "19",
        "Meaning": "for X.25 PSDN address",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1183]",
        "Type": "ISDN",
        "Value": "20",
        "Meaning": "for ISDN address",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1183]",
        "Type": "RT",
        "Value": "21",
        "Meaning": "for Route Through",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1706]",
        "Type": "NSAP",
        "Value": "22",
        "Meaning": "for NSAP address, NSAP style A record",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1348][RFC1637][RFC1706]",
        "Type": "NSAP-PTR",
        "Value": "23",
        "Meaning": "for domain name pointer, NSAP style",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008]",
        "Type": "SIG",
        "Value": "24",
        "Meaning": "for security signature",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110]",
        "Type": "KEY",
        "Value": "25",
        "Meaning": "for security key",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC2163]",
        "Type": "PX",
        "Value": "26",
        "Meaning": "X.400 mail mapping information",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1712]",
        "Type": "GPOS",
        "Value": "27",
        "Meaning": "Geographical Position",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC3596]",
        "Type": "AAAA",
        "Value": "28",
        "Meaning": "IP6 Address",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1876]",
        "Type": "LOC",
        "Value": "29",
        "Meaning": "Location Information",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC3755][RFC2535]",
        "Type": "NXT",
        "Value": "30",
        "Meaning": "Next Domain (OBSOLETE)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]",
        "Type": "EID",
        "Value": "31",
        "Meaning": "Endpoint Identifier",
        "Template": "",
        "Registration Date": "1995-06",
    },
    {
        "Reference": "[1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]",
        "Type": "NIMLOC",
        "Value": "32",
        "Meaning": "Nimrod Locator",
        "Template": "",
        "Registration Date": "1995-06",
    },
    {
        "Reference": "[1][RFC2782]",
        "Type": "SRV",
        "Value": "33",
        "Meaning": "Server Selection",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[\n        ATM Forum Technical Committee, \"ATM Name System, V2.0\", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]",
        "Type": "ATMA",
        "Value": "34",
        "Meaning": "ATM Address",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC2915][RFC2168][RFC3403]",
        "Type": "NAPTR",
        "Value": "35",
        "Meaning": "Naming Authority Pointer",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC2230]",
        "Type": "KX",
        "Value": "36",
        "Meaning": "Key Exchanger",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4398]",
        "Type": "CERT",
        "Value": "37",
        "Meaning": "CERT",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC3226][RFC2874][RFC6563]",
        "Type": "A6",
        "Value": "38",
        "Meaning": "A6 (OBSOLETE - use AAAA)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6672]",
        "Type": "DNAME",
        "Value": "39",
        "Meaning": "DNAME",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink]",
        "Type": "SINK",
        "Value": "40",
        "Meaning": "SINK",
        "Template": "",
        "Registration Date": "1997-11",
    },
    {
        "Reference": "[RFC6891][RFC3225]",
        "Type": "OPT",
        "Value": "41",
        "Meaning": "OPT",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC3123]",
        "Type": "APL",
        "Value": "42",
        "Meaning": "APL",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3658]",
        "Type": "DS",
        "Value": "43",
        "Meaning": "Delegation Signer",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4255]",
        "Type": "SSHFP",
        "Value": "44",
        "Meaning": "SSH Key Fingerprint",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4025]",
        "Type": "IPSECKEY",
        "Value": "45",
        "Meaning": "IPSECKEY",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3755]",
        "Type": "RRSIG",
        "Value": "46",
        "Meaning": "RRSIG",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3755]",
        "Type": "NSEC",
        "Value": "47",
        "Meaning": "NSEC",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3755]",
        "Type": "DNSKEY",
        "Value": "48",
        "Meaning": "DNSKEY",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4701]",
        "Type": "DHCID",
        "Value": "49",
        "Meaning": "DHCID",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC5155]",
        "Type": "NSEC3",
        "Value": "50",
        "Meaning": "NSEC3",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC5155]",
        "Type": "NSEC3PARAM",
        "Value": "51",
        "Meaning": "NSEC3PARAM",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6698]",
        "Type": "TLSA",
        "Value": "52",
        "Meaning": "TLSA",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC5205]",
        "Type": "HIP",
        "Value": "55",
        "Meaning": "Host Identity Protocol",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[Jim_Reid]",
        "Type": "NINFO",
        "Value": "56",
        "Meaning": "NINFO",
        "Template": "NINFO/ninfo-completed-template",
        "Registration Date": "2008-01-21",
    },
    {
        "Reference": "[Jim_Reid]",
        "Type": "RKEY",
        "Value": "57",
        "Meaning": "RKEY",
        "Template": "RKEY/rkey-completed-template",
        "Registration Date": "2008-01-21",
    },
    {
        "Reference": "[Wouter_Wijngaards]",
        "Type": "TALINK",
        "Value": "58",
        "Meaning": "Trust Anchor LINK",
        "Template": "TALINK/talink-completed-template",
        "Registration Date": "2010-02-17",
    },
    {
        "Reference": "[George_Barwood]",
        "Type": "CDS",
        "Value": "59",
        "Meaning": "Child DS",
        "Template": "CDS/cds-completed-template",
        "Registration Date": "2011-06-06",
    },
    {
        "Reference": "[RFC4408]",
        "Type": "SPF",
        "Value": "99",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[IANA-Reserved]",
        "Type": "UINFO",
        "Value": "100",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[IANA-Reserved]",
        "Type": "UID",
        "Value": "101",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[IANA-Reserved]",
        "Type": "GID",
        "Value": "102",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[IANA-Reserved]",
        "Type": "UNSPEC",
        "Value": "103",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6742]",
        "Type": "NID",
        "Value": "104",
        "Meaning": "",
        "Template": "ILNP/nid-completed-template",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6742]",
        "Type": "L32",
        "Value": "105",
        "Meaning": "",
        "Template": "ILNP/l32-completed-template",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6742]",
        "Type": "L64",
        "Value": "106",
        "Meaning": "",
        "Template": "ILNP/l64-completed-template",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6742]",
        "Type": "LP",
        "Value": "107",
        "Meaning": "",
        "Template": "ILNP/lp-completed-template",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC7043]",
        "Type": "EUI48",
        "Value": "108",
        "Meaning": "an EUI-48 address",
        "Template": "EUI48/eui48-completed-template",
        "Registration Date": "2013-03-27",
    },
    {
        "Reference": "[RFC7043]",
        "Type": "EUI64",
        "Value": "109",
        "Meaning": "an EUI-64 address",
        "Template": "EUI64/eui64-completed-template",
        "Registration Date": "2013-03-27",
    },
    {
        "Reference": "[RFC2930]",
        "Type": "TKEY",
        "Value": "249",
        "Meaning": "Transaction Key",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC2845]",
        "Type": "TSIG",
        "Value": "250",
        "Meaning": "Transaction Signature",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1995]",
        "Type": "IXFR",
        "Value": "251",
        "Meaning": "incremental transfer",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035][RFC5936]",
        "Type": "AXFR",
        "Value": "252",
        "Meaning": "transfer of an entire zone",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MAILB",
        "Value": "253",
        "Meaning": "mailbox-related RRs (MB, MG or MR)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MAILA",
        "Value": "254",
        "Meaning": "mail agent RRs (OBSOLETE - see MX)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035][RFC6895]",
        "Type": "*",
        "Value": "255",
        "Meaning": "A request for all records the server/cache has available",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[Patrik_Faltstrom]",
        "Type": "URI",
        "Value": "256",
        "Meaning": "URI",
        "Template": "URI/uri-completed-template",
        "Registration Date": "2011-02-22",
    },
    {
        "Reference": "[RFC6844]",
        "Type": "CAA",
        "Value": "257",
        "Meaning": "Certification Authority Restriction",
        "Template": "CAA/caa-completed-template",
        "Registration Date": "2011-04-07",
    },
    {
        "Reference": "[Sam_Weiler][http://cameo.library.cmu.edu/][\n        Deploying DNSSEC Without a Signed Root.  Technical Report 1999-19,\nInformation Networking Institute, Carnegie Mellon University, April 2004.]",
        "Type": "TA",
        "Value": "32768",
        "Meaning": "DNSSEC Trust Authorities",
        "Template": "",
        "Registration Date": "2005-12-13",
    },
    {
        "Reference": "[RFC4431]",
        "Type": "DLV",
        "Value": "32769",
        "Meaning": "DNSSEC Lookaside Validation",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "",
        "Type": "Reserved",
        "Value": "65535",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
]

app = FastAPI(
    title="Passive DNS Server API",
    description="A Passive DNS server compliant with Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)",
    version="1.0.0",
    contact={"name": "CIRCL", "url": "https://www.circl.lu", "email": "info@circl.lu"},
    license_info={"name": "GNU Affero General Public License v3", "url": "https://www.gnu.org/licenses/agpl-3.0.html"}
)

analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6400))

r = redis.StrictRedis(host=analyzer_redis_host, port=analyzer_redis_port, db=0)

rrset_supported = ['1', '2', '5', '15', '16', '28', '33', '46']
expiring_type = ['16']


origin = "origin not configured"


# Pydantic models for request/response
class DNSRecord(BaseModel):
    rrname: str
    rrtype: str
    rdata: str
    time_first: int
    time_last: int
    count: int
    origin: Optional[str] = None

class Sensor(BaseModel):
    sensor_id: str
    count: int

class InfoResponse(BaseModel):
    version: str
    software: str
    stats: int
    sensors: List[Sensor]


def get_first_seen(t1: str = None, t2: str = None) -> Optional[int]:
    if t1 is None or t2 is None:
        return None
    rec = f's:{t1.lower()}:{t2.lower()}'
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            recget = r.get(qrec)
            if recget is not None:
                return int(recget.decode(encoding='UTF-8'))
    return None

def get_last_seen(t1: str = None, t2: str = None) -> Optional[int]:
    if t1 is None or t2 is None:
        return None
    rec = f'l:{t1.lower()}:{t2.lower()}'
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            recget = r.get(qrec)
            if recget:
                return int(recget.decode(encoding='UTF-8'))
    return None

def get_count(t1: str = None, t2: str = None) -> Optional[int]:
    if not t1 or not t2:
        return None
    rec = f'o:{t1.lower()}:{t2.lower()}'
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            recget = r.get(qrec)
            if recget is not None:
                return int(recget.decode(encoding='UTF-8'))
    return None

def get_record(t: str = None, cursor: Optional[str] = None, count: Optional[int] = None) -> tuple[List[dict], Optional[str]]:
    """
    Retrieve DNS records with optional pagination.
    - If cursor and count are None, fetch all records (original behavior).
    - Otherwise, use SSCAN for large sets and return a page.
    Returns: (records, next_cursor)
    """
    if t is None:
        return False
    rrfound = []
    next_cursor = None
    
    for rr in rrset:
        if rr['Value'] in rrset_supported:
            rec = f'r:{t}:{rr["Value"]}'
            setsize = r.scard(rec)
            
            if cursor is None and count is None:
                # No pagination: fetch all records
                rs = r.smembers(rec)
            else:
                # Pagination: use SSCAN if large, SMEMBERS if small
                effective_cursor = cursor if cursor is not None else "0"
                effective_count = count if count is not None else 200  # Default to 200
                if setsize < 200:
                    rs = r.smembers(rec)
                else:
                    scan_result = r.sscan(rec, cursor=effective_cursor, count=effective_count)
                    rs, next_cursor = scan_result[1], str(scan_result[0]) if scan_result[0] != 0 else None
            
            if rs:
                for v in rs:
                    rdata = v.decode('utf-8').strip()
                    time_first = get_first_seen(t1=t, t2=rdata)
                    if time_first is None:
                        continue
                    rrval = {
                        "time_first": time_first,
                        "time_last": get_last_seen(t1=t, t2=rdata),
                        "count": get_count(t1=t, t2=rdata),
                        "rrtype": rr['Type'],
                        "rrname": t,
                        "rdata": rdata,
                        "origin": origin if origin else None
                    }
                    rrfound.append(rrval)
    
    return rrfound, next_cursor
    
def get_associated_records(rdata: str = None) -> List[str]:
    if rdata is None:
        return []
    rec = f'v:{rdata.lower()}'
    records = []
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            if r.smembers(qrec):
                for v in r.smembers(qrec):
                    records.append(v.decode('utf-8'))
    return records

async def stream_records(t: str = None, chunk_size: int = 100) -> AsyncGenerator[str, None]:
    """Generate DNS records as a stream using SSCAN for large sets."""
    if t is None:
        return
    
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            rec = f'r:{t}:{rr["Value"]}'
            setsize = r.scard(rec)
            
            if setsize < 200:
                # Small sets: fetch all at once
                rs = r.smembers(rec)
                for v in rs:
                    rdata = v.decode(encoding='UTF-8').strip()
                    time_first = get_first_seen(t1=t, t2=rdata)
                    if time_first is None:
                        continue
                    record = {
                        "time_first": time_first,
                        "time_last": get_last_seen(t1=t, t2=rdata),
                        "count": get_count(t1=t, t2=rdata),
                        "rrtype": rr['Type'],
                        "rrname": t,
                        "rdata": rdata,
                        "origin": origin if origin else None
                    }
                    yield f"{json.dumps(record)}\n"
            else:
                # Large sets: use SSCAN to stream incrementally
                cursor = "0"
                while cursor != "0":
                    scan_result = r.sscan(rec, cursor=cursor, count=chunk_size)
                    cursor = str(scan_result[0])
                    rs = scan_result[1]
                    for v in rs:
                        rdata = v.decode('utf-8').strip()
                        time_first = get_first_seen(t1=t, t2=rdata)
                        if time_first is None:
                            continue
                        record = {
                            "time_first": time_first,
                            "time_last": get_last_seen(t1=t, t2=rdata),
                            "count": get_count(t1=t, t2=rdata),
                            "rrtype": rr['Type'],
                            "rrname": t,
                            "rdata": rdata,
                            "origin": origin if origin else None
                        }
                        yield f"{json.dumps(record)}\n"


def rem_duplicate(d: List[dict] = None) -> List[dict]:
    if d is None:
        return []
    outd = [dict(t) for t in set(tuple(o.items()) for o in d)]
    return outd

def json_qof(rrfound: List[dict] = None, remove_duplicate: bool = True) -> str:
    if rrfound is None:
        return ""

    if remove_duplicate:
        rrfound = rem_duplicate(d=rrfound)
    
    return "\n".join(json.dumps(rr) for rr in rrfound)

# API Endpoints
@app.get("/info", response_model=InfoResponse)
async def get_info():
    # [Unchanged]
    pass

@app.get("/query/{q}", response_model=List[DNSRecord])
async def query(
    q: str,
    cursor: Optional[str] = Query(default=None, description="Cursor for pagination, omit for full result"),
    count: Optional[int] = Query(default=None, ge=1, le=1000, description="Number of records per page, defaults to 200 if cursor provided")
):
    print(f'query: {q}, cursor: {cursor}, count: {count}')
    result = []
    effective_count = 200 if cursor is not None and count is None else count
    if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
        for x in get_associated_records(q):
            records, next_cursor = get_record(x, cursor, effective_count)
            result.extend(records)
            if (cursor is not None or effective_count is not None) and next_cursor:
                break
    else:
        records, next_cursor = get_record(t=q.strip(), cursor=cursor, count=effective_count)
        result.extend(records)
    if not result and (cursor is None or cursor == "0"):
        raise HTTPException(status_code=404, detail="No records found")
    headers = {}
    if (cursor is not None or effective_count is not None) and next_cursor:
        headers["X-Next-Cursor"] = next_cursor
    return Response(content=json.dumps(result), media_type="application/json", headers=headers)

@app.get("/fquery/{q}", response_model=List[DNSRecord])
async def full_query(
    q: str,
    cursor: Optional[str] = Query(default=None, description="Cursor for pagination, omit for full result"),
    count: Optional[int] = Query(default=None, ge=1, le=1000, description="Number of records per page, defaults to 200 if cursor provided")
):
    print(f'fquery: {q}, cursor: {cursor}, count: {count}')
    result = []
    effective_count = 200 if cursor is not None and count is None else count
    if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
        for x in get_associated_records(q):
            records, next_cursor = get_record(x, cursor, effective_count)
            result.extend(records)
            if (cursor is not None or effective_count is not None) and next_cursor:
                break
    else:
        for x in get_associated_records(q):
            records, next_cursor = get_record(t=x.strip(), cursor=cursor, count=effective_count)
            result.extend(records)
            if (cursor is not None or effective_count is not None) and next_cursor:
                break
    if not result and (cursor is None or cursor == "0"):
        raise HTTPException(status_code=404, detail="No records found")
    headers = {}
    if (cursor is not None or effective_count is not None) and next_cursor:
        headers["X-Next-Cursor"] = next_cursor
    return Response(content=json.dumps(result), media_type="application/json", headers=headers)

@app.get("/stream/{q}")
async def stream(
    q: str,
    chunk_size: int = Query(default=100, ge=1, le=1000, description="Number of records per chunk")
):
    """Stream Passive DNS records as newline-delimited JSON (NDJSON) for a given resource record name or IP address."""
    print(f'stream query: {q}, chunk_size: {chunk_size}')
    async def event_stream():
        try:
            if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
                associated = get_associated_records(q)
                if not associated:
                    yield "[]\n"
                    return
                for x in associated:
                    async for record in stream_records(x, chunk_size):
                        yield record
            else:
                found = False
                async for record in stream_records(q.strip(), chunk_size):
                    found = True
                    yield record
                if not found:
                    yield "[]\n"
        except redis.RedisError as e:
            yield f"{json.dumps({'error': f'Redis error: {str(e)}'})}\n"
    return StreamingResponse(event_stream(), media_type="application/x-ndjson")

if __name__ == "test":
    qq = ["foo.be", "8.8.8.8"]
    for q in qq:
        if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
            for x in get_associated_records(q):
                records, _ = get_record(x)
                print(json_qof(records))
        else:
            records, _ = get_record(t=q)
            print(json_qof(records))
else:
    uvicorn.run(app, host="0.0.0.0", port=8400)