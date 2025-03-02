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

from fastapi import FastAPI, HTTPException, Query, Response, Depends, Request
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2AuthorizationCodeBearer
from pydantic import BaseModel
from typing import List, Optional, AsyncGenerator, Union, Tuple
import uvicorn
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import iptools
import redis.asyncio as redis
import json
import os
from datetime import datetime

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
    description="A Passive DNS server compliant with Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof). Use `cursor` and `limit` for results > 200.",
    version="1.0.0",
    contact={"name": "CIRCL", "url": "https://www.circl.lu", "email": "info@circl.lu"},
    license_info={"name": "GNU Affero General Public License v3", "url": "https://www.gnu.org/licenses/agpl-3.0.html"}
)

# Structured logging setup with JSON output
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("pdns-cof-fastapi.log")
    ]
)
logger = logging.getLogger(__name__)

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": record.msg if isinstance(record.msg, str) else json.dumps(record.msg)
        }
        return json.dumps(log_entry)

for handler in logger.handlers:
    handler.setFormatter(JSONFormatter())

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)

# Authentication setup
TOKEN_FILE = os.getenv("AUTH_TOKEN_FILE", os.path.join(os.path.dirname(__file__), ".tokens.json"))
VALID_TOKENS = []
AUTH_MODE = os.getenv("AUTH_MODE", "none").lower()  # Default to "none"

def load_bearer_tokens():
    global VALID_TOKENS
    try:
        with open(TOKEN_FILE, "r") as f:
            data = json.load(f)
        now = datetime.utcnow().isoformat() + "Z"
        VALID_TOKENS = [t["value"] for t in data["tokens"] if "expires" not in t or t["expires"] > now]
        logger.info({"event": "tokens_loaded", "file": TOKEN_FILE, "count": len(VALID_TOKENS)})
    except Exception as e:
        raise RuntimeError(f"Failed to load token file {TOKEN_FILE}: {str(e)}")

# Load tokens only if bearer mode is enabled
if AUTH_MODE == "bearer":
    if not os.path.exists(TOKEN_FILE):
        raise RuntimeError(f"Bearer authentication requires token file {TOKEN_FILE}")
    load_bearer_tokens()
elif AUTH_MODE == "none":
    logger.info({"event": "authentication_disabled", "message": "No authentication required by default"})
elif AUTH_MODE == "openid":
    logger.info({"event": "openid_placeholder", "message": "OpenID Connect not yet implemented"})
else:
    raise ValueError(f"Invalid AUTH_MODE: {AUTH_MODE}. Use 'none', 'bearer', or 'openid'")

class TokenFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == TOKEN_FILE and AUTH_MODE == "bearer":
            load_bearer_tokens()

observer = Observer()
observer.schedule(TokenFileHandler(), os.path.dirname(TOKEN_FILE), recursive=False)
observer.start()

# Authentication dependencies
security_bearer = HTTPBearer(auto_error=False)
security_openid = OAuth2AuthorizationCodeBearer(
    authorizationUrl="placeholder_auth_url",
    tokenUrl="placeholder_token_url",
    auto_error=False
)

def get_auth_dependency():
    if AUTH_MODE == "none":
        async def no_auth():
            logger.debug({"event": "auth_check_skipped", "reason": "No authentication required"})
            return None
        return no_auth
    
    elif AUTH_MODE == "bearer":
        async def bearer_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)):
            if credentials is None or credentials.credentials not in VALID_TOKENS:
                raise HTTPException(401, detail="Invalid or missing bearer token", headers={"WWW-Authenticate": "Bearer"})
            logger.info({"event": "authenticated", "token_ending": credentials.credentials[-4:]})
            return credentials
        return bearer_auth
    
    elif AUTH_MODE == "openid":
        async def openid_auth(credentials: Optional[str] = Depends(security_openid)):
            # Placeholder for OIDC validation (to be implemented later)
            logger.warning({"event": "openid_not_implemented", "message": "OpenID Connect support pending"})
            raise HTTPException(501, detail="OpenID Connect not yet implemented")
        return openid_auth

optional_auth = get_auth_dependency()

analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6400))

# Redis async connection pool
redis_pool = redis.ConnectionPool.from_url(f"redis://{analyzer_redis_host}:{analyzer_redis_port}/0")

rrset_supported = ['1', '2', '5', '15', '16', '28', '33', '46']
origin = "origin not configured"

# Pydantic models with examples for Python 3.8 (Pydantic V1)
class DNSRecord(BaseModel):
    rrname: str
    rrtype: str
    rdata: str
    time_first: Union[int, str]
    time_last: Union[int, str]
    count: int
    origin: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "rrname": "example.com",
                "rrtype": "A",
                "rdata": "93.184.216.34",
                "time_first": 1234567890,
                "time_last": 1234567899,
                "count": 100,
                "origin": "origin.example"
            }
        }

class Sensor(BaseModel):
    sensor_id: str
    count: int

class InfoResponse(BaseModel):
    version: str
    software: str
    stats: int
    sensors: List[Sensor]

    class Config:
        json_schema_extra = {
            "example": {
                "version": "git",
                "software": "analyzer-d4-passivedns",
                "stats": 5000,
                "sensors": [{"sensor_id": "sensor1", "count": 3000}]
            }
        }

class MetadataResponse(BaseModel):
    data: List[DNSRecord]
    total: int
    next_cursor: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "data": [{"rrname": "large.com", "rrtype": "A", "rdata": "1.2.3.4", "time_first": 1234567890, "time_last": 1234567899, "count": 100}],
                "total": 300,
                "next_cursor": "100"
            }
        }

async def get_redis():
    client = redis.Redis.from_pool(redis_pool)
    try:
        # Ping Redis to check availability
        await client.ping()
        yield client
    except redis.exceptions.BusyLoadingError as e:
        logger.warning({"event": "redis_busy_loading", "error": str(e), "message": "Redis is loading dataset, temporarily unavailable"})
        raise HTTPException(
            status_code=503,
            detail="Loading dataset... Please try again shortly.",
            headers={"Retry-After": "10"}  # Suggest retrying after 10 seconds
        )
    except redis.ConnectionError as e:
        logger.error({"event": "redis_unavailable", "error": str(e), "message": "Redis service not available"})
        raise HTTPException(
            status_code=503,
            detail="Redis service is temporarily unavailable. Please try again later.",
            headers={"Retry-After": "5"}
        )
    except Exception as e:
        logger.error({"event": "redis_error", "error": str(e), "message": "Unexpected error connecting to Redis"})
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        await client.aclose()


# Helper functions
async def get_timestamps_and_count(redis_client: redis.Redis, t1: str, t2: str, rr_values: List[str]) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    if not t1 or not t2:
        return None, None, None
    
    keys = [f's:{t1.lower()}:{t2.lower()}:{v}' for v in rr_values] + \
           [f'l:{t1.lower()}:{t2.lower()}:{v}' for v in rr_values] + \
           [f'o:{t1.lower()}:{t2.lower()}:{v}' for v in rr_values]
    
    results = await redis_client.mget(keys)
    time_first = next((int(r.decode()) for r in results[:len(rr_values)] if r), None)
    time_last = next((int(r.decode()) for r in results[len(rr_values):2*len(rr_values)] if r), None)
    count = next((int(r.decode()) for r in results[2*len(rr_values):] if r), None)
    
    return time_first, time_last, count

async def get_record(redis_client: redis.Redis, t: str, cursor: Optional[str] = None, limit: int = 200, rrtype: Optional[str] = None) -> Tuple[List[dict], Optional[str], int]:
    if not t:
        return [], None, 0
    
    rrfound = []
    next_cursor = None
    total_count = 0
    rr_values = [rr['Value'] for rr in rrset if rr['Value'] in rrset_supported and (rrtype is None or rr['Type'] == rrtype.upper())]
    
    for value in rr_values:
        rec = f'r:{t}:{value}'
        setsize = await redis_client.scard(rec)
        total_count += setsize
        
        if cursor is None:
            rs = await redis_client.smembers(rec)
        else:
            effective_cursor = cursor if cursor else "0"
            if setsize < 200:
                rs = await redis_client.smembers(rec)
            else:
                scan_result = await redis_client.sscan(rec, cursor=effective_cursor, count=limit)
                rs, next_cursor = scan_result[1], str(scan_result[0]) if scan_result[0] != 0 else None
        
        if rs:
            for v in rs:
                rdata = v.decode('utf-8').strip()
                time_first, time_last, count = await get_timestamps_and_count(redis_client, t, rdata, rr_values)
                if time_first is None:
                    continue
                rrval = {
                    "time_first": time_first,
                    "time_last": time_last,
                    "count": count,
                    "rrtype": next(rr['Type'] for rr in rrset if rr['Value'] == value),
                    "rrname": t,
                    "rdata": rdata,
                    "origin": origin if origin else None
                }
                rrfound.append(rrval)
    
    return rrfound, next_cursor, total_count

async def get_associated_records(redis_client: redis.Redis, rdata: str) -> List[str]:
    if not rdata:
        return []
    rec = f'v:{rdata.lower()}'
    records = []
    for rr in rrset:
        if rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            rs = await redis_client.smembers(qrec)
            if rs:
                records.extend(v.decode('utf-8') for v in rs)
    return records

async def stream_records(redis_client: redis.Redis, t: str, chunk_size: int) -> AsyncGenerator[str, None]:
    if not t:
        return
    for rr in rrset:
        if rr['Value'] in rrset_supported:
            rec = f'r:{t}:{rr["Value"]}'
            setsize = await redis_client.scard(rec)
            if setsize < 200:
                rs = await redis_client.smembers(rec)
                for v in rs:
                    rdata = v.decode('utf-8').strip()
                    time_first, time_last, count = await get_timestamps_and_count(redis_client, t, rdata, [rr['Value']])
                    if time_first is None:
                        continue
                    record = {
                        "time_first": time_first,
                        "time_last": time_last,
                        "count": count,
                        "rrtype": rr['Type'],
                        "rrname": t,
                        "rdata": rdata,
                        "origin": origin if origin else None
                    }
                    yield f"{json.dumps(record)}\n"
            else:
                cursor = "0"
                while cursor != "0":
                    scan_result = await redis_client.sscan(rec, cursor=cursor, count=chunk_size)
                    cursor = str(scan_result[0])
                    rs = scan_result[1]
                    for v in rs:
                        rdata = v.decode('utf-8').strip()
                        time_first, time_last, count = await get_timestamps_and_count(redis_client, t, rdata, [rr['Value']])
                        if time_first is None:
                            continue
                        record = {
                            "time_first": time_first,
                            "time_last": time_last,
                            "count": count,
                            "rrtype": rr['Type'],
                            "rrname": t,
                            "rdata": rdata,
                            "origin": origin if origin else None
                        }
                        yield f"{json.dumps(record)}\n"

def format_record(record: dict, time_format: str) -> dict:
    if time_format == "iso":
        return {
            **record,
            "time_first": datetime.utcfromtimestamp(record["time_first"]).isoformat() + "Z",
            "time_last": datetime.utcfromtimestamp(record["time_last"]).isoformat() + "Z"
        }
    return record

# API Endpoints
@app.get("/info", response_model=InfoResponse)
@limiter.limit("100/minute")
async def get_info(request: Request, redis_client: redis.Redis = Depends(get_redis), auth: None = Depends(optional_auth)):
    stats = int(await redis_client.get("stats:processed") or 0)
    sensors = await redis_client.zrevrange('stats:sensors', 0, -1, withscores=True)
    rsensors = [{"sensor_id": x[0].decode(), "count": int(float(x[1]))} for x in sensors]
    response = {"version": "git", "software": "analyzer-d4-passivedns", "stats": stats, "sensors": rsensors}
    logger.info({"endpoint": "/info", "client_ip": get_remote_address(request), "status": 200})
    return response


@app.get("/query/{q}")
@limiter.limit("50/minute")
async def query(
    request: Request,
    q: str,
    cursor: Optional[str] = Query(default=None, description="Cursor for pagination, required if > limit"),
    limit: int = Query(default=200, ge=10, le=1000, description="Max records per page or total without cursor"),
    rrtype: Optional[str] = Query(default=None, description="Filter by RR type (e.g., A, AAAA)"),
    metadata: bool = Query(default=False, description="Wrap results in metadata object"),
    time_format: str = Query(default="unix", pattern="^(unix|iso)$", description="Timestamp format: unix (int) or iso (string)"),
    format: str = Query(default="ndjson", pattern="^(ndjson|json)$", description="Response format: ndjson (newline-separated) or json (array/object)"),
    redis_client: redis.Redis = Depends(get_redis),
    auth: None = Depends(optional_auth)
):
    # Validate rrtype if provided
    if rrtype:
        valid_rrtypes = [rr['Type'] for rr in rrset if rr['Value'] in rrset_supported]
        if rrtype.upper() not in valid_rrtypes:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid rrtype: {rrtype}. Supported types: {', '.join(valid_rrtypes)}"
            )
    
    records, next_cursor, total = await get_record(redis_client, q.strip(), cursor, limit, rrtype)
    
    headers = {"X-Total-Count": str(total)}
    if total > limit:
        if cursor is None:
            records = records[:limit]
            headers["X-Next-Cursor"] = str(limit)
            headers["X-Pagination-Required"] = "true"
            logger.warning({"endpoint": "/query", "query": q, "client_ip": get_remote_address(request), "total": total, "limit": limit, "message": "Partial results returned; use cursor for full set"})
        elif next_cursor:
            headers["X-Next-Cursor"] = next_cursor
    
    formatted_records = [format_record(r, time_format) for r in records]
    
    if format == "ndjson":
        # NDJSON response (cof)
        response_content = "\n".join(json.dumps(record) for record in formatted_records) + "\n"
        media_type = "application/x-ndjson"
    else:  # format == "json"
        # True JSON response
        response_content = json.dumps(formatted_records if not metadata else {"data": formatted_records, "total": total, "next_cursor": next_cursor})
        media_type = "application/json"
    
    logger.info({"endpoint": "/query", "query": q, "client_ip": get_remote_address(request), "status": 200, "record_count": len(records)})
    return Response(content=response_content, media_type=media_type, headers=headers)


@app.get("/fquery/{q}")
@limiter.limit("50/minute")
async def full_query(
    request: Request,
    q: str,
    cursor: Optional[str] = Query(default=None, description="Cursor for pagination, required if > limit"),
    limit: int = Query(default=200, ge=10, le=1000, description="Max records per page or total without cursor"),
    rrtype: Optional[str] = Query(default=None, description="Filter by RR type (e.g., A, AAAA)"),
    metadata: bool = Query(default=False, description="Wrap results in metadata object"),
    time_format: str = Query(default="unix", pattern="^(unix|iso)$", description="Timestamp format: unix (int) or iso (string)"),
    format: str = Query(default="ndjson", pattern="^(ndjson|json)$", description="Response format: ndjson (cof) or json (array/object)"),
    redis_client: redis.Redis = Depends(get_redis),
    auth: None = Depends(optional_auth)
):
    # Validate rrtype if provided
    if rrtype:
        valid_rrtypes = [rr['Type'] for rr in rrset if rr['Value'] in rrset_supported]
        if rrtype.upper() not in valid_rrtypes:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid rrtype: {rrtype}. Supported types: {', '.join(valid_rrtypes)}"
            )
    
    result = []
    total = 0
    next_cursor = None
    
    if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
        associated = await get_associated_records(redis_client, q)
        for x in associated:
            records, nc, tc = await get_record(redis_client, x, cursor, limit, rrtype)
            result.extend(records)
            total += tc
            if (cursor is not None or total > limit) and nc:
                next_cursor = nc
                break
    else:
        associated = await get_associated_records(redis_client, q)
        for x in associated:
            records, nc, tc = await get_record(redis_client, x.strip(), cursor, limit, rrtype)
            result.extend(records)
            total += tc
            if (cursor is not None or total > limit) and nc:
                next_cursor = nc
                break
    
    headers = {"X-Total-Count": str(total)}
    if total > limit:
        if cursor is None:
            result = result[:limit]
            headers["X-Next-Cursor"] = str(limit)
            headers["X-Pagination-Required"] = "true"
            logger.warning({"endpoint": "/fquery", "query": q, "client_ip": get_remote_address(request), "total": total, "limit": limit, "message": "Partial results returned; use cursor for full set"})
        elif next_cursor:
            headers["X-Next-Cursor"] = next_cursor
    
    formatted_records = [format_record(r, time_format) for r in result]
    
    if format == "ndjson":
        # NDJSON response (cof)
        response_content = "\n".join(json.dumps(record) for record in formatted_records) + "\n"
        media_type = "application/x-ndjson"
    else:  # format == "json"
        # True JSON response
        response_content = json.dumps(formatted_records if not metadata else {"data": formatted_records, "total": total, "next_cursor": next_cursor})
        media_type = "application/json"
    
    logger.info({"endpoint": "/fquery", "query": q, "client_ip": get_remote_address(request), "status": 200, "record_count": len(result)})
    return Response(content=response_content, media_type=media_type, headers=headers)

@app.get("/stream/{q}")
@limiter.limit("20/minute")
async def stream(
    request: Request,
    q: str,
    chunk_size: int = Query(default=100, ge=10, le=1000, description="Number of records per chunk"),
    rrtype: Optional[str] = Query(default=None, description="Filter by RR type (e.g., A, AAAA)"),
    time_format: str = Query(default="unix", pattern="^(unix|iso)$", description="Timestamp format: unix (int) or iso (string)"),
    redis_client: redis.Redis = Depends(get_redis),
    auth: None = Depends(optional_auth)
):
    # Validate rrtype if provided
    if rrtype:
        valid_rrtypes = [rr['Type'] for rr in rrset if rr['Value'] in rrset_supported]
        if rrtype.upper() not in valid_rrtypes:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid rrtype: {rrtype}. Supported types: {', '.join(valid_rrtypes)}"
            )
    
    async def event_stream():
        try:
            if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
                associated = await get_associated_records(redis_client, q)
                if not associated:
                    yield "[]\n"
                    return
                for x in associated:
                    async for record in stream_records(redis_client, x, chunk_size):
                        parsed = json.loads(record.strip())
                        yield f"{json.dumps(format_record(parsed, time_format))}\n"
            else:
                found = False
                async for record in stream_records(redis_client, q.strip(), chunk_size):
                    parsed = json.loads(record.strip())
                    if rrtype is None or parsed["rrtype"] == rrtype.upper():
                        found = True
                        yield f"{json.dumps(format_record(parsed, time_format))}\n"
                if not found:
                    yield "[]\n"
        except redis.RedisError as e:
            logger.error({"endpoint": "/stream", "query": q, "client_ip": get_remote_address(request), "error": str(e)})
            yield f"{json.dumps({'error': f'Redis error: {str(e)}'})}\n"
    
    logger.info({"endpoint": "/stream", "query": q, "client_ip": get_remote_address(request), "status": 200})
    return StreamingResponse(event_stream(), media_type="application/x-ndjson")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8400)
