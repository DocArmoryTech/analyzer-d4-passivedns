# pdns/pdns_ingestion.py
from .default.helpers import logger
from rrtypes import rrset
from .default.exceptions import DNSParseError
from .db.base import Database

async def process_record(db: Database, rdns: dict, dnstype: dict, excludesubstrings: list, expirations: dict, stats: bool = True) -> bool:
    """Process a DNS record and store it in the database."""
    if not rdns or 'rrname' not in rdns:
        logger.debug(f"Parsing of passive DNS line is incomplete: {rdns}")
        return False
    if not rdns['rrname'] or not rdns['rrtype']:
        return False
    if rdns['rrtype'] not in dnstype:
        logger.debug(f"Unknown DNS type '{rdns['rrtype']}' in record: {rdns}")
        return False
    rdns['type'] = dnstype[rdns['rrtype']]
    rdns['v'] = rdns['rdata']
    
    # Check exclusions
    for exclude in excludesubstrings:
        if exclude in rdns['rrname']:
            logger.debug(f"Excluded {rdns['rrname']}")
            return False
    
    # Get expiration
    expiration = expirations.get(rdns['type'])
    if expiration is not None:
        expiration = int(expiration)
    
    # Handle TXT record quotes
    if rdns['type'] == '16':
        rdns['v'] = rdns['v'].replace("\"", "", 1)
    
    # Store using abstract Database (assumes store_record takes care of expiration)
    await db.store_record(rdns)
    
    return True
    
    def format_record(record: dict, time_format: str) -> dict:
        if time_format == "iso":
            return {
                **record,
                "time_first": datetime.utcfromtimestamp(record["time_first"]).isoformat() + "Z",
                "time_last": datetime.utcfromtimestamp(record["time_last"]).isoformat() + "Z"
            }
        return record

    def normalize_domain(domain: str) -> str:
        return domain.strip('.').lower()

