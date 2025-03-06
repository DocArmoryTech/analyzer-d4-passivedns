#!/usr/bin/env python3
#
# pdns-import is a simple import from Passive DNS cof format (in an array)
# and import these back into a Passive DNS backend
#
# This software is part of the D4 project.
#
# The software is released under the GNU Affero General Public version 3.
#
# Copyright (c) 2019 Alexandre Dulaunoy - a@foo.be
# Copyright (c) Computer Incident Response Center Luxembourg (CIRCL)

import argparse
import sys
import json
from .default import load_config, get_config, get_redis, load_dns_types, load_logging_config, normalize_domain
from .pdns_ingestion import process_record
from .default.exceptions import DNSParseError

logger = load_logging_config()

def main():
    parser = argparse.ArgumentParser(description='Import Passive DNS COF format array')
    parser.add_argument('--file', dest='filetoimport', required=True, help='JSON file to import')
    args = parser.parse_args()

    if not args.filetoimport or not os.path.exists(args.filetoimport):
        logger.critical(f"Input file not found: {args.filetoimport}")
        sys.exit(1)

    load_config()
    logger.info("Starting Passive DNS array import")
    r = get_redis('analyzer')
    r_d4 = get_redis('metadata')
    dnstype = load_dns_types()
    excludesubstrings = get_config('exclude', 'substrings')
    expirations = get_config('expiration')

    try:
        with open(args.filetoimport) as dnsimport:
            records = json.load(dnsimport)
    except json.JSONDecodeError as e:
        logger.critical(f"Invalid JSON in file {args.filetoimport}: {e}")
        sys.exit(1)

    for rdns in records:
        try:
            rdns['rrname'] = normalize_domain(rdns['rrname'])
            rdns['rdata'] = normalize_domain(rdns['rdata'])
            process_record(r, rdns, dnstype, excludesubstrings, expirations)
        except DNSParseError as e:
            logger.debug(f"Failed to process record: {rdns} - {e}")

if __name__ == "__main__":
    main()