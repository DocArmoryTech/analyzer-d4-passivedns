#!/usr/bin/env python3
#
# pdns-import is a simple import from Passive DNS cof format (from NDJSON)
# and import these back into a Passive DNS backend
#
# This software is part of the D4 project.
#
# The software is released under the GNU Affero General Public version 3.
#
# Copyright (c) 2019-2022 Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2019 Computer Incident Response Center Luxembourg (CIRCL)

import argparse
import sys
import json
import ndjson
import websocket
import os
from .default import load_config, get_config, get_redis, load_dns_types, load_logging_config, normalize_domain
from .pdns_ingestion import process_record
from .default.exceptions import DNSParseError

logger = load_logging_config()

def main():
    parser = argparse.ArgumentParser(description='Import Passive DNS COF format from NDJSON or WebSocket')
    parser.add_argument('--file', dest='filetoimport', help='NDJSON file to import')
    parser.add_argument('--websocket', dest='websocket', help='WebSocket stream URL')
    args = parser.parse_args()

    if args.filetoimport and args.websocket:
        logger.critical("Cannot specify both --file and --websocket")
        sys.exit(1)
    if not args.filetoimport and not args.websocket:
        parser.print_help()
        sys.exit(0)

    load_config()
    logger.info("Starting Passive DNS stream import")
    r = get_redis()
    dnstype = load_dns_types()
    excludesubstrings = get_config('exclude', 'substrings')
    expirations = get_config('expiration')

    def on_open(ws):
        logger.debug('[websocket] connection open')

    def on_close(ws):
        logger.debug('[websocket] connection closed')

    def on_message(ws, message):
        logger.debug('Message received via websocket')
        try:
            rdns = json.loads(message)
            rdns['rrname'] = normalize_domain(rdns['rrname'])
            rdns['rdata'] = normalize_domain(rdns['rdata'])
            process_record(r, rdns, dnstype, excludesubstrings, expirations)
        except (json.JSONDecodeError, DNSParseError) as e:
            logger.debug(f"Invalid JSON or parsing error in websocket message: {e}")

    def on_error(ws, error):
        logger.error(f"Websocket error: {error}")

    if args.filetoimport:
        if not os.path.exists(args.filetoimport):
            logger.critical(f"Input file not found: {args.filetoimport}")
            sys.exit(1)
        try:
            with open(args.filetoimport, "r") as dnsimport:
                reader = ndjson.load(dnsimport)
                for rdns in reader:
                    rdns['rrname'] = normalize_domain(rdns['rrname'])
                    rdns['rdata'] = normalize_domain(rdns['rdata'])
                    process_record(r, rdns, dnstype, excludesubstrings, expirations)
        except json.JSONDecodeError as e:
            logger.critical(f"Invalid NDJSON in file {args.filetoimport}: {e}")
            sys.exit(1)
        except DNSParseError as e:
            logger.debug(f"Failed to process NDJSON record: {e}")
    elif args.websocket:
        ws = websocket.WebSocketApp(
            args.websocket, on_open=on_open, on_close=on_close, on_message=on_message, on_error=on_error
        )
        try:
            ws.run_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down websocket gracefully")
            ws.close()
            sys.exit(0)

if __name__ == "__main__":
    main()