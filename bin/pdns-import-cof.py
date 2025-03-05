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
from common import setup_logger, load_config, init_redis, load_dns_types, process_record
parser = argparse.ArgumentParser(
    description='Import array of standard Passive DNS cof format into your Passive DNS server'
)
parser.add_argument('--file', dest='filetoimport', help='JSON file to import')
parser.add_argument(
    '--websocket', dest='websocket', help='Import from a websocket stream'
)
args = parser.parse_args()

if args.filetoimport and args.websocket:
    logger = setup_logger('pdns_ingestor')
    logger.critical("Cannot specify both --file and --websocket")
    sys.exit(1)
if not args.filetoimport and not args.websocket:
    parser.print_help()
    sys.exit(0)

config_path = os.path.join(os.path.dirname(__file__), '..', 'etc', 'analyzer.conf')
config = load_config(config_path)
logger = setup_logger('pdns_ingestor', config)
logger.info("Starting COF ingestor")

r = init_redis('D4_ANALYZER_REDIS_HOST', 'D4_ANALYZER_REDIS_PORT')
rtype_path = os.path.join(os.path.dirname(__file__), '..', 'etc', 'records-type.json')
dnstype = load_dns_types(rtype_path)
excludesubstrings = config.get('exclude', 'substring', fallback='spamhaus.org,asn.cymru.com').split(',')
expirations = config.items('expiration')

def on_open(ws):
    logger.debug('[websocket] connection open')


def on_close(ws):
    logger.debug('[websocket] connection closed')


def on_message(ws, message):
    logger.debug('Message received via websocket')
    try:
        rdns = json.loads(message)
        process_record(r, rdns, dnstype, excludesubstrings, expirations)
    except json.JSONDecodeError as e:
        logger.debug(f"Invalid JSON in websocket message: {e}")

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
                process_record(r, rdns, dnstype, excludesubstrings, expirations)
    except json.JSONDecodeError as e:
        logger.critical(f"Invalid NDJSON in file {args.filetoimport}: {e}")
        sys.exit(1)
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