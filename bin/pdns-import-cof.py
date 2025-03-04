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


import redis
import json
import logging
import sys
import argparse
import os
import ndjson

# ! websocket-client not websocket
import websocket

# Initialize logger early
logger = logging.getLogger('pdns ingestor')
ch = logging.StreamHandler()
mylogginglevel = 'INFO'  # Temporary default (INFO is safer than DEBUG)
if mylogginglevel == 'DEBUG':
    logger.setLevel(logging.DEBUG)
    ch.setLevel(logging.DEBUG)
elif:  # Default to INFO
    logger.setLevel(logging.INFO)
    ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
    
parser = argparse.ArgumentParser(
    description='Import array of standard Passive DNS cof format into your Passive DNS server'
)
parser.add_argument('--file', dest='filetoimport', help='JSON file to import')
parser.add_argument(
    '--websocket', dest='websocket', help='Import from a websocket stream'
)
args = parser.parse_args()

if args.filetoimport and args.websocket:
    logger.critical("Cannot specify both --file and --websocket")
    sys.exit(1)
if not args.filetoimport and not args.websocket:
    parser.print_help()
    sys.exit(0)

if args.filetoimport:
    if not os.path.exists(args.filetoimport):
        logger.critical(f"Input file not found: {args.filetoimport}")
        sys.exit(1)
    try:
        with open(args.filetoimport, "r") as dnsimport:
            reader = ndjson.load(dnsimport)
            for rdns in reader:
                add_record(rdns=rdns)
    except json.JSONDecodeError as e:
        logger.critical(f"Invalid NDJSON in file {args.filetoimport}: {e}")
        sys.exit(1)

config = configparser.RawConfigParser()
config_path = os.path.join(os.path.dirname(__file__), '..', 'etc', 'analyzer.conf')
if not os.path.exists(config_path):
    logger.critical(f"Configuration file not found: {config_path}")
    exit(1)
config.read(config_path)

# Update logging level after reading config
mylogginglevel = config.get('global', 'logging-level', fallback='INFO')
if mylogginglevel == 'DEBUG':
    logger.setLevel(logging.DEBUG)
    ch.setLevel(logging.DEBUG)
elif mylogginglevel == 'INFO':
    logger.setLevel(logging.INFO)
    ch.setLevel(logging.INFO)

logger.info("Starting COF ingestor")

try:
    expirations = config.items('expiration')
except configparser.NoSectionError:
    logger.critical("Missing 'expiration' section in config")
    sys.exit(1)

analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6400))

r = redis.Redis(host=analyzer_redis_host, port=analyzer_redis_port)
try:
    r.ping()
except redis.ConnectionError as e:
    logger.critical(f"Failed to connect to Redis: {e}")
    sys.exit(1)
    

excludesubstrings = config.get('exclude', 'substring', fallback='spamhaus.org,asn.cymru.com').split(',')
rtype_path = os.path.join(os.path.dirname(__file__), '..', 'etc', 'records-type.json')
if not os.path.exists(rtype_path):
    logger.critical(f"Records type file not found: {rtype_path}")
    sys.exit(1)
with open(rtype_path) as rtypefile:
    rtype = json.load(rtypefile)

dnstype = {}

stats = True

for v in rtype:
    dnstype[(v['type'])] = v['value']


expiration = None
if (not (args.filetoimport)) and (not (args.websocket)):
    parser.print_help()
    sys.exit(0)


def add_record(rdns=None):
    if rdns is None:
        return False
    logger.debug("parsed record: {}".format(rdns))
    if 'rrname' not in rdns:
        logger.debug(
            'Parsing of passive DNS line is incomplete: {}'.format(rdns.strip())
        )
        return False
    if rdns['rrname'] and rdns['rrtype']:
        rdns['type'] = dnstype[rdns['rrtype']]
        rdns['v'] = rdns['rdata']
        excludeflag = False
        for exclude in excludesubstrings:
            if exclude in rdns['rrname']:
                excludeflag = True
        if excludeflag:
            logger.debug('Excluded {}'.format(rdns['rrname']))
            return False
        # Set expiration based on numeric type
        expiration = None
        for exp_type, exp_time in expirations:
            if exp_type == rdns['type']:
                expiration = int(exp_time)
                break
        if rdns['type'] == '16':
            rdns['v'] = rdns['v'].replace("\"", "", 1)
        query = "r:{}:{}".format(rdns['rrname'], rdns['type'])
        logger.debug('redis sadd: {} -> {}'.format(query, rdns['v']))
        r.sadd(query, rdns['v'])
        if expiration:
            r.expire(query, expiration)
            logger.debug(f"Expiration {expiration} applied to {query}")

        res = "v:{}:{}".format(rdns['v'], rdns['type'])
        logger.debug('redis sadd: {} -> {}'.format(res, rdns['rrname']))
        r.sadd(res, rdns['rrname'])
        if expiration:
            r.expire(res, expiration)
            logger.debug(f"Expiration {expiration} applied to {res}")

        firstseen = "s:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        if not r.exists(firstseen):
            try:
                firstseen_val = int(float(rdns['time_first']))
                r.set(firstseen, firstseen_val)
                logger.debug('redis set: {} -> {}'.format(firstseen, rdns['time_first']))
            except (ValueError, TypeError, KeyError):
                logger.debug(f"Invalid or missing time_first in record: {rdns}")
                return False
        if expiration:
            r.expire(firstseen, expiration)
            logger.debug(f"Expiration {expiration} applied to {firstseen}")

        lastseen = "l:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        last = r.get(lastseen)
        try:
            lastseen_val = int(float(rdns['time_last']))
            if last is None or int(float(last)) < lastseen_val:
                r.set(lastseen, lastseen_val)
                logger.debug('redis set: {} -> {}'.format(lastseen, rdns['time_last']))
        except (ValueError, TypeError, KeyError):
            logger.debug(f"Invalid or missing time_last in record: {rdns}")
            return False
        if expiration:
            r.expire(lastseen, expiration)
            logger.debug(f"Expiration {expiration} applied to {lastseen}")

        occ = "o:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        r.incrby(occ, int(rdns.get('count', 1)))
        if expiration:
            r.expire(occ, expiration)
            logger.debug(f"Expiration {expiration} applied to {occ}")

        if stats:
            r.incrby('stats:processed', amount=1)
            r.sadd('sensors:seen', rdns["sensor_id"])
            r.zincrby('stats:sensors', 1, rdns["sensor_id"])
    if not rdns:
        logger.info('empty passive dns record')
        return False


def on_open(ws):
    logger.debug('[websocket] connection open')


def on_close(ws):
    logger.debug('[websocket] connection closed')


def on_message(ws, message):
    logger.debug('Message received via websocket')
    try:
        add_record(rdns=json.loads(message))
    except json.JSONDecodeError as e:
        logger.debug(f"Invalid JSON in websocket message: {e}")

def on_error(ws, error):
    logger.error(f"Websocket error: {error}")
    
if args.filetoimport:
    for rdns in reader:
        add_record(rdns=rdns)
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