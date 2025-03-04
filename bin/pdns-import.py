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



import redis
import json
import configparser

import logging
import sys
import argparse
import os

parser = argparse.ArgumentParser(description='Import array of standard Passive DNS cof format into your Passive DNS server')
parser.add_argument('--file', dest='filetoimport', help='JSON file to import')
args = parser.parse_args()

if not os.path.exists(args.filetoimport):
    logger.critical(f"Input file not found: {args.filetoimport}")
    sys.exit(1)
with open(args.filetoimport) as dnsimport:
    records = json.load(dnsimport)

config = configparser.RawConfigParser()
config_path = os.path.join(os.path.dirname(__file__), '..', 'etc', 'analyzer.conf')
if not os.path.exists(config_path):
    logger.critical(f"Configuration file not found: {config_path}")
    sys.exit(1)
config.read(config_path)
    
try:
    expirations = config.items('expiration')
except configparser.NoSectionError:
    logger.critical("Missing 'expiration' section in config")
    sys.exit(1)
excludesubstrings = config.get('exclude', 'substring', fallback='spamhaus.org,asn.cymru.com').split(',')
try:
    myuuid = config.get('global', 'my-uuid')
except (configparser.NoSectionError, configparser.NoOptionError):
    logger.critical("Missing 'my-uuid' in 'global' section of config")
    sys.exit(1)
myqueue = "analyzer:8:{}".format(myuuid)
mylogginglevel = config.get('global', 'logging-level', fallback='INFO')
logger = logging.getLogger('pdns ingestor')
ch = logging.StreamHandler()
if mylogginglevel == 'DEBUG':
    logger.setLevel(logging.DEBUG)
    ch.setLevel(logging.DEBUG)
elif mylogginglevel == 'INFO':
    logger.setLevel(logging.INFO)
    ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

logger.info("Starting and using FIFO {} from D4 server".format(myqueue))

analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6400))
try:
    d4_server, d4_port = config.get('global', 'd4-server').split(':')
except (configparser.NoSectionError, configparser.NoOptionError):
    logger.critical("Missing 'd4-server' in 'global' section of config")
    sys.exit(1)
except ValueError:
    logger.critical("'d4-server' must be in 'host:port' format")
    sys.exit(1)

r = redis.Redis(host=analyzer_redis_host, port=analyzer_redis_port)
r_d4 = redis.Redis(host=host_redis_metadata, port=port_redis_metadata, db=2)
try:
    r.ping()
    r_d4.ping()
except redis.ConnectionError as e:
    logger.critical(f"Failed to connect to Redis: {e}")
    sys.exit(1)

rtype_path = os.path.join(os.path.dirname(__file__), '..', 'etc', 'records-type.json')
if not os.path.exists(rtype_path):
    logger.critical(f"Records type file not found: {rtype_path}")
    sys.exit(1)
try:
    with open(args.filetoimport) as dnsimport:
        records = json.load(dnsimport)
except json.JSONDecodeError as e:
    logger.critical(f"Invalid JSON in input file {args.filetoimport}: {e}")
    sys.exit(1)

dnstype = {}

stats = True

for v in rtype:
    dnstype[(v['type'])] = v['value']

expiration = None
if not (args.filetoimport):
    parser.print_help()
    sys.exit(0)
with open(args.filetoimport) as dnsimport:
    records = json.load(dnsimport)

print (records)
for rdns in records:
    logger.debug("parsed record: {}".format(rdns))
    if 'rrname' not in rdns:
        logger.debug('Parsing of passive DNS line is incomplete: {}'.format(rdns))
        continue
    if rdns['rrname'] and rdns['rrtype']:
        rdns['type'] = dnstype[rdns['rrtype']]
        rdns['v'] = rdns['rdata']
        excludeflag = False
        for exclude in excludesubstrings:
            if exclude in rdns['rrname']:
                excludeflag = True
        if excludeflag:
            logger.debug('Excluded {}'.format(rdns['rrname']))
            continue
        # Set expiration based on type
        for y in expirations:
            if y[0] == rdns['type']:
                expiration = y[1]
                break
        if rdns['type'] == '16':
            rdns['v'] = rdns['v'].replace("\"", "", 1)
        query = "r:{}:{}".format(rdns['rrname'], rdns['type'])
        logger.debug('redis sadd: {} -> {}'.format(query, rdns['v']))
        r.sadd(query, rdns['v'])
        if expiration:
            r.expire(query, expiration)
            logger.debug("Expiration {} applied to {}".format(expiration, query))
        
        res = "v:{}:{}".format(rdns['v'], rdns['type'])
        logger.debug('redis sadd: {} -> {}'.format(res, rdns['rrname']))
        r.sadd(res, rdns['rrname'])
        if expiration:
            r.expire(res, expiration)
            logger.debug("Expiration {} applied to {}".format(expiration, res))

        firstseen = "s:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        if not r.exists(firstseen):
            r.set(firstseen, rdns['time_first'])
            logger.debug('redis set: {} -> {}'.format(firstseen, rdns['time_first']))
        if expiration:
            r.expire(firstseen, expiration)
            logger.debug("Expiration {} applied to {}".format(expiration, firstseen))

        lastseen = "l:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        last = r.get(lastseen)
        if last is None or int(last) < int(rdns['time_last']):
            r.set(lastseen, rdns['time_last'])
            logger.debug('redis set: {} -> {}'.format(lastseen, rdns['time_last']))
        if expiration:
            r.expire(lastseen, expiration)
            logger.debug("Expiration {} applied to {}".format(expiration, lastseen))

        occ = "o:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        r.set(occ, rdns['count'])
        if expiration:
            r.expire(occ, expiration)
            logger.debug("Expiration {} applied to {}".format(expiration, occ))

        if stats:
            r.incrby('stats:processed', amount=1)
    if not rdns:
        logger.info('empty passive dns record')
        continue