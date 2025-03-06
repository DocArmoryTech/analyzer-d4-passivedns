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
from .default.helpers import setup_logger, load_config, init_redis, load_dns_types, process_record

parser = argparse.ArgumentParser(description='Import array of standard Passive DNS cof format into your Passive DNS server')
parser.add_argument('--file', dest='filetoimport', help='JSON file to import')
args = parser.parse_args()

config_path = os.path.join(os.path.dirname(__file__), '..', 'etc', 'analyzer.conf')
config = load_config(config_path)
logger = setup_logger('pdns_ingestor', config)
logger.info("Starting Passive DNS array import")

r = init_redis('D4_ANALYZER_REDIS_HOST', 'D4_ANALYZER_REDIS_PORT')
rtype_path = os.path.join(os.path.dirname(__file__), '..', 'etc', 'records-type.json')
dnstype = load_dns_types(rtype_path)
excludesubstrings = config.get('exclude', 'substring', fallback='spamhaus.org,asn.cymru.com').split(',')
expirations = config.items('expiration')

with open(args.filetoimport) as dnsimport:
    records = json.load(dnsimport)
for rdns in records:
    process_record(r, rdns, dnstype, excludesubstrings, expirations)