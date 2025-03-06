#!/usr/bin/env python3
#
# pdns-ingestion is the D4 analyzer for the Passive DNS backend.
#
# This software parses input (via a Redis list) from a D4 server and
# ingest it into a redis compliant server to server the records for
# the passive DNS at later stage.
#
# This software is part of the D4 project.
#
# The software is released under the GNU Affero General Public version 3.
#
# Copyright (c) 2019 Alexandre Dulaunoy - a@foo.be
# Copyright (c) Computer Incident Response Center Luxembourg (CIRCL)

import time
import redis
from .default.helpers import setup_logger, load_config, init_redis, load_dns_types, process_record

config_path = os.path.join(os.path.dirname(__file__), '..', 'etc', 'analyzer.conf')
config = load_config(config_path)
logger = setup_logger('pdns_ingestor', config)
logger.info("Starting Passive DNS ingestion")

myuuid = config.get('global', 'my-uuid', fallback='unknown')
myqueue = f"analyzer:8:{myuuid}"
r = init_redis('D4_ANALYZER_REDIS_HOST', 'D4_ANALYZER_REDIS_PORT')
d4_server, d4_port = config.get('global', 'd4-server').split(':')
host_redis_metadata = os.getenv('D4_REDIS_METADATA_HOST', d4_server)
port_redis_metadata = int(os.getenv('D4_REDIS_METADATA_PORT', d4_port))
r_d4 = redis.Redis(host=host_redis_metadata, port=port_redis_metadata, db=2)
try:
    r_d4.ping()
except redis.ConnectionError as e:
    logger.critical(f"Failed to connect to metadata Redis: {e}")
    sys.exit(1)
rtype_path = os.path.join(os.path.dirname(__file__), '..', 'etc', 'records-type.json')
dnstype = load_dns_types(rtype_path)
excludesubstrings = config.get('exclude', 'substring', fallback='spamhaus.org,asn.cymru.com').split(',')
expirations = config.items('expiration')

def process_format_passivedns(line=None):
    # log line example
    # timestamp||ip-src||ip-dst||class||q||type||v||ttl||count
    # 1548624738.280922||192.168.1.12||8.8.8.8||IN||www-google-analytics.l.google.com.||AAAA||2a00:1450:400e:801::200e||299||12
    vkey = ['timestamp','ip-src','ip-dst','class','q','type','v','ttl','count']
    record = {}
    if line is None or line == '':
        return False
    v = line.split("||")
    i = 0
    for r in v:
        # trailing dot is removed and avoid case sensitivity
        if i == 4 or i == 6:
            r = r.lower().strip('.')
        # timestamp is just epoch - second precision is only required
        if i == 0:
            r = r.split('.')[0]
        record[vkey[i]] = r
        # replace DNS type with the known DNS record type value
        if i == 5:
            record[vkey[i]] = dnstype[r]
        i = i + 1
    return record

while True:
    d4_record_line = r_d4.rpop(myqueue)
    if d4_record_line is None:
        time.sleep(1)
        continue
    l = d4_record_line.decode('utf-8').strip()
    rdns = process_format_passivedns(line=l.strip())
    process_record(r, rdns, dnstype, excludesubstrings, expirations)