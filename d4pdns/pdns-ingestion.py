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
import sys
from .default import load_config, get_config, get_redis, load_dns_types, load_logging_config, normalize_domain
from .default.exceptions import DNSParseError

logger = load_logging_config()
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

def process_record(r: 'redis.Redis', rdns: dict, dnstype: dict, excludesubstrings: list, expirations: dict, stats: bool = True) -> bool:
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
    for exclude in excludesubstrings:
        if exclude in rdns['rrname']:
            logger.debug(f"Excluded {rdns['rrname']}")
            return False
    expiration = expirations.get(rdns['type'])
    if expiration is not None:
        expiration = int(expiration)
    if rdns['type'] == '16':
        rdns['v'] = rdns['v'].replace("\"", "", 1)
    query = f"r:{rdns['rrname']}:{rdns['type']}"
    r.sadd(query, rdns['v'])
    if expiration:
        r.expire(query, expiration)
    res = f"v:{rdns['v']}:{rdns['type']}"
    r.sadd(res, rdns['rrname'])
    if expiration:
        r.expire(res, expiration)
    firstseen = f"s:{rdns['rrname']}:{rdns['v']}:{rdns['type']}"
    try:
        firstseen_val = int(float(rdns['time_first']))
        if not r.exists(firstseen):
            r.set(firstseen, firstseen_val)
        if expiration:
            r.expire(firstseen, expiration)
    except (ValueError, TypeError, KeyError) as e:
        logger.debug(f"Invalid or missing time_first in record: {rdns}")
        raise DNSParseError(f"Failed to parse time_first: {e}")
    lastseen = f"l:{rdns['rrname']}:{rdns['v']}:{rdns['type']}"
    try:
        lastseen_val = int(float(rdns['time_last']))
        last = r.get(lastseen)
        if last is None or int(float(last)) < lastseen_val:
            r.set(lastseen, lastseen_val)
        if expiration:
            r.expire(lastseen, expiration)
    except (ValueError, TypeError, KeyError) as e:
        logger.debug(f"Invalid or missing time_last in record: {rdns}")
        raise DNSParseError(f"Failed to parse time_last: {e}")
    occ = f"o:{rdns['rrname']}:{rdns['v']}:{rdns['type']}"
    r.incrby(occ, int(rdns.get('count', 1)))
    if expiration:
        r.expire(occ, expiration)
    if stats:
        r.incrby('stats:processed', 1)
        if 'sensor_id' in rdns:
            r.sadd('sensors:seen', rdns['sensor_id'])
            r.zincrby('stats:sensors', 1, rdns['sensor_id'])
    return True

def main():
  
    parser = argparse.ArgumentParser(description="Passive DNS ingestion script")
    parser.add_argument("--redis", dest="redis", help="Redis server (format: ip:port or socket path)")
    parser.add_argument("--myuuid", dest="myuuid", help="Unique identifier for this instance")
    args = parser.parse_args()
    
    load_config()  # Ensure config is loaded
    logger.info("Starting Passive DNS ingestion")

    myuuid = args.myuuid
    myqueue = f"analyzer:8:{myuuid}"

    
    redis_params = {}
    if args.redis:
      if ":" in args.redis:
          parts = args.redis.split(":")
          if len(parts) != 2 or not parts[1].isdigit():
            raise ValueError("Invalid format for --redis. Expected ip:port or a valid socket path.")
          else:
            redis_params["host"] = parts[0]
          redis_params["port"] = int(parts[1])
      else:
          redis_params["unix_socket_path"] = args.redis
    else:
       redis_params["host"] = os.getenv('D4_REDIS_METADATA_HOST', '127.0.0.1')
       redis_params["port"] = int(os.getenv('D4_REDIS_METADATA_PORT', '6380'))
    
    redis_params["db"] = 2
    try:
        r_d4 = redis.Redis(**redis_params)
    except ValueError as e:
        logger.critical(str(e))
        sys.exit(1)

    # Resolve UUID
    myuuid = args.myuuid or os.getenv('D4_UUID')
    if not myuuid or not re.match(r"^[a-f0-9\-]{36}$", myuuid):
        logger.critical("Invalid or missing UUID")
        sys.exit(1)

    myqueue = f"analyzer:8:{myuuid}"
    r = get_redis()
    dnstype = load_dns_types()
    excludesubstrings = get_config('exclude', 'substrings')
    expirations = get_config('expiration')

    while True:
        d4_record_line = r_d4.rpop(myqueue)
        if d4_record_line is None:
            time.sleep(1)
            continue
        
        l = d4_record_line.strip()
        try:
            rdns = process_format_passivedns(line=l.strip())
            process_record(r, rdns, dnstype, excludesubstrings, expirations)
        except (IndexError, DNSParseError) as e:
            logger.debug(f"Failed to parse record: {l} - {e}")

if __name__ == "__main__":
    main()
