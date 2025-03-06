#!/usr/bin/env python3
import redis
import json
import logging
import configparser
import os
import sys

def setup_logger(name, config=None):
    logger = logging.getLogger(name)
    ch = logging.StreamHandler()
    level = config.get('global', 'logging-level', fallback='INFO') if config else 'INFO'
    if level == 'DEBUG':
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger

def load_config(config_path):
    config = configparser.RawConfigParser()
    if not os.path.exists(config_path):
        logger = logging.getLogger('d4_common')
        logger.critical(f"Configuration file not found: {config_path}")
        sys.exit(1)
    config.read(config_path)
    return config

def init_redis(host_env, port_env):
    host = os.getenv(host_env, '127.0.0.1')
    port = int(os.getenv(port_env, 6400))
    r = redis.Redis(host=host, port=port)
    try:
        r.ping()
    except redis.ConnectionError as e:
        logger = logging.getLogger('d4_common')
        logger.critical(f"Failed to connect to Redis: {e}")
        sys.exit(1)
    return r

def load_dns_types(file_path):
    if not os.path.exists(file_path):
        logger = logging.getLogger('d4_common')
        logger.critical(f"Records type file not found: {file_path}")
        sys.exit(1)
    with open(file_path) as rtypefile:
        rtype = json.load(rtypefile)
    return {v['type']: v['value'] for v in rtype}

def process_record(r, rdns, dnstype, excludesubstrings, expirations, stats=True):
    if not rdns or 'rrname' not in rdns:
        logger = logging.getLogger('d4_common')
        logger.debug(f"Parsing of passive DNS line is incomplete: {rdns}")
        return False
    if not rdns['rrname'] or not rdns['rrtype']:
        return False
    if rdns['rrtype'] not in dnstype:
        logger = logging.getLogger('d4_common')
        logger.debug(f"Unknown DNS type '{rdns['rrtype']}' in record: {rdns}")
        return False
    rdns['type'] = dnstype[rdns['rrtype']]
    rdns['v'] = rdns['rdata']
    for exclude in excludesubstrings:
        if exclude in rdns['rrname']:
            logger = logging.getLogger('d4_common')
            logger.debug(f"Excluded {rdns['rrname']}")
            return False
    expiration = None
    for exp_type, exp_time in expirations:
        if exp_type == rdns['type']:
            expiration = int(exp_time)
            break
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
    except (ValueError, TypeError, KeyError):
        logger = logging.getLogger('d4_common')
        logger.debug(f"Invalid or missing time_first in record: {rdns}")
        return False
    lastseen = f"l:{rdns['rrname']}:{rdns['v']}:{rdns['type']}"
    try:
        lastseen_val = int(float(rdns['time_last']))
        last = r.get(lastseen)
        if last is None or int(float(last)) < lastseen_val:
            r.set(lastseen, lastseen_val)
        if expiration:
            r.expire(lastseen, expiration)
    except (ValueError, TypeError, KeyError):
        logger = logging.getLogger('d4_common')
        logger.debug(f"Invalid or missing time_last in record: {rdns}")
        return False
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