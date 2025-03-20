#!/usr/bin/env python3
# pdns/cli.py
#
# CLI tool to import Passive DNS COF format from various sources into a Passive DNS backend.
#
# Copyright (c) 2019-2022 Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2019-2022 Computer Incident Response Center Luxembourg (CIRCL)
# Licensed under GNU Affero General Public License v3.

import argparse
import asyncio
import sys
import os
from .default.helpers import logger, load_config, get_config, load_logging_config, load_dns_types
from .main import get_database_backend
from .ingestors.websocket import WebSocketIngestor
from .ingestors.json_file import JSONFileIngestor
from .ingestors.ndjson_file import NDJSONFileIngestor

async def main():
    parser = argparse.ArgumentParser(description='Import Passive DNS COF format from various sources')
    parser.add_argument('--ndjson', dest='ndjson_file', help='NDJSON file to import')
    parser.add_argument('--json', dest='json_file', help='JSON file to import')
    parser.add_argument('--websocket', dest='websocket_url', help='WebSocket stream URL')
    parser.add_argument('--pdns', dest='pdns_file', help='passivedns || separated file to import')
    parser.add_argument('--redis-queue', dest='redis_queue', help='Redis queue name to ingest from')
    args = parser.parse_args()

    # Validate arguments
    sources = [args.ndjson_file, args.json_file, args.websocket_url, args.pdns_file, args.redis_queue]
    if sum(1 for s in sources if s) > 1:
        logger.critical("Cannot specify more than one source")
        sys.exit(1)
    if not any(sources):
        parser.print_help()
        sys.exit(0)

    # Load configurations
    load_logging_config()
    load_config()
    logger.info({"event": "cli_start", "message": "Starting Passive DNS import"})
    
    db = get_database_backend()
    await db.connect()
    dnstype = load_dns_types()
    excludesubstrings = get_config('exclude', 'substrings')
    expirations = get_config('expiration')

    try:
        if args.ndjson_file:
            # ... (unchanged)
            ingestor = NDJSONFileIngestor(db, args.ndjson_file, dnstype, excludesubstrings, expirations)
        elif args.json_file:
            # ... (unchanged)
            ingestor = JSONFileIngestor(db, args.json_file, dnstype, excludesubstrings, expirations)
        elif args.websocket_url:
            ingestor = WebSocketIngestor(db, args.websocket_url, dnstype, excludesubstrings, expirations)
        elif args.d4_file:
            # ... (unchanged)
            ingestor = D4FileIngestor(db, args.d4_file, dnstype, excludesubstrings, expirations)
        elif args.redis_queue:
            ingestor = RedisQueueIngestor(db, args.redis_queue, dnstype, excludesubstrings, expirations)
        
        await ingestor.ingest()
    except KeyboardInterrupt:
        logger.info({"event": "cli_shutdown", "message": "Shutting down gracefully"})
        ingestor.stop()
    except Exception as e:
        logger.error({"event": "cli_error", "error": str(e)})
        sys.exit(1)
    finally:
        await db.disconnect()

if __name__ == "__main__":
    asyncio.run(main())