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
from .default.helpers import logger, get_config, load_logging_config, load_dns_types
from .main import get_database
from .ingestors.websocket import WebSocketIngestor
from .ingestors.json import JSONFileIngestor
from .ingestors.ndjson import NDJSONFileIngestor
from .ingestors.passivedns import PDNSIngestor
from .ingestors.redis_queue import RedisQueueIngestor
from .db.base import Database

async def main():
    parser = argparse.ArgumentParser(description="Import Passive DNS COF format from various sources")
    parser.add_argument("--ndjson", dest="ndjson_file", help="NDJSON file to import")
    parser.add_argument("--json", dest="json_file", help="JSON file to import")
    parser.add_argument("--websocket", dest="websocket_url", help="WebSocket stream URL")
    parser.add_argument("--pdns", dest="pdns_file", help="passivedns || separated file to import")
    parser.add_argument("--redis-queue", dest="redis_queue", help="Redis queue name to ingest from")
    args = parser.parse_args()

    # Validate arguments
    sources = [args.ndjson_file, args.json_file, args.websocket_url, args.pdns_file, args.redis_queue]
    if sum(1 for s in sources if s) > 1:
        logger.critical({"event": "cli_validation_error", "message": "Cannot specify more than one source"})
        print("Error: Cannot specify more than one source", file=sys.stderr)
        sys.exit(1)
    if not any(sources):
        parser.print_help()
        sys.exit(0)

    # Load configurations
    load_logging_config()  # Assuming this sets up logging
    logger.info({"event": "cli_start", "message": "Starting Passive DNS import"})
    
    db = await get_database()  # Use the abstracted database manager
    dnstype = load_dns_types()  # Load RR type mappings
    excludesubstrings = get_config("exclude", {}).get("substrings", [])  # Exclusion list
    expirations = get_config("expiration", {})  # Expiration settings

    try:
        if args.ndjson_file:
            ingestor = NDJSONFileIngestor(db, args.ndjson_file)
        elif args.json_file:
            ingestor = JSONFileIngestor(db, args.json_file)
        elif args.websocket_url:
            ingestor = WebSocketIngestor(db, args.websocket_url)
        elif args.pdns_file:
            ingestor = PDNSIngestor(db, args.pdns_file)
        elif args.redis_queue:
            ingestor = RedisQueueIngestor(db, args.redis_queue)
                    
        await ingestor.ingest()
        logger.info({"event": "cli_ingest_complete", "source": args.ndjson_file or args.json_file or args.websocket_url or args.pdns_file or args.redis_queue})
    except KeyboardInterrupt:
        logger.info({"event": "cli_shutdown", "message": "Shutting down gracefully"})
        if "ingestor" in locals():
            ingestor.stop()
    except Exception as e:
        logger.error({"event": "cli_error", "error": str(e)})
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())