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
from .default.helpers import logger, get_config, load_logging_config, load_dns_types, init_configs
from .main import get_database, app  # Import app for serve command
from .db.manager import DatabaseManager
import uvicorn


INGESTORS_AVAILABLE = True
try:
    from .ingestors.stream.websocket import WebSocketIngestor
    from .ingestors.file.json import JSONFileIngestor
    from .ingestors.file.line.ndjson import NDJSONFileIngestor
    from .ingestors.file.line.passivedns import PDNSIngestor
    from .ingestors.stream.redis_queue import RedisQueueIngestor
    from .ingestors.file.line.zeek import ZeekIngestor
except ImportError as e:
    logger.error({"event": "ingestor_import_error", "error": str(e)})

    # In refactored layouts, ingestor modules may move or be disabled.
    # Keep the CLI importable for the 'serve' command even if ingestion
    # backends are not wired in this build.
    INGESTORS_AVAILABLE = False
    WebSocketIngestor = JSONFileIngestor = NDJSONFileIngestor = PDNSIngestor = RedisQueueIngestor = ZeekIngestor = None


async def ingest_source(args: argparse.Namespace, db: DatabaseManager) -> None:
    """Handle ingestion based on provided source argument."""
    if not INGESTORS_AVAILABLE:
        raise RuntimeError("Ingestion backends are not available in this build")

    try:
        if args.ndjson_file:
            ingestor = NDJSONFileIngestor(db, {"file_path": args.ndjson_file})
            source = args.ndjson_file
        elif args.json_file:
            ingestor = JSONFileIngestor(db, {"file_path": args.json_file})
            source = args.json_file
        elif args.websocket_url:
            ingestor = WebSocketIngestor(db, {"ws_url": args.websocket_url})
            source = args.websocket_url
        elif args.pdns_file:
            ingestor = PDNSIngestor(db, {"file_path": args.pdns_file})
            source = args.pdns_file
        elif args.redis_queue:
            ingestor = RedisQueueIngestor(db, {"redis_uri": args.redis_queue})
            source = args.redis_queue
        elif args.zeek_file:
            ingestor = ZeekIngestor(db, {"file_path": args.zeek_file})
            source = args.zeek_file
        else:
            raise ValueError("No ingestion source specified")

        await ingestor.ingest()
        logger.info({"event": "cli_ingest_complete", "source": source})
    except KeyboardInterrupt:
        logger.info({"event": "cli_shutdown", "message": "Shutting down gracefully"})
        ingestor.stop()
    except Exception as e:
        logger.error({"event": "cli_error", "error": str(e)})
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


async def _async_main():
    parser = argparse.ArgumentParser(description="Passive DNS Server CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start the FastAPI server")
    serve_parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind the server to"
    )
    serve_parser.add_argument(
        "--port", default=8000, type=int, help="Port to bind the server to"
    )

    # Ingest command
    ingest_parser = subparsers.add_parser(
        "ingest", help="Import Passive DNS COF format from various sources"
    )
    ingest_parser.add_argument(
        "--ndjson", dest="ndjson_file", help="NDJSON file to import"
    )
    ingest_parser.add_argument("--json", dest="json_file", help="JSON file to import")
    ingest_parser.add_argument(
        "--websocket", dest="websocket_url", help="WebSocket stream URL"
    )
    ingest_parser.add_argument(
        "--pdns", dest="pdns_file", help="passivedns || separated file to import"
    )
    ingest_parser.add_argument(
        "--redis-queue",
        dest="redis_queue",
        help="Redis queue connection string (e.g., 'host:port:queue_name')",
    )
    ingest_parser.add_argument(
        "--zeek", dest="zeek_file", help="Zeek DNS JSON log file to import"
    )

    args = parser.parse_args()

    # Load configurations
    load_logging_config()
    await init_configs()
    logger.info(
        {
            "event": "cli_start",
            "message": f"Starting CLI with command: {args.command or 'none'}",
        }
    )

    if args.command == "serve":
        logger.info({"event": "cli_serve", "host": args.host, "port": args.port})
        config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()
    elif args.command == "ingest":
        # Validate ingestion arguments
        sources = [
            args.ndjson_file,
            args.json_file,
            args.websocket_url,
            args.pdns_file,
            args.redis_queue,
            args.zeek_file,
        ]
        if sum(1 for s in sources if s) > 1:
            logger.critical(
                {
                    "event": "cli_validation_error",
                    "message": "Cannot specify more than one source",
                }
            )
            print("Error: Cannot specify more than one source", file=sys.stderr)
            sys.exit(1)
        if not any(sources):
            ingest_parser.print_help()
            sys.exit(0)

        # Load additional configurations
        dnstype = load_dns_types()
        excludesubstrings = get_config("generic", "excludesubstrings", default=[])
        expirations = get_config("generic", "expiration", default={})

        # Get DatabaseManager instance
        db_gen = get_database()
        db = await db_gen.__anext__()
        try:
            await ingest_source(args, db)
        finally:
            await db_gen.aclose()
    else:
        parser.print_help()
        sys.exit(0)


def main() -> None:
    """Synchronous entry point for console_script.

    Wrap the async implementation so that the Poetry-generated
    ``pdns`` script can call this like a normal function.
    """

    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
