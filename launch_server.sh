#!/bin/bash

echo "launch_server.sh is deprecated."
echo "Use Poetry/uvicorn and the pdns CLI instead, for example:"
echo "  export PDNS_HOME=\"$(pwd)\""
echo "  poetry run uvicorn pdns.main:app --host 0.0.0.0 --port 8000"
echo "  poetry run pdns ingest --websocket ws://crh.circl.lu:8888 &"
exit 1
