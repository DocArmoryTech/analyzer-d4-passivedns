# analyzer-d4-passivedns

analyzer-d4-passivedns is an advanced analyzer for D4 network sensors, featuring a fully compliant Passive DNS server. It processes data from D4 sensors in [passivedns](https://github.com/gamelinux/passivedns) CSV format and independently via [COF websocket](https://datatracker.ietf.org/doc/html/draft-dulaunoy-dnsop-passive-dns-cof) streams. The package includes a Passive DNS server that adheres to the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof), enabling efficient querying of DNS records.

## Background and Origins

The `analyzer-d4-passivedns` project originated from the need for a robust Passive DNS solution tailored for D4 network sensors. It builds upon the original [analyzer-d4-passivedns](https://github.com/D4-project/analyzer-d4-passivedns) by the D4 Project, drawing inspiration from tools like [passivedns](https://github.com/gamelinux/passivedns) and the COF standard. The project evolved to address scalability, performance, and modern API requirements, transitioning to FastAPI for its auto-generated OpenAPI spec and enhanced developer experience.

## Utility

This tool is invaluable for network security analysts, researchers, and administrators. It offers:
- Real-time collection and storage of DNS data from D4 sensors and COF streams.
- A queryable Passive DNS database for historical analysis.
- Flexible configuration to filter and process specific DNS records.
- Integration with modern notification systems for alerting on DNS events.

## Origins and Influences

The project is influenced by:
- **D4 Project**: Providing the foundational framework for sensor integration.
- **passivedns**: Inspiring the initial CSV-based data processing.
- **COF Standard**: Driving the adoption of a standardized output format.
- **FastAPI**: Enabling a modern, auto-documented API framework.

## Features

- **[Input Streams]**:
  - **D4 Analyzer**: Connects to one or more [D4 servers](https://github.com/D4-project/d4-core) to stream DNS records.
  - **COF Websocket**: Processes NDJSON COF format from websockets or files.
- **[Output API]**: A fully compliant Passive DNS ReST server with auto-generated OpenAPI documentation via FastAPI.
- **Flexible Configuration**: Configurable via JSON to collect specific DNS records.
- **Modular Design**: Supports custom ingestors and notifiers for extensibility.
- **High Performance**: Optimized with Redis or KV Rocks backends.
- **Authentication and Rate Limiting**: Secure API access with configurable controls.

## Comparative Benefits

Compared to the original [analyzer-d4-passivedns](https://github.com/D4-project/analyzer-d4-passivedns), this version offers:
- **Modern API**: FastAPI replaces the Tornado-based server, providing an interactive OpenAPI spec.
- **Enhanced Performance**: Improved database interactions with Redis and KV Rocks.
- **Modularity**: Dynamic loading of ingestors and notifiers via `generic.json`.
- **Documentation**: Comprehensive guides with Mermaid diagrams for developers.
- **Scalability**: Better handling of large datasets with streaming and pagination.

## Architecture

The project leverages Python 3.8+ and FastAPI, with a modular architecture:
- **Database Layer**: Redis or KV Rocks with dynamic backend selection.
- **Ingestors**: Modular components for data ingestion (e.g., D4, COF).
- **Notifiers**: Configurable alert system (e.g., email, webhooks).
- **API Layer**: FastAPI-driven endpoints with OpenAPI documentation.
- **Configuration**: Centralized JSON-based settings.

## Requirements

- **Python**: 3.8 or higher.
- **Database**: Redis (>5.0) or [KV Rocks](https://github.com/apache/incubator-kvrocks).
- **Dependencies**: Managed via Poetry (replacing virtualenv setup).

## Install

### Redis

```bash
./bin/install_server_redis.sh
```

### KV Rocks

```bash
./bin/install_server_kvrocks.sh
```

Install dependencies:
```bash
poetry install
```

## Running

### Start the Database

For Redis:
```bash
./redis/src/redis-server ./etc/redis.conf
```

For KV Rocks:
```bash
./kvrocks/src/kvrocks -c ./etc/kvrocks.conf
```

### Start the Passive DNS Server

```bash
poetry run uvicorn pdns.main:app --host 0.0.0.0 --port 8000
```

## Feeding the Passive DNS Server

### Via COF Websocket Stream

```bash
poetry run python3 bin/pdns-import-cof.py --websocket ws://crh.circl.lu:8888
```

### Via D4 Analyzer

Configure `etc/analyzer.conf`:
```ini
[global]
my-uuid = 6072e072-bfaa-4395-9bb1-cdb3b470d715
d4-server = 127.0.0.1:6380
logging-level = INFO
```

Start the analyzer:
```bash
poetry run python3 bin/pdns-ingestion.py
```

## Usage

Query the server:
```bash
curl -s http://127.0.0.1:8000/query/example.com
```

Explore the auto-generated API docs at `http://127.0.0.1:8000/docs`.

## License

The software is released under the GNU Affero General Public License version 3.