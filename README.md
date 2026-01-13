# analyzer-d4-passivedns

analyzer-d4-passivedns is a Passive DNS analyzer and server for D4 network sensors. It ingests DNS records from multiple sources (D4 queues, COF streams, log files, Zeek logs, DNSTap, PCAP) and exposes a Passive DNS API compliant with the [Passive DNS – Common Output Format](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof).

The project is a modern reimplementation of the original [D4 analyzer-d4-passivedns](https://github.com/D4-project/analyzer-d4-passivedns), with a focus on clearer configuration, modular components, and a FastAPI-based HTTP API.

## Features

- Input from D4 Redis queues, COF WebSocket streams, PassiveDNS text logs, NDJSON/JSON files, Zeek DNS logs, DNSTap, and PCAP.
- FastAPI HTTP API (`/info`, `/query`, `/fquery`, `/stream`) with OpenAPI documentation at `/docs`.
- Redis or KV Rocks backend, selected via configuration.
- Pluggable ingestors and notifiers, configured declaratively.
- JSON-based configuration and explicit behaviour (no hidden global state).

## Requirements

- Python 3.10 or higher.
- Redis (>5.0) or [KV Rocks](https://github.com/apache/incubator-kvrocks).
- [Poetry](https://python-poetry.org/) for dependency management.

## Installation

Clone the repository and install Python dependencies:

```bash
git clone https://github.com/D4-project/analyzer-d4-passivedns.git
cd analyzer-d4-passivedns
poetry install
```

Set the project home and prepare the main configuration:

```bash
export PDNS_HOME=$(pwd)
cp config/generic.json.sample config/generic.json
```

Install and start a database backend (Redis example):

```bash
./bin/install_server_redis.sh
./redis/src/redis-server ./etc/redis.conf
```

See [docs/admin/installation.md](docs/admin/installation.md) for KV Rocks and production deployment details.

## Running the API server

Start the FastAPI server with uvicorn:

```bash
poetry run uvicorn pdns.main:app --host 0.0.0.0 --port 8000
```

The OpenAPI documentation is available at:

- `http://localhost:8000/docs`

Basic query example:

```bash
curl -s "http://localhost:8000/query/example.com"
```

Authentication, rate limiting, and other API settings are controlled via `config/generic.json` (see the documentation).

## Running with Docker

For a quick local setup using Docker and docker-compose:

1. Ensure Docker and docker-compose are installed.
2. Prepare configuration (Docker-oriented sample):
	 ```bash
	 cp config/generic.docker.json.sample config/generic.json
	 cp config/logging.json.sample config/logging.json
	 ```
3. Start the stack:
	 ```bash
	 docker compose up --build
	 ```
4. Access the API:
	 - OpenAPI docs: `http://localhost:8000/docs`
	 - Info endpoint: `http://localhost:8000/info`

Logs are written to stdout/stderr of the `pdns-api` container by default and can be viewed with:

```bash
docker compose logs -f pdns-api
```

To build and push the image manually (outside docker-compose):

```bash
docker build -t d4/pdns-api .
docker push d4/pdns-api   # optional
```

## Ingestion

DNS records can be ingested from different sources using ingestors. Ingestors are configured under the `ingestors` key in `config/generic.json` and implemented in [pdns/ingestors](pdns/ingestors).

Typical sources include:

- PassiveDNS-formatted text files.
- NDJSON and JSON arrays of COF records.
- D4 Redis queues.
- Zeek DNS JSON logs.
- DNSTap framed data and PCAP files.
- WebSocket streams of JSON DNS records.

For configuration examples and operational guidance, see [docs/admin/ingestors.md](docs/admin/ingestors.md).

## Notifiers

The notifier subsystem allows the server to emit alerts when records match configurable conditions. Notifiers are defined under the `notifiers` key in `config/generic.json` and implemented in [pdns/notifiers](pdns/notifiers).

Supported backends include log, email, Matrix, Mattermost, Rocket.Chat, and generic webhooks. Each notifier:

- Implements a shared `Notifier` base interface.
- Uses Jinja2 templates for message rendering.
- Applies one or more filters before delivery.

Design and extension guidelines for notifiers and filters are documented in:

- [docs/admin/notifiers.md](docs/admin/notifiers.md)
- [docs/dev/adding-notifiers.md](docs/dev/adding-notifiers.md)
- [docs/dev/contributing.md](docs/dev/contributing.md)

## Documentation

The repository includes a MkDocs documentation tree under [docs](docs), covering:

- User guide (querying, examples, schemas).
- Administrator guide (installation, configuration, ingestors, notifiers, scaling, troubleshooting).
- Developer guide (codebase overview, API development, testing, extending ingestors and notifiers).

Start at [docs/index.md](docs/index.md) for an overview.

## License

The software is released under the GNU Affero General Public License version 3.