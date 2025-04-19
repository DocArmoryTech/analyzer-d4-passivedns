# Welcome to analyzer-d4-passivedns Documentation

The `analyzer-d4-passivedns` project is a modern Passive DNS server that collects, stores, and serves DNS data compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). Built with FastAPI, it offers a high-performance, modular platform for processing DNS records from D4 sensors, COF websocket streams, and other sources, with auto-generated OpenAPI documentation for seamless integration.

## Overview

This project provides:
- **Data Ingestion**: Modular ingestors for D4 sensors, COF websockets, and custom sources.
- **Storage**: Dynamic database backends (Redis, Redis JSON) configured via `generic.json`.
- **API**: FastAPI-based endpoints (`/info`, `/query`, `/fquery`, `/stream`) with interactive OpenAPI docs at `/docs`.
- **Notifications**: Configurable alerts (e.g., email, webhooks) with a no-retry policy for efficiency.
- **Extensibility**: Easy addition of new ingestors, notifiers, and endpoints.

The documentation is divided into three sections:
- **[User Guide](./user/getting-started.md)**: For end-users querying the API to access Passive DNS data.
- **[Admin Guide](./admin/installation.md)**: For administrators installing, configuring, and managing the server.
- **[Developer Guide](./dev/contributing.md)**: For developers contributing to or extending the project.

## Getting Started

- **Users**: Start with the [User Guide](./user/getting-started.md) to learn how to query DNS records using the API.
- **Admins**: Follow the [Installation Guide](./admin/installation.md) to set up the server and configure the database.
- **Developers**: Check out the [Contributing Guide](./dev/contributing.md) to set up a development environment and start coding.

## Quick Start

1. **Install the Server**:
   ```bash
   git clone https://github.com/D4-project/analyzer-d4-passivedns.git
   cd analyzer-d4-passivedns
   poetry install
   ```

2. **Configure**:
   Edit `config/generic.json` to set the database backend:
   ```json
   {
     "database": {
       "type": "redis",
       "config": { "host": "localhost", "port": 6379, "db": 0 }
     }
   }
   ```

3. **Run the Server**:
   ```bash
   poetry run uvicorn pdns.main:app --host 0.0.0.0 --port 8000
   ```

4. **Explore the API**:
   Visit `http://localhost:8000/docs` for interactive OpenAPI documentation.

## Documentation

Built with [MkDocs](https://www.mkdocs.org/) and the Material theme, this documentation is sourced from the `docs/` directory. The source code and documentation are available on [GitHub](https://github.com/D4-project/analyzer-d4-passivedns).

For detailed setup, configuration, and development instructions, explore the respective guides linked above.