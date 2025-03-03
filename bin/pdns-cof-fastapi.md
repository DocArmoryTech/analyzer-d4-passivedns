# Passive DNS COF FastAPI Server

**pdns-cof-fastapi.py** is an asynchronous implementation of a Passive DNS server, compliant with the [Passive DNS - Common Output Format (COF)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). Built with [FastAPI](https://fastapi.tiangolo.com/), it is an alternative to the Tornado-based server, offering interactive documentation, and extensible authentication. This server queries DNS data stored in a Redis compatible data store, supporting both newline-separated JSON (NDJSON) and true JSON responses for backwards compatibility and flexibility.

## Features

- **COF Compliance**: Returns DNS records in the Passive DNS Common Output Format.
- **Endpoints**: 
  - `/info`: Server statistics and sensor info.
  - `/query/{q}`: Single-domain lookups with pagination and filtering.
  - `/fquery/{q}`: Full associated record lookups (e.g., IPs to domains).
  - `/stream/{q}`: Streaming DNS records in NDJSON format.
- **Response Formats**: Supports NDJSON (default, backwards compatible) and JSON (array or object with metadata).
- **Interactive Docs**: Swagger UI at `/docs` (default via redirect from `/`) and ReDoc at `/redoc`.
- **Authentication**: Configurable via `AUTH_MODE` (none, bearer tokens, OpenID Connect placeholder).
- **Rate Limiting**: Built-in via `slowapi` to prevent abuse.
- **Pagination**: Cursor-based with `X-Total-Count`, `X-Next-Cursor`, and `X-Pagination-Required` headers.

## Requirements (supplemental)

- Python 3.8+
- Dependencies (install via `pip`):
  ```bash
  . ./PDNSENV/bin/activate/
  pip install fastapi uvicorn redis slowapi iptools
  ```
- Redis server (e.g., `redis-server` running on `127.0.0.1:6400`).

## Installation

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.fastapi
   ```
   Or manually:
   ```bash
   pip install fastapi uvicorn redis slowapi iptools
   ```

2. **Ensure Redis is Running**:
   Start Redis with defaults or configure via environment variables (see Configuration).

3. **Run the Server**:
   ```bash
   python pdns-cof-fastapi.py
   ```
   - Default: `http://0.0.0.0:8400/`
   - Access Swagger UI at `http://localhost:8400/` (redirects to `/docs`).

## Configuration

Environment variables customize the server’s behavior:

| Variable                  | Default                | Description                                      |
|---------------------------|------------------------|--------------------------------------------------|
| `D4_ANALYZER_REDIS_HOST`  | `127.0.0.1`           | Redis host address.                              |
| `D4_ANALYZER_REDIS_PORT`  | `6400`                | Redis port.                                      |
| `AUTH_MODE`               | `none`                | Authentication mode: `none`, `bearer`, `openid`. |
| `AUTH_TOKEN_FILE`         | `.tokens.json`        | Path to bearer token JSON file (for `bearer`).   |

### Authentication Modes
- **`none`**: No authentication (default).
- **`bearer`**: Requires a `.tokens.json` file with tokens:
  ```json
  {
    "tokens": [
      {"value": "abc123", "description": "Admin token"},
      {"value": "xyz789", "description": "User token"}
    ]
  }
  ```
  - Tokens reload every 60 seconds in a background thread.
- **`openid`**: Placeholder for future OpenID Connect support (returns 501).

## API Endpoints

### Root (`/`)
- **GET**: Redirects to `/docs` (Swagger UI).
- **Purpose**: Default entry point for interactive documentation.

### Info (`/info`)
- **GET**: Retrieve server statistics and sensor data.
- **Response**: JSON object (e.g., `{"version": "git", "software": "analyzer-d4-passivedns", "stats": 5000, "sensors": [...]}`).
- **Rate Limit**: 100/minute.
- **Example**: `curl http://localhost:8400/info`

### Query (`/query/{q}`)
- **GET**: Query DNS records for a single domain.
- **Parameters**:
  - `q` (path): Domain name (e.g., `example.com`).
  - `cursor` (query, optional): Pagination cursor.
  - `limit` (query, default=200): Max records per response (10-1000).
  - `rrtype` (query, optional): Filter by RR type (e.g., `A`, `AAAA`).
  - `metadata` (query, default=false): Include total and cursor in JSON response.
  - `time_format` (query, default=`unix`): `unix` (timestamps) or `iso` (ISO 8601).
  - `format` (query, default=`ndjson`): `ndjson` (newline-separated) or `json` (array/object).
- **Response**:
  - `ndjson`: Newline-separated JSON strings (`application/x-ndjson`).
  - `json`: Array or object with metadata (`application/json`).
- **Headers**: `X-Total-Count`, `X-Next-Cursor`, `X-Pagination-Required`.
- **Rate Limit**: 50/minute.
- **Example**:
  - NDJSON: `curl http://localhost:8400/query/example.com`
  - JSON: `curl http://localhost:8400/query/example.com?format=json`

### Full Query (`/fquery/{q}`)
- **GET**: Query associated DNS records (e.g., IP to domains).
- **Parameters**: Same as `/query/{q}`.
- **Response**: Same as `/query/{q}`.
- **Rate Limit**: 50/minute.
- **Example**: `curl http://localhost:8400/fquery/8.8.8.8`

### Stream (`/stream/{q}`)
- **GET**: Stream DNS records for a domain or IP.
- **Parameters**:
  - `q` (path): Domain or IP.
  - `chunk_size` (query, default=100): Records per chunk (10-1000).
  - `rrtype` (query, optional): Filter by RR type.
  - `time_format` (query, default=`unix`): `unix` or `iso`.
- **Response**: NDJSON (`application/x-ndjson`).
- **Rate Limit**: 20/minute.
- **Example**: `curl http://localhost:8400/stream/example.com`

## Interactive Documentation
- **Swagger UI**: `/docs` (default via redirect from `/`).
- **ReDoc**: `/redoc`.
- Access via browser at `http://localhost:8400/` or `http://localhost:8400/redoc`.

## Error Handling
- **503 Service Unavailable**: Returned when Redis is unavailable or loading:
  - `"Loading dataset... Please try again shortly."` (`Retry-After: 10`).
  - `"Dataset temporarily unavailable. Please try again later."` (`Retry-After: 5`).
- **400 Bad Request**: Invalid `rrtype` with supported types listed.
- **429 Too Many Requests**: Rate limit exceeded.

## Development
- **Source**: Part of the D4 Project by CIRCL.
- **License**: GNU Affero General Public License v3.
- **Contributing**: Submit issues or PRs to the repository (if hosted).

## Notes
- Redis must be configured with Passive DNS data (e.g., via `analyzer-d4-passivedns`).
- Bearer token reloading occurs every 60 seconds in a background thread.

For support, contact [CIRCL](mailto:info@circl.lu).