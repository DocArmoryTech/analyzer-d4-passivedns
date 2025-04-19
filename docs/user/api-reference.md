# API Reference

This section documents the available API endpoints for the `analyzer-d4-passivedns` server, a FastAPI-based Passive DNS server compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). Endpoints include `/info`, `/query/{q}`, `/fquery/{q}`, and `/stream/{q}`. All endpoints are accessible via the interactive OpenAPI interface at `http://localhost:8000/docs`.

## Authentication

Some endpoints may require authentication, configured in `config/generic.json` under the `auth` section. If `auth` is set to `bearer` for an endpoint, include a token from `auth.tokens` in the `Authorization` header:

```bash
curl -H "Authorization: Bearer xyz123" http://localhost:8000/query/example.com
```

Example `generic.json` snippet:

```json
{
  "auth": {
    "endpoints": {
      "query": {"auth": "bearer"},
      "info": {"auth": "none"}
    },
    "tokens": {
      "admin": "xyz123",
      "user": "abc456"
    }
  }
}
```

Check with your administrator for token details.

## /info

**Description**: Returns metadata about the Passive DNS server, including version, statistics, and sensor information.

- **Method**: GET
- **Path**: `/info`
- **Parameters**: None
- **Authentication**: Configurable (`none` or `bearer` via `generic.json`).
- **Response**:
  - `version` (string): Software version.
  - `software` (string): Software name.
  - `stats` (object): Database statistics (e.g., `total_records`).
  - `sensors` (array): List of sensors with IDs and record counts.

**Example**:

```bash
curl http://localhost:8000/info
```

**Response**:

```json
{
  "version": "1.0.0",
  "software": "analyzer-d4-passivedns",
  "stats": { "total_records": 10000 },
  "sensors": [ { "sensor_id": "sensor1", "count": 5000 } ]
}
```

## /query/{q}

**Description**: Retrieves DNS records for a specific domain.

- **Method**: GET
- **Path**: `/query/{q}`
- **Parameters**:
  - `q` (string, required): Domain (e.g., `example.com`).
  - `cursor` (string, optional): Pagination cursor for next page.
  - `limit` (integer, optional): Max records to return (1–1000, default: 200).
  - `rrtype` (string, optional): Filter by record type (e.g., `A`).
  - `metadata` (boolean, optional): Include metadata like total count (default: `false`).
  - `time_format` (string, optional): Timestamp format (`unix` or `iso`, default: `unix`).
  - `format` (string, optional): Response format (`ndjson` or `json`, default: `ndjson`).
- **Authentication**: Configurable (`none` or `bearer` via `generic.json`).
- **Response**:
  - NDJSON or JSON array of records.
  - Headers: `X-Total-Count` (total matching records), `X-Next-Cursor` (next page cursor).
  - If `metadata=true`, returns a JSON object with `data`, `total`, and `next_cursor`.

**Example**:

```bash
curl "http://localhost:8000/query/example.com?limit=2&format=json"
```

**Response (JSON)**:

```json
[
  {
    "time_first": 1698777600,
    "time_last": 1698777600,
    "rrname": "example.com",
    "rrtype": "A",
    "rdata": "93.184.216.34"
  },
  {
    "time_first": 1698777600,
    "time_last": 1698777600,
    "rrname": "example.com",
    "rrtype": "AAAA",
    "rdata": "2606:2800:220:1:248:1893:25c8:1946"
  }
]
```

**Example with Metadata**:

```bash
curl "http://localhost:8000/query/example.com?metadata=true&format=json"
```

**Response**:

```json
{
  "data": [
    {
      "time_first": 1698777600,
      "time_last": 1698777600,
      "rrname": "example.com",
      "rrtype": "A",
      "rdata": "93.184.216.34"
    }
  ],
  "total": 1,
  "next_cursor": null
}
```

## /fquery/{q}

**Description**: Queries associated DNS records for a domain or IP, returning records linked to the query term.

- **Method**: GET
- **Path**: `/fquery/{q}`
- **Parameters**:
  - Same as `/query/{q}`.
- **Authentication**: Configurable (`none` or `bearer` via `generic.json`).
- **Response**: NDJSON or JSON array of associated records with headers `X-Total-Count` and `X-Next-Cursor`.

**Example**:

```bash
curl http://localhost:8000/fquery/93.184.216.34
```

**Response (NDJSON)**:

```
{"time_first": 1698777600, "time_last": 1698777600, "rrname": "example.com", "rrtype": "A", "rdata": "93.184.216.34"}
{"time_first": 1698777600, "time_last": 1698777600, "rrname": "another.com", "rrtype": "A", "rdata": "93.184.216.34"}
```

## /stream/{q}

**Description**: Streams DNS records for a domain or IP, ideal for large datasets.

- **Method**: GET
- **Path**: `/stream/{q}`
- **Parameters**:
  - `q` (string, required): Domain or IP.
  - `chunk_size` (integer, optional): Records per chunk (10–1000, default: 100).
  - `rrtype` (string, optional): Filter by record type.
  - `time_format` (string, optional): Timestamp format (`unix` or `iso`, default: `unix`).
- **Authentication**: Configurable (`none` or `bearer` via `generic.json`).
- **Response**: NDJSON stream of records.

**Example**:

```bash
curl http://localhost:8000/stream/example.com?chunk_size=1
```

**Response (NDJSON)**:

```
{"time_first": 1698777600, "time_last": 1698777600, "rrname": "example.com", "rrtype": "A", "rdata": "93.184.216.34"}
```

## Error Responses

- **401 Unauthorized**:
  - Missing or invalid bearer token when authentication is required.
  - Example:
    ```json
    {"detail": "Invalid or missing authentication credentials"}
    ```

- **429 Too Many Requests**:
  - Rate limit exceeded (configured via `generic.json`’s `rate_limit` section).
  - Example:
    ```json
    {"detail": "Too many requests"}
    ```

- **500 Internal Server Error**:
  - Database or internal issue.
  - Check server logs (`pdns.log`) for details.

## Interactive Exploration

- Access the interactive OpenAPI documentation at `http://localhost:8000/docs` to test endpoints, view schemas, and execute queries.
- Download the OpenAPI spec:
  ```bash
  curl http://localhost:8000/openapi.json
  ```

For practical examples, see [Examples](./examples.md). For response schemas, see [Schemas](./schemas.md).