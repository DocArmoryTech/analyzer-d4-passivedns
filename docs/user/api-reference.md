# API Reference

This document provides a comprehensive reference for the `analyzer-d4-passivedns` API, a FastAPI-based Passive DNS server compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). All endpoints are documented with methods, parameters, authentication requirements, and response formats. The API’s OpenAPI specification is available at `http://localhost:8000/docs`.

## Overview

The API supports querying DNS data, retrieving server information, and streaming records. Endpoints are configured in `config/generic.json`, including authentication and rate limiting. Most endpoints require bearer token authentication.

## Endpoints

### 1. `/info`

**Description**: Retrieves server information, including version, statistics, and sensor details.

- **Method**: GET
- **Path**: `/info`
- **Authentication**: None (configurable in `generic.json`).
- **Rate Limit**: Configurable (e.g., 100 requests/60 seconds).
- **Parameters**: None.
- **Response**: JSON object with server details (`InfoResponse` schema).

**Example Request**:

```bash
curl http://localhost:8000/info
```

**Example Response**:

```json
{
  "version": "1.0.0",
  "software": "analyzer-d4-passivedns",
  "stats": {
    "total_records": 10000
  },
  "sensors": [
    {
      "sensor_id": "sensor1",
      "count": 5000
    }
  ]
}
```

**Errors**:
- `500 Internal Server Error`: Database connection failure or internal issue.
  ```json
  {"detail": "Database unavailable"}
  ```

### 2. `/query/{q}`

**Description**: Queries DNS records for a specific term (e.g., domain, IP).

- **Method**: GET
- **Path**: `/query/{q}`
- **Authentication**: Bearer token (configured in `generic.json`).
- **Rate Limit**: Configurable (e.g., 100 requests/60 seconds).
- **Parameters**:
  - `q` (path, string, required): Query term (e.g., `example.com`, `93.184.216.34`).
  - `limit` (query, integer, optional): Maximum records (default: 200, range: 1–1000).
  - `rrtype` (query, string, optional): Filter by record type (e.g., `A`, `AAAA`).
  - `format` (query, string, optional): Response format (`json`, `csv`, default: `json`).
- **Response**: List of `DNSRecord` objects (JSON) or CSV string.

**Example Request (JSON)**:

```bash
curl -H "Authorization: Bearer xyz123" "http://localhost:8000/query/example.com?limit=10&rrtype=A&format=json"
```

**Example Response (JSON)**:

```json
[
  {
    "rrname": "example.com",
    "rrtype": "A",
    "rdata": "93.184.216.34",
    "time_first": 1698777600,
    "time_last": 1698777600,
    "count": 1,
    "sensor_id": "sensor1"
  }
]
```

**Example Request (CSV)**:

```bash
curl -H "Authorization: Bearer xyz123" "http://localhost:8000/query/example.com?format=csv"
```

**Example Response (CSV)**:

```csv
rrname,rrtype,rdata,time_first,time_last,count,sensor_id
example.com,A,93.184.216.34,1698777600,1698777600,1,sensor1
```

**Errors**:
- `400 Bad Request`: Invalid query term or parameters.
  ```json
  {"detail": "Invalid rrtype"}
  ```
- `401 Unauthorized`: Missing or invalid token.
  ```json
  {"detail": "Invalid authentication credentials"}
  ```
- `429 Too Many Requests`: Rate limit exceeded.
  ```json
  {"detail": "Too many requests"}
  ```
- `500 Internal Server Error`: Query or database issue.
  ```json
  {"detail": "Internal server error"}
  ```

### 3. `/fquery/{q}`

**Description**: Performs a fuzzy query for DNS records, supporting partial matches.

- **Method**: GET
- **Path**: `/fquery/{q}`
- **Authentication**: Bearer token (configured in `generic.json`).
- **Rate Limit**: Configurable (e.g., 50 requests/60 seconds).
- **Parameters**:
  - `q` (path, string, required): Query term (e.g., `example`).
  - `limit` (query, integer, optional): Maximum records (default: 200, range: 1–1000).
  - `rrtype` (query, string, optional): Filter by record type.
- **Response**: List of `DNSRecord` objects.

**Example Request**:

```bash
curl -H "Authorization: Bearer xyz123" "http://localhost:8000/fquery/example?limit=5"
```

**Example Response**:

```json
[
  {
    "rrname": "example.com",
    "rrtype": "A",
    "rdata": "93.184.216.34",
    "time_first": 1698777600,
    "time_last": 1698777600,
    "count": 1,
    "sensor_id": "sensor1"
  },
  {
    "rrname": "example.org",
    "rrtype": "A",
    "rdata": "198.51.100.10",
    "time_first": 1698777600,
    "time_last": 1698777600,
    "count": 1,
    "sensor_id": "sensor1"
  }
]
```

**Errors**:
- `400 Bad Request`: Invalid query term or parameters.
- `401 Unauthorized`: Missing or invalid token.
- `429 Too Many Requests`: Rate limit exceeded.
- `500 Internal Server Error`: Query or database issue.

### 4. `/stream/{q}`

**Description**: Streams DNS records for a given term in real-time (WebSocket).

- **Method**: WebSocket
- **Path**: `/stream/{q}`
- **Authentication**: Bearer token (configured in `generic.json`).
- **Rate Limit**: Configurable (e.g., 10 connections/60 seconds).
- **Parameters**:
  - `q` (path, string, required): Query term (e.g., `example.com`).
  - `rrtype` (query, string, optional): Filter by record type.
- **Response**: Stream of `DNSRecord` objects as JSON.

**Example (Python)**:

```python
import asyncio
import websockets

async def stream():
    uri = "ws://localhost:8000/stream/example.com?rrtype=A"
    async with websockets.connect(uri, extra_headers={"Authorization": "Bearer xyz123"}) as ws:
        while True:
            message = await ws.recv()
            print(message)

asyncio.run(stream())
```

**Example Message**:

```json
{
  "rrname": "example.com",
  "rrtype": "A",
  "rdata": "93.184.216.34",
  "time_first": 1698777600,
  "time_last": 1698777600,
  "count": 1,
  "sensor_id": "sensor1"
}
```

**Errors**:
- `401 Unauthorized`: Invalid or missing token (WebSocket handshake fails).
- `429 Too Many Requests`: Too many active connections.
- `500 Internal Server Error`: Streaming or database issue.

## Authentication

Authentication is configured in `config/generic.json`:

```json
{
  "auth": {
    "endpoints": {
      "query": {"auth": "bearer"},
      "fquery": {"auth": "bearer"},
      "stream": {"auth": "bearer"},
      "info": {"auth": "none"}
    },
    "tokens": [
      {"name": "user", "value": "xyz123"}
    ]
  }
}
```

Include the token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer xyz123" http://localhost:8000/query/example.com
```

For WebSocket, include it in the request headers.

## Rate Limiting

Rate limits are configured in `config/generic.json`:

```json
{
  "rate_limit": {
    "query": {"requests": 100, "window": 60},
    "fquery": {"requests": 50, "window": 60},
    "stream": {"requests": 10, "window": 60}
  }
}
```

Exceeding limits returns a `429 Too Many Requests` error with a `Retry-After` header indicating the wait time.

## Notes

- **CSV Output**: The `/query/{q}` endpoint supports `format=csv` for data export, useful for analysis in tools like Excel or pandas.
- **COF Compliance**: Responses adhere to the COF standard, ensuring interoperability with other Passive DNS systems.
- **OpenAPI Spec**: Explore interactive endpoint documentation at `http://localhost:8000/docs`.

## Mermaid Diagram: API Interaction Workflow

```mermaid
graph TD
    A[Client] -->|GET /info| B[FastAPI Server]
    A -->|GET /query/{q}| C[Authenticate]
    A -->|GET /fquery/{q}| C
    A -->|WS /stream/{q}| C
    C -->|Check generic.json| D[Rate Limit]
    D -->|Query DB| E[DBManager]
    E -->|Return Records| B
    B -->|JSON/CSV Response| A
```

For related guides, see:

- [Querying DNS Data](./querying-dns.md)
- [Examples](./examples.md)
- [Schemas](./schemas.md)
- [Configuration](../admin/configuration.md)
- [Troubleshooting](../admin/troubleshooting.md)