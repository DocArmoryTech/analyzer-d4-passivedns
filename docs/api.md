# API Documentation

The Passive DNS Analyzer exposes the following endpoints, built with FastAPI and rate-limited using `slowapi`.

## Base URL
- `/`

## Endpoints

### `/fquery/{q}`
- **Method**: GET
- **Description**: Queries DNS records and associated records (e.g., domains for an IP).
- **Rate Limit**: 50/minute
- **Parameters**:
  - `q` (path): Query string (domain or IP).
  - `cursor` (query, optional): Pagination cursor.
  - `limit` (query, default=200): Max records (10-1000).
  - `rrtype` (query, optional): Filter by RR type (e.g., "A", "AAAA").
  - `metadata` (query, default=false): Wrap response in metadata object.
  - `time_format` (query, default="unix"): "unix" (int) or "iso" (string).
  - `format` (query, default="ndjson"): "ndjson" or "json".
- **Response**:
  - **NDJSON** (`format=ndjson`): Stream of `PDNSRecordSchema` objects.
  - **JSON** (`format=json`, `metadata=false`): List of `PDNSRecordSchema` objects.
  - **JSON with Metadata** (`format=json`, `metadata=true`): `MetadataResponse` object.
- **Headers**: `X-Total-Count`, `X-Next-Cursor`, `X-Pagination-Required`.
- **Example**:
  ```
  GET /fquery/example.com?format=json&metadata=true
  ```
  ```json
  {
    "data": [{"rrname": "example.com", "rrtype": "A", "rdata": ["192.0.2.1"], "time_first": 1548624738, "time_last": 1548624799, "count": 5, "sensor_id": null}],
    "total": 1,
    "next_cursor": null
  }
  ```

### `/stream/{q}`
- **Method**: GET
- **Description**: Streams DNS records for a query in NDJSON format.
- **Rate Limit**: 20/minute
- **Parameters**:
  - `q` (path): Query string (domain or IP).
  - `chunk_size` (query, default=100): Records per chunk (10-1000).
  - `rrtype` (query, optional): Filter by RR type.
  - `time_format` (query, default="unix"): "unix" or "iso".
- **Response**: NDJSON stream of `PDNSRecordSchema` objects.
- **Example**:
  ```
  GET /stream/example.com
  ```
  ```
  {"rrname": "example.com", "rrtype": "A", "rdata": ["192.0.2.1"], "time_first": 1548624738, "time_last": 1548624799, "count": 5, "sensor_id": null}
  ```

### `/query/{q}`
- **Method**: GET
- **Description**: Queries DNS records for a specific domain.
- **Rate Limit**: 50/minute
- **Parameters**: Same as `/fquery`.
- **Response**: Same as `/fquery`.
- **Example**: Similar to `/fquery`.

### `/info`
- **Method**: GET
- **Description**: Returns system stats and sensor info.
- **Rate Limit**: 100/minute
- **Response**: `InfoResponse` object.
- **Example**:
  ```
  GET /info
  ```
  ```json
  {
    "version": "git",
    "software": "analyzer-d4-passivedns",
    "stats": {"records": 1000},
    "sensors": [{"sensor_id": "sensor1", "count": 500}]
  }
  ```
