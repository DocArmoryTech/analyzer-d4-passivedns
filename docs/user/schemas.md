# Schemas

This document describes the data schemas used in the `analyzer-d4-passivedns` API responses, defined using Pydantic models and exposed via the FastAPI OpenAPI specification at `http://localhost:8000/docs`. These schemas ensure consistent data structures for DNS records and API metadata, compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof).

## DNSRecord

The `DNSRecord` schema represents a single DNS record, used in responses from `/query/{q}`, `/fquery/{q}`, and `/stream/{q}` endpoints.

- **Fields**:
  - `time_first` (integer or string): Earliest timestamp of the record (Unix epoch or ISO format, based on `time_format` parameter).
  - `time_last` (integer or string): Latest timestamp of the record.
  - `rrname` (string): Domain name (e.g., `example.com`).
  - `rrtype` (string): Record type (e.g., `A`, `AAAA`, `CNAME`).
  - `rdata` (string or array): Record data (e.g., IP address, CNAME target). May be an array for multiple values.
  - `count` (integer): Number of times the record was observed.
  - `sensor_id` (string, optional): Identifier of the sensor that captured the record.

- **Example** (NDJSON, default format for `/query`):
  ```
  {"time_first": 1698777600, "time_last": 1698777600, "rrname": "example.com", "rrtype": "A", "rdata": "93.184.216.34", "count": 1, "sensor_id": "sensor1"}
  ```

- **Example** (JSON, with `format=json`):
  ```json
  {
    "time_first": 1698777600,
    "time_last": 1698777600,
    "rrname": "example.com",
    "rrtype": "A",
    "rdata": "93.184.216.34",
    "count": 1,
    "sensor_id": "sensor1"
  }
  ```

- **Example** (ISO time format, with `time_format=iso`):
  ```json
  {
    "time_first": "2023-10-31T12:00:00Z",
    "time_last": "2023-10-31T12:00:00Z",
    "rrname": "example.com",
    "rrtype": "A",
    "rdata": "93.184.216.34",
    "count": 1,
    "sensor_id": "sensor1"
  }
  ```

## MetadataResponse

The `MetadataResponse` schema wraps DNS records with pagination metadata, used when the `metadata=true` parameter is set in `/query/{q}` or `/fquery/{q}`.

- **Fields**:
  - `data` (array): List of `DNSRecord` objects.
  - `total` (integer): Total number of matching records.
  - `next_cursor` (string, optional): Cursor for the next page of results.

- **Example**:
  ```json
  {
    "data": [
      {
        "time_first": 1698777600,
        "time_last": 1698777600,
        "rrname": "example.com",
        "rrtype": "A",
        "rdata": "93.184.216.34",
        "count": 1,
        "sensor_id": "sensor1"
      }
    ],
    "total": 1,
    "next_cursor": null
  }
  ```

## InfoResponse

The `InfoResponse` schema provides metadata about the server, used in the `/info` endpoint.

- **Fields**:
  - `version` (string): Software version (e.g., `1.0.0`).
  - `software` (string): Software name (e.g., `analyzer-d4-passivedns`).
  - `stats` (object): Database statistics (e.g., `total_records`).
  - `sensors` (array): List of sensor objects with `sensor_id` (string) and `count` (integer).

- **Example**:
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

## ErrorResponse

The `ErrorResponse` schema is used for error responses (e.g., 401, 429, 500).

- **Fields**:
  - `detail` (string): Error message.

- **Example** (401 Unauthorized):
  ```json
  {
    "detail": "Invalid or missing authentication credentials"
  }
  ```

- **Example** (429 Too Many Requests):
  ```json
  {
    "detail": "Too many requests"
  }
  ```

## Usage Notes

- **Formats**: By default, `/query` and `/fquery` return NDJSON for streaming compatibility. Use `format=json` for JSON arrays or `metadata=true` for `MetadataResponse`.
- **Authentication**: Endpoints requiring authentication (configured in `generic.json`’s `auth.endpoints`) need a bearer token from `auth.tokens`:
  ```bash
  curl -H "Authorization: Bearer xyz123" http://localhost:8000/query/example.com
  ```
  Example `generic.json` snippet:
  ```json
  {
    "auth": {
      "endpoints": {
        "query": {"auth": "bearer"}
      },
      "tokens": {
        "admin": "xyz123"
      }
    }
  }
  ```
- **Interactive Exploration**: View these schemas in the OpenAPI documentation at `http://localhost:8000/docs` or download the spec:
  ```bash
  curl http://localhost:8000/openapi.json
  ```

For practical examples using these schemas, see [Examples](./examples.md). For endpoint details, see [API Reference](./api-reference.md).