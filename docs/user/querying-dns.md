# Querying DNS Records

This guide explains how to query DNS records using the `analyzer-d4-passivedns` API, a FastAPI-based Passive DNS server compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). The API provides endpoints (`/query/{q}`, `/fquery/{q}`, `/stream/{q}`) to retrieve DNS records, with flexible parameters for filtering, pagination, and formatting. All endpoints are documented in the interactive OpenAPI interface at `http://localhost:8000/docs`.

## Authentication

Some endpoints may require authentication, configured in `config/generic.json` under the `auth` section. If `auth` is set to `bearer`, include a token from `auth.tokens` in the `Authorization` header:

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
    "tokens": [
      {"name": "user", "value": "xyz123"}
    ]
  }
}
```

Check with your administrator for token details.

## Query Endpoints

### /query/{q}

Retrieves DNS records for a specific domain.

- **Parameters**:
  - `q` (string, required): Domain name (e.g., `example.com`).
  - `cursor` (string, optional): Pagination cursor for the next page.
  - `limit` (integer, optional): Max records to return (1–1000, default: 200).
  - `rrtype` (string, optional): Filter by record type (e.g., `A`, `AAAA`).
  - `metadata` (boolean, optional): Include metadata like total count (default: `false`).
  - `time_format` (string, optional): Timestamp format (`unix` or `iso`, default: `unix`).
  - `format` (string, optional): Response format (`ndjson` or `json`, default: `ndjson`).

- **Example** (Filter by RR type, JSON format):

  ```bash
  curl -H "Authorization: Bearer xyz123" "http://localhost:8000/query/example.com?rrtype=A&limit=1&format=json"
  ```

  **Response**:

  ```json
  [
    {
      "time_first": 1698777600,
      "time_last": 1698777600,
      "rrname": "example.com",
      "rrtype": "A",
      "rdata": "93.184.216.34",
      "count": 1,
      "sensor_id": "sensor1"
    }
  ]
  ```

- **Example** (With metadata):

  ```bash
  curl -H "Authorization: Bearer xyz123" "http://localhost:8000/query/example.com?metadata=true&format=json"
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
        "rdata": "93.184.216.34",
        "count": 1,
        "sensor_id": "sensor1"
      }
    ],
    "total": 1,
    "next_cursor": null
  }
  ```

### /fquery/{q}

Queries associated DNS records for a domain or IP, returning records linked to the query term (e.g., domains resolving to an IP).

- **Parameters**: Same as `/query/{q}`.
- **Example** (Query IP):

  ```bash
  curl -H "Authorization: Bearer xyz123" "http://localhost:8000/fquery/93.184.216.34?format=json"
  ```

  **Response**:

  ```json
  [
    {
      "time_first": 1698777600,
      "time_last": 1698777600,
      "rrname": "example.com",
      "rrtype": "A",
      "rdata": "93.184.216.34",
      "count": 1,
      "sensor_id": "sensor1"
    },
    {
      "time_first": 1698777600,
      "time_last": 1698777600,
      "rrname": "another.com",
      "rrtype": "A",
      "rdata": "93.184.216.34",
      "count": 1,
      "sensor_id": "sensor2"
    }
  ]
  ```

### /stream/{q}

Streams DNS records for a domain or IP, ideal for large datasets.

- **Parameters**:
  - `q` (string, required): Domain or IP.
  - `chunk_size` (integer, optional): Records per chunk (10–1000, default: 100).
  - `rrtype` (string, optional): Filter by record type.
  - `time_format` (string, optional): Timestamp format (`unix` or `iso`, default: `unix`).

- **Example**:

  ```bash
  curl -H "Authorization: Bearer xyz123" "http://localhost:8000/stream/example.com?chunk_size=1&time_format=iso"
  ```

  **Response** (NDJSON):

  ```
  {"time_first": "2023-10-31T12:00:00Z", "time_last": "2023-10-31T12:00:00Z", "rrname": "example.com", "rrtype": "A", "rdata": "93.184.216.34", "count": 1, "sensor_id": "sensor1"}
  ```

## Query Tips

- **Pagination**:
  - Use `cursor` to fetch the next page of results:
    ```bash
    curl -H "Authorization: Bearer xyz123" "http://localhost:8000/query/example.com?cursor=<previous_cursor>"
    ```
  - Check `X-Next-Cursor` header or `next_cursor` in `MetadataResponse` for the next cursor value.

- **Filtering**:
  - Combine `rrtype` with `limit` to narrow results:
    ```bash
    curl -H "Authorization: Bearer xyz123" "http://localhost:8000/query/example.com?rrtype=CNAME&limit=10"
    ```

- **Format Options**:
  - Use `format=json` for structured JSON arrays, ideal for programmatic use.
  - Use `format=ndjson` (default) for streaming or lightweight responses.
  - Use `time_format=iso` for human-readable timestamps.

- **Error Handling**:
  - **401 Unauthorized**: Invalid or missing token. Verify your token in `generic.json`’s `auth.tokens`.
  - **429 Too Many Requests**: Rate limit exceeded. Check `generic.json`’s `rate_limit` settings.
  - **500 Internal Server Error**: Server issue. Contact your administrator and check `pdns.log`.

- **Interactive Testing**:
  - Use the OpenAPI interface at `http://localhost:8000/docs` to experiment with parameters and view responses.
  - Download the OpenAPI spec:
    ```bash
    curl http://localhost:8000/openapi.json
    ```

## Use Cases

- **Threat Hunting**: Use `/fquery/{q}` to find domains resolving to a suspicious IP.
- **Historical Analysis**: Use `/query/{q}` with `metadata=true` to analyze record counts over time.
- **Real-Time Monitoring**: Use `/stream/{q}` to feed DNS data into a SIEM system.

For practical examples, see [Examples](./examples.md). For schema details, see [Schemas](./schemas.md). For endpoint documentation, see [API Reference](./api-reference.md).