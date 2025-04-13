# API Reference

This section documents the available API endpoints: `/info`, `/query/{q}`, `/fquery/{q}`, and `/stream/{q}`.

## /info

**Description**: Returns metadata about the Passive DNS server.

- **Method**: GET
- **Path**: `/info`
- **Parameters**: None
- **Response**:
  - `version` (string): Software version.
  - `software` (string): Software name.
  - `stats` (object): Database statistics.
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
  - `q` (string, required): Domain (e.g., "example.com").
  - `cursor` (string, optional): Pagination cursor.
  - `limit` (integer, optional): Max records (1–1000, default: 200).
  - `rrtype` (string, optional): Filter by RR type (e.g., "A").
  - `metadata` (boolean, optional): Include metadata (default: false).
  - `time_format` (string, optional): "unix" or "iso" (default: "unix").
  - `format` (string, optional): "ndjson" or "json" (default: "ndjson").

**Response**: NDJSON or JSON array of records with headers `X-Total-Count` and `X-Next-Cursor`.

**Example**:
```bash
curl http://localhost:8000/query/example.com?limit=2
```

**Response (NDJSON)**:
```
{"time_first": 1698777600, "time_last": 1698777600, "rrname": "example.com", "rrtype": "A", "rdata": "93.184.216.34"}
{"time_first": 1698777600, "time_last": 1698777600, "rrname": "example.com", "rrtype": "AAAA", "rdata": "2606:2800:220:1:248:1893:25c8:1946"}
```

## /fquery/{q}

**Description**: Queries associated DNS records for a domain or IP.

- **Method**: GET
- **Path**: `/fquery/{q}`
- **Parameters**: Same as `/query/{q}`.

**Response**: NDJSON or JSON with associated records.

**Example**:
```bash
curl http://localhost:8000/fquery/93.184.216.34
```

## /stream/{q}

**Description**: Streams DNS records for a domain or IP.

- **Method**: GET
- **Path**: `/stream/{q}`
- **Parameters**:
  - `q` (string, required): Domain or IP.
  - `chunk_size` (integer, optional): Records per chunk (10–1000, default: 100).
  - `rrtype` (string, optional): Filter by RR type.
  - `time_format` (string, optional): "unix" or "iso".

**Response**: NDJSON stream.

**Example**:
```bash
curl http://localhost:8000/stream/example.com
```
