# Schemas

This guide describes the data schemas used in the `analyzer-d4-passivedns` API, a FastAPI-based Passive DNS server compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). The API uses Pydantic models defined in `pdns/schemas/` to validate and structure responses. This document details the primary schemas (`DNSRecord` and `InfoResponse`) and their fields, which are used in endpoints like `/info`, `/query/{q}`, `/fquery/{q}`, and `/stream/{q}`.

## Overview

The schemas ensure that API responses are consistent, typed, and compliant with the COF standard. They are used to:
- Validate data returned by the database (e.g., Redis, KV Rocks).
- Structure JSON responses for API endpoints.
- Provide clear documentation via the OpenAPI specification at `http://localhost:8000/docs`.

## Schema: `DNSRecord`

The `DNSRecord` schema represents a single Passive DNS record, used in the `/query/{q}`, `/fquery/{q}`, and `/stream/{q}` endpoints.

### Fields

| Field         | Type   | Description                                                                 | COF Compliance | Required | Example Value         |
|---------------|--------|-----------------------------------------------------------------------------|----------------|----------|-----------------------|
| `rrname`      | String | The resource record name (e.g., domain name).                                | Required       | Yes      | `example.com`         |
| `rrtype`      | String | The resource record type (e.g., `A`, `AAAA`, `CNAME`).                       | Required       | Yes      | `A`                   |
| `rdata`       | String | The resource record data (e.g., IP address, CNAME target).                   | Required       | Yes      | `93.184.216.34`       |
| `time_first`  | Integer| UNIX timestamp of when the record was first seen.                           | Required       | Yes      | `1698777600`          |
| `time_last`   | Integer| UNIX timestamp of when the record was last seen.                            | Required       | Yes      | `1698777600`          |
| `count`       | Integer| Number of times the record was observed.                                    | Optional       | No       | `1`                   |
| `sensor_id`   | String | Identifier of the sensor that captured the record.                           | Optional       | No       | `sensor1`             |

### JSON Schema Representation

```json
{
  "type": "object",
  "required": ["rrname", "rrtype", "rdata", "time_first", "time_last"],
  "properties": {
    "rrname": {"type": "string"},
    "rrtype": {"type": "string", "enum": ["A", "AAAA", "CNAME"]},
    "rdata": {"type": "string"},
    "time_first": {"type": "integer"},
    "time_last": {"type": "integer"},
    "count": {"type": "integer", "minimum": 1},
    "sensor_id": {"type": "string"}
  }
}
```

### Example

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

### Usage

- **`/query/{q}`**: Returns a list of `DNSRecord` objects matching the query term.
- **`/fquery/{q}`**: Returns a list of `DNSRecord` objects for fuzzy matches.
- **`/stream/{q}`**: Streams `DNSRecord` objects in real-time via WebSocket.

## Schema: `InfoResponse`

The `InfoResponse` schema represents the server information returned by the `/info` endpoint.

### Fields

| Field       | Type   | Description                                                                 | Required | Example Value                              |
|-------------|--------|-----------------------------------------------------------------------------|----------|--------------------------------------------|
| `version`   | String | The server software version.                                                | Yes      | `1.0.0`                                    |
| `software`  | String | The name of the server software.                                            | Yes      | `analyzer-d4-passivedns`                   |
| `stats`     | Object | Statistics about the server, including total records.                       | Yes      | `{"total_records": 10000}`                 |
| `sensors`   | Array  | List of sensor objects with their IDs and record counts.                    | Yes      | `[{"sensor_id": "sensor1", "count": 5000}]`|

#### `stats` Sub-Object

| Field            | Type   | Description                              | Required | Example Value |
|------------------|--------|------------------------------------------|----------|---------------|
| `total_records`  | Integer| Total number of records in the database. | Yes      | `10000`       |

#### `sensors` Sub-Object

| Field        | Type   | Description                          | Required | Example Value |
|--------------|--------|--------------------------------------|----------|---------------|
| `sensor_id`  | String | Identifier of the sensor.            | Yes      | `sensor1`     |
| `count`      | Integer| Number of records from this sensor.  | Yes      | `5000`        |

### Example

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
    },
    {
      "sensor_id": "sensor2",
      "count": 5000
    }
  ]
}
```

### Usage

- **`/info`**: Returns an `InfoResponse` object with server metadata.

## Schema Validation

Pydantic ensures that:
- Required fields (`rrname`, `rrtype`, `rdata`, `time_first`, `time_last` for `DNSRecord`) are present.
- `rrtype` values match `rrset_supported` in `generic.json`:
  ```json
  {
    "rrset_supported": ["A", "AAAA", "CNAME"]
  }
  ```
- Timestamps (`time_first`, `time_last`) are valid UNIX integers.
- Optional fields (`count`, `sensor_id`) are included only when available.

Validation errors are caught before data reaches the API response, ensuring COF-compliant output. For example, an invalid `rrtype` will raise a server-side error, logged in `pdns.log`.

## Configuration Context

Schemas are influenced by the `generic.json` configuration:

```json
{
  "rrset_supported": ["A", "AAAA", "CNAME"],
  "expiration": {
    "A": 86400,
    "AAAA": 86400,
    "CNAME": 86400
  }
}
```

- `rrset_supported`: Restricts `rrtype` values in `DNSRecord`.
- `expiration`: Determines record retention, affecting `time_first` and `time_last`.

See [Configuration](../admin/configuration.md) for details.

## Mermaid Diagram: Schema Relationships

```mermaid
classDiagram
    class DNSRecord {
        +String rrname
        +String rrtype
        +String rdata
        +Integer time_first
        +Integer time_last
        +Integer count
        +String sensor_id
    }
    class InfoResponse {
        +String version
        +String software
        +Stats stats
        +Sensor[] sensors
    }
    class Stats {
        +Integer total_records
    }
    class Sensor {
        +String sensor_id
        +Integer count
    }
    InfoResponse o--> "1" Stats
    InfoResponse o--> "many" Sensor
    DNSRecord --> "/query,/fquery,/stream" : Used in
    InfoResponse --> "/info" : Used in
```

## Notes

- **COF Compliance**: The `DNSRecord` schema adheres to the COF standard, ensuring interoperability with other Passive DNS systems.
- **Optional Fields**: `count` and `sensor_id` are included only when provided by ingestors, enhancing flexibility.
- **OpenAPI Integration**: Schemas are exposed in the OpenAPI spec at `http://localhost:8000/docs` for interactive exploration.
- **Extensibility**: Additional fields can be added to `DNSRecord` for custom use cases, as long as COF-required fields are preserved.

For related guides, see:

- [Querying DNS Data](./querying-dns.md)
- [API Reference](./api-reference.md)
- [Examples](./examples.md)
- [Configuration](../admin/configuration.md)
- [Troubleshooting](../admin/troubleshooting.md)