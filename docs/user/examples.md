# API Usage Examples

This guide provides practical examples for using the `analyzer-d4-passivedns` API to query Passive DNS data, compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). Built with FastAPI, the API offers endpoints like `/info`, `/query/{q}`, `/fquery/{q}`, and `/stream/{q}`, accessible via the interactive OpenAPI interface at `http://localhost:8000/docs`. These examples demonstrate common use cases for network security analysts, researchers, and administrators.

## Prerequisites

- A running Passive DNS server (e.g., `http://localhost:8000`).
- A bearer token if authentication is enabled in `config/generic.json` (check with your administrator).
- Tools like `curl`, Python (`requests`), or Postman for making HTTP requests.

## Example 1: Check Server Status

**Goal**: Verify the server is running and view its metadata.

**Request**:

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

**Use Case**: Confirm the server’s availability and check the number of records or active sensors before querying.

## Example 2: Query DNS Records for a Domain

**Goal**: Retrieve all DNS records for `example.com` with authentication.

**Request**:

Assuming `generic.json` requires a bearer token for `/query`:

```json
{
  "auth": {
    "endpoints": { "query": {"auth": "bearer"} },
    "tokens": { "user": "xyz123" }
  }
}
```

```bash
curl -H "Authorization: Bearer xyz123" "http://localhost:8000/query/example.com?limit=2&format=json"
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
    "rrname": "example.com",
    "rrtype": "AAAA",
    "rdata": "2606:2800:220:1:248:1893:25c8:1946",
    "count": 1,
    "sensor_id": "sensor1"
  }
]
```

**Use Case**: Investigate the IP addresses associated with a domain to identify potential malicious infrastructure.

## Example 3: Query Associated Records for an IP

**Goal**: Find all domains resolving to a specific IP address.

**Request**:

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

**Use Case**: Identify domains hosted on a suspicious IP to detect shared infrastructure in phishing campaigns.

## Example 4: Stream Large Datasets

**Goal**: Stream DNS records for a domain to handle large volumes of data.

**Request**:

```bash
curl -H "Authorization: Bearer xyz123" "http://localhost:8000/stream/example.com?chunk_size=1&time_format=iso"
```

**Response** (NDJSON):

```
{"time_first": "2023-10-31T12:00:00Z", "time_last": "2023-10-31T12:00:00Z", "rrname": "example.com", "rrtype": "A", "rdata": "93.184.216.34", "count": 1, "sensor_id": "sensor1"}
```

**Use Case**: Process large datasets incrementally for analysis in tools like Splunk or custom scripts.

## Example 5: Query with Metadata

**Goal**: Retrieve DNS records with pagination metadata for a specific RR type.

**Request**:

```bash
curl -H "Authorization: Bearer xyz123" "http://localhost:8000/query/example.com?rrtype=A&metadata=true&format=json"
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

**Use Case**: Build a paginated UI for displaying DNS records or track the total number of matches.

## Example 6: Python Script for Querying

**Goal**: Automate queries using Python and the `requests` library.

**Code**:

```python
import requests

url = "http://localhost:8000/query/example.com"
headers = {"Authorization": "Bearer xyz123"}
params = {"limit": 10, "format": "json", "rrtype": "A"}

response = requests.get(url, headers=headers, params=params)
if response.status_code == 200:
    records = response.json()
    for record in records:
        print(f"Domain: {record['rrname']}, IP: {record['rdata']}")
else:
    print(f"Error: {response.json()['detail']}")
```

**Output**:

```
Domain: example.com, IP: 93.184.216.34
```

**Use Case**: Automate DNS record collection for integration with threat intelligence platforms.

## Tips

- **Interactive Testing**: Use the OpenAPI interface at `http://localhost:8000/docs` to test endpoints without writing code.
- **Authentication**: Always include the bearer token if required (check `generic.json`’s `auth.endpoints`).
- **Error Handling**: Handle `401 Unauthorized` (invalid token) or `429 Too Many Requests` (rate limit) errors gracefully.
- **Explore Schemas**: See [Schemas](./schemas.md) for response formats and field details.

For endpoint details, see [API Reference](./api-reference.md). For query syntax, see [Querying DNS Records](./querying-dns.md).