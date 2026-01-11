# Examples

This guide provides practical examples for querying the `analyzer-d4-passivedns` API, a FastAPI-based Passive DNS server compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). It demonstrates how to use the API endpoints (`/info`, `/query/{q}`, `/fquery/{q}`, `/stream/{q}`) with tools like `curl`, Python, and JavaScript, covering use cases such as domain lookups, IP queries, fuzzy searches, CNAME queries, real-time streaming, and error handling.

## Prerequisites

- **API Access**: Server running at `http://localhost:8000` (see [Installation](../admin/installation.md)).
- **Authentication Token**: Configured in `config/generic.json`:
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
- **Tools**: `curl`, Python with `requests` or `httpx`, Node.js with `ws`, or a browser for JavaScript `fetch`.

## Example 1: Get Server Information (`/info`)

Retrieve server version, stats, and sensor details.

### Using `curl`

```bash
curl http://localhost:8000/info
```

**Expected Response**:

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

### Using JavaScript (`fetch`)

```javascript
fetch('http://localhost:8000/info')
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));
```

## Example 2: Query DNS Records (`/query/{q}`)

Query records for a specific domain or IP with filters.

### Using `curl` (Domain with CNAME)

Query `www.example.com` for `CNAME` records:

```bash
curl -H "Authorization: Bearer xyz123" "http://localhost:8000/query/www.example.com?limit=5&rrtype=CNAME&format=json"
```

**Expected Response**:

```json
[
  {
    "rrname": "www.example.com",
    "rrtype": "CNAME",
    "rdata": "example.com",
    "time_first": 1698777600,
    "time_last": 1698777600,
    "count": 1,
    "sensor_id": "sensor1"
  }
]
```

### Using Python (`httpx`)

Query an IP address:

```python
import httpx

url = "http://localhost:8000/query/93.184.216.34?limit=5&format=json"
headers = {"Authorization": "Bearer xyz123"}
response = httpx.get(url, headers=headers)
if response.status_code == 200:
    print(response.json())
elif response.status_code == 401:
    print("Error: Invalid token")
else:
    print(f"Error: {response.status_code}")
```

## Example 3: Fuzzy Query (`/fquery/{q}`)

Perform a fuzzy search for domains containing a term.

### Using `curl`

Search for domains containing `example`:

```bash
curl -H "Authorization: Bearer xyz123" "http://localhost:8000/fquery/example?limit=5"
```

**Expected Response**:

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

### Using JavaScript (`fetch`)

```javascript
fetch('http://localhost:8000/fquery/google?limit=3', {
  headers: {
    Authorization: 'Bearer xyz123'
  }
})
  .then(response => {
    if (!response.ok) throw new Error(`HTTP error ${response.status}`);
    return response.json();
  })
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));
```

## Example 4: Stream DNS Records (`/stream/{q}`)

Stream real-time DNS records for a domain or IP via WebSocket.

### Using Python (`websockets`)

Stream `A` records for `example.com`:

```python
import asyncio
import websockets

async def stream():
    uri = "ws://localhost:8000/stream/example.com?rrtype=A"
    try:
        async with websockets.connect(uri, extra_headers={"Authorization": "Bearer xyz123"}) as ws:
            while True:
                message = await ws.recv()
                print(message)
    except websockets.exceptions.InvalidStatusCode as e:
        print(f"Error: {e}")

asyncio.run(stream())
```

**Expected Message**:

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

### Using JavaScript (`ws`)

```javascript
const WebSocket = require('ws');

const ws = new WebSocket('ws://localhost:8000/stream/example.com?rrtype=A', {
  headers: {
    Authorization: 'Bearer xyz123'
  }
});

ws.on('open', () => console.log('Connected to stream'));
ws.on('message', (data) => console.log(JSON.parse(data)));
ws.on('error', (error) => console.error('Error:', error));
ws.on('close', () => console.log('Disconnected'));
```

## Example 5: Query in CSV Format

Retrieve records in CSV format for analysis.

### Using `curl`

```bash
curl -H "Authorization: Bearer xyz123" "http://localhost:8000/query/example.com?format=csv"
```

**Expected Response**:

```csv
rrname,rrtype,rdata,time_first,time_last,count,sensor_id
example.com,A,93.184.216.34,1698777600,1698777600,1,sensor1
```

### Using Python (`requests`)

```python
import requests

url = "http://localhost:8000/query/example.com?format=csv"
headers = {"Authorization": "Bearer xyz123"}
response = requests.get(url, headers=headers)
if response.status_code == 200:
    with open('records.csv', 'w') as f:
        f.write(response.text)
else:
    print(f"Error: {response.status_code}")
```

## Example 6: Handling Errors

Simulate an invalid token to demonstrate error handling.

### Using `curl`

```bash
curl -H "Authorization: Bearer invalid_token" "http://localhost:8000/query/example.com"
```

**Expected Response**:

```json
{
  "detail": "Invalid authentication credentials"
}
```

### Using Python (`httpx`)

```python
import httpx

url = "http://localhost:8000/query/example.com"
headers = {"Authorization": "Bearer invalid_token"}
response = httpx.get(url, headers=headers)
if response.status_code == 401:
    print("Error: Invalid token")
else:
    print(response.text)
```

## Troubleshooting

- **401 Unauthorized**:
  - Verify token in `config/generic.json`.
  - Ensure `Authorization: Bearer xyz123` header is included.
- **429 Too Many Requests**:
  - Check rate limits in `generic.json`:
    ```json
    {
      "rate_limit": {
        "query": {"requests": 100, "window": 60}
      }
    }
    ```
  - Wait or adjust limits (see [Configuration](../admin/configuration.md)).
- **500 Internal Server Error**:
  - Check server logs:
    ```bash
    tail -f pdns.log | grep "ERROR"
    ```
  - Ensure database is running (see [Troubleshooting](../admin/troubleshooting.md)).

## Mermaid Diagram: Query Workflow

```mermaid
graph TD
    A[Client] -->|Choose Tool: curl/Python/JS| B[Construct Request]
    B -->|Add Auth Header| C[Send Request]
    C -->|GET /info| D[FastAPI Server]
    C -->|GET /query/{q}| E[Authenticate]
    C -->|GET /fquery/{q}| E
    C -->|WS /stream/{q}| E
    E -->|Check Rate Limit| F[Query DB]
    F -->|Return Data| D
    D -->|JSON/CSV Response| A
```

For related guides, see:

- [Querying DNS Data](./querying-dns.md)
- [API Reference](./api-reference.md)
- [Schemas](./schemas.md)
- [Configuration](../admin/configuration.md)
- [Troubleshooting](../admin/troubleshooting.md)