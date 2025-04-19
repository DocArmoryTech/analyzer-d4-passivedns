# Getting Started with the Passive DNS API

The `analyzer-d4-passivedns` API allows users to query DNS records collected from various sensors, compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). Built with FastAPI, it provides an interactive OpenAPI interface for easy exploration. This guide offers a quick introduction to using the API.

## Prerequisites

- **Access**: A running Passive DNS server (e.g., `http://localhost:8000`).
- **Authentication**: A bearer token if authentication is enabled (check with your administrator).
- **Tools**: `curl` or a similar HTTP client for testing (e.g., Postman, HTTPie).

## Quick Start

1. **Verify Server Status**:

   - Check if the API is running:
     ```bash
     curl http://localhost:8000/info
     ```
   - Expected response:
     ```json
     {
       "version": "1.0.0",
       "software": "analyzer-d4-passivedns",
       "stats": { "total_records": 10000 },
       "sensors": [ { "sensor_id": "sensor1", "count": 5000 } ]
     }
     ```

2. **Query a Domain**:

   - Retrieve DNS records for a domain:
     ```bash
     curl http://localhost:8000/query/example.com
     ```
   - Example response (NDJSON):
     ```
     {"time_first": 1698777600, "time_last": 1698777600, "rrname": "example.com", "rrtype": "A", "rdata": "93.184.216.34"}
     {"time_first": 1698777600, "time_last": 1698777600, "rrname": "example.com", "rrtype": "AAAA", "rdata": "2606:2800:220:1:248:1893:25c8:1946"}
     ```

3. **Use Authentication (if enabled)**:

   - If authentication is enabled in `config/generic.json`, include a bearer token from the `auth.tokens` section:
     ```bash
     curl -H "Authorization: Bearer <token>" http://localhost:8000/query/example.com
     ```
   - Example `generic.json` snippet:
     ```json
     {
       "auth": {
         "endpoints": {
           "query": {"auth": "bearer"}
         },
         "tokens": {
           "admin": "xyz123",
           "user": "abc456"
         }
       }
     }
     ```

4. **Explore the OpenAPI Docs**:

   - Visit `http://localhost:8000/docs` in a browser to interact with the API using the auto-generated OpenAPI interface.
   - Alternatively, access the raw OpenAPI spec:
     ```bash
     curl http://localhost:8000/openapi.json
     ```

## Advanced Queries

- **Associated Records**:
  - Use `/fquery/{q}` to find records linked to a domain or IP:
    ```bash
    curl http://localhost:8000/fquery/93.184.216.34
    ```

- **Streaming Large Datasets**:
  - Use `/stream/{q}` for continuous record streaming:
    ```bash
    curl http://localhost:8000/stream/example.com
    ```

- **Filtering**:
  - Filter by RR type or other parameters:
    ```bash
    curl "http://localhost:8000/query/example.com?rrtype=A&limit=10"
    ```

## Next Steps

- **Learn Query Syntax**: See [Querying DNS Records](./querying-dns.md) for advanced query options.
- **Explore Endpoints**: Check the [API Reference](./api-reference.md) for detailed endpoint documentation.
- **Understand Schemas**: Review [Schemas](./schemas.md) for response formats.
- **Try Examples**: Follow [Examples](./examples.md) for practical use cases.

For detailed endpoint documentation and interactive testing, visit `http://localhost:8000/docs`.