# Getting Started with the Passive DNS API

The Passive DNS API allows you to query DNS records collected from various sensors. This guide provides a quick introduction to using the API.

## Prerequisites

- Access to a running Passive DNS server (e.g., `http://localhost:8000`).
- Optional: Authentication token if configured by the administrator.

## Quick Start

1. **Verify Server Status**  
   Check if the API is running:
   ```bash
   curl http://localhost:8000/info
   ```
   Expected response:
   ```json
   {
     "version": "1.0.0",
     "software": "analyzer-d4-passivedns",
     "stats": { "total_records": 10000 },
     "sensors": [ { "sensor_id": "sensor1", "count": 5000 } ]
   }
   ```

2. **Query a Domain**  
   Retrieve DNS records for a domain:
   ```bash
   curl http://localhost:8000/query/example.com
   ```
   This returns records in NDJSON format.

3. **Explore Advanced Queries**  
   - Use `/fquery/{q}` for associated records (domains or IPs).
   - Use `/stream/{q}` for streaming large datasets.

For detailed endpoint documentation, see the [API Reference](./api-reference.md).