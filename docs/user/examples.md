# API Examples

Here are practical examples of using the API.

## Querying a Domain with Filters

**Request**:
```bash
curl "http://localhost:8000/query/example.com?rrtype=A&format=json&metadata=true"
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
      "rdata": "93.184.216.34"
    }
  ],
  "total": 1,
  "next_cursor": null
}
```

## Streaming Records for an IP

**Request**:
```bash
curl "http://localhost:8000/stream/93.184.216.34?chunk_size=1"
```

**Response (NDJSON)**:
```
{"time_first": 1698777600, "time_last": 1698777600, "rrname": "example.com", "rrtype": "A", "rdata": "93.184.216.34"}
{"time_first": 1698777600, "time_last": 1698777600, "rrname": "another.com", "rrtype": "A", "rdata": "93.184.216.34"}
```

## Paginating Results

**Initial Request**:
```bash
curl "http://localhost:8000/query/large-domain.com?limit=100"
```
Headers: `X-Next-Cursor: 100`

**Next Page**:
```bash
curl "http://localhost:8000/query/large-domain.com?limit=100&cursor=100"
```