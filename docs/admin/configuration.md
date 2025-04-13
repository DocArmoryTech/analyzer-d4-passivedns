# Configuration Guide

Configuration files are located in `config/`.

## Main Configuration (`generic.json`)

- **Database**:
  ```json
  {
    "database": {
      "type": "redis",
      "config": { "host": "localhost", "port": 6379, "db": 0 }
    }
  }
  ```

- **Ingestors**:
  ```json
  {
    "ingestors": {
      "json_ingestor": {
        "type": "json",
        "config": { "file_path": "/path/to/data.json" }
      }
    }
  }
  ```

- **Notifiers**:
  ```json
  {
    "notifiers": {
      "email": {
        "type": "mail",
        "config": { "to": "admin@example.com", "smtp_server": "localhost" }
      }
    }
  }
  ```

## Logging (`logging.json`)

Configure log levels and output:
```json
{
  "level": "INFO",
  "file": "pdns.log"
}
```