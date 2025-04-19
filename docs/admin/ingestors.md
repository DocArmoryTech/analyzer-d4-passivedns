# Ingestors

This guide explains how to configure and manage ingestors in the `analyzer-d4-passivedns` server, a FastAPI-based Passive DNS server compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). Ingestors are responsible for collecting DNS data from sources like D4 sensors, COF websocket streams, or custom feeds, and storing them in the configured database backend (e.g., Redis, KV Rocks).

## Overview

Ingestors are modular and dynamically loaded from `config/generic.json`. Each ingestor is defined in the `ingestors` section and corresponds to a Python class in `pdns/ingestors/`. Common ingestors include:

- **COF Ingestor**: Processes data from COF websocket streams (e.g., `ws://crh.circl.lu:8888`).
- **D4 Ingestor**: Connects to D4 servers for DNS record ingestion.
- **Custom Ingestors**: User-defined ingestors for specific data sources.

## Configuration

Ingestors are configured in `config/generic.json` under the `ingestors` key. Each ingestor requires a unique name, type, and configuration settings.

### Example Configuration

```json
{
  "ingestors": {
    "cof_ingestor": {
      "type": "cof",
      "config": {
        "websocket": "ws://crh.circl.lu:8888",
        "frequency": "realtime"
      }
    },
    "d4_ingestor": {
      "type": "d4",
      "config": {
        "server": "127.0.0.1:6380",
        "uuid": "6072e072-bfaa-4395-9bb1-cdb3b470d715",
        "frequency": "daily"
      }
    }
  }
}
```

- **Fields**:
  - `<ingestor_name>`: Unique identifier (e.g., `cof_ingestor`).
  - `type`: Ingestor type (`cof`, `d4`, or custom).
  - `config`: Source-specific settings (e.g., `websocket` URL, `server` address, `uuid`).
  - `frequency` (optional): Ingestion schedule (`realtime`, `daily`, `hourly`).

### Validation

- Validate the configuration:
  ```bash
  python tools/validate_config_files.py --check
  ```
- Update missing fields from `generic.json.sample`:
  ```bash
  python tools/validate_config_files.py --update
  ```

## Running Ingestors

Ingestors run as separate processes from the main FastAPI server and are managed via command-line scripts in `bin/`.

1. **Set Environment Variable**:
   - Ensure `PDNS_HOME` is set:
     ```bash
     export PDNS_HOME=/path/to/analyzer-d4-passivedns
     ```

2. **Start the COF Ingestor**:
   - For a COF websocket stream:
     ```bash
     poetry run python bin/pdns-import-cof.py --websocket ws://crh.circl.lu:8888
     ```
   - This connects to the specified websocket and processes records in real-time.

3. **Start the D4 Ingestor**:
   - For a D4 server:
     ```bash
     poetry run python bin/pdns-ingestion.py
     ```
   - Ensure `etc/analyzer.conf` is configured with D4 server details if not using `generic.json`.

4. **Monitor Logs**:
   - Check `pdns.log` (configured in `config/logging.json`) for ingestion activity:
     ```bash
     tail -f pdns.log | grep "ingestor"
     ```
   - Example log:
     ```
     [2025-04-19 10:00:00] INFO: cof_ingestor processed 100 records
     ```

## Managing Ingestors

- **Starting Ingestors**:
  - Run ingestors in the background using a process manager like `systemd` or `supervisord`:
    ```bash
    poetry run python bin/pdns-import-cof.py --websocket ws://crh.circl.lu:8888 &
    ```

- **Stopping Ingestors**:
  - Find the process ID:
    ```bash
    ps aux | grep pdns-import-cof
    ```
  - Terminate the process:
    ```bash
    kill <pid>
    ```

- **Scaling**:
  - Run multiple ingestors for different sources by adding entries to `generic.json`.
  - Ensure database capacity (e.g., Redis memory) supports the ingestion rate.

## Troubleshooting Ingestors

- **Symptom**: Ingestor fails to start or logs connection errors.
  - **Solution**:
    1. Verify the source URL or server address in `generic.json`.
    2. Test connectivity:
       ```bash
       curl ws://crh.circl.lu:8888
       ```
    3. Check logs for specific errors:
       ```bash
       tail -f pdns.log | grep "ERROR"
       ```

- **Symptom**: No data ingested.
  - **Solution**:
    1. Ensure `rrset_supported` in `generic.json` includes desired record types:
       ```json
       {
         "rrset_supported": ["A", "AAAA", "CNAME"]
       }
       ```
    2. Check `excludesubstrings` for accidental filtering:
       ```json
       {
         "excludesubstrings": []
       }
       ```
    3. Update `rrtypes.json`:
       ```bash
       python tools/3rdparty.py
       ```

- **Symptom**: High database load.
  - **Solution**:
    1. Adjust `expiration` in `generic.json` to reduce record retention:
       ```json
       {
         "expiration": { "A": 86400, "AAAA": 86400 }
       }
       ```
    2. Monitor database metrics:
       ```bash
       redis-cli -p 6379 INFO MEMORY
       ```

## Best Practices

- **Secure Configurations**: Protect sensitive fields like `uuid` in `generic.json` with file permissions:
  ```bash
  chmod 600 config/generic.json
  ```
- **Log Monitoring**: Regularly check `pdns.log` for ingestion errors or warnings.
- **Source Validation**: Test data sources before adding to `generic.json` to ensure reliability.
- **Incremental Scaling**: Start with one ingestor and monitor performance before adding more.

For related guides, see:

- [Installation](./installation.md)
- [Configuration](./configuration.md)
- [Server Management](./management.md)
- [Troubleshooting](./troubleshooting.md)
- [Notifiers](./notifiers.md)