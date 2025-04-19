# Notifiers

This guide explains how to configure and manage notifiers in the `analyzer-d4-passivedns` server, a FastAPI-based Passive DNS server compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). Notifiers send alerts based on DNS record conditions, enabling real-time monitoring of DNS events. They are modular, with configurations in `config/generic.json` or notifier-specific `config.json` files.

## Overview

Notifiers are managed by the `NotificationManager` and triggered when DNS records match predefined conditions. Each notifier resides in `pdns/notifiers/<name>/`, containing a `notifier.py` implementation, a `config.json` file (except for the `log` notifier), and a `template.jinja` for message formatting. The system does not retry failed notifications to minimize load, logging failures instead.

### Supported Notifiers

- `log`: Logs alerts to the application logger (configured in `generic.json`).
- `webhook`: Sends alerts via HTTP POST to a webhook URL.
- `mail`: Sends email alerts via SMTP.
- `mattermost`: Posts alerts to a Mattermost webhook.
- `rocketchat`: Posts alerts to a Rocket.Chat webhook.
- `matrix`: Sends alerts to a Matrix room.

## Configuration

Notifiers are primarily configured in `config/generic.json` under the `notifiers` key, with some using dedicated `config.json` files in `pdns/notifiers/<name>/`.

### Configuring in `generic.json`

The `log` notifier and others can be configured directly in `generic.json`.

- **Example**:
  ```json
  {
    "notifiers": {
      "log_alert": {
        "type": "log",
        "config": {
          "name": "log_alert",
          "condition": {"rrtype": "A"},
          "level": "info"
        }
      },
      "webhook_alert": {
        "type": "webhook",
        "config": {
          "name": "webhook_alert",
          "condition": {"rrname": "example.com"},
          "url": "https://webhook.example.com/notify"
        }
      }
    }
  }
  ```

- **Fields**:
  - `<notifier_name>`: Unique identifier (e.g., `log_alert`).
  - `type`: Notifier type (`log`, `webhook`, etc.).
  - `config`:
    - `name`: Unique alert name.
    - `condition`: Matching conditions (e.g., `{"rrtype": "A"}`, `{"rdata": "in:10.0.0.0/24"}`, `{"rrname": "regex:.*\\.com"}`).
    - Type-specific settings (e.g., `url` for `webhook`, `level` for `log`).

### Notifier-Specific `config.json`

For notifiers like `mail`, `mattermost`, `rocketchat`, and `matrix`, configurations are stored in `pdns/notifiers/<name>/config.json`.

- **Mail Example** (`pdns/notifiers/mail/config.json`):
  ```json
  {
    "name": "mail_alert",
    "condition": {"rdata": "in:10.0.0.0/24"},
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "sender": "alerts@example.com",
    "recipient": "admin@example.com"
  }
  ```

- **Matrix Example** (`pdns/notifiers/matrix/config.json`):
  ```json
  {
    "name": "matrix_alert",
    "condition": {"rrtype": "A"},
    "homeserver_url": "https://matrix.org",
    "access_token": "syt_abc123...",
    "room_id": "!roomid:matrix.org"
  }
  ```

### Conditions

Conditions determine when a notifier triggers:

- **Exact Match**: `{"key": "value"}` (e.g., `{"rrname": "example.com"}`).
- **Regex**: `{"key": "regex:pattern"}` (e.g., `{"rdata": "regex:192\\.168\\..*"}`).
- **IP Network**: `{"key": "in:network"}` (e.g., `{"rdata": "in:10.0.0.0/24"}`).
- **Multiple Conditions**: Combine conditions (e.g., `{"rrtype": "A", "rrname": "example.com"}`).

### Validation

- Validate configurations:
  ```bash
  python tools/validate_config_files.py --check
  ```
- Update missing fields:
  ```bash
  python tools/validate_config_files.py --update
  ```

## Managing Notifiers

Notifiers are automatically loaded and managed by the FastAPI server during startup.

1. **Set Environment Variable**:
   - Ensure `PDNS_HOME` is set:
     ```bash
     export PDNS_HOME=/path/to/analyzer-d4-passivedns
     ```

2. **Start the Server**:
   - Run the FastAPI server to enable notifiers:
     ```bash
     poetry run uvicorn pdns.main:app --host 0.0.0.0 --port 8000
     ```

3. **Monitor Notifications**:
   - Check `pdns.log` for notification events or failures:
     ```bash
     tail -f pdns.log | grep "notify"
     ```
   - Example log for a failed notification:
     ```
     [2025-04-19 10:00:00] ERROR: mail_notify_failed: Connection refused
     ```

## Troubleshooting Notifiers

- **Symptom**: Notifications not sent, logs show `notify_failed`.
  - **Solution**:
    1. Verify the notifier configuration (e.g., `smtp_host`, `webhook_url`).
    2. Test connectivity to the service:
       ```bash
       telnet smtp.example.com 587
       ```
    3. Check logs for specific errors:
       ```bash
       tail -f pdns.log | grep "ERROR"
       ```
    4. Note: Failed notifications are not retried to minimize system load.

- **Symptom**: Too many notifications triggered.
  - **Solution**:
    1. Refine conditions in `config.json` or `generic.json`:
       ```json
       {
         "condition": {"rrname": "example.com", "rrtype": "A"}
       }
       ```
    2. Restart the server to apply changes:
       ```bash
       poetry run uvicorn pdns.main:app --host 0.0.0.0 --port 8000
       ```

- **Symptom**: No notifications triggered.
  - **Solution**:
    1. Ensure conditions match incoming records:
       ```json
       {
         "condition": {"rrtype": "A"}
       }
       ```
    2. Verify `rrset_supported` in `generic.json` includes relevant types:
       ```json
       {
         "rrset_supported": ["A", "AAAA"]
       }
       ```

## Best Practices

- **Secure Configurations**: Protect sensitive fields (e.g., `access_token`, `smtp_credentials`) with file permissions:
  ```bash
  chmod 600 pdns/notifiers/matrix/config.json
  ```
- **Specific Conditions**: Use precise conditions to avoid excessive notifications.
- **Log Monitoring**: Regularly check `pdns.log` for failed notifications or misconfigurations.
- **Test Notifiers**: Simulate DNS records to test notifier behavior before deploying in production.

For related guides, see:

- [Installation](./installation.md)
- [Configuration](./configuration.md)
- [Server Management](./management.md)
- [Troubleshooting](./troubleshooting.md)
- [Ingestors](./ingestors.md)