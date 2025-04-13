# Notifiers Documentation

The notifier system triggers alerts based on DNS record conditions, using a modular directory-based design.

## Structure
Each notifier lives in `pdns/notifiers/<name>/` with:
- `notifier.py`: Python class implementation.
- `config.json`: Configuration (except `log`, which uses `get_config`).
- `template.jinja`: Jinja2 template for notification messages.

## Notifiers

### `log`
- **Description**: Logs alerts to the application logger.
- **Config**: Loaded via `get_config("notifiers").get("log")`.
- **Fields**:
  - `name`: Alert name.
  - `condition`: Matching conditions (e.g., `{"rrtype": "A"}`).
  - `level`: Log level ("debug", "info", "warning", "error", "critical").
- **Example Config** (in `pdns/config.json`):
  ```json
  {
    "notifiers": {
      "log": {
        "name": "log_alert",
        "condition": {"rrtype": "A"},
        "level": "info"
      }
    }
  }
  ```

### `webhook`
- **Description**: Sends alerts via HTTP POST to a webhook URL.
- **Config**: `pdns/notifiers/webhook/config.json`.
- **Fields**:
  - `name`: Alert name.
  - `condition`: Matching conditions.
  - `url`: Webhook URL.
- **Example**:
  ```json
  {
    "name": "webhook_alert",
    "condition": {"rrname": "example.com"},
    "url": "https://webhook.example.com/notify"
  }
  ```

### `mail`
- **Description**: Sends email alerts via SMTP.
- **Config**: `pdns/notifiers/mail/config.json`.
- **Fields**:
  - `name`: Alert name.
  - `condition`: Matching conditions.
  - `smtp_host`: SMTP server host.
  - `smtp_port`: SMTP server port.
  - `sender`: Sender email.
  - `recipient`: Recipient email.
- **Example**:
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

### `mattermost`
- **Description**: Posts alerts to a Mattermost webhook.
- **Config**: `pdns/notifiers/mattermost/config.json`.
- **Fields**:
  - `name`: Alert name.
  - `condition`: Matching conditions.
  - `webhook_url`: Mattermost webhook URL.
- **Example**:
  ```json
  {
    "name": "mattermost_alert",
    "condition": {"rrtype": "A", "rdata": "regex:192\\.168\\..*"},
    "webhook_url": "https://mattermost.example.com/hooks/xyz123"
  }
  ```

### `rocketchat`
- **Description**: Posts alerts to a Rocket.Chat webhook.
- **Config**: `pdns/notifiers/rocketchat/config.json`.
- **Fields**: Same as `mattermost`.
- **Example**:
  ```json
  {
    "name": "rocketchat_alert",
    "condition": {"rrname": "example.com"},
    "webhook_url": "https://rocketchat.example.com/hooks/abc456"
  }
  ```

### `matrix`
- **Description**: Sends alerts to a Matrix room.
- **Config**: `pdns/notifiers/matrix/config.json`.
- **Fields**:
  - `name`: Alert name.
  - `condition`: Matching conditions.
  - `homeserver_url`: Matrix homeserver URL.
  - `access_token`: Matrix access token.
  - `room_id`: Matrix room ID.
- **Example**:
  ```json
  {
    "name": "matrix_alert",
    "condition": {"rdata": "in:10.0.0.0/24"},
    "homeserver_url": "https://matrix.org",
    "access_token": "syt_abc123...",
    "room_id": "!roomid:matrix.org"
  }
  ```

## Conditions
- **Exact Match**: `{"key": "value"}` (e.g., `{"rrname": "example.com"}`).
- **Regex**: `{"key": "regex:pattern"}` (e.g., `{"rdata": "regex:192\\.168\\..*"}`).
- **IP Network**: `{"key": "in:network"}` (e.g., `{"rdata": "in:10.0.0.0/24"}`).

## Triggering
- Managed by `NotificationManager`, which loads notifiers from `pdns/notifiers/` and matches conditions centrally.
