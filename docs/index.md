# Passive DNS Analyzer

The Passive DNS Analyzer is a FastAPI-based application for querying and analyzing passive DNS data stored in a Redis database. It provides RESTful endpoints for retrieving DNS records and a modular notifier system for alerting based on specific conditions.

## Features
- **API Endpoints**: Query DNS records (`/query`), full queries with associations (`/fquery`), streaming records (`/stream`), and system info (`/info`).
- **Notifiers**: Configurable notification handlers (e.g., log, webhook, email, Mattermost, Rocket.Chat, Matrix) triggered by DNS record matches.
- **Data Model**: Uses `PDNSRecord` from `pypdns` for DNS data, with Pydantic schemas for serialization.

## Getting Started
1. **Install Dependencies**: `pip install fastapi pyyaml jinja2 aiohttp aiosmtplib pypdns redis`
2. **Configure**: Set up Redis and a central config file (e.g., `pdns/config.json`) for notifiers like `log`.
3. **Run**: `uvicorn pdns.main:app --reload`

## Project Structure
- `pdns/routes/`: API endpoint definitions.
- `pdns/notifiers/`: Modular notifier system.
- `pdns/schemas.py`: Pydantic models for API responses.
- `pdns/queries.py`: Database query functions.
- `pdns/db/`: Database abstraction (e.g., `RedisDatabase`).
