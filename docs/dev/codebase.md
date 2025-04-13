# Codebase Overview

- **`pdns/`**:
  - `cli.py`: CLI for ingestors and management.
  - `db/`: Database abstractions.
  - `ingestors/`: Data ingestion modules.
  - `main.py`: FastAPI app setup.
  - `notifiers/`: Notification modules.
  - `routes/`: API endpoints.
  - `schemas/`: Pydantic models.

- **`tests/`**: Test suite.
- **`tools/`**: Utilities (e.g., config validation).