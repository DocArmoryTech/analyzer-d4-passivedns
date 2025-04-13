# Installation Guide

## Prerequisites

- **OS**: Linux (e.g., Ubuntu 20.04+).
- **Python**: 3.8 or higher.
- **Poetry**: Install via `curl -sSL https://install.python-poetry.org | python3 -`.
- **Database**: Redis or KV Rocks.

## Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/D4-project/analyzer-d4-passivedns.git
   cd analyzer-d4-passivedns
   ```

2. **Install Dependencies**:
   ```bash
   poetry install
   ```

3. **Set Up the Database**:
   - Redis: `./bin/install_server_redis.sh`
   - KV Rocks: `./bin/install_server_kvrocks.sh`

4. **Configure the Server**:
   - Copy `config/generic.json.sample` to `config/generic.json`.
   - Edit `generic.json`:
     ```json
     {
       "database": {
         "type": "redis",
         "config": { "host": "localhost", "port": 6379, "db": 0 }
       }
     }
     ```

5. **Run the Server**:
   ```bash
   poetry run uvicorn pdns.main:app --host 0.0.0.0 --port 8000
   ```

See [Configuration](./configuration.md) for more options.
