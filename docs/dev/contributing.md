# Contributing

Thank you for your interest in contributing to `analyzer-d4-passivedns`, a FastAPI-based Passive DNS server compliant with the [Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof)](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof). This guide outlines the process for setting up a development environment, making changes, and submitting contributions via GitHub.

## Getting Started

### Prerequisites

- **Python**: 3.8 or higher.
- **Poetry**: Dependency manager for Python projects.
- **Git**: For version control.
- **Database**: Redis (>5.0) or [KV Rocks](https://github.com/apache/incubator-kvrocks) for testing.
- **Operating System**: Linux (e.g., Ubuntu 20.04+ recommended).

### Setting Up the Development Environment

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/D4-project/analyzer-d4-passivedns.git
   cd analyzer-d4-passivedns
   ```

2. **Install Poetry**:

   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

3. **Install Dependencies**:

   ```bash
   poetry install --with dev
   ```

   The `--with dev` flag includes development dependencies like `pytest`, `black`, and `flake8`.

4. **Set Up the Database**:

   - **Redis**:
     ```bash
     ./bin/install_server_redis.sh
     ./redis/src/redis-server ./etc/redis.conf
     ```
     Verify:
     ```bash
     redis-cli -p 6379 ping
     ```

   - **KV Rocks**:
     ```bash
     ./bin/install_server_kvrocks.sh
     ./kvrocks/src/kvrocks -c ./etc/kvrocks.conf
     ```
     Verify:
     ```bash
     ./kvrocks/src/kvrocks-cli -p 6666 PING
     ```

5. **Configure the Environment**:

   - Copy the sample configuration:
     ```bash
     cp config/generic.json.sample config/generic.json
     ```
   - Edit `config/generic.json` to match your database:
     ```json
     {
       "database": {
         "type": "redis",
         "config": {
           "host": "localhost",
           "port": 6379,
           "db": 0
         }
       },
       "rrset_supported": ["A", "AAAA"],
       "excludesubstrings": [],
       "expiration": { "A": 86400, "AAAA": 86400 },
       "ingestors": {},
       "notifiers": {}
     }
     ```

   - Set `PDNS_HOME`:
     ```bash
     export PDNS_HOME=$(pwd)
     ```

6. **Run the Server**:

   ```bash
   poetry run uvicorn pdns.main:app --host 0.0.0.0 --port 8000
   ```

   Verify by accessing `http://localhost:8000/docs`.

## Contribution Workflow

1. **Fork the Repository**:

   - Fork `analyzer-d4-passivedns` on GitHub and clone your fork:
     ```bash
     git clone https://github.com/<your-username>/analyzer-d4-passivedns.git
     ```

2. **Create a Branch**:

   - Create a feature or bugfix branch:
     ```bash
     git checkout -b feature/<feature-name>
     ```

3. **Make Changes**:

   - Follow the project’s coding standards:
     - Use `black` for formatting:
       ```bash
       poetry run black .
       ```
     - Run `flake8` for linting:
       ```bash
       poetry run flake8 .
       ```
     - Write type hints where applicable.
     - Update or add tests in `tests/`.

   - Update documentation in `docs/` if your changes affect user, admin, or developer guides.

4. **Run Tests**:

   - Execute the test suite:
     ```bash
     poetry run pytest
     ```
   - Ensure 100% coverage for new code:
     ```bash
     poetry run pytest --cov=pdns --cov-report=html
     ```

5. **Commit Changes**:

   - Write clear, concise commit messages:
     ```bash
     git commit -m "Add feature: <description>"
     ```

6. **Push and Create a Pull Request**:

   - Push your branch:
     ```bash
     git push origin feature/<feature-name>
     ```
   - Open a pull request (PR) on the main repository, describing:
     - The problem solved or feature added.
     - Any dependencies or configuration changes.
     - Relevant test coverage.

## Coding Guidelines

- **Modularity**: Leverage the project’s modular design for ingestors, notifiers, and database backends.
- **Performance**: Use async/await for I/O-bound operations (e.g., database queries, HTTP requests).
- **Error Handling**: Catch and log exceptions, raising appropriate HTTP errors for API endpoints.
- **Configuration**: Use `generic.json` for all configurations (e.g., database, ingestors, notifiers, auth).
  - Example for adding a test notifier:
    ```json
    {
      "notifiers": {
        "test_log": {
          "type": "log",
          "config": {
            "name": "test_log",
            "condition": {"rrtype": "A"},
            "level": "debug"
          }
        }
      }
    }
    ```
- **Documentation**: Update `docs/` for new features, especially `api-reference.md` for API changes.
- **Testing**: Write unit and integration tests for new functionality in `tests/`.

## Common Contribution Areas

- **Bug Fixes**: Address issues listed on GitHub.
- **New Ingestors**: Add support for new data sources (see [Adding Ingestors](./adding-ingestors.md)).
- **New Notifiers**: Implement new alert mechanisms (see [Adding Notifiers](./adding-notifiers.md)).
- **API Enhancements**: Add or improve endpoints (see [API Development](./api-development.md)).
- **Performance**: Optimize database queries or ingestion pipelines.
- **Documentation**: Improve user, admin, or developer guides.

## Community

- **Issues**: Report bugs or suggest features on the [GitHub Issues](https://github.com/D4-project/analyzer-d4-passivedns/issues) page.
- **Discussions**: Join discussions on GitHub or contact the D4 Project team for guidance.
- **Code of Conduct**: Follow the project’s code of conduct to ensure a welcoming environment.

For related guides, see:

- [Codebase Overview](./codebase-overview.md)
- [Adding Ingestors](./adding-ingestors.md)
- [Adding Notifiers](./adding-notifiers.md)
- [API Development](./api-development.md)
- [Testing](./testing.md)