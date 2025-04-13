# Server Management

## Starting the Server

```bash
poetry run uvicorn pdns.main:app --host 0.0.0.0 --port 8000
```

## Monitoring

- **Logs**: Check console or log files specified in `logging.json`.
- **Health Check**: Query `/info`.

## Stopping the Server

Press `Ctrl+C` or use a process manager in production.