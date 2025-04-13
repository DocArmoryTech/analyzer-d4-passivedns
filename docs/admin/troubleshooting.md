# Troubleshooting

- **Database Errors**:
  - Verify Redis/KV Rocks is running.
  - Check `generic.json` settings.

- **Ingestor Issues**:
  - Ensure file paths or connections are correct.
  - Review logs for errors.

- **API Access Denied**:
  - If authentication is enabled, include a valid `Authorization: Bearer <token>` header.