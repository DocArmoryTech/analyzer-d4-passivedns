# Adding Features

## New Ingestor

1. Subclass `BaseIngestor` in `pdns/ingestors/`:
   ```python
   from .base import BaseIngestor
   class CustomIngestor(BaseIngestor):
       def ingest(self, data):
           self.db.store(data)
   ```
2. Add to `generic.json`.

## New API Endpoint

1. Add a route in `pdns/routes/`:
   ```python
   from fastapi import APIRouter
   router = APIRouter(prefix="/new")
   @router.get("/")
   async def new_endpoint():
       return {"message": "New endpoint"}
   ```
2. Include in `main.py`.