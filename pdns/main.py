# pdns/main.py
from contextlib import asynccontextmanager
import threading
from time import sleep
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from .default.helpers import logger, get_config
from .databases.redis import RedisDatabase
from .databases.memory import MemoryDatabase  # Optional, if implemented
from .databases.base import Database
from .routes import info, query, fquery, stream
import json
import os

limiter = Limiter(key_func=get_remote_address)

TOKEN_FILE = os.getenv("AUTH_TOKEN_FILE", "config/tokens.json")
VALID_TOKENS = []
AUTH_CONFIG_FILE = os.getenv("AUTH_CONFIG_FILE", "config/auth.json")

def load_bearer_tokens():
    global VALID_TOKENS
    try:
        tokens_data = get_config("tokens")
        VALID_TOKENS = [t["value"] for t in tokens_data.get("tokens", [])]
        logger.info(f"Loaded {len(VALID_TOKENS)} tokens from {TOKEN_FILE}")
    except Exception as e:
        logger.error(f"Failed to load token file {TOKEN_FILE}: {str(e)}")

def token_reload_thread():
    while True:
        load_bearer_tokens()
        sleep(60)

def get_database_backend() -> Database:
    try:
        db_config = get_config("database")
        db_type = db_config["type"]
        config = db_config.get("config", {})
    except Exception as e:
        logger.warning(f"Failed to load database config: {str(e)}, defaulting to Redis")
        db_type, config = "redis", {"host": "127.0.0.1", "port": 6400, "db": 0}

    if db_type == "redis":
        return RedisDatabase(**config)
    elif db_type == "memory":
        return MemoryDatabase()  # Optional, if implemented
    else:
        raise ValueError(f"Unknown database type: {db_type}")

async def get_database() -> Database:
    db = get_database_backend()
    await db.connect()
    try:
        yield db
    finally:
        await db.disconnect()

@asynccontextmanager
async def lifespan(app: FastAPI):
    thread = threading.Thread(target=token_reload_thread, daemon=True)
    thread.start()
    logger.info({"event": "startup", "message": "Token reload thread started"})
    yield
    logger.info({"event": "shutdown", "message": "Application shutting down"})

app = FastAPI(
    title="Passive DNS Server API",
    description="A Passive DNS server compliant with Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof).",
    version="1.0.0",
    openapi_tags=[
        {"name": "query", "description": "Single domain lookups"},
        {"name": "fquery", "description": "Full associated record queries"},
        {"name": "stream", "description": "Streaming DNS records"}
    ],
    contact={"name": "CIRCL", "url": "https://www.circl.lu", "email": "info@circl.lu"},
    license_info={"name": "GNU Affero General Public License v3", "url": "https://www.gnu.org/licenses/agpl-3.0.html"},
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)

security_bearer = HTTPBearer(auto_error=False)
DEFAULT_CONFIG = {
    "endpoints": {
        "info": {"auth": "none"},
        "query": {"auth": "none"},
        "fquery": {"auth": "none"},
        "stream": {"auth": "none"}
        }
    }

try:
    auth_config = get_config("auth")
except Exception:
    auth_config = DEFAULT_CONFIG

def get_auth_dependency():
    async def dynamic_auth(request: Request):
        path_parts = request.url.path.strip("/").split("/")
        endpoint = path_parts[0] if path_parts else ""
        mode = auth_config["endpoints"].get(endpoint, {"auth": "none"})["auth"]
        if mode == "none":
            return None
        elif mode == "bearer":
            credentials = await security_bearer(request)
            if not credentials or credentials.credentials not in VALID_TOKENS:
                raise HTTPException(401, detail="Invalid or missing bearer token", headers={"WWW-Authenticate": "Bearer"})
            return credentials
        elif mode == "openid":
            raise HTTPException(501, detail="OpenID Connect not yet implemented")
        else:
            logger.error(f"Unknown auth mode '{mode}' for endpoint /{endpoint}")
            raise HTTPException(500, detail="Invalid authentication configuration")
    return dynamic_auth

optional_auth = get_auth_dependency()

@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")

app.include_router(info.router)
app.include_router(query.router)
app.include_router(fquery.router)
app.include_router(stream.router)