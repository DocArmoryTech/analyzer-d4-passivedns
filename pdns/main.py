from contextlib import asynccontextmanager
import asyncio
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from .default.helpers import logger, get_config
from .db.redis import RedisDatabase
from .ingestors import DaemonIngestor
from .db.base import Database
from .routes import info, query, fquery, stream
import importlib
import inspect
from .db.manager import DatabaseManager


# Initialize limiter and token storage
limiter = Limiter(key_func=get_remote_address)
VALID_TOKENS = []

# Load bearer tokens once at startup
def load_bearer_tokens():
    global VALID_TOKENS
    try:
        tokens_data = get_config("tokens", quiet=True) or {}
        VALID_TOKENS = [t["value"] for t in tokens_data.get("tokens", [])]
        logger.info(f"Loaded {len(VALID_TOKENS)} tokens at startup")
    except Exception as e:
        logger.error(f"Failed to load tokens: {str(e)}")

# Database backend configuration
def get_database_backend() -> Database:
    try:
        db_config = get_config("database", quiet=True) or {}
        db_type = db_config.get("type", "redis")
        config = db_config.get("config", {"host": "127.0.0.1", "port": 6400, "db": 0})
    except Exception as e:
        logger.warning(f"Failed to load database config: {str(e)}, defaulting to Redis")
        db_type, config = "redis", {"host": "127.0.0.1", "port": 6400, "db": 0}

    if db_type == "redis":
        return RedisDatabase(**config)
    else:
        raise ValueError(f"Unknown database type: {db_type}")

# DatabaseManager dependency
async def get_database() -> DatabaseManager:
    db_backend = get_database_backend()
    db = DatabaseManager(db_backend)
    await db.initialize()
    logger.info({"event": "database_initialized"})
    try:
        yield db
    finally:
        await db.shutdown()
        logger.info({"event": "database_shutdown"})

async def start_ingestors(db: DatabaseManager):
    """Start zero or more ingestors based on configuration."""
    ingestors_config = get_config("ingestors", quiet=True) or {}
    
    if not ingestors_config:
        logger.info({"event": "ingestors_skipped", "message": "No ingestors configured"})
        return
    
    # Dynamically load all ingestor classes from the ingestors module
    ingestor_module = importlib.import_module(".ingestors", package="pdns")
    ingestor_classes = {
        cls.type: cls
        for name, cls in inspect.getmembers(ingestor_module, inspect.isclass)
        if hasattr(cls, "type") and issubclass(cls, DaemonIngestor) and cls != DaemonIngestor
    }
    
    for ingestor_name, config in ingestors_config.items():
        try:
            ingestor_type = config.get("type")
            if not ingestor_type:
                raise ValueError("Missing 'type' field in ingestor config")
            
            ingestor_class = ingestor_classes.get(ingestor_type)
            if not ingestor_class:
                raise ValueError(f"Unknown ingestor type: {ingestor_type}")
            
            # Instantiate and start the ingestor
            ingestor_config = config.get("config", {})
            ingestor = ingestor_class(db, **ingestor_config)
            asyncio.create_task(ingestor.ingest())
            logger.info({
                "event": "ingestor_started",
                "name": ingestor_name,
                "type": ingestor_type,
                "config": ingestor_config
            })
        except Exception as e:
            logger.error({
                "event": "ingestor_start_failed",
                "name": ingestor_name,
                "error": str(e)
            })

# Application lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load tokens once at startup
    load_bearer_tokens()
    logger.info({"event": "startup", "message": "Application starting"})

    # Initialize DatabaseManager for ingestors
    db = DatabaseManager(get_database_backend())
    await db.initialize()
    await start_ingestors(db)

    yield

    # Cleanup
    await db.shutdown()
    logger.info({"event": "shutdown", "message": "Application shutting down"})

# FastAPI app setup
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

# Authentication setup
security_bearer = HTTPBearer(auto_error=False)
DEFAULT_CONFIG = {
    "endpoints": {
        "info": {"auth": "none"},
        "query": {"auth": "none"},
        "fquery": {"auth": "none"},
        "stream": {"auth": "none"}
    }
}

auth_config = get_config("auth", quiet=True) or DEFAULT_CONFIG

def get_auth_dependency():
    async def dynamic_auth(request: Request):
        path_parts = request.url.path.strip("/").split("/")
        endpoint = path_parts[0] if path_parts else ""
        mode = auth_config.get("endpoints", {}).get(endpoint, {"auth": "none"})["auth"]
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

# Root redirect
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")

# Include routers
app.include_router(info.router)
app.include_router(query.router)
app.include_router(fquery.router)
app.include_router(stream.router)