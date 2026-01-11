from contextlib import asynccontextmanager
import asyncio
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from .default.helpers import logger, get_config, init_configs
from .default.exceptions import DBConnectionError, InvalidConfigError
from .db.manager import DatabaseManager
from .ingestors import DaemonIngestor
from .routes import info, query, fquery, stream
import importlib
import inspect

# Initialize limiter and token storage
rate_limit_cfg = get_config("generic", "rate_limit", default={}) or {}
default_limits = []

# Minimal, config-driven rate limiting: if any endpoint has a rate_limit entry,
# derive a simple default limit of "<max_requests>/<window>s" using the
# highest requests/window pair. This keeps runtime behavior aligned with
# generic.json without requiring per-endpoint decorators.
if isinstance(rate_limit_cfg, dict) and rate_limit_cfg:
    try:
        # rate_limit entries are of the form {"endpoint": {"requests": int, "window": int}}
        limits = []
        for _, v in rate_limit_cfg.items():
            if isinstance(v, dict) and "requests" in v and "window" in v:
                requests = int(v["requests"])
                window = int(v["window"])
                if requests > 0 and window > 0:
                    limits.append((requests, window))
        if limits:
            max_requests, window = max(limits, key=lambda x: x[0])
            default_limits = [f"{max_requests}/{window} second"]
    except Exception as e:
        logger.error({
            "event": "rate_limit_config_error",
            "error": str(e),
        })

limiter = Limiter(key_func=get_remote_address, default_limits=default_limits or None)
VALID_TOKENS = []

# FastAPI app setup
app = FastAPI(
    title="Passive DNS Server API",
    description="A Passive DNS server compliant with Passive DNS - Common Output Format (draft-dulaunoy-dnsop-passive-dns-cof).",
    version="1.0.0",
    openapi_tags=[
        {"name": "query", "description": "Single domain lookups"},
        {"name": "fquery", "description": "Full associated record queries"},
        {"name": "stream", "description": "Streaming DNS records"},
    ],
    contact={"name": "CIRCL", "url": "https://www.circl.lu", "email": "info@circl.lu"},
    license_info={
        "name": "GNU Affero General Public License v3",
        "url": "https://www.gnu.org/licenses/agpl-3.0.html"},
)

app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)

def load_bearer_tokens() -> None:
    """Load bearer tokens from generic auth configuration.

    Supports both list-of-objects and simple dict styles to ease migration
    from earlier configs.
    """
    global VALID_TOKENS
    try:
        auth_cfg = get_config("generic", "auth", default={}) or {}
    except InvalidConfigError as e:
        logger.error({"event": "tokens_load_failed", "error": str(e)})
        VALID_TOKENS = []
        return

    tokens_cfg = auth_cfg.get("tokens", [])
    tokens: list[str] = []

    # Support dict style: {"user": "token", ...}
    if isinstance(tokens_cfg, dict):
        tokens = [str(v) for v in tokens_cfg.values()]
    # Support list style: [{"value": "token", "name": "user"}, ...]
    elif isinstance(tokens_cfg, list):
        for item in tokens_cfg:
            if isinstance(item, dict) and "value" in item:
                tokens.append(str(item["value"]))

    VALID_TOKENS = tokens
    logger.info({"event": "tokens_loaded", "count": len(VALID_TOKENS)})

# Application lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    # Load configs and tokens at startup
    try:
        await init_configs()
        load_bearer_tokens()
        logger.info({"event": "startup", "message": "Application starting"})
    except InvalidConfigError as e:
        logger.error({"event": "config_load_failed", "error": str(e)})
        raise

    # Initialize DatabaseManager for ingestors
    db = DatabaseManager()
    try:
        await db.initialize()
        await start_ingestors(db)
        logger.info({"event": "ingestors_initialized"})
    except DBConnectionError as e:
        logger.error({"event": "db_init_failed", "error": str(e)})
        raise

    yield

    # Cleanup
    await db.shutdown()
    logger.info({"event": "shutdown", "message": "Application shutting down"})

app.lifespan = lifespan

# Authentication setup
security_bearer = HTTPBearer(auto_error=False)
DEFAULT_CONFIG = {
    "endpoints": {
        "info": {"auth": "none"},
        "query": {"auth": "none"},
        "fquery": {"auth": "none"},
        "stream": {"auth": "none"},
    },
}

def get_auth_dependency():
    """Create dynamic authentication dependency based on auth config."""

    async def dynamic_auth(request: Request):
        try:
            auth_cfg = get_config("generic", "auth", default=DEFAULT_CONFIG) or DEFAULT_CONFIG
        except InvalidConfigError:
            auth_cfg = DEFAULT_CONFIG

        path_parts = request.url.path.strip("/").split("/")
        endpoint = path_parts[0] if path_parts else ""
        mode = auth_cfg.get("endpoints", {}).get(endpoint, {"auth": "none"})["auth"]
        if mode == "none":
            return None
        elif mode == "bearer":
            credentials = await security_bearer(request)
            if not credentials or credentials.credentials not in VALID_TOKENS:
                raise HTTPException(
                    401,
                    detail="Invalid or missing bearer token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return credentials
        elif mode == "openid":
            raise HTTPException(501, detail="OpenID Connect not yet implemented")
        else:
            logger.error({"event": "auth_error", "endpoint": endpoint, "mode": mode})
            raise HTTPException(500, detail="Invalid authentication configuration")

    return dynamic_auth

optional_auth = get_auth_dependency()

# DatabaseManager dependency
async def get_database() -> DatabaseManager:
    """Provide DatabaseManager as a FastAPI dependency."""
    db = DatabaseManager()
    try:
        await db.initialize()
        logger.info({"event": "database_initialized"})
        yield db
    except DBConnectionError as e:
        logger.error({"event": "db_init_failed", "error": str(e)})
        raise HTTPException(500, detail="Database connection failed")
    finally:
        await db.shutdown()
        logger.info({"event": "database_shutdown"})

async def start_ingestors(db: DatabaseManager):
    """Start zero or more ingestors based on configuration."""
    ingestors_config = get_config("generic", "ingestors", default={})
    if not ingestors_config:
        logger.info({"event": "ingestors_skipped", "message": "No ingestors configured"})
        return

    ingestor_module = importlib.import_module(".ingestors", package="pdns")
    ingestor_classes = {
        cls.type: cls
        for name, cls in inspect.getmembers(ingestor_module, inspect.isclass)
        if hasattr(cls, "type")
        and issubclass(cls, DaemonIngestor)
        and cls != DaemonIngestor
    }

    for ingestor_name, config in ingestors_config.items():
        try:
            ingestor_type = config.get("type")
            if not ingestor_type:
                raise ValueError("Missing 'type' field in ingestor config")

            ingestor_class = ingestor_classes.get(ingestor_type)
            if not ingestor_class:
                raise ValueError(f"Unknown ingestor type: {ingestor_type}")

            ingestor_config = config.get("config", {})
            ingestor = ingestor_class(db, **ingestor_config)
            asyncio.create_task(ingestor.ingest())
            logger.info(
                {
                    "event": "ingestor_started",
                    "name": ingestor_name,
                    "type": ingestor_type,
                    "config": ingestor_config,
                }
            )
        except Exception as e:
            logger.error(
                {
                    "event": "ingestor_start_failed",
                    "name": ingestor_name,
                    "error": str(e),
                }
            )

# Root redirect
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")

# Include routers
app.include_router(info.router)
app.include_router(query.router, dependencies=[Depends(optional_auth)])
app.include_router(fquery.router, dependencies=[Depends(optional_auth)])
app.include_router(stream.router, dependencies=[Depends(optional_auth)])