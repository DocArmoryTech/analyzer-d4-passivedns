# pdns/default/helpers.py
from __future__ import annotations
import json
import logging
import logging.config
import os
from functools import lru_cache
from pathlib import Path
from typing import Any
import aiofiles
import asyncio

from . import env_global_name
from .exceptions import InvalidConfigError, MissingEnv

_configs: dict[str, dict[str, Any]] = {}
logger = logging.getLogger("Helpers")
_config_lock = asyncio.Lock()
LOGGING_CONFIG_FILE: str | None = None

@lru_cache(64)
def get_homedir() -> Path:
    """
    Resolve the project home directory from PDNS_HOME or .env.

    Returns:
        Path to the project root.

    Raises:
        MissingEnv: If PDNS_HOME is not set and .env is missing or invalid.

    Example:
        >>> get_homedir()
        PosixPath('/path/to/analyzer-d4-passivedns')
    """
    if not os.environ.get(env_global_name):
        env_file = Path(__file__).resolve().parent.parent.parent / ".env"
        if env_file.exists():
            with env_file.open() as f:
                for line in f:
                    key, value = line.strip().split("=", 1)
                    if value[0] in ['"', "'"]:
                        value = value[1:-1]
                    os.environ[key] = value

    if not os.environ.get(env_global_name):
        guessed_home = Path(__file__).resolve().parent.parent.parent
        raise MissingEnv(
            f"{env_global_name} is missing. "
            f"Run: export {env_global_name}='{guessed_home}'"
        )
    return Path(os.environ[env_global_name])

async def init_configs(path_to_config_files: str | Path | None = None) -> None:
    """
    Load all JSON config files asynchronously at application startup.

    Args:
        path_to_config_files: Optional path to config directory; defaults to PDNS_HOME/config.

    Raises:
        InvalidConfigError: If config directory is missing or invalid.

    Example:
        >>> await init_configs()
        # Loads config/generic.json, config/redis.json
    """
    global _configs
    async with _config_lock:
        if _configs:
            logger.warning("Configs already loaded, skipping initialization")
            return
        config_path = Path(path_to_config_files) if path_to_config_files else get_homedir() / "config"
        if not config_path.exists() or not config_path.is_dir():
            raise InvalidConfigError(f"Configuration directory {config_path} is invalid")

        for entry in config_path.glob("*.json"):
            try:
                async with aiofiles.open(entry, "r") as f:
                    content = await f.read()
                    _configs[entry.stem] = json.loads(content)
                logger.debug(f"Loaded config: {entry.name}")
            except json.JSONDecodeError as e:
                raise InvalidConfigError(f"Invalid JSON in {entry}: {e}")


async def load_configs(path_to_config_files: str | Path | None = None) -> None:
    """Backward-compatible alias for init_configs.

    Legacy code may still import and await load_configs(); keep it as a
    thin wrapper around init_configs so those call sites continue to work.
    """
    await init_configs(path_to_config_files)

def get_config(config_type: str, entry: str | None = None, default: Any = None) -> Any:
    """
    Get a config entry from the specified config type.

    Args:
        config_type: Config file name without .json (e.g., 'generic', 'redis').
        entry: Specific key within the config (e.g., 'redis.backend').
        default: Default value if config or entry is missing.

    Returns:
        Config value or default if not found.

    Raises:
        InvalidConfigError: If configs are not initialized.

    Example:
        >>> get_config('generic', 'excludesubstrings')
        ['bad.com']
        >>> get_config('redis')
        {'backend': 'redis_json', 'host': 'localhost'}
    """
    if not _configs:
        raise InvalidConfigError("Configs not initialized. Call init_configs() first")

    config = _configs.get(config_type, {})
    if not config:
        logger.warning(f"No {config_type} config found, returning default: {default}")
        return default

    if entry:
        result = config.get(entry, default)
        if result is None:
            logger.warning(f"Entry {entry} not found in {config_type}, returning default: {default}")
        return result
    return config


def load_logging_config() -> None:
    """Load logging configuration from config/logging.json.

    Supports two formats:
    - A full logging dictConfig (with a top-level "version" key).
    - A simple JSON object with "level", "file", and "format" fields.

    Falls back to a basic INFO-level configuration if anything fails.
    """

    # Determine logging config path, allowing tests to override via LOGGING_CONFIG_FILE.
    try:
        env_path = os.environ.get("LOGGING_CONFIG_FILE")
        if env_path:
            path = Path(env_path)
        else:
            path = Path(LOGGING_CONFIG_FILE) if LOGGING_CONFIG_FILE else get_homedir() / "config" / "logging.json"
    except MissingEnv as e:
        # If home cannot be resolved, just configure basic logging.
        logging.basicConfig(level=logging.INFO)
        logger.error({"event": "logging_config_env_missing", "error": str(e)})
        return

    if not path.exists():
        logging.basicConfig(level=logging.INFO)
        logger.warning({"event": "logging_config_missing", "path": str(path)})
        return

    try:
        with path.open("r") as f:
            config = json.load(f)

        # If this looks like a dictConfig, delegate to logging.config.
        if isinstance(config, dict) and "version" in config:
            logging.config.dictConfig(config)
            logger.info({"event": "logging_config_loaded", "mode": "dictConfig", "path": str(path)})
            return

        # Otherwise, interpret it as a simple shorthand config.
        level_name = str(config.get("level", "INFO")).upper()
        level = getattr(logging, level_name, logging.INFO)
        fmt = config.get("format", "%(asctime)s %(levelname)s: %(message)s")
        log_file = config.get("file")

        if log_file:
            logging.basicConfig(level=level, format=fmt, filename=log_file)
        else:
            logging.basicConfig(level=level, format=fmt)

        logger.info({"event": "logging_config_loaded", "mode": "simple", "path": str(path)})
    except Exception as e:
        # On any error, fall back to a safe default.
        logging.basicConfig(level=logging.INFO)
        logger.error({"event": "logging_config_error", "path": str(path), "error": str(e)})


def load_dns_types():
    """Lazy helper to load DNS RR type definitions.

    Importing inside the function avoids triggering rrtypes loading at
    module import time. The current CLI only uses the return value for
    side effects, so we simply return the imported module.
    """
    from .. import rrtypes as _rrtypes

    return _rrtypes