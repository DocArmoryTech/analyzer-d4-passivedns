# pdns/default/helpers.py
from __future__ import annotations
import json
import logging
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
    Preload all JSON config files asynchronously at application startup.

    Args:
        path_to_config_files: Optional path to config directory; defaults to PDNS_HOME/config.

    Raises:
        InvalidConfigError: If config directory is missing or invalid.

    Example:
        >>> await init_configs()
        # Loads config/generic.json, config/redis.json
    """
    async with _config_lock:
        if _configs:
            return
        await load_configs(path_to_config_files)

@lru_cache(64)
async def load_configs(path_to_config_files: str | Path | None = None) -> None:
    """
    Load all JSON config files from config/ into a global dictionary asynchronously.

    Args:
        path_to_config_files: Optional path to config directory; defaults to PDNS_HOME/config.

    Raises:
        InvalidConfigError: If config directory is missing or invalid.

    Example:
        >>> await load_configs()
        # Loads config/generic.json, config/redis.json
    """
    global _configs
    async with _config_lock:
        if _configs:
            return
        config_path = Path(path_to_config_files) if path_to_config_files else get_homedir() / "config"
        if not config_path.exists():
            raise InvalidConfigError(f"Configuration directory {config_path} does not exist.")
        if not config_path.is_dir():
            raise InvalidConfigError(f"Configuration directory {config_path} is not a directory.")

        _configs.clear()
        for entry in os.scandir(config_path):
            if entry.is_file() and entry.name.endswith(".json"):
                async with aiofiles.open(entry.path, mode="r") as f:
                    content = await f.read()
                    _configs[Path(entry.name).stem] = json.loads(content)
                logger.debug(f"Loaded config: {entry.name}")

@lru_cache(64)
async def get_config(config_type: str, entry: str | None = None, quiet: bool = False) -> Any:
    """
    Get a config entry from the specified config type, with fallback to sample file.

    Args:
        config_type: Config file name without .json (e.g., 'generic', 'redis').
        entry: Specific key within the config (e.g., 'redis.backend').
        quiet: Suppress warnings if True.

    Returns:
        Config value or entire config dict if entry is None.

    Raises:
        InvalidConfigError: If neither config nor sample file exists.

    Example:
        >>> await get_config('generic', 'excludesubstrings')
        ['bad.com']
        >>> await get_config('redis')
        {'backend': 'redis_json', 'host': 'localhost'}
    """
    global _configs
    async with _config_lock:
        if not _configs:
            await load_configs()

        if config_type in _configs:
            if entry:
                if entry in _configs[config_type]:
                    return _configs[config_type][entry]
                else:
                    if not quiet:
                        logger.warning(f"Unable to find {entry} in config file.")
            else:
                return _configs[config_type]
        else:
            if not quiet:
                logger.warning(f"No {config_type} config file available.")

        sample_path = get_homedir() / "config" / f"{config_type}.json.sample"
        if not sample_path.exists():
            logger.warning(f"No sample config available: {sample_path}")
            raise InvalidConfigError(f"No {config_type} config or sample file available.")

        if not quiet:
            logger.warning(f"Falling back on sample config: {sample_path}")
        async with aiofiles.open(sample_path, mode="r") as f:
            content = await f.read()
            sample_config = json.loads(content)
        return sample_config[entry] if entry else sample_config