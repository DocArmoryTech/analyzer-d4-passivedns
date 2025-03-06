from pathlib import Path
import json
import redis
import logging.config
import os
import sys

# Global caches
redis_analyzer = None
redis_metadata = None
_logger = None

def get_homedir() -> Path:
    return Path(__file__).parent.parent.parent

def get_config_dir() -> Path:
    return get_homedir() / 'config'

def get_config_file(config_name: str) -> Path:
    return get_config_dir() / f'{config_name}.json'

def load_config() -> dict:
    config_file = get_config_file('generic')
    if not config_file.exists():
        logger = load_logging_config()
        logger.critical(f"Configuration file not found: {config_file}")
        sys.exit(1)
    try:
        with config_file.open() as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger = load_logging_config()
        logger.critical(f"Invalid JSON in config file {config_file}: {e}")
        sys.exit(1)

def get_config(category: str, value: str = None):
    conf = load_config()
    if value is None:
        return conf.get(category, {})
    return conf.get(category, {}).get(value)

def load_logging_config() -> logging.Logger:
    global _logger
    if _logger is None:
        logging_conf = get_config_file('logging')
        if not logging_conf.exists():
            # Fallback to basic config if logging.json is missing
            logging.basicConfig(level=logging.INFO)
        else:
            try:
                with logging_conf.open() as f:
                    logging.config.dictConfig(json.load(f))
            except (json.JSONDecodeError, ValueError) as e:
                logging.basicConfig(level=logging.INFO)
                logging.getLogger('d4_pdns').critical(f"Invalid logging config {logging_conf}: {e}")
        _logger = logging.getLogger('d4_pdns')
    return _logger

def get_socket_path(section: str) -> str:
    socket_path = get_config('redis', section).get('socket_path')
    if not socket_path:
        env_var = f'D4_{section.upper()}_REDIS_SOCKET'
        socket_path = os.getenv(env_var, f'./cache/{section}.sock')
    full_path = str(get_homedir() / socket_path) if not socket_path.startswith('/') else socket_path
    if not os.path.exists(full_path):
        logger = load_logging_config()
        logger.critical(f"Redis socket not found: {full_path}")
        sys.exit(1)
    return full_path

def get_redis(section: str = 'analyzer') -> redis.Redis:
    from .exceptions import RedisConnectionError
    global redis_analyzer, redis_metadata
    if section == 'analyzer' and redis_analyzer is not None:
        return redis_analyzer
    if section == 'metadata' and redis_metadata is not None:
        return redis_metadata
    socket_path = get_socket_path(section)
    db = get_config('redis', section).get('db', 0)
    try:
        conn = redis.Redis(unix_socket_path=socket_path, db=db, decode_responses=True)
        conn.ping()
    except redis.ConnectionError as e:
        logger = load_logging_config()
        logger.critical(f"Failed to connect to Redis ({section}) at {socket_path}: {e}")
        raise RedisConnectionError(f"Redis ({section}) connection failed: {e}")
    if section == 'analyzer':
        redis_analyzer = conn
    elif section == 'metadata':
        redis_metadata = conn
    return conn

def normalize_domain(domain: str) -> str:
    return domain.strip('.').lower()