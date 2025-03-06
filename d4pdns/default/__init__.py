env_global_name = "D4PDNS_HOME"

from .helpers import (
    get_homedir, load_configs, get_config, safe_create_dir, 
    get_redis, try_make_file, load_logging_config, normalize_domain
)

from .exceptions import RedisConnectionError, InvalidConfigError, DNSParseError
from .dns_types import load_dns_types

os.chdir(get_homedir())

__all__ = [
    'RedisConnectionError',
    'InvalidConfigError',
    'DNSParseError',
    'get_homedir',
    'load_configs',
    'get_config',
    'safe_create_dir',
    'get_redis',
    'try_make_file',
    'normalize_domain',
    'load_logging_config'
    'load_dns_types'
]
