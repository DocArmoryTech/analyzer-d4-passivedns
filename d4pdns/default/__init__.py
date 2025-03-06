env_global_name = "D4_PDNS"

from .helpers import (
    get_homedir, get_config_dir, get_config_file, load_config, get_config,
    load_logging_config, get_socket_path, get_redis, normalize_domain
)
from .exceptions import RedisConnectionError, InvalidConfigError, DNSParseError
from .dns_types import load_dns_types

os.chdir(get_homedir())

__all__ = [
    'setup_logger',
    'load_config',
    'init_redis',
    'load_dns_types',
    'process_record'
]
