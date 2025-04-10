env_global_name = "PDNS_HOME"

from .helpers import get_homedir, load_configs, get_config

from .exceptions import RedisConnectionError, InvalidConfigError, DNSParseError

os.chdir(get_homedir())

__all__ = [
    "RedisConnectionError",
    "InvalidConfigError",
    "DNSParseError",
    "get_homedir",
    "load_configs",
    "get_config",
]
