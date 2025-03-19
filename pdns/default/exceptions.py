class RedisConnectionError(Exception):
    """Raised when a Redis connection fails."""
    pass

class InvalidConfigError(Exception):
    """Raised when the configuration is missing or invalid."""
    pass

class DNSParseError(Exception):
    """Raised when DNS record parsing fails."""
    pass