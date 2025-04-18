# pdns/default/exceptions.py
class MissingEnv(Exception):
    """Raised when a required environment variable (e.g., PDNS_HOME) is missing."""
    pass

class DBConnectionError(Exception):
    """Raised when a database connection fails."""
    pass

class InvalidConfigError(Exception):
    """Raised when the configuration is missing or invalid."""
    pass

class DNSParseError(Exception):
    """Raised when DNS record parsing fails."""
    pass