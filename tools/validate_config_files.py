#!/usr/bin/env python3
# ./tools/validate_config_files.py
"""Validate configuration files for analyzer-d4-passivedns."""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any

# Assuming PDNS_HOME is set, or default to project root
try:
    from pdns.default.helpers import get_homedir

    CONFIG_DIR = get_homedir() / "config"
except ImportError:
    # Fallback for standalone execution
    CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

# Setup basic logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger("validate_config")

# Expected configuration schemas
CONFIG_SCHEMAS = {
    "generic": {
        "required": ["exclude", "expiration", "rrset_supported"],
        "defaults": {
            "exclude": ["spamhaus.org", "asn.cymru.com"],
            "expiration": {},
            "rrset_supported": ["1", "2", "5", "15", "16", "28", "33", "46"],
            "notifiers": {},
        },
        "validate": lambda config: (
            isinstance(config["exclude"], list)
            and all(isinstance(s, str) for s in config["exclude"])
            and isinstance(config["expiration"], dict)
            and all(
                k.isdigit() and isinstance(v, int)
                for k, v in config["expiration"].items()
            )
            and isinstance(config["rrset_supported"], list)
            and all(isinstance(t, str) for t in config["rrset_supported"])
        ),
    },
    "rrtypes": {
        "required": [],
        "defaults": {},
        "validate": lambda config: (
            isinstance(config, list)
            and all(
                isinstance(r, dict) and "type" in r and "value" in r for r in config
            )
        ),
    },
    "tokens": {
        "required": ["tokens"],
        "defaults": {"tokens": []},
        "validate": lambda config: (
            isinstance(config["tokens"], list)
            and all(
                isinstance(t, dict) and "value" in t and isinstance(t["value"], str)
                for t in config["tokens"]
            )
        ),
    },
    "alerts": {
        "required": ["alerts"],
        "defaults": {"alerts": []},
        "validate": lambda config: (
            isinstance(config["alerts"], list)
            and all(
                isinstance(a, dict)
                and "name" in a
                and "condition" in a
                and "method" in a
                for a in config["alerts"]
            )
        ),
    },
    "database": {
        "required": ["type", "config"],
        "defaults": {
            "type": "redis",
            "config": {"host": "127.0.0.1", "port": 6400, "db": 0},
        },
        "validate": lambda config: (
            isinstance(config["type"], str)
            and config["type"] in ["redis"]
            and isinstance(config["config"], dict)
            and "host" in config["config"]
            and "port" in config["config"]
        ),
    },
    "auth": {
        "required": ["endpoints"],
        "defaults": {
            "endpoints": {
                "info": {"auth": "none"},
                "query": {"auth": "none"},
                "fquery": {"auth": "none"},
                "stream": {"auth": "none"},
            }
        },
        "validate": lambda config: (
            isinstance(config["endpoints"], dict)
            and all(
                isinstance(v, dict)
                and "auth" in v
                and v["auth"] in ["none", "bearer", "openid"]
                for v in config["endpoints"].values()
            )
        ),
    },
    "logging": {
        "required": ["version", "handlers", "loggers"],
        "defaults": {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "verbose": {
                    "format": "%(levelname)s %(asctime)s %(name)s %(module)s:%(lineno)s %(message)s"
                }
            },
            "handlers": {
                "console": {
                    "level": "INFO",
                    "class": "logging.StreamHandler",
                    "formatter": "verbose",
                }
            },
            "loggers": {
                "pdns": {"level": "INFO", "handlers": ["console"], "propagate": False}
            },
        },
        "validate": lambda config: (
            isinstance(config["version"], int)
            and isinstance(config["handlers"], dict)
            and isinstance(config["loggers"], dict)
        ),
    },
}


def validate_config_file(file_name: str) -> Dict[str, Any]:
    """Validate a single configuration file and return its contents with defaults applied."""
    path = CONFIG_DIR / f"{file_name}.json"
    schema = CONFIG_SCHEMAS.get(file_name, {})
    config = {}

    if not path.exists():
        logger.warning(f"Missing config file: {path}. Checking for sample...")
        sample_path = CONFIG_DIR / f"{file_name}.json.sample"
        if sample_path.exists():
            with sample_path.open() as f:
                config = json.load(f)
            logger.info(f"Using sample config from {sample_path}")
        else:
            logger.error(f"No config or sample found for {file_name}. Using defaults.")
            config = schema.get("defaults", {})
    else:
        with path.open() as f:
            config = json.load(f)

    # Apply defaults for missing required keys
    for key in schema.get("required", []):
        if key not in config:
            if key in schema["defaults"]:
                config[key] = schema["defaults"][key]
                logger.info(f"Added default value for {key} in {file_name}")
            else:
                logger.error(
                    f"Required key {key} missing in {file_name} and no default available"
                )
                sys.exit(1)

    # Validate structure
    if "validate" in schema and not schema["validate"](config):
        logger.error(f"Invalid structure in {file_name}.json: {config}")
        sys.exit(1)

    return config


def main():
    """Validate all configuration files."""
    logger.info("Starting configuration validation...")
    for config_name in CONFIG_SCHEMAS:
        try:
            config = validate_config_file(config_name)
            logger.info(f"Validated {config_name}.json: {config}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse {config_name}.json: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error validating {config_name}.json: {e}")
            sys.exit(1)
    logger.info("All configuration files validated successfully.")


if __name__ == "__main__":
    main()
