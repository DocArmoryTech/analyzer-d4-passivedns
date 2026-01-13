"""DNS RR type definitions derived from JSON config.

This module reads ``config/rrtypes.json`` and ``config/generic.json``
directly using :func:`get_homedir` to locate ``PDNS_HOME``. This avoids
relying on the async configuration initialisation used elsewhere
(:func:`init_configs`) and allows the enums to be constructed safely at
import time in both local and container environments.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import List

from .default.helpers import get_homedir, logger
from .default.exceptions import InvalidConfigError


def _config_dir() -> Path:
    """Return the configuration directory under PDNS_HOME."""

    return get_homedir() / "config"


def _load_rrtypes_config() -> list[dict]:
    """Load the rrtypes.json configuration file.

    Raises InvalidConfigError on any structural or decoding issue.
    """

    path = _config_dir() / "rrtypes.json"
    if not path.exists():
        raise InvalidConfigError("rrtypes.json is missing or invalid")

    try:
        with path.open("r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise InvalidConfigError(f"Invalid JSON in rrtypes.json: {e}")

    if not isinstance(data, list):
        raise InvalidConfigError("rrtypes.json must be a list of objects")

    return data


def _load_supported_types(rrtypes_config: list[dict]) -> list[str]:
    """Load the list of supported RR types from generic.json."""

    path = _config_dir() / "generic.json"
    if not path.exists():
        raise InvalidConfigError("generic.json is missing or invalid")

    try:
        with path.open("r") as f:
            generic_cfg = json.load(f)
    except json.JSONDecodeError as e:
        raise InvalidConfigError(f"Invalid JSON in generic.json: {e}")

    supported = generic_cfg.get("rrset_supported", [])
    if not supported or not isinstance(supported, list):
        raise InvalidConfigError("generic.rrset_supported is missing or invalid")

    # Normalise to strings
    return [str(t) for t in supported]


# Load and validate rrtypes
rrtypes_config = _load_rrtypes_config()

RRType = Enum(
    "RRType",
    {
        entry["type"].upper(): entry["value"]
        for entry in rrtypes_config
        if isinstance(entry, dict) and "type" in entry and "value" in entry
    },
    type=str,
)


def create_supported_enum(supported: List[str]) -> Enum:
    """Create an enum for supported RR types based on config.

    Args:
        supported: List of supported RR type names or numeric values.

    Returns:
        Enum of supported RR types.
    """

    enum_dict: dict[str, str] = {}
    rrset = {entry["type"].upper(): entry["value"] for entry in rrtypes_config}

    for t in supported:
        t_upper = t.upper()
        if t_upper in rrset:
            enum_dict[t_upper] = rrset[t_upper]
        elif t in rrset.values():
            name = next((k for k, v in rrset.items() if v == t), None)
            if name:
                enum_dict[name] = t
        else:
            logger.warning(
                f"Invalid supported RR type in generic.rrset_supported: {t}"
            )

    if not enum_dict:
        raise InvalidConfigError(
            "No valid supported RR types found in generic.rrset_supported"
        )

    return Enum("SupportedRRType", enum_dict, type=str)


supported_types = _load_supported_types(rrtypes_config)
SupportedRRType = create_supported_enum(supported_types)

__all__ = ["RRType", "SupportedRRType"]