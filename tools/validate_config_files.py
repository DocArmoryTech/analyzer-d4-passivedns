#!/usr/bin/env python3
"""Validate and update configuration files for analyzer-d4-passivedns."""

import json
import logging
import argparse
from pathlib import Path
from typing import Any

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger("validate_config")

# Assuming PDNS_HOME is set, or default to project root
try:
    from pdns.default.helpers import get_homedir
    CONFIG_DIR = get_homedir() / "config"
except ImportError:
    # Fallback for standalone execution
    CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

def validate_generic_config_file() -> bool:
    """Validate generic.json against generic.json.sample."""
    sample_path = CONFIG_DIR / "generic.json.sample"
    user_path = CONFIG_DIR / "generic.json"

    # Load sample config
    if not sample_path.exists():
        raise FileNotFoundError(f"Sample config not found: {sample_path}")
    with sample_path.open() as f:
        sample_config = json.load(f)

    # Check documentation in _notes
    for key in sample_config.keys():
        if key == "_notes":
            continue
        if key not in sample_config["_notes"]:
            raise ValueError(f"Documentation missing for '{key}' in {sample_path}")

    # If user config doesn’t exist, create it from sample
    if not user_path.exists():
        with user_path.open("w") as fw:
            json.dump(sample_config, fw, indent=2, sort_keys=True)
        logger.info(f"Created {user_path} from sample since it was missing")
        return True

    # Load user config
    with user_path.open() as f:
        user_config = json.load(f)

    # Validate keys and types recursively
    def validate_structure(sample: Any, user: Any, path: str = "") -> None:
        if isinstance(sample, dict):
            for key, sample_value in sample.items():
                if key == "_notes":
                    continue
                user_value = user.get(key)
                current_path = f"{path}.{key}" if path else key

                if user_value is None:
                    logger.warning(f"Entry missing in user config at '{current_path}'. Will default to: {sample_value}")
                    continue

                if type(user_value) != type(sample_value):
                    raise ValueError(
                        f"Invalid type for '{current_path}'. Got: {type(user_value)} ({user_value}), "
                        f"expected: {type(sample_value)} ({sample_value})"
                    )

                # Recursively validate nested structures
                if isinstance(sample_value, (dict, list)):
                    validate_structure(sample_value, user_value, current_path)

        elif isinstance(sample, list):
            if not isinstance(user, list):
                raise ValueError(f"Expected a list at '{path}', got: {type(user)} ({user})")
            if not user and sample:  # Allow empty lists if sample isn’t empty
                logger.warning(f"List at '{path}' is empty in user config, sample has: {sample}")
            # For simplicity, don’t enforce list item types unless critical (e.g., tokens)
            if path == "tokens" and user:
                for u, s in zip(user, sample):
                    validate_structure(s, u, path)

    # Check sample keys are in user config
    validate_structure(sample_config, user_config)

    # Check for extra keys in user config not in sample
    for key in user_config.keys():
        if key not in sample_config:
            raise ValueError(f"'{key}' is missing in {sample_path}. Compare with {user_path}")

    return True

def update_user_config() -> bool:
    """Update generic.json with missing entries from generic.json.sample."""
    sample_path = CONFIG_DIR / "generic.json.sample"
    user_path = CONFIG_DIR / "generic.json"

    # Load configs
    with sample_path.open() as f:
        sample_config = json.load(f)
    if not user_path.exists():
        with user_path.open("w") as fw:
            json.dump(sample_config, fw, indent=2, sort_keys=True)
        logger.info(f"Created {user_path} from sample")
        return True

    with user_path.open() as f:
        user_config = json.load(f)

    has_new_entry = False

    def update_structure(sample: dict, user: dict, path: str = "") -> None:
        nonlocal has_new_entry
        for key, sample_value in sample.items():
            if key == "_notes":
                continue
            current_path = f"{path}.{key}" if path else key
            if key not in user:
                logger.info(f"'{current_path}' missing in user config, adding: {sample_value}")
                logger.info(f"Description: {sample_config['_notes'].get(key, 'No description')}")
                user[key] = sample_value
                has_new_entry = True
            elif isinstance(sample_value, dict):
                if not isinstance(user[key], dict):
                    logger.info(f"Replacing invalid type at '{current_path}' with: {sample_value}")
                    user[key] = sample_value
                    has_new_entry = True
                else:
                    update_structure(sample_value, user[key], current_path)

    update_structure(sample_config, user_config)

    if has_new_entry:
        with user_path.open("w") as fw:
            json.dump(user_config, fw, indent=2, sort_keys=True)
        logger.info(f"Updated {user_path} with new entries")

    return has_new_entry

def main():
    """Validate or update configuration files based on arguments."""
    parser = argparse.ArgumentParser(description="Check and update config files for analyzer-d4-passivedns.")
    parser.add_argument("--check", action="store_true", help="Check if generic.json matches generic.json.sample")
    parser.add_argument("--update", action="store_true", help="Update generic.json with missing entries from sample")
    args = parser.parse_args()

    if not args.check and not args.update:
        parser.print_help()
        sys.exit(1)

    if args.check:
        try:
            if validate_generic_config_file():
                logger.info(f"The entries in {CONFIG_DIR / 'generic.json'} are valid.")
        except Exception as e:
            logger.error(f"Validation failed: {e}")
            sys.exit(1)

    if args.update:
        try:
            if not update_user_config():
                logger.info(f"No updates needed in {CONFIG_DIR / 'generic.json'}.")
        except Exception as e:
            logger.error(f"Update failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()