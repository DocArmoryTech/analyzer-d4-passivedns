from pathlib import Path
import json
from .helpers import load_logging_config

def load_dns_types() -> dict:
    logger = load_logging_config()
    rtype_path = Path(__file__).parent.parent.parent / 'config' / 'records-type.json'
    if not rtype_path.exists():
        logger.critical(f"Records type file not found: {rtype_path}")
        sys.exit(1)
    try:
        with rtype_path.open() as rtypefile:
            rtype = json.load(rtypefile)
    except json.JSONDecodeError as e:
        logger.critical(f"Invalid JSON in records-type file {rtype_path}: {e}")
        sys.exit(1)
    return {v['type']: v['value'] for v in rtype}