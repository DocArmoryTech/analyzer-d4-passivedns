import importlib
import inspect
import pathlib
from typing import Dict, Type, List, Union
from .base import Ingestor, LineIngestor, StreamIngestor, FrameIngestor
from ..db.manager import DatabaseManager
from ..default.helpers import logger

def _discover_ingestors(base_class: Type[Ingestor], subdir: str) -> Dict[str, Type[Ingestor]]:
    """Discover ingestor subclasses in the specified subdirectory."""
    ingestor_classes = {}
    ingestor_dir = pathlib.Path(__file__).parent / subdir
    for py_file in ingestor_dir.glob("*.py"):
        if py_file.name == "__init__.py":
            continue
        module_name = f"pdns.ingestors.{subdir}.{py_file.stem}"
        try:
            module = importlib.import_module(module_name)
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, base_class) and obj != base_class and hasattr(obj, "type"):
                    ingestor_classes[obj.type] = obj
                    logger.debug({"event": f"{subdir}_ingestor_discovered", "type": obj.type, "class": name})
        except ImportError as e:
            logger.error({"event": f"{subdir}_ingestor_import_error", "module": module_name, "error": str(e)})
    return ingestor_classes

def load_ingestors(db_manager: DatabaseManager, config: Dict) -> List[Ingestor]:
    """Load and instantiate ingestor subclasses based on configuration."""
    ingestor_classes = {
        "line": _discover_ingestors(LineIngestor, "line"),
        "stream": _discover_ingestors(StreamIngestor, "stream"),
        "frame": _discover_ingestors(FrameIngestor, "frame"),
    }
    ingestors = []
    for name, ingestor_config in config.get("ingestors", {}).items():
        ingestor_type = ingestor_config.get("type")
        if not ingestor_type:
            logger.error({"event": "ingestor_config_error", "name": name, "error": "Missing type"})
            continue
        ingestor_class = None
        category = None
        for cat, classes in ingestor_classes.items():
            if ingestor_type in classes:
                ingestor_class = classes[ingestor_type]
                category = cat
                break
        if not ingestor_class:
            logger.error({"event": "ingestor_not_found", "type": ingestor_type, "name": name})
            continue
        try:
            ingestor_config = ingestor_config.get("config", {})
            ingestor = ingestor_class(db_manager, ingestor_config)
            ingestors.append(ingestor)
            logger.info({"event": "ingestor_loaded", "type": ingestor_type, "name": name, "category": category})
        except Exception as e:
            logger.error({"event": "ingestor_instantiation_error", "type": ingestor_type, "name": name, "error": str(e)})
    return ingestors

__all__ = ["Ingestor", "LineIngestor", "StreamIngestor", "FrameIngestor", "load_ingestors"]