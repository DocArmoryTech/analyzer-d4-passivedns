# tests/test_helpers.py
import pytest
import logging
import json
from pdns.default.helpers import logger, get_config, load_logging_config

def test_logger(caplog):
    caplog.set_level(logging.INFO)
    logger.info({"event": "test_event", "message": "Hello, world!"})
    assert "test_event" in caplog.text
    assert "Hello, world!" in caplog.text

def test_get_config(tmp_path):
    # Mock a config file
    config_file = tmp_path / "generic.json"
    config_file.write_text('{"test_section": {"key": "value"}}')
    
    with pytest.MonkeyPatch.context() as m:
        # Assuming get_config reads from a global CONFIG_FILE or similar
        m.setattr("pdns.default.helpers.CONFIG_FILE", str(config_file))
        config = get_config("test_section")
        assert config == {"key": "value"}
    
    # Test missing section
    assert get_config("missing_section") == {}

def test_load_logging_config(tmp_path, caplog):
    # Mock a logging config file
    log_config_file = tmp_path / "logging.json"
    log_config = {
        "version": 1,
        "handlers": {"console": {"class": "logging.StreamHandler", "level": "INFO"}},
        "root": {"level": "INFO", "handlers": ["console"]}
    }
    log_config_file.write_text(json.dumps(log_config))
    
    with pytest.MonkeyPatch.context() as m:
        m.setattr("pdns.default.helpers.LOGGING_CONFIG_FILE", str(log_config_file))
        load_logging_config()
    
    caplog.set_level(logging.INFO)
    logger.info("Test logging config")
    assert "Test logging config" in caplog.text