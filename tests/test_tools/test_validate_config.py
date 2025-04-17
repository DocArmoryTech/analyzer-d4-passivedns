# tests/test_tools/test_validate_config.py
import pytest
from tools.validate_config_files import validate_generic_config_file, update_user_config
from pathlib import Path

@pytest.fixture
def config_dir(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    return config_dir

def test_validate_config(config_dir):
    """Test config validation."""
    (config_dir / "generic.json.sample").write_text('{"redis": {}, "_notes": {"redis": "Redis settings"}}')
    (config_dir / "generic.json").write_text('{"redis": {}}')
    assert validate_generic_config_file()

def test_update_config(config_dir):
    """Test config update."""
    sample = {"redis": {"backend": "redis"}, "_notes": {"redis": "Redis settings"}}
    (config_dir / "generic.json.sample").write_text(json.dumps(sample))
    (config_dir / "generic.json").write_text('{}')
    assert update_user_config()
    assert json.loads((config_dir / "generic.json").read_text()) == {"redis": {"backend": "redis"}}