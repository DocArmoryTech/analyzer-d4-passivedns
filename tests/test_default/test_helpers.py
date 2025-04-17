# tests/test_default/test_helpers.py
import pytest
from pdns.default.helpers import get_homedir, load_configs, get_config, init_configs
from pdns.default.exceptions import InvalidConfigError, MissingEnv
from pathlib import Path
import aiofiles
from unittest.mock import patch, mock_open

@pytest.fixture
def mock_env():
    with patch.dict("os.environ", {}, clear=True):
        yield

@pytest.mark.asyncio
async def test_get_homedir(mock_env, tmp_path):
    """Test get_homedir with .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text('PDNS_HOME="/fake/path"')
    with patch("pdns.default.helpers.Path", return_value=tmp_path):
        assert get_homedir() == Path("/fake/path")

@pytest.mark.asyncio
async def test_load_configs(tmp_path):
    """Test async load_configs with valid JSON."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    async with aiofiles.open(config_dir / "generic.json", "w") as f:
        await f.write('{"redis": {"backend": "redis"}}')
    with patch("pdns.default.helpers.get_homedir", return_value=tmp_path):
        await load_configs()
        assert await get_config("generic") == {"redis": {"backend": "redis"}}

@pytest.mark.asyncio
async def test_get_config_fallback(tmp_path):
    """Test async get_config fallback to sample."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    async with aiofiles.open(config_dir / "generic.json.sample", "w") as f:
        await f.write('{"redis": {"backend": "redis"}}')
    with patch("pdns.default.helpers.get_homedir", return_value=tmp_path):
        assert await get_config("generic", "redis") == {"backend": "redis"}

@pytest.mark.asyncio
async def test_init_configs(tmp_path):
    """Test init_configs preloading."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    async with aiofiles.open(config_dir / "generic.json", "w") as f:
        await f.write('{"redis": {"backend": "redis"}}')
    with patch("pdns.default.helpers.get_homedir", return_value=tmp_path):
        await init_configs()
        assert await get_config("generic") == {"redis": {"backend": "redis"}}