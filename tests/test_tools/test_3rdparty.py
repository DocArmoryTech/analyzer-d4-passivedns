# tests/test_tools/test_3rdparty.py
import pytest
from tools.3rdparty import fetch_and_convert
from unittest.mock import patch, MagicMock
from pathlib import Path

@pytest.fixture
def mock_csv():
    return """TYPE,Value,Meaning
A,1,a host address
AAAA,28,an IPv6 host address"""

def test_fetch_and_convert(tmp_path, mock_csv):
    """Test RR types fetch and conversion."""
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.text = mock_csv
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        output = tmp_path / "rrtypes.json"
        fetch_and_convert(url="fake_url", output=output)
        data = json.loads(output.read_text())
        assert len(data) == 2
        assert data[0]["Type"] == "A"