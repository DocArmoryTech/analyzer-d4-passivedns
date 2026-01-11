import pytest
from pathlib import Path
from unittest.mock import AsyncMock

from pdns.db.manager import DatabaseManager
from pdns.ingestors.file.line.ndjson import NDJSONFileIngestor


@pytest.mark.asyncio
async def test_ingest_original_readme_ndjson_dataset():
    """Ingest the tiny NDJSON dataset derived from the original README examples.

    This is a tip-of-the-hat fixture ensuring the COF-style records from the
    historical README remain parseable by the NDJSON ingestor.
    """
    db_manager = AsyncMock(spec=DatabaseManager)

    dataset_path = (
        Path(__file__).parent.parent / "testdata" / "original_readme_tip.ndjson"
    )

    ingestor = NDJSONFileIngestor(db_manager, {"file_path": str(dataset_path)})
    await ingestor.ingest()

    # We expect three valid records from the dataset
    assert db_manager.store_record.call_count == 3
    calls = db_manager.store_record.call_args_list

    rrnames = [call.args[0].rrname for call in calls]
    assert "xn--ihuvudetpevap-xfb.se" in rrnames
    assert "media.vastporten.se" in rrnames
    assert "serbiagreenbuildingexpo.com" in rrnames
