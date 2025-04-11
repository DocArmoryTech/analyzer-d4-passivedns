# Schemas Documentation

Pydantic models in `pdns/schemas.py` define the structure of API responses.

## `PDNSRecordSchema`
- **Description**: Represents a DNS record, mirroring `pypdns.PDNSRecord`.
- **Fields**:
  - `rrname` (str): Resource record name.
  - `rrtype` (str): Record type (e.g., "A", "AAAA").
  - `rdata` (str | List[str]): Record data (single value or list).
  - `time_first` (int): First seen timestamp (Unix).
  - `time_last` (int): Last seen timestamp (Unix).
  - `count` (int): Observation count.
  - `sensor_id` (str, optional): Sensor identifier.
- **Methods**:
  - `from_pdns(record: PDNSRecord)`: Converts a `PDNSRecord` to this schema.
  - `to_json(time_format: str)`: Serializes to JSON with "unix" or "iso" timestamps.
  - `to_ndjson(time_format: str)`: Serializes to NDJSON.

## `MetadataResponse`
- **Description**: Wraps a list of records with metadata for `/fquery` and `/query` when `metadata=true`.
- **Fields**:
  - `data` (List[PDNSRecordSchema]): List of records.
  - `total` (int): Total matching records.
  - `next_cursor` (str, optional): Pagination cursor.

## `InfoResponse`
- **Description**: System information for `/info`.
- **Fields**:
  - `version` (str): Software version.
  - `software` (str): Software name.
  - `stats` (dict): System statistics.
  - `sensors` (List[dict]): Sensor data.
