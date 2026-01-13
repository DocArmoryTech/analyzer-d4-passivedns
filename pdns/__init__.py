from importlib.metadata import PackageNotFoundError, version

try:
	__version__ = version("pdns")  # "pdns" matches the package name in pyproject.toml
except PackageNotFoundError:
	# Fallback when package metadata is not available (for example when
	# running from a source checkout or inside certain container builds).
	__version__ = "0.0.0"


# Compatibility shim for pypdns.PDNSRecord
#
# The refactored codebase expects a PDNSRecord type that can be
# constructed with keyword arguments like rrname, rrtype, rdata,
# time_first, time_last, count, and optional sensor_id. Recent
# versions of the external ``pypdns`` package no longer expose this
# class, providing only the PyPDNS HTTP client instead. To keep the
# rest of the code (and its imports) working with modern pypdns
# versions, we create a light-weight local PDNSRecord implementation
# and attach it to the imported pypdns module when needed.
try:  # pragma: no cover - defensive compatibility shim
	import pypdns as _pypdns  # type: ignore[import]

	if not hasattr(_pypdns, "PDNSRecord"):
		from dataclasses import dataclass
		from datetime import datetime
		from typing import List, Optional, Union

		@dataclass
		class PDNSRecord:  # type: ignore[too-many-instance-attributes]
			rrname: str
			rrtype: str
			rdata: List[str]
			time_first: Union[int, float, datetime]
			time_last: Union[int, float, datetime]
			count: int
			sensor_id: Optional[str] = None

		# Expose the shim so ``from pypdns import PDNSRecord`` works
		_pypdns.PDNSRecord = PDNSRecord  # type: ignore[attr-defined]
except Exception:
	# If pypdns is not installed at all, imports that depend on it will
	# fail as before; this shim only targets the "pypdns present but
	# PDNSRecord missing" scenario.
	pass
