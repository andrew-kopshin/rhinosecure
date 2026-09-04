"""Ingest adapter registry -- `rhino run --format <name>` resolves here.

See adapters/base.py for what an adapter is and for the `not_collected`
representation every adapter uses for fields its source format lacks.
"""

from __future__ import annotations

from rhinosecure.adapters.base import (
    NOT_COLLECTED_DEFAULTS,
    ROLE_DEFAULT_BY_OS_CLASS,
    AdapterError,
    IngestAdapter,
)
from rhinosecure.adapters.bluepeak import BluePeakAdapter
from rhinosecure.adapters.defender import DefenderAdapter
from rhinosecure.adapters.native import NativeAdapter

DEFAULT_FORMAT = NativeAdapter.format

FORMATS: dict[str, type[IngestAdapter]] = {
    NativeAdapter.format: NativeAdapter,
    DefenderAdapter.format: DefenderAdapter,
    BluePeakAdapter.format: BluePeakAdapter,
}


def get_adapter(name: str) -> IngestAdapter:
    try:
        return FORMATS[name]()
    except KeyError:
        raise AdapterError(f"unknown ingest format {name!r}; known formats: {sorted(FORMATS)}") from None


__all__ = [
    "DEFAULT_FORMAT",
    "FORMATS",
    "NOT_COLLECTED_DEFAULTS",
    "ROLE_DEFAULT_BY_OS_CLASS",
    "AdapterError",
    "BluePeakAdapter",
    "DefenderAdapter",
    "IngestAdapter",
    "NativeAdapter",
    "get_adapter",
]
