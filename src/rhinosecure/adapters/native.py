"""The native assets.csv / findings.csv format, as an adapter.

Nothing here is new behavior: `ingest.load_assets` / `ingest.load_findings`
were always the native loaders. Wrapping them in the `IngestAdapter` shape
is what lets `rhino run --format native` (the default) and `--format
defender` go through one code path in cli.py, and what makes "native" a
format like any other rather than the format everything silently assumes.
"""

from __future__ import annotations

from collections.abc import Collection, Iterator
from pathlib import Path

from rhinosecure import ingest
from rhinosecure.adapters.base import IngestAdapter
from rhinosecure.schema import Asset, Finding


class NativeAdapter(IngestAdapter):
    format = "native"
    assets_filename = "assets.csv"
    findings_filename = "findings.csv"

    def load_assets(self, path: Path) -> Iterator[Asset]:
        yield from ingest.load_assets(path)

    def load_findings(self, path: Path, asset_ids: Collection[str]) -> Iterator[Finding]:
        # No orphan pre-check here: ingest.join raises on the first unknown
        # asset_id, exactly as it always has for this format.
        yield from ingest.load_findings(path)
