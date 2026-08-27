"""CSV ingest for the two input files.

Rows are read and validated one at a time via generators — nothing here
collects a whole file into memory, and nothing branches on how many rows a
particular dataset happens to have. A future adapter for a real scanner
export (Nessus/Qualys/InsightVM/Defender VM) sits in front of these loaders:
it normalizes that export's native columns into assets.csv / findings.csv
shape and hands rows to the same `Asset` / `Finding` models. Nothing below
needs to change for that to work.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

from pydantic import ValidationError

from rhinosecure.schema import Asset, EnrichedFinding, Finding


class IngestError(Exception):
    """A row failed schema validation."""


def _rows(path: Path) -> Iterator[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        yield from csv.DictReader(f)


def load_assets(path: Path) -> Iterator[Asset]:
    for row in _rows(path):
        try:
            yield Asset.model_validate(row)
        except ValidationError as exc:
            raise IngestError(f"{path}: invalid asset row {row!r}: {exc}") from exc


def load_findings(path: Path) -> Iterator[Finding]:
    for row in _rows(path):
        try:
            yield Finding.model_validate(row)
        except ValidationError as exc:
            raise IngestError(f"{path}: invalid finding row {row!r}: {exc}") from exc


def load_asset_index(path: Path) -> dict[str, Asset]:
    """Build an asset_id -> Asset lookup.

    Findings are the side of this join expected to scale with fleet size, so
    only they are kept as a lazy stream; the asset inventory is the natural
    side to index for O(1) lookup during that stream's consumption.
    """
    index: dict[str, Asset] = {}
    for asset in load_assets(path):
        index[asset.asset_id] = asset
    return index


def join_findings(
    findings_path: Path, assets_path: Path
) -> Iterator[EnrichedFinding]:
    asset_index = load_asset_index(assets_path)
    for finding in load_findings(findings_path):
        asset = asset_index.get(finding.asset_id)
        if asset is None:
            raise IngestError(
                f"{findings_path}: finding {finding.finding_id!r} references "
                f"unknown asset_id {finding.asset_id!r}"
            )
        yield EnrichedFinding(finding=finding, asset=asset)
