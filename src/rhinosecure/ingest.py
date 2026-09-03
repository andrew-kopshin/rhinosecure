"""CSV ingest for the two input files, plus attaching live threat signals
to what was ingested.

Rows are read and validated one at a time via generators — nothing here
collects a whole file into memory, and nothing branches on how many rows a
particular dataset happens to have. A future adapter for a real scanner
export (Nessus/Qualys/InsightVM/Defender VM) sits in front of these loaders:
it normalizes that export's native columns into assets.csv / findings.csv
shape and hands rows to the same `Asset` / `Finding` models. Nothing below
needs to change for that to work.

That adapter layer now exists: `adapters/` (base.py for the contract and
the `not_collected` representation of fields a source format lacks;
defender.py for Microsoft Defender Vulnerability Management). `join` is the
loader-agnostic half of the old `join_findings`: an adapter hands it an
already-indexed inventory and a lazy finding stream in whatever way its
source format requires, and it does the one thing every format needs
identically -- attach each finding to its asset, refusing an orphan.
`join_findings` (the native two-path form every existing caller uses) is
unchanged in behavior and delegates to it; `load_batch` is what cli.py
calls for any format. `IngestStats`/`IngestReport` live here rather than
in `adapters/` because they describe a batch, not a format, and cli.py
prints them for every format alike.

`attach_threat_signals` was originally private to `cli.py`'s deterministic
`run()`. Moved here (public, unchanged behavior) so `agents/coordinator.py`'s
fleet-wide capacity constraint flow can reuse the exact same real,
network/cache-sourced KEV/EPSS/NVD/ATT&CK enrichment without going through
the Research agent -- CLAUDE.md Section 10's "only five patches fit this
window" example needs the *real* bucket a finding is in to decide who
competes for capacity, but the reallocation itself has to stay
deterministic (Section 8 rule 2's "no LLM calls" discipline, applied here
to "no LLM call decides who's in the competing pool" too -- see
scoring.apply_capacity_limit's own docstring). `coordinator.py` importing
this from `cli.py` directly would have been the wrong direction (the
entry-point module reaching down into a lower-level one); this module
already sits below both and was the natural shared home -- ingest a
finding, then attach what's known about its real-world threat, are two
facets of "get a finding ready for score_finding," not different concerns.
This module still makes no LLM calls and needs none of `crewai` -- only
network/cache access via `SnapshotCache`, safe to import from either the
deterministic or agents path.
"""

from __future__ import annotations

import csv
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from rhinosecure.enrich.attack import TechniqueIndex
from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.enrich.epss import lookup as epss_lookup
from rhinosecure.enrich.kev import KevCatalog
from rhinosecure.enrich.nvd import lookup as nvd_lookup
from rhinosecure.schema import Asset, AttackTechniqueRef, EnrichedFinding, Finding

if TYPE_CHECKING:  # adapters/base.py imports this module; keep the runtime import graph one-directional
    from rhinosecure.adapters.base import IngestAdapter


class IngestError(Exception):
    """A row failed schema validation, or an adapter refused its input
    (adapters.AdapterError subclasses this)."""


@dataclass
class IngestStats:
    """What an adapter collapsed on the way in. Mutable: a streaming
    `load_findings` can only count as its iterator is consumed."""

    duplicate_assets_collapsed: int = 0
    duplicate_findings_collapsed: int = 0


@dataclass(frozen=True)
class IngestReport:
    """One batch's data-gap summary -- how many records left each schema
    field `not_collected` (adapters/base.py), plus what was collapsed.
    Empty for a native run (no gaps, nothing collapsed), so cli.py prints
    nothing and the demo fixture's output stays byte-identical."""

    format: str
    assets_total: int
    findings_total: int
    duplicate_assets_collapsed: int
    duplicate_findings_collapsed: int
    asset_gaps: dict[str, int] = field(default_factory=dict)  # field -> assets where not collected
    finding_gaps: dict[str, int] = field(default_factory=dict)

    @property
    def has_gaps(self) -> bool:
        return bool(self.asset_gaps or self.finding_gaps)

    @property
    def has_anything_to_report(self) -> bool:
        return self.has_gaps or bool(self.duplicate_assets_collapsed or self.duplicate_findings_collapsed)


class GapTally:
    """Accumulates `IngestReport` counts while a caller streams findings,
    so the report costs no second pass over anything."""

    def __init__(self) -> None:
        self.findings_total = 0
        self._finding_gaps: Counter[str] = Counter()

    def observe(self, finding: Finding) -> None:
        self.findings_total += 1
        self._finding_gaps.update(finding.not_collected)

    def report(self, fmt: str, assets: Mapping[str, Asset], stats: IngestStats) -> IngestReport:
        asset_gaps: Counter[str] = Counter()
        for asset in assets.values():
            asset_gaps.update(asset.not_collected)
        return IngestReport(
            format=fmt,
            assets_total=len(assets),
            findings_total=self.findings_total,
            duplicate_assets_collapsed=stats.duplicate_assets_collapsed,
            duplicate_findings_collapsed=stats.duplicate_findings_collapsed,
            asset_gaps=dict(sorted(asset_gaps.items())),
            finding_gaps=dict(sorted(self._finding_gaps.items())),
        )


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


def join(
    assets: Mapping[str, Asset], findings: Iterable[Finding], *, source: str = "findings"
) -> Iterator[EnrichedFinding]:
    """Attach each finding to its asset, lazily. `source` only labels the
    error. Raises on the first orphan -- an adapter that wants to report
    every orphan at once checks membership itself before handing rows here
    (adapters/defender.py does)."""
    for finding in findings:
        asset = assets.get(finding.asset_id)
        if asset is None:
            raise IngestError(
                f"{source}: finding {finding.finding_id!r} references "
                f"unknown asset_id {finding.asset_id!r}"
            )
        yield EnrichedFinding(finding=finding, asset=asset)


def join_findings(
    findings_path: Path, assets_path: Path
) -> Iterator[EnrichedFinding]:
    yield from join(load_asset_index(assets_path), load_findings(findings_path), source=str(findings_path))


def load_batch(data_dir: Path, adapter: IngestAdapter) -> tuple[dict[str, Asset], Iterator[EnrichedFinding]]:
    """The format-agnostic entry point cli.py uses: the adapter's inventory,
    indexed, and its findings joined to it, lazily. The inventory is
    materialized here (it always was -- load_asset_index) and returned so
    the caller can report per-asset data gaps without a second load."""
    assets = {a.asset_id: a for a in adapter.load_assets(data_dir / adapter.assets_filename)}
    findings_path = data_dir / adapter.findings_filename
    findings = adapter.load_findings(findings_path, assets)
    return assets, join(assets, findings, source=str(findings_path))


def attach_threat_signals(
    enriched: EnrichedFinding,
    kev_catalog: KevCatalog,
    attack_index: TechniqueIndex,
    cache: SnapshotCache,
) -> EnrichedFinding:
    """Live KEV/EPSS/NVD/ATT&CK signals, via `SnapshotCache` (offline-capable,
    see `enrich/cache.py`) -- the real, sourced enrichment `scoring.score_finding`
    needs, computed with no LLM call. `kev_catalog`/`attack_index` are the two
    bulk, single-fetch resources (load once per run, not once per finding --
    see both callers)."""
    cve_id = enriched.finding.cve_id
    epss = epss_lookup(cve_id, cache)
    nvd_cvss = nvd_lookup(cve_id, cache)
    matches = attack_index.lookup(cve_id, enriched.finding.product, enriched.finding.evidence)
    confirmed_prevalence = [m.technique.prevalence for m in matches if m.confidence == "confirmed"]
    return enriched.model_copy(
        update={
            "is_kev": kev_catalog.status(cve_id).is_listed,
            "epss": epss.score if epss.is_scored else None,
            "nvd_base_score": nvd_cvss.base_score if nvd_cvss is not None else None,
            "nvd_severity": nvd_cvss.base_severity if nvd_cvss is not None else None,
            "attack_techniques": tuple(
                AttackTechniqueRef(
                    technique_id=m.technique.technique_id,
                    name=m.technique.name,
                    confidence=m.confidence,
                )
                for m in matches
            ),
            "attack_prevalence": max(confirmed_prevalence, default=None),
        }
    )
