"""CSV ingest for the two input files, plus attaching live threat signals
to what was ingested.

Rows are read and validated one at a time via generators — nothing here
collects a whole file into memory, and nothing branches on how many rows a
particular dataset happens to have. A future adapter for a real scanner
export (Nessus/Qualys/InsightVM/Defender VM) sits in front of these loaders:
it normalizes that export's native columns into assets.csv / findings.csv
shape and hands rows to the same `Asset` / `Finding` models. Nothing below
needs to change for that to work.

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
from collections.abc import Iterator
from pathlib import Path

from pydantic import ValidationError

from rhinosecure.enrich.attack import TechniqueIndex
from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.enrich.epss import lookup as epss_lookup
from rhinosecure.enrich.kev import KevCatalog
from rhinosecure.enrich.nvd import lookup as nvd_lookup
from rhinosecure.schema import Asset, AttackTechniqueRef, EnrichedFinding, Finding


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
