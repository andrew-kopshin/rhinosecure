"""FIRST EPSS (Exploit Prediction Scoring System) fetcher.

Structured, exact-key retrieval per CLAUDE.md Section 4: like NVD, EPSS is
queried per CVE against the live `api.first.org/data/v1/epss` endpoint --
not the bulk daily CSV, which covers every CVE in existence and is
overkill for the handful this project's enrichment layer actually asks
about. Each result is cached individually via `SnapshotCache`:
source="epss", key=<cve_id> -> `data/snapshots/epss/<cve_id>.json`, a
directory of per-CVE entries like `nvd/` rather than the single
`epss.json` the Section 9 layout sketch originally assumed for a
bulk-CSV implementation (that sketch has been updated to match).

Not wired into scoring yet. `ThreatInputs.epss` in scoring.py stays None
until a later commit threads this lookup into the threat term.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

from rhinosecure.enrich.cache import SnapshotCache

EPSS_URL = "https://api.first.org/data/v1/epss"
SOURCE = "epss"
REQUEST_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class EpssScore:
    """A CVE's EPSS probability and percentile as of `score_date`.

    `score`/`percentile`/`score_date` are all None when FIRST has no
    EPSS model entry for the CVE yet.
    """

    cve_id: str
    score: float | None
    percentile: float | None
    score_date: str | None

    @property
    def is_scored(self) -> bool:
        return self.score is not None


def _fetch_one(cve_id: str) -> dict[str, Any]:
    response = requests.get(
        EPSS_URL, params={"cve": cve_id}, timeout=REQUEST_TIMEOUT_SECONDS
    )
    response.raise_for_status()
    return response.json()


def _to_score(cve_id: str, body: dict[str, Any]) -> EpssScore:
    records = body.get("data") or []
    if not records:
        return EpssScore(cve_id=cve_id, score=None, percentile=None, score_date=None)
    record = records[0]
    return EpssScore(
        cve_id=cve_id,
        score=float(record["epss"]),
        percentile=float(record["percentile"]),
        score_date=record.get("date"),
    )


def lookup(cve_id: str, cache: SnapshotCache) -> EpssScore:
    """Read-through the EPSS score for one CVE via `cache`.

    On a cache miss this queries the live FIRST API (or raises
    `OfflineCacheMissError` if `cache.offline` is set) and persists the
    raw response before returning -- see `SnapshotCache.get_or_fetch`.
    """
    entry = cache.get_or_fetch(SOURCE, cve_id, lambda: _fetch_one(cve_id))
    return _to_score(cve_id, entry.payload)
