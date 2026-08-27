"""CISA Known Exploited Vulnerabilities (KEV) catalog fetcher.

Structured, exact-key retrieval per CLAUDE.md Section 4: KEV membership is
looked up by CVE ID, not embedded or reranked. The catalog is a single
bulk feed covering every listed CVE, so it is cached as one file --
`data/snapshots/kev.json` (source="kev", no key) -- rather than per-CVE,
same as `SnapshotCache`'s "no key" path is meant for.

Not wired into scoring yet. `ThreatInputs.is_kev` in scoring.py stays
False until a later commit threads this lookup into the threat term.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

from rhinosecure.enrich.cache import SnapshotCache

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SOURCE = "kev"
REQUEST_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class KevStatus:
    """Whether a CVE is on the CISA KEV catalog, and if so since when."""

    is_listed: bool
    date_added: str | None = None
    due_date: str | None = None


def _fetch_catalog() -> dict[str, Any]:
    response = requests.get(KEV_URL, timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def _index_by_cve(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["cveID"]: entry for entry in catalog.get("vulnerabilities", [])}


class KevCatalog:
    """A fetched-and-indexed KEV catalog, ready for CVE lookups."""

    def __init__(self, index: dict[str, dict[str, Any]]):
        self._index = index

    def status(self, cve_id: str) -> KevStatus:
        entry = self._index.get(cve_id)
        if entry is None:
            return KevStatus(is_listed=False)
        return KevStatus(
            is_listed=True,
            date_added=entry.get("dateAdded"),
            due_date=entry.get("dueDate"),
        )


def load_catalog(cache: SnapshotCache) -> KevCatalog:
    """Read-through the KEV catalog via `cache` and return an indexed lookup.

    On a cache miss this fetches the live CISA feed (or raises
    `OfflineCacheMissError` if `cache.offline` is set) and persists it
    before returning -- see `SnapshotCache.get_or_fetch`.
    """
    entry = cache.get_or_fetch(SOURCE, None, _fetch_catalog)
    return KevCatalog(_index_by_cve(entry.payload))
