"""NVD (National Vulnerability Database) CVSS fetcher, API v2.0.

Structured, exact-key retrieval per CLAUDE.md Section 4: NVD is queried per
CVE and cached one file per CVE -- `data/snapshots/nvd/<cve_id>.json`
(source="nvd", key=cve_id), same shape as epss.py.

NVD enforces real rate limits (5 requests/30s unauthenticated, 50/30s with
an API key in the `apiKey` header -- CLAUDE.md Section 11) and returns
403/429 once exceeded, so requests retry with exponential backoff instead
of failing on the first throttle. `NVD_API_KEY` is read from the
environment (`.env`, via python-dotenv) and omitted from the request
entirely when unset -- NVD accepts unauthenticated requests, just at the
lower rate.

Wired into scoring.py as the authoritative severity source: when NVD has
CVSS data for a CVE, its base score overrides scanner_severity's fixed
per-tier proxy -- outright when the two disagree at the tier level, and
still preferred for precision when they happen to agree, because it's a
real number instead of a proxy. See scoring._resolve_severity.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

import requests
from dotenv import load_dotenv

from rhinosecure.enrich.cache import SnapshotCache

load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE = "nvd"
REQUEST_TIMEOUT_SECONDS = 30
MAX_ATTEMPTS = 5
RETRY_BACKOFF_BASE_SECONDS = 3  # attempt N waits BASE * 2**N before retrying

# Preference order: newest CVSS version NVD has scored wins.
_CVSS_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


@dataclass(frozen=True)
class NvdCvss:
    """Authoritative CVSS data for one CVE, as recorded by NVD."""

    cve_id: str
    version: str  # "3.1", "3.0", "2.0"
    base_score: float
    base_severity: str  # lowercase -- matches the ScannerSeverity vocabulary
    vector_string: str
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None


def _headers() -> dict[str, str]:
    api_key = os.environ.get("NVD_API_KEY")
    return {"apiKey": api_key} if api_key else {}


def _fetch_one(cve_id: str) -> dict[str, Any]:
    response = None
    for attempt in range(MAX_ATTEMPTS):
        response = requests.get(
            NVD_URL,
            params={"cveId": cve_id},
            headers=_headers(),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code == 200:
            return response.json()
        if response.status_code in (403, 429) and attempt < MAX_ATTEMPTS - 1:
            time.sleep(RETRY_BACKOFF_BASE_SECONDS * (2**attempt))
            continue
        break
    response.raise_for_status()
    raise requests.HTTPError(f"NVD fetch for {cve_id} failed: HTTP {response.status_code}")


def _select_authoritative(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """NVD's metric arrays commonly hold more than one scorer for the same
    CVSS version -- the reporting CNA (e.g. secure@microsoft.com) and NVD's
    own analysis -- and they can disagree substantially. ZeroLogon
    (CVE-2020-1472) is a real example: Microsoft's own CVSS v3.1 score is
    5.5/medium, NVD's is 10.0/critical. Taking entries[0] is not safe --
    ordering is not guaranteed to put NVD's entry first. Prefer, in order:
    an entry NVD tags "Primary" (its own convention for "this is NVD's
    scoring"), then an entry explicitly sourced from nvd@nist.gov, then
    whatever is first if neither applies (CNA-only data is still real
    CVSS data, just not NVD's own analysis of it).
    """
    for entry in entries:
        if entry.get("type") == "Primary":
            return entry
    for entry in entries:
        if entry.get("source") == "nvd@nist.gov":
            return entry
    return entries[0]


def _best_metric(body: dict[str, Any]) -> dict[str, Any] | None:
    results = body.get("vulnerabilities") or []
    if not results:
        return None
    metrics = results[0].get("cve", {}).get("metrics", {})
    for key in _CVSS_METRIC_KEYS:
        entries = metrics.get(key)
        if entries:
            return _select_authoritative(entries)
    return None


def _to_cvss(cve_id: str, body: dict[str, Any]) -> NvdCvss | None:
    metric = _best_metric(body)
    if metric is None:
        return None
    data = metric.get("cvssData", {})
    if "baseScore" not in data:
        return None
    severity = (data.get("baseSeverity") or metric.get("baseSeverity") or "").lower()
    return NvdCvss(
        cve_id=cve_id,
        version=str(data.get("version", "")),
        base_score=float(data["baseScore"]),
        base_severity=severity,
        vector_string=data.get("vectorString", ""),
        attack_vector=data.get("attackVector"),
        attack_complexity=data.get("attackComplexity"),
        privileges_required=data.get("privilegesRequired"),
        user_interaction=data.get("userInteraction"),
        scope=data.get("scope"),
        confidentiality_impact=data.get("confidentialityImpact"),
        integrity_impact=data.get("integrityImpact"),
        availability_impact=data.get("availabilityImpact"),
    )


def lookup(cve_id: str, cache: SnapshotCache) -> NvdCvss | None:
    """Read-through the authoritative CVSS record for one CVE via `cache`.

    Returns None if NVD has no CVSS data for this CVE (record not found,
    or found but not yet scored) -- callers fall back to scanner_severity.
    On a cache miss this queries the live NVD API, retrying on 403/429
    with exponential backoff (or raises `OfflineCacheMissError` if
    `cache.offline` is set) and persists the raw response before
    returning -- see `SnapshotCache.get_or_fetch`.
    """
    entry = cache.get_or_fetch(SOURCE, cve_id, lambda: _fetch_one(cve_id))
    return _to_cvss(cve_id, entry.payload)
