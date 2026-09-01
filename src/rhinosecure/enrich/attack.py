"""MITRE ATT&CK Enterprise technique fetcher and CVE/product-to-technique lookup.

Fetches the Enterprise ATT&CK STIX 2.1 bundle from `mitre-attack/attack-stix-data`
on GitHub (CLAUDE.md Section 11), filters to techniques (`attack-pattern` objects)
whose `x_mitre_platforms` includes "Windows" and that are not revoked or
deprecated, and exposes a lookup from a finding's CVE ID and/or affected
product/evidence text to the techniques it implicates.

Unlike kev.py/epss.py/nvd.py, the *raw* fetched response is not what gets
cached. The raw bundle is ~50MB and covers every platform (macOS, Linux,
cloud, network devices, PRE, ...) and every STIX object type this project has
no use for (mitigations, campaigns, data sources); committing that verbatim
would bloat the repo with data nothing here reads. Instead the fetch function
itself filters down to the Windows-platform technique set plus the derived
fields `lookup` needs, and *that* reduced structure is what SnapshotCache
persists under source="attack" -- one key ("enterprise-windows") covering the
whole filtered set, landing at `data/snapshots/attack/enterprise-windows.json`
per Section 9's layout (a directory, like nvd/ and epss/, even though this is
a single bulk fetch rather than one entry per key).

There is no direct CVE -> technique edge anywhere in ATT&CK's own data (that
bridge normally runs through CAPEC/CWE, which CLAUDE.md Section 11 does not
name as a source for this project). Two tiers, in order:

1. Confirmed: many ATT&CK "uses" relationships (a tracked group or malware/tool
   STIX object "using" a technique) document real procedure examples in prose,
   and that prose frequently names the CVE exploited -- e.g. HAFNIUM's
   relationship to T1190 cites CVE-2021-26855 (ProxyLogon) by name. Regex-
   scanning every kept relationship's description for a CVE ID builds a real
   cve_id -> technique_id index sourced entirely from ATT&CK's own
   documentation. This is exact-key structured retrieval, same spirit as
   nvd.py/epss.py/kev.py -- CLAUDE.md Section 4.
2. Candidate: vector retrieval over technique descriptions (retrieval/vector.py,
   a TF-IDF space fit to this technique corpus), reranked with MMR
   (retrieval/mmr.py) so the returned set is diverse rather than several
   restatements of the same technique family -- CLAUDE.md Section 4's
   "retrieve a wider candidate set, then rerank down to roughly 5-8 items."
   Used for CVEs no ATT&CK procedure example happens to mention -- expected to
   be most of a fixture's obscure, low-EPSS CVEs; famous anchors like
   ProxyLogon/ZeroLogon/Follina are exactly the ones well-documented enough
   for tier 1. Even genuine semantic retrieval over a small, specific corpus
   is not certain evidence the way an explicit procedure-example citation is
   -- lexical/statistical similarity can still coincide without real topical
   relevance (see MIN_CANDIDATE_SIMILARITY below) -- so tier 2 stays
   candidate-only; see cli.py, which only lets *confirmed* matches feed
   attack_prevalence and keeps candidates informational.

Prevalence ("Whether mapped ATT&CK techniques are commonly observed" --
CLAUDE.md Section 3) is each technique's percentile rank, among the Windows
technique set, of how many "uses" relationships target it -- how commonly
real tracked groups/software are documented using it, not a CVE-specific
number. Percentile rank rather than count/max: technique usage is long-tailed
(a handful of very generic techniques dominate absolute counts), so
normalizing against the single busiest technique crushes every genuinely
well-attested but more specific technique toward the bottom of the range.
Percentile rank is scale-invariant to that tail and keeps 'commonly observed'
meaning what it says.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

import requests

from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.retrieval import mmr
from rhinosecure.retrieval.vector import VectorIndex

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
SOURCE = "attack"
CACHE_KEY = "enterprise-windows"
# The bundle is ~50MB, vs. the KB-sized per-CVE responses nvd.py/epss.py
# fetch -- a 30s timeout (their default) fails this download outright.
REQUEST_TIMEOUT_SECONDS = 120

DEFAULT_LIMIT = 5
# The wide candidate pool retrieval.vector.VectorIndex.search returns before
# retrieval.mmr.rerank narrows it to DEFAULT_LIMIT -- CLAUDE.md Section 4's
# "retrieve a wider candidate set, then rerank down." 4x the final limit is
# enough headroom for MMR to actually have redundant near-duplicates to
# diversify away from (see the Outlook Forms/Rules/Home Page cluster in
# PROGRESS.md); at this corpus size (474 documents) a wider pool costs
# nothing -- cosine similarity over all of them is already computed.
CANDIDATE_POOL_SIZE = 20
# Empirically chosen against the live bundle: queries with no real topical
# overlap with the corpus (e.g. a PDF-viewer memory-disclosure CVE, which has
# no natural ATT&CK vocabulary) top out under this; queries with at least
# some genuine signal clear it. Like PATCH_NOW_THRESHOLD in scoring.py, this
# is a calibrated constant, not a derived one -- open to retuning. It is not,
# and cannot be, a guarantee of topical relevance: lexical cosine similarity
# can still coincide by chance (see the module docstring's tier 2 note), so
# this filters out clear noise, not false positives in general.
MIN_CANDIDATE_SIMILARITY = 0.10

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")
_CITATION_PATTERN = re.compile(r"\s*\(Citation: [^)]*\)")


@dataclass(frozen=True)
class Technique:
    technique_id: str  # "T1190" (sub-techniques like "T1055.011" included)
    name: str
    description: str
    tactics: tuple[str, ...]  # kill-chain phase slugs, e.g. "initial-access"
    platforms: tuple[str, ...]
    use_count: int  # "uses" relationships targeting this technique
    prevalence: float  # percentile rank of use_count among Windows techniques


@dataclass(frozen=True)
class TechniqueMatch:
    technique: Technique
    confidence: str  # "confirmed" or "candidate" -- see module docstring
    reason: str


def _technique_ext_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _fetch_and_filter() -> dict[str, Any]:
    response = requests.get(BUNDLE_URL, timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    objects = response.json().get("objects", [])

    techniques_by_stix_id: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if "Windows" not in (obj.get("x_mitre_platforms") or []):
            continue
        technique_id = _technique_ext_id(obj)
        if technique_id is None:
            continue
        description = _CITATION_PATTERN.sub("", obj.get("description", ""))
        techniques_by_stix_id[obj["id"]] = {
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": description,
            "tactics": sorted(
                {
                    phase["phase_name"]
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                }
            ),
            "platforms": obj.get("x_mitre_platforms", []),
        }

    use_counts: Counter[str] = Counter()
    cve_mentions: dict[str, set[str]] = defaultdict(set)
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        target = obj.get("target_ref")
        if target not in techniques_by_stix_id:
            continue
        use_counts[target] += 1
        for cve_id in _CVE_PATTERN.findall(obj.get("description") or ""):
            cve_mentions[cve_id].add(target)

    all_counts = sorted(use_counts.get(sid, 0) for sid in techniques_by_stix_id)
    total = len(all_counts)

    def _prevalence(stix_id: str) -> float:
        count = use_counts.get(stix_id, 0)
        return sum(1 for c in all_counts if c <= count) / total

    technique_records = [
        {
            **record,
            "use_count": use_counts.get(stix_id, 0),
            "prevalence": _prevalence(stix_id),
        }
        for stix_id, record in techniques_by_stix_id.items()
    ]
    cve_index = {
        cve_id: sorted(techniques_by_stix_id[sid]["technique_id"] for sid in stix_ids)
        for cve_id, stix_ids in cve_mentions.items()
    }
    return {"techniques": technique_records, "cve_mentions": cve_index}


class TechniqueIndex:
    """A fetched-and-filtered Windows ATT&CK technique set, ready for
    CVE/product lookups. See module docstring for the two-tier match."""

    def __init__(self, payload: dict[str, Any]):
        self._techniques: dict[str, Technique] = {
            r["technique_id"]: Technique(
                technique_id=r["technique_id"],
                name=r["name"],
                description=r["description"],
                tactics=tuple(r["tactics"]),
                platforms=tuple(r["platforms"]),
                use_count=r["use_count"],
                prevalence=r["prevalence"],
            )
            for r in payload["techniques"]
        }
        self._cve_mentions: dict[str, tuple[str, ...]] = {
            cve_id: tuple(tids) for cve_id, tids in payload["cve_mentions"].items()
        }
        self._vector_index = VectorIndex(
            {technique_id: f"{t.name} {t.description}" for technique_id, t in self._techniques.items()}
        )

    def _semantic_candidates(self, text: str, limit: int) -> list[TechniqueMatch]:
        pool = [
            (technique_id, score)
            for technique_id, score in self._vector_index.search(text, top_k=CANDIDATE_POOL_SIZE)
            if score >= MIN_CANDIDATE_SIMILARITY
        ]
        if not pool:
            return []
        relevance = dict(pool)
        reranked = mmr.rerank(
            [technique_id for technique_id, _score in pool],
            relevance=relevance,
            similarity=self._vector_index.similarity,
            k=limit,
        )
        return [
            TechniqueMatch(
                technique=self._techniques[technique_id],
                confidence="candidate",
                reason=(
                    f"semantic similarity={relevance[technique_id]:.3f} "
                    f"(MMR-reranked from a {len(pool)}-candidate pool)"
                ),
            )
            for technique_id in reranked
        ]

    def lookup(
        self, cve_id: str, product: str = "", evidence: str = "", *, limit: int = DEFAULT_LIMIT
    ) -> list[TechniqueMatch]:
        """Techniques implicated by this CVE, most confident first.

        Returns confirmed matches only when ATT&CK's own procedure-example
        text names this CVE explicitly; otherwise falls back to MMR-reranked
        semantic candidates against `product`/`evidence`, which may be empty.
        Never mixes the two tiers in one result -- a confirmed hit is not
        made more or less certain by whatever vector retrieval would also
        have found.
        """
        confirmed_ids = self._cve_mentions.get(cve_id)
        if confirmed_ids:
            return [
                TechniqueMatch(
                    technique=self._techniques[technique_id],
                    confidence="confirmed",
                    reason=f"{cve_id} is explicitly named in an ATT&CK procedure example for {technique_id}",
                )
                for technique_id in confirmed_ids[:limit]
                if technique_id in self._techniques
            ]
        return self._semantic_candidates(f"{product} {evidence}", limit)


def load_index(cache: SnapshotCache) -> TechniqueIndex:
    """Read-through the filtered Windows ATT&CK technique set via `cache`.

    On a cache miss this fetches and filters the live Enterprise STIX bundle
    (or raises `OfflineCacheMissError` if `cache.offline` is set) and persists
    the reduced structure before returning -- see `SnapshotCache.get_or_fetch`.
    """
    entry = cache.get_or_fetch(SOURCE, CACHE_KEY, _fetch_and_filter)
    return TechniqueIndex(entry.payload)
