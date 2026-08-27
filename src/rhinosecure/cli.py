"""`rhino run` — ingest, enrich with live KEV/EPSS/NVD threat signals,
score, rank. Scoring itself stays LLM-free and network-free (see
scoring.py); enrichment goes through SnapshotCache, which makes it
offline-capable and lets --offline force that rather than silently
reaching the network."""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from rhinosecure.enrich.cache import OfflineCacheMissError, SnapshotCache
from rhinosecure.enrich.epss import lookup as epss_lookup
from rhinosecure.enrich.kev import KevCatalog, load_catalog as load_kev_catalog
from rhinosecure.enrich.nvd import lookup as nvd_lookup
from rhinosecure.ingest import IngestError, join_findings
from rhinosecure.schema import EnrichedFinding
from rhinosecure.scoring import ScoredFinding, rank, score_finding

REPO_ROOT = Path(__file__).resolve().parents[2]


def _resolve_data_dir(data_arg: str) -> Path:
    named = REPO_ROOT / "data" / data_arg
    if named.is_dir():
        return named
    path = Path(data_arg)
    if path.is_dir():
        return path
    raise SystemExit(f"no such data set: {data_arg!r} (looked for {named} and {path})")


def _attach_threat_signals(
    enriched: EnrichedFinding, kev_catalog: KevCatalog, cache: SnapshotCache
) -> EnrichedFinding:
    cve_id = enriched.finding.cve_id
    epss = epss_lookup(cve_id, cache)
    nvd_cvss = nvd_lookup(cve_id, cache)
    return enriched.model_copy(
        update={
            "is_kev": kev_catalog.status(cve_id).is_listed,
            "epss": epss.score if epss.is_scored else None,
            "nvd_base_score": nvd_cvss.base_score if nvd_cvss is not None else None,
            "nvd_severity": nvd_cvss.base_severity if nvd_cvss is not None else None,
        }
    )


def run(data_dir: Path, seed: int, *, offline: bool = False) -> list[ScoredFinding]:
    # Scoring is fully deterministic (no sampling); the seed is accepted
    # now so the CLI contract does not change once Slice 4's ToT beam
    # search introduces anything seed-sensitive.
    random.seed(seed)

    assets_path = data_dir / "assets.csv"
    findings_path = data_dir / "findings.csv"

    cache = SnapshotCache(offline=offline)
    kev_catalog = load_kev_catalog(cache)  # one bulk feed, loaded once for the whole run

    scored = [
        score_finding(_attach_threat_signals(e, kev_catalog, cache))
        for e in join_findings(findings_path, assets_path)
    ]
    return rank(scored)


def _print_table(scored: list[ScoredFinding]) -> None:
    headers = ("finding_id", "cve_id", "hostname", "bucket", "risk_score")
    rows = [
        (s.finding_id, s.cve_id, s.hostname, s.bucket.value, f"{s.risk_score:.1f}")
        for s in scored
    ]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rhino")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="ingest, score, and rank findings")
    run_parser.add_argument("--data", default="demo", help="dataset name under data/, or a path")
    run_parser.add_argument("--seed", type=int, default=42)
    run_parser.add_argument("--explain", action="store_true", help="print rationale for every finding")
    run_parser.add_argument(
        "--offline",
        action="store_true",
        help="forbid network fetches; fail loudly on any snapshot cache miss instead of fetching",
    )

    args = parser.parse_args(argv)

    if args.command == "run":
        data_dir = _resolve_data_dir(args.data)
        try:
            scored = run(data_dir, args.seed, offline=args.offline)
        except IngestError as exc:
            print(f"ingest error: {exc}", file=sys.stderr)
            return 1
        except OfflineCacheMissError as exc:
            print(f"offline error: {exc}", file=sys.stderr)
            return 1

        _print_table(scored)

        if args.explain:
            for s in scored:
                print(f"\n{s.finding_id} ({s.cve_id} on {s.hostname}) -> {s.bucket.value}")
                for line in s.rationale:
                    print(f"  - {line}")

        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
