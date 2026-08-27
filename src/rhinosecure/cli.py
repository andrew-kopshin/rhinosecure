"""`rhino run` — Slice 1: ingest, score, rank. No LLM calls, no network."""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from rhinosecure.ingest import IngestError, join_findings
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


def run(data_dir: Path, seed: int, *, offline: bool = False) -> list[ScoredFinding]:
    # Scoring is fully deterministic today (no sampling, no enrichment
    # lookups yet); the seed is accepted now so the CLI contract does not
    # change once Slice 2+ introduces anything seed-sensitive. Same for
    # offline: Slice 1 makes no network calls, so there is nothing yet for
    # it to gate -- it is threaded through now so Slice 2 enrichment can
    # pass it straight to SnapshotCache(offline=...) without a CLI change.
    random.seed(seed)

    assets_path = data_dir / "assets.csv"
    findings_path = data_dir / "findings.csv"
    scored = [score_finding(e) for e in join_findings(findings_path, assets_path)]
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
