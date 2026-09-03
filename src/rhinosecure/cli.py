"""`rhino run` — ingest, enrich with live KEV/EPSS/NVD/ATT&CK threat
signals, score, rank. Scoring itself stays LLM-free and network-free (see
scoring.py); enrichment goes through SnapshotCache, which makes it
offline-capable and lets --offline force that rather than silently
reaching the network.

`--agents` switches the same command to the Slice 3 crew (Coordinator
dispatching Research -> Environment -> Risk, agents/coordinator.py)
instead of the deterministic pipeline above -- same --data/--seed/
--offline/--explain flags, so the two paths are invoked identically and
their output is directly comparable. Importing agents.coordinator pulls
in crewai, which only imports on Python 3.12 (see CLAUDE.md Section 11)
-- deferred to inside run_agents() so `rhino run` without --agents keeps
working on any interpreter this project's deterministic half supports.

`--quiet` (agents path only) silences CrewAI's own console event-bus
logging -- "Agent Started" boxes, per-tool-call echo lines, etc. --
via `set_suppress_console_output`, so `--agents --quiet` prints only
what this module itself prints (the table, and --explain's rationale).

`_ensure_utf8_stdio` is unconditional and independent of --quiet: on
Windows, the default console codepage can't encode the emoji CrewAI's
event bus prints, which without it surfaced as recurring "'charmap'
codec can't encode character..." lines on every agent run even though
nothing was actually failing -- reconfiguring stdout/stderr to UTF-8
fixes that regardless of --quiet, and regardless of the console's own
codepage.

`--explain` output -- verdict_summary/narrative and every
rationale/scoring_rationale bullet, on both the deterministic and agents
paths -- is wrapped to NARRATIVE_WRAP_WIDTH (`_wrap`/`_wrap_bullet`) so
none of it runs off-screen; a scoring_rationale bullet listing several
ATT&CK candidates, or a contested bucket's explanation, can otherwise run
well past 300 characters on one line.
"""

from __future__ import annotations

import argparse
import random
import sys
import textwrap
from pathlib import Path

from rhinosecure.enrich.attack import TechniqueIndex, load_index as load_attack_index
from rhinosecure.enrich.cache import OfflineCacheMissError, SnapshotCache
from rhinosecure.enrich.epss import lookup as epss_lookup
from rhinosecure.enrich.kev import KevCatalog, load_catalog as load_kev_catalog
from rhinosecure.enrich.nvd import lookup as nvd_lookup
from rhinosecure.ingest import IngestError, join_findings
from rhinosecure.schema import AttackTechniqueRef, EnrichedFinding
from rhinosecure.scoring import ScoredFinding, rank, score_finding

REPO_ROOT = Path(__file__).resolve().parents[2]


def _ensure_utf8_stdio() -> None:
    """Best effort: reconfigure stdout/stderr to UTF-8 regardless of the
    console's own codepage. Some stream replacements (pytest's capsys,
    certain redirects) don't support `reconfigure` -- silently skip those
    rather than let a cosmetic fix break anything real."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass


def _resolve_data_dir(data_arg: str) -> Path:
    named = REPO_ROOT / "data" / data_arg
    if named.is_dir():
        return named
    path = Path(data_arg)
    if path.is_dir():
        return path
    raise SystemExit(f"no such data set: {data_arg!r} (looked for {named} and {path})")


def _attach_threat_signals(
    enriched: EnrichedFinding,
    kev_catalog: KevCatalog,
    attack_index: TechniqueIndex,
    cache: SnapshotCache,
) -> EnrichedFinding:
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


def run(data_dir: Path, seed: int, *, offline: bool = False) -> list[ScoredFinding]:
    # Scoring is fully deterministic (no sampling); the seed is accepted
    # now so the CLI contract does not change once Slice 4's ToT beam
    # search introduces anything seed-sensitive.
    random.seed(seed)

    assets_path = data_dir / "assets.csv"
    findings_path = data_dir / "findings.csv"

    cache = SnapshotCache(offline=offline)
    kev_catalog = load_kev_catalog(cache)  # one bulk feed, loaded once for the whole run
    attack_index = load_attack_index(cache)  # same shape: one filtered bundle, loaded once

    scored = [
        score_finding(_attach_threat_signals(e, kev_catalog, attack_index, cache))
        for e in join_findings(findings_path, assets_path)
    ]
    return rank(scored)


def run_agents(data_dir: Path, seed: int, *, offline: bool = False) -> Coordinator:
    """Dispatches the Slice 3 crew over every finding in `data_dir`, the
    agent equivalent of `run`. Returns the `Coordinator` itself, not just
    the ranked list -- `coordinator.state.*_failures` is how a caller sees
    which findings (if any) were recorded and skipped rather than
    blocking the run (agents/coordinator.py's module docstring has the
    full incident this exists to survive). Imports agents.* lazily -- see
    this module's own docstring for why.
    """
    from rhinosecure.agents.coordinator import Coordinator

    random.seed(seed)  # see run()'s comment -- still a no-op for now
    assets_path = data_dir / "assets.csv"
    findings_path = data_dir / "findings.csv"
    findings = list(join_findings(findings_path, assets_path))
    coordinator = Coordinator(data_dir, cache=SnapshotCache(offline=offline))
    coordinator.run(findings)
    return coordinator


def _print_rows(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)))


NARRATIVE_WRAP_WIDTH = 100


def _wrap(text: str, indent: str = "  ", *, continuation_indent: str | None = None) -> str:
    """Wrap free-form text to NARRATIVE_WRAP_WIDTH so it doesn't run
    off-screen. `continuation_indent` (default: same as `indent`) lets a
    bullet's wrapped lines align under its text instead of repeating the
    "- " marker -- see `_wrap_bullet`."""
    return textwrap.fill(
        text,
        width=NARRATIVE_WRAP_WIDTH,
        initial_indent=indent,
        subsequent_indent=continuation_indent if continuation_indent is not None else indent,
    )


def _wrap_bullet(text: str) -> str:
    """A rationale bullet (deterministic ScoredFinding.rationale or its
    verbatim copy, RiskRecommendation.scoring_rationale) can run well past
    100 characters -- e.g. a long ATT&CK candidate list, or a contested-
    bucket's explanation. Same NARRATIVE_WRAP_WIDTH treatment as
    verdict_summary/narrative, just with the continuation lines aligned
    under the bullet's text rather than its "-" marker."""
    return _wrap(text, indent="  - ", continuation_indent="    ")


def _print_table(scored: list[ScoredFinding]) -> None:
    headers = ("finding_id", "cve_id", "hostname", "bucket", "risk_score")
    rows = [
        (s.finding_id, s.cve_id, s.hostname, s.bucket.value, f"{s.risk_score:.1f}")
        for s in scored
    ]
    _print_rows(headers, rows)


def _print_agent_table(recommendations: list) -> None:
    headers = ("finding_id", "cve_id", "hostname", "bucket", "risk_score")
    rows = [
        (r.finding_id, r.cve_id, r.hostname, r.bucket, f"{r.risk_score:.1f}")
        for r in recommendations
    ]
    _print_rows(headers, rows)


def _print_failures(coordinator: Coordinator) -> None:
    """Findings recorded and skipped (rather than left blocking the run)
    at any stage -- see agents/coordinator.py's module docstring."""
    stages = (
        ("research", coordinator.state.research_failures),
        ("environment", coordinator.state.environment_failures),
        ("risk", coordinator.state.risk_failures),
    )
    total = sum(len(failures) for _stage, failures in stages)
    if total == 0:
        return
    print(f"\n{total} finding(s) failed and were skipped:", file=sys.stderr)
    for stage, failures in stages:
        for finding_id, reason in failures.items():
            print(f"  {finding_id} ({stage}): {reason}", file=sys.stderr)


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
    run_parser.add_argument(
        "--agents",
        action="store_true",
        help=(
            "dispatch the Slice 3 crew (Research -> Environment -> Risk) instead of the "
            "deterministic pipeline -- makes real LLM calls, one per finding per stage"
        ),
    )
    run_parser.add_argument(
        "--quiet",
        action="store_true",
        help=(
            "with --agents, silence CrewAI's own console logging (agent-started boxes, "
            "per-tool-call echo lines) so only the table and --explain's rationale print"
        ),
    )

    args = parser.parse_args(argv)
    _ensure_utf8_stdio()

    if args.command == "run":
        data_dir = _resolve_data_dir(args.data)

        if args.agents:
            from rhinosecure.llm import LLMConfigError

            if args.quiet:
                from crewai.events.utils.console_formatter import set_suppress_console_output

                set_suppress_console_output(True)

            # No CoordinatorError/ScoringMismatchError handler here: a
            # per-finding failure is recorded and skipped inside
            # Coordinator.run (see agents/coordinator.py), not raised --
            # neither exception can propagate out of run_agents.
            try:
                coordinator = run_agents(data_dir, args.seed, offline=args.offline)
            except IngestError as exc:
                print(f"ingest error: {exc}", file=sys.stderr)
                return 1
            except OfflineCacheMissError as exc:
                print(f"offline error: {exc}", file=sys.stderr)
                return 1
            except LLMConfigError as exc:
                print(f"LLM config error: {exc}", file=sys.stderr)
                return 1

            recommendations = coordinator.ranked()
            _print_agent_table(recommendations)
            _print_failures(coordinator)

            if args.explain:
                for r in recommendations:
                    print(f"\n{r.finding_id} ({r.cve_id} on {r.hostname}) -> {r.bucket}")
                    print(f"\n{_wrap(r.verdict_summary)}")
                    for line in r.scoring_rationale:
                        print(_wrap_bullet(line))
                    print(f"\n{_wrap(r.narrative)}")

            return 0

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
                    print(_wrap_bullet(line))

        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
