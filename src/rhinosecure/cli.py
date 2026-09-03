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

Both paths print a "Contested: n/total" line after the table --
scoring.contested_rate, CLAUDE.md Section 6's quantitative gate ("keep
contested findings under roughly 1% of the corpus") checked against a
real run instead of only asserted. On `--agents --explain`, a contested
finding's Tree-of-Thought outcome (tot.py, Section 6's beam search --
winner, or both near-tied candidates surfaced for a human, per finding)
prints alongside its narrative; a ToT dispatch failure prints its reason
instead, the same skip-and-report treatment agents/coordinator.py already
gives a Research/Environment/Risk failure.

`rhino constraint add "<text>"` is CLAUDE.md Section 5's "Human submits a
constraint" edge and Section 7's memory worked example, made real:
`agents/coordinator.py`'s `submit_constraint` interprets the text,
persists it, re-plans only the findings it resolves to, and this module
prints the resulting diff -- what changed between the finding(s)' prior
score and the new one, and why (the agent's own narrative already
explains a constraint's effect whenever one was applied; see
`agents/risk.py`). `--agents` (this module's `run`/`run_agents`) always
constructs a `memory.Memory` at `--db` (default `memory.DEFAULT_DB_PATH`)
and passes it to `Coordinator`, so a plain `rhino run --agents` picks up
whatever constraints are already on file automatically -- CLAUDE.md
Section 7's worked example ("persists and is applied automatically on
the next run without being restated") applies to every `--agents` run,
not just the one that just submitted a constraint. The plain
(non-`--agents`) deterministic path never touches `memory.py` -- `memory`
requires a `Coordinator`, and this module's own docstring already
explains why `agents.*` (and now `memory` alongside it, imported lazily
in the same places) stays out of that path's import graph.
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
from rhinosecure.scoring import ContestedRate, ScoredFinding, contested_rate, rank, score_finding

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


def run_agents(
    data_dir: Path, seed: int, *, offline: bool = False, db_path: Path | str | None = None
) -> Coordinator:
    """Dispatches the Slice 3 crew over every finding in `data_dir`, the
    agent equivalent of `run`. Returns the `Coordinator` itself, not just
    the ranked list -- `coordinator.state.*_failures` is how a caller sees
    which findings (if any) were recorded and skipped rather than
    blocking the run (agents/coordinator.py's module docstring has the
    full incident this exists to survive). Imports agents.*/memory
    lazily -- see this module's own docstring for why.

    `db_path` defaults to `memory.DEFAULT_DB_PATH` -- a `Memory` is
    always constructed and passed to `Coordinator`, so this always picks
    up whatever constraints are already on file (CLAUDE.md Section 7's
    worked example), not just when a constraint was just submitted in
    the same invocation.
    """
    from rhinosecure.agents.coordinator import Coordinator
    from rhinosecure.memory import DEFAULT_DB_PATH, Memory

    random.seed(seed)  # see run()'s comment -- still a no-op for now
    assets_path = data_dir / "assets.csv"
    findings_path = data_dir / "findings.csv"
    findings = list(join_findings(findings_path, assets_path))
    memory = Memory(db_path if db_path is not None else DEFAULT_DB_PATH)
    coordinator = Coordinator(data_dir, cache=SnapshotCache(offline=offline), memory=memory)
    coordinator.run(findings)
    return coordinator


def submit_constraint(
    text: str,
    data_dir: Path,
    seed: int,
    *,
    offline: bool = False,
    db_path: Path | str | None = None,
) -> ConstraintSubmissionResult:
    """CLI entry point for `rhino constraint add` -- the agent equivalent
    of `run`/`run_agents`, dispatching `agents/coordinator.py`'s
    `submit_constraint` against every finding in `data_dir`. Imports
    agents.*/memory lazily, same reason as `run_agents`."""
    from rhinosecure.agents.coordinator import Coordinator
    from rhinosecure.memory import DEFAULT_DB_PATH, Memory

    random.seed(seed)
    assets_path = data_dir / "assets.csv"
    findings_path = data_dir / "findings.csv"
    findings = list(join_findings(findings_path, assets_path))
    memory = Memory(db_path if db_path is not None else DEFAULT_DB_PATH)
    coordinator = Coordinator(data_dir, cache=SnapshotCache(offline=offline), memory=memory)
    return coordinator.submit_constraint(text, findings, seed=seed)


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
    at any stage -- see agents/coordinator.py's module docstring. A ToT
    failure is reported the same way but never removes the finding from
    the table above -- Risk already succeeded for it (see
    agents/coordinator.py's _dispatch_tot docstring)."""
    stages = (
        ("research", coordinator.state.research_failures),
        ("environment", coordinator.state.environment_failures),
        ("risk", coordinator.state.risk_failures),
        ("tot", coordinator.state.tot_failures),
    )
    total = sum(len(failures) for _stage, failures in stages)
    if total == 0:
        return
    print(f"\n{total} finding(s) failed and were skipped:", file=sys.stderr)
    for stage, failures in stages:
        for finding_id, reason in failures.items():
            print(f"  {finding_id} ({stage}): {reason}", file=sys.stderr)


def _print_contested_rate(rate: ContestedRate) -> None:
    print(f"\nContested: {rate.contested}/{rate.total} ({rate.pct:.1f}%) of scored findings")


_TERMINATION_LABELS = {
    "clear_winner": "clear winner",
    "depth_limit": "depth limit",
    "exhausted_evidence": "exhausted evidence",
}


def _print_tot_result(finding_id: str, coordinator: Coordinator) -> None:
    """Prints a contested finding's Tree-of-Thought outcome right after
    its narrative, if it has one -- either a single winning strategy, or
    (Section 6: "Near-tie -> surface both branches to the human") every
    candidate in a near-tied final beam, with no branch picked for the
    reader. Silently does nothing for a finding with neither a result nor
    a recorded failure -- i.e. every finding that was never contested."""
    if finding_id in coordinator.state.tot_failures:
        print(f"\n  Tree-of-Thought: failed -- {coordinator.state.tot_failures[finding_id]}")
        return
    result = coordinator.state.tot_by_id.get(finding_id)
    if result is None:
        return
    reason = _TERMINATION_LABELS.get(result.termination_reason, result.termination_reason)
    if result.near_tie:
        print(
            f"\n  Tree-of-Thought: near-tie after {result.depth_reached} round(s) ({reason}) "
            "-- surfaced to human, no single winner:"
        )
        for t in result.candidates:
            print(f"    [{t.strategy.value}] score={t.score:.1f}/10")
            print(_wrap(t.proposal, indent="      "))
    else:
        winner = result.winner
        print(
            f"\n  Tree-of-Thought: winner = {winner.strategy.value} "
            f"(score={winner.score:.1f}/10) after {result.depth_reached} round(s) ({reason})"
        )
        print(_wrap(winner.proposal, indent="      "))


def _print_constraint_interpretation(interpretation: ConstraintInterpretation) -> None:
    print("Interpreting constraint...")
    if interpretation.asset_id is None:
        print(f"  could not resolve to a single asset -- {interpretation.rationale}")
        return
    print(f"  asset: {interpretation.asset_id}")
    print(f"  effect: {interpretation.effect_kind} = {interpretation.effect_value!r}")
    print(f"  affects: {', '.join(interpretation.affected_finding_ids) or '(none)'}")
    print(_wrap(interpretation.rationale, indent="  rationale: ", continuation_indent="    "))


def _print_constraint_result(result: ConstraintSubmissionResult) -> None:
    """The diff CLAUDE.md Section 10's exit criteria asks for: what
    changed between the finding(s)' prior score and the new one, and
    why -- `FindingDelta.after_verdict_summary` already states the "why"
    in plain language (agents/risk.py's task prompt requires it to,
    whenever a constraint was actually applied)."""
    if result.unresolved_finding_ids:
        print(
            f"\nWarning: the interpreter named finding_id(s) not found on "
            f"{result.interpretation.asset_id}, ignored: {', '.join(result.unresolved_finding_ids)}",
            file=sys.stderr,
        )
    if not result.persisted:
        print("\nNothing persisted or re-planned.", file=sys.stderr)
        return

    print(f"\nConstraint #{result.constraint_id} persisted. Re-planned {len(result.deltas)} finding(s).")
    changed = result.changed_deltas
    if not changed:
        print("\nNo findings changed bucket or risk score.")
        return

    print(f"\nDiff ({len(changed)}/{len(result.deltas)} finding(s) changed):")
    for d in changed:
        print(
            f"\n  {d.finding_id} ({d.cve_id} on {d.hostname}): "
            f"{d.before_bucket} ({d.before_risk_score:.1f}) -> "
            f"{d.after_bucket} ({d.after_risk_score:.1f})"
        )
        for line in d.rationale_added:
            print(_wrap(line, indent="    + ", continuation_indent="      "))
        for line in d.rationale_removed:
            print(_wrap(line, indent="    - ", continuation_indent="      "))
        print(_wrap(f"why: {d.after_verdict_summary}", indent="    ", continuation_indent="    "))


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
    run_parser.add_argument(
        "--db",
        default=None,
        help=(
            "with --agents, path to the memory.py SQLite file (default: "
            "memory.DEFAULT_DB_PATH) -- constraints on file there are picked up automatically"
        ),
    )

    constraint_parser = subparsers.add_parser(
        "constraint", help="submit or manage operational constraints (memory.py's constraints table)"
    )
    constraint_subparsers = constraint_parser.add_subparsers(dest="constraint_command", required=True)
    constraint_add_parser = constraint_subparsers.add_parser(
        "add", help="submit a free-form operational constraint and re-plan the findings it affects"
    )
    constraint_add_parser.add_argument("text", help="the constraint, in plain English")
    constraint_add_parser.add_argument("--data", default="demo", help="dataset name under data/, or a path")
    constraint_add_parser.add_argument("--seed", type=int, default=42)
    constraint_add_parser.add_argument(
        "--offline",
        action="store_true",
        help="forbid network fetches; fail loudly on any snapshot cache miss instead of fetching",
    )
    constraint_add_parser.add_argument(
        "--quiet", action="store_true", help="silence CrewAI's own console logging"
    )
    constraint_add_parser.add_argument(
        "--db", default=None, help="path to the memory.py SQLite file (default: memory.DEFAULT_DB_PATH)"
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
                coordinator = run_agents(data_dir, args.seed, offline=args.offline, db_path=args.db)
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
            _print_contested_rate(contested_rate(r.bucket for r in recommendations))

            if args.explain:
                for r in recommendations:
                    print(f"\n{r.finding_id} ({r.cve_id} on {r.hostname}) -> {r.bucket}")
                    print(f"\n{_wrap(r.verdict_summary)}")
                    for line in r.scoring_rationale:
                        print(_wrap_bullet(line))
                    print(f"\n{_wrap(r.narrative)}")
                    _print_tot_result(r.finding_id, coordinator)

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
        _print_contested_rate(contested_rate(s.bucket.value for s in scored))

        if args.explain:
            for s in scored:
                print(f"\n{s.finding_id} ({s.cve_id} on {s.hostname}) -> {s.bucket.value}")
                for line in s.rationale:
                    print(_wrap_bullet(line))

        return 0

    if args.command == "constraint" and args.constraint_command == "add":
        from rhinosecure.agents.coordinator import ConstraintInterpretationError
        from rhinosecure.llm import LLMConfigError

        data_dir = _resolve_data_dir(args.data)
        if args.quiet:
            from crewai.events.utils.console_formatter import set_suppress_console_output

            set_suppress_console_output(True)

        try:
            result = submit_constraint(args.text, data_dir, args.seed, offline=args.offline, db_path=args.db)
        except IngestError as exc:
            print(f"ingest error: {exc}", file=sys.stderr)
            return 1
        except OfflineCacheMissError as exc:
            print(f"offline error: {exc}", file=sys.stderr)
            return 1
        except LLMConfigError as exc:
            print(f"LLM config error: {exc}", file=sys.stderr)
            return 1
        except ConstraintInterpretationError as exc:
            print(f"could not interpret constraint: {exc}", file=sys.stderr)
            return 1

        _print_constraint_interpretation(result.interpretation)
        _print_constraint_result(result)
        return 0 if result.persisted else 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
