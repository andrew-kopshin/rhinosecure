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

`rhino constraint add` inverts that polarity: it suppresses by default
and takes an opt-in `--verbose` to show CrewAI's console output instead.
`rhino run --agents` is an exploratory command where seeing per-stage
agent activity is often exactly what's wanted, so verbose-by-default with
opt-in `--quiet` fits it; `rhino constraint add` is a single-decision
command where the interpretation, the pool ranking, and the diff (or, for
an asset-scoped constraint, the before/after) already say everything a
person needs, and the underlying agent prompt/reasoning is debugging
detail, not the normal case -- so it defaults to quiet and `--verbose`
opts back into the same `set_suppress_console_output` mechanism, just
with the flag's meaning reversed.

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

`--format` (default `native`) picks the ingest adapter (`adapters/`) --
CLAUDE.md Section 1's "swapping in a real scanner export should require a
new ingest adapter and nothing else", made a CLI flag. `--format defender`
reads Microsoft Defender Vulnerability Management exports (devices.csv +
vulnerabilities.csv, adapters/defender.py) and scores them through the
identical deterministic pipeline. After the table, `_print_ingest_report`
prints a data-gap summary -- which schema fields the export had no
concept of, on how many records -- and `--explain` adds a per-finding
note, both driven by `Asset.not_collected`/`Finding.not_collected`
(adapters/base.py); for the native fixture both are empty, so nothing
extra prints and output stays byte-identical. `run()` keeps its
list-of-ScoredFinding return (test_scoring.py and others call it that
way); `run_with_report` is the same pipeline returning the assets and the
report alongside, which is what `main` uses.

`--format` works on all three paths -- the deterministic pipeline,
`--agents`, and `rhino constraint add`. `Coordinator` used to build its
own asset index by reading `<data>/assets.csv` directly, which made a
non-native format impossible there; it now takes the already-loaded,
already-validated inventory as `assets=` (plus `ingest_format=` for the
`runs` record), and every path here loads it the same way through
`ingest.load_batch`. That matters most for `rhino constraint add`: an
export that carries no patch window, no compensating control, and no
role is exactly the input a human has to fill in by hand, so the
constraint path is the one that has to work for it, not the one that
refuses it.

`rhino web --export PATH [--port PORT]` launches the read-only FastAPI
viewer (`web/server.py`) over one `--export` JSON file (export.py) --
additive, its own subcommand, touching nothing above. It imports
`fastapi`/`uvicorn` lazily, same pattern as `crewai`/`memory` above, so
`rhino run`/`rhino constraint add` never need the `web` extra installed;
a missing extra is reported as a normal CLI error, not an ImportError
traceback. `web/server.py`'s own module docstring has the read-only
contract: that module reads the export file off disk and nothing else --
no pipeline run, no agent/LLM call, no memory.py write, ever.
"""

from __future__ import annotations

import argparse
import random
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

from rhinosecure.adapters import DEFAULT_FORMAT, FORMATS, get_adapter
from rhinosecure.enrich.attack import load_index as load_attack_index
from rhinosecure.enrich.cache import OfflineCacheMissError, SnapshotCache
from rhinosecure.enrich.kev import load_catalog as load_kev_catalog
from rhinosecure.ingest import (
    GapTally,
    IngestError,
    IngestReport,
    attach_threat_signals,
    load_batch,
)
from rhinosecure.schema import Asset
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


@dataclass(frozen=True)
class RunResult:
    """The deterministic path's output plus the inventory it was scored
    against and the ingest report -- `main` needs the last two to print
    data gaps (`_print_ingest_report`, `_print_gap_note`), which
    `ScoredFinding` alone can't supply: it carries no Asset and no
    `not_collected`. `not_collected_by_finding` only holds findings that
    have any (empty for the native fixture)."""

    scored: list[ScoredFinding]
    assets: dict[str, Asset]
    not_collected_by_finding: dict[str, frozenset[str]]
    report: IngestReport


def run(data_dir: Path, seed: int, *, offline: bool = False, fmt: str = DEFAULT_FORMAT) -> list[ScoredFinding]:
    """Ingest (via the `fmt` adapter), enrich, score, rank. The
    list-returning form every existing caller uses; see run_with_report."""
    return run_with_report(data_dir, seed, offline=offline, fmt=fmt).scored


def run_with_report(
    data_dir: Path, seed: int, *, offline: bool = False, fmt: str = DEFAULT_FORMAT
) -> RunResult:
    # Scoring is fully deterministic (no sampling); the seed is accepted
    # now so the CLI contract does not change once Slice 4's ToT beam
    # search introduces anything seed-sensitive.
    random.seed(seed)

    adapter = get_adapter(fmt)
    assets, enriched = load_batch(data_dir, adapter)

    cache = SnapshotCache(offline=offline)
    kev_catalog = load_kev_catalog(cache)  # one bulk feed, loaded once for the whole run
    attack_index = load_attack_index(cache)  # same shape: one filtered bundle, loaded once

    tally = GapTally()
    scored: list[ScoredFinding] = []
    not_collected_by_finding: dict[str, frozenset[str]] = {}
    for e in enriched:  # still one lazy pass over the findings stream
        tally.observe(e.finding)
        if e.finding.not_collected:
            not_collected_by_finding[e.finding.finding_id] = e.finding.not_collected
        scored.append(score_finding(attach_threat_signals(e, kev_catalog, attack_index, cache)))
    return RunResult(
        scored=rank(scored),
        assets=assets,
        not_collected_by_finding=not_collected_by_finding,
        report=tally.report(fmt, assets, adapter.stats),
    )


def run_agents(
    data_dir: Path,
    seed: int,
    *,
    offline: bool = False,
    db_path: Path | str | None = None,
    fmt: str = DEFAULT_FORMAT,
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
    assets, enriched = load_batch(data_dir, get_adapter(fmt))
    findings = list(enriched)
    memory = Memory(db_path if db_path is not None else DEFAULT_DB_PATH)
    coordinator = Coordinator(
        data_dir,
        cache=SnapshotCache(offline=offline),
        memory=memory,
        assets=assets,
        ingest_format=fmt,
    )
    coordinator.run(findings)
    return coordinator


def submit_constraint(
    text: str,
    data_dir: Path,
    seed: int,
    *,
    offline: bool = False,
    db_path: Path | str | None = None,
    fmt: str = DEFAULT_FORMAT,
) -> ConstraintSubmissionResult | CapacitySubmissionResult:
    """CLI entry point for `rhino constraint add` -- the agent equivalent
    of `run`/`run_agents`, dispatching `agents/coordinator.py`'s
    `submit_constraint` against every finding in `data_dir`. Imports
    agents.*/memory lazily, same reason as `run_agents`.

    `fmt` selects the ingest adapter exactly as it does for `run`. This is
    the path that most needs a non-native format to work: a real scanner
    export carries no patch window, compensating control, or role (see
    adapters/base.py), and this command is how a human supplies them."""
    from rhinosecure.agents.coordinator import Coordinator
    from rhinosecure.memory import DEFAULT_DB_PATH, Memory

    random.seed(seed)
    assets, enriched = load_batch(data_dir, get_adapter(fmt))
    findings = list(enriched)
    memory = Memory(db_path if db_path is not None else DEFAULT_DB_PATH)
    coordinator = Coordinator(
        data_dir,
        cache=SnapshotCache(offline=offline),
        memory=memory,
        assets=assets,
        ingest_format=fmt,
    )
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


def _print_raw_output(raw: str, *, indent: str, file) -> None:
    """--verbose only. The exact, untrusted, unparsed model text behind a
    short failure summary -- withheld from the summary itself on purpose,
    see agents/parsing.py's AgentOutputParseError docstring."""
    print(f"{indent}raw model output:", file=file)
    for line in raw.splitlines() or [""]:
        print(f"{indent}  {line}", file=file)


def _print_failures(coordinator: Coordinator, *, verbose: bool = False) -> None:
    """Findings recorded and skipped (rather than left blocking the run)
    at any stage -- see agents/coordinator.py's module docstring. A ToT
    failure is reported the same way but never removes the finding from
    the table above -- Risk already succeeded for it (see
    agents/coordinator.py's _dispatch_tot docstring). `reason` is always
    a short summary (never the agent's raw output, which can be
    arbitrary-length untrusted model text) -- pass verbose=True (--verbose)
    to also print the failing attempt's raw output, when one was recorded."""
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
            if verbose:
                raw = coordinator.state.last_raw_output.get(finding_id)
                if raw is not None:
                    _print_raw_output(raw, indent="    ", file=sys.stderr)


def _print_contested_rate(rate: ContestedRate) -> None:
    print(f"\nContested: {rate.contested}/{rate.total} ({rate.pct:.1f}%) of scored findings")


_TERMINATION_LABELS = {
    "clear_winner": "clear winner",
    "depth_limit": "depth limit",
    "exhausted_evidence": "exhausted evidence",
}


def _print_tot_result(finding_id: str, coordinator: Coordinator, *, verbose: bool = False) -> None:
    """Prints a contested finding's Tree-of-Thought outcome right after
    its narrative, if it has one -- either a single winning strategy, or
    (Section 6: "Near-tie -> surface both branches to the human") every
    candidate in a near-tied final beam, with no branch picked for the
    reader. Silently does nothing for a finding with neither a result nor
    a recorded failure -- i.e. every finding that was never contested.
    verbose=True (--verbose) also prints a failed search's last raw
    model output, when one was recorded -- see _print_failures."""
    if finding_id in coordinator.state.tot_failures:
        print(f"\n  Tree-of-Thought: failed -- {coordinator.state.tot_failures[finding_id]}")
        if verbose:
            raw = coordinator.state.last_raw_output.get(finding_id)
            if raw is not None:
                _print_raw_output(raw, indent="    ", file=sys.stdout)
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
    """`asset_id is None` alone no longer means "declined" -- a fleet-wide
    capacity statement also has no single asset to resolve to (Section 10)
    but is a real, handled outcome, not a refusal. Branch on
    `constraint_kind` explicitly instead."""
    print("Interpreting constraint...")
    if interpretation.constraint_kind == "capacity":
        print(f"  capacity constraint -- patch_limit={interpretation.patch_limit}")
        print(_wrap(interpretation.rationale, indent="  rationale: ", continuation_indent="    "))
        return
    if interpretation.constraint_kind != "asset" or interpretation.asset_id is None:
        print(f"  could not resolve to a single asset or a capacity limit -- {interpretation.rationale}")
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


def _print_capacity_result(result: CapacitySubmissionResult) -> None:
    """The fleet-wide capacity diff (CLAUDE.md Section 10's "only five
    patches fit this window") needs different framing from
    `_print_constraint_result` above: `risk_score` is identical before and
    after for every finding here (`agents/coordinator.py`'s `CapacityDelta`
    docstring) -- what changed is a finding's rank-position against the
    declared limit, not anything about its risk. Diff'd by rank and bucket
    instead of a risk_score before/after pair."""
    if not result.persisted:
        print("\nNothing computed or persisted.", file=sys.stderr)
        return

    print(
        f"\nCapacity constraint #{result.capacity_constraint_id} persisted "
        f"(limit={result.interpretation.patch_limit})."
    )
    if not result.deltas:
        print("\nNo next_window finding(s) currently in the pool -- nothing to allocate.")
        return

    limit = result.deltas[0].limit
    pool_size = result.deltas[0].pool_size
    print(f"\n{pool_size} next_window finding(s) competing for {limit} slot(s) this cycle:")
    for d in sorted(result.deltas, key=lambda d: d.rank):
        marker = "fits" if d.fits else "deferred_capacity"
        print(f"  #{d.rank} {d.finding_id} ({d.cve_id} on {d.hostname}) risk_score={d.risk_score:.1f} -> {marker}")

    changed = result.changed_deltas
    if not changed:
        print("\nAll findings fit within capacity -- no bucket changes.")
        return

    print(f"\nDiff ({len(changed)}/{len(result.deltas)} finding(s) deferred):")
    for d in changed:
        print(f"\n  {d.finding_id} ({d.cve_id} on {d.hostname}): {d.original_bucket} -> {d.effective_bucket}")
        print(
            _wrap(
                f"risk_score unchanged at {d.risk_score:.1f} -- ranked {d.rank} of {d.pool_size}, "
                f"exceeding this cycle's limit of {d.limit}. This finding lost a rank-position race, "
                "not a change in risk.",
                indent="    ",
                continuation_indent="    ",
            )
        )


def _print_ingest_report(report: IngestReport) -> None:
    """The data-gap summary for a non-native format: which schema fields
    the export had no concept of (or left blank), on how many records,
    and what the adapter collapsed on the way in. Prints nothing when
    there is nothing to say -- the native fixture's output is unchanged.
    The last paragraph exists because scoring.py's own rationale still
    says "no patch_window declared" for these assets (scoring is
    untouched by the adapter layer; see adapters/base.py): this is where
    the reader learns that blank means "not collected" here."""
    if not report.has_anything_to_report:
        return
    print()
    if report.has_gaps:
        print(f"Data gaps (--format {report.format}): fields this export has no concept of, or left blank.")
        print(
            _wrap(
                "The values in effect for them are documented defaults (adapters/base.py, "
                "NOT_COLLECTED_DEFAULTS), not facts from the export."
            )
        )
        for kind, total, gaps in (
            ("assets", report.assets_total, report.asset_gaps),
            ("findings", report.findings_total, report.finding_gaps),
        ):
            by_count: dict[int, list[str]] = {}
            for name, count in gaps.items():
                by_count.setdefault(count, []).append(name)
            for count in sorted(by_count, reverse=True):
                label = f"  {kind:<8} {count}/{total}  "
                print(_wrap(", ".join(sorted(by_count[count])), indent=label, continuation_indent=" " * len(label)))
        if {"patch_window", "compensating_controls"} & set(report.asset_gaps):
            print(
                _wrap(
                    'The bucket rules read a blank patch_window as "no declared restriction" and blank '
                    'compensating_controls as "none"; for these assets both mean "not collected". '
                    "Supply the real ones per asset with `rhino constraint add`."
                )
            )
    if report.duplicate_findings_collapsed or report.duplicate_assets_collapsed:
        print(
            f"  Collapsed {report.duplicate_findings_collapsed} duplicate finding row(s) and "
            f"{report.duplicate_assets_collapsed} repeated device row(s)."
        )


def _print_gap_note(asset: Asset, finding_gaps: frozenset[str]) -> None:
    """--explain's per-finding companion to _print_ingest_report: sits
    right after scoring.py's rationale bullets and names the fields on
    this asset/finding whose values are defaults, with the value in effect
    for any that isn't blank. Silent for a native record."""
    parts = []
    for name in sorted(asset.not_collected):
        value = getattr(asset, name)
        parts.append(name if value == "" else f"{name}={value}")
    parts.extend(sorted(finding_gaps))
    if not parts:
        return
    print(
        _wrap(
            "not collected: " + ", ".join(parts) + ' -- read the bullets above as "unknown" for these, '
            'not "none declared"; the values shown are defaults',
            indent="  ! ",
            continuation_indent="    ",
        )
    )


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
        "--verbose",
        action="store_true",
        help=(
            "with --agents, also print the raw model output behind any finding/ToT search "
            "that failed after exhausting retries -- omitted by default (debugging only)"
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
    run_parser.add_argument(
        "--format",
        default=DEFAULT_FORMAT,
        choices=sorted(FORMATS),
        help=(
            "ingest adapter for --data's files (adapters/): native reads assets.csv + findings.csv; "
            "defender reads Microsoft Defender Vulnerability Management exports devices.csv "
            "(DeviceInfo) + vulnerabilities.csv (DeviceTvmSoftwareVulnerabilities)"
        ),
    )
    run_parser.add_argument(
        "--export",
        default=None,
        help="write the full run report as JSON to this path, in addition to the console output",
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
        "--verbose",
        action="store_true",
        help=(
            "show CrewAI's own console logging (agent-started boxes, per-tool-call echo "
            "lines) -- suppressed by default, unlike rhino run --agents"
        ),
    )
    constraint_add_parser.add_argument(
        "--db", default=None, help="path to the memory.py SQLite file (default: memory.DEFAULT_DB_PATH)"
    )
    constraint_add_parser.add_argument(
        "--format",
        default=DEFAULT_FORMAT,
        choices=sorted(FORMATS),
        help=(
            "ingest adapter for --data's files, same as `rhino run --format`. A real scanner "
            "export carries no patch window, compensating control, or role, so this is the "
            "command that supplies them"
        ),
    )

    web_parser = subparsers.add_parser(
        "web", help="serve a read-only web viewer for one `rhino run --export` JSON file"
    )
    web_parser.add_argument(
        "--export",
        default=None,
        help=(
            "path to a JSON file written by `rhino run --export` (default: "
            "out/export_demo.json under the repo root, or $RHINOSECURE_EXPORT_PATH)"
        ),
    )
    web_parser.add_argument("--port", type=int, default=8420)
    web_parser.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost only)")

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
                coordinator = run_agents(
                    data_dir, args.seed, offline=args.offline, db_path=args.db, fmt=args.format
                )
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
            _print_failures(coordinator, verbose=args.verbose)
            _print_contested_rate(contested_rate(r.bucket for r in recommendations))

            if args.explain:
                for r in recommendations:
                    print(f"\n{r.finding_id} ({r.cve_id} on {r.hostname}) -> {r.bucket}")
                    print(f"\n{_wrap(r.verdict_summary)}")
                    for line in r.scoring_rationale:
                        print(_wrap_bullet(line))
                    print(f"\n{_wrap(r.narrative)}")
                    _print_tot_result(r.finding_id, coordinator, verbose=args.verbose)

            if args.export:
                from rhinosecure.export import write_run_export

                try:
                    write_run_export(
                        Path(args.export),
                        fmt=args.format,
                        data_dir=data_dir,
                        seed=args.seed,
                        offline=args.offline,
                        agents=True,
                        coordinator=coordinator,
                        memory=coordinator.memory,
                    )
                except OSError as exc:
                    print(f"export error: {exc}", file=sys.stderr)
                    return 1

            return 0

        try:
            result = run_with_report(data_dir, args.seed, offline=args.offline, fmt=args.format)
        except IngestError as exc:
            print(f"ingest error: {exc}", file=sys.stderr)
            return 1
        except OfflineCacheMissError as exc:
            print(f"offline error: {exc}", file=sys.stderr)
            return 1

        scored = result.scored
        _print_table(scored)
        _print_contested_rate(contested_rate(s.bucket.value for s in scored))
        _print_ingest_report(result.report)

        if args.explain:
            for s in scored:
                print(f"\n{s.finding_id} ({s.cve_id} on {s.hostname}) -> {s.bucket.value}")
                for line in s.rationale:
                    print(_wrap_bullet(line))
                _print_gap_note(
                    result.assets[s.asset_id],
                    result.not_collected_by_finding.get(s.finding_id, frozenset()),
                )

        if args.export:
            from rhinosecure.export import write_run_export
            from rhinosecure.memory import Memory

            export_memory = Memory(args.db) if args.db else Memory()
            try:
                write_run_export(
                    Path(args.export),
                    fmt=args.format,
                    data_dir=data_dir,
                    seed=args.seed,
                    offline=args.offline,
                    agents=False,
                    result=result,
                    memory=export_memory,
                )
            except OSError as exc:
                print(f"export error: {exc}", file=sys.stderr)
                return 1

        return 0

    if args.command == "constraint" and args.constraint_command == "add":
        from rhinosecure.agents.coordinator import CapacitySubmissionResult, ConstraintInterpretationError
        from rhinosecure.llm import LLMConfigError

        data_dir = _resolve_data_dir(args.data)
        if not args.verbose:
            from crewai.events.utils.console_formatter import set_suppress_console_output

            set_suppress_console_output(True)

        try:
            result = submit_constraint(
                args.text, data_dir, args.seed, offline=args.offline, db_path=args.db, fmt=args.format
            )
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
            print(f"could not interpret constraint: {exc}. Nothing was persisted.", file=sys.stderr)
            if args.verbose:
                raw = getattr(exc.__cause__, "raw", None)
                if raw is not None:
                    _print_raw_output(raw, indent="  ", file=sys.stderr)
            return 1

        _print_constraint_interpretation(result.interpretation)
        if isinstance(result, CapacitySubmissionResult):
            _print_capacity_result(result)
        else:
            _print_constraint_result(result)
        return 0 if result.persisted else 1

    if args.command == "web":
        try:
            import uvicorn

            from rhinosecure.web.server import create_app
        except ImportError as exc:
            print(
                f"the web viewer needs the 'web' extra -- pip install -e '.[web]' ({exc})",
                file=sys.stderr,
            )
            return 1

        app = create_app(args.export)
        resolved = app.state.export_path
        if not resolved.exists():
            print(f"warning: export file does not exist yet: {resolved}", file=sys.stderr)
        print(f"RhinoSecure web viewer -- serving {resolved}")
        print(f"  http://{args.host}:{args.port}/")
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
