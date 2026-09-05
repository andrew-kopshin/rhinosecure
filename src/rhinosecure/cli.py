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

`--format bluepeak` reads a pre-enriched single-file export
(synthetic_cve_inventory_50.csv, adapters/bluepeak.py) whose own CVSS,
exploitation, and ATT&CK-technique fields are trusted directly instead of
fetched -- `IngestAdapter.provides_enrichment` (adapters/base.py) is the
switch `run_with_report` reads to call `ingest.attach_source_enrichment`
instead of `attach_threat_signals`, skipping the live KEV/EPSS/NVD/ATT&CK
lookups (and their two bulk loads) entirely for a source whose CVE IDs
would never resolve there anyway. `run_agents`/`submit_constraint` below
are not format-aware in this respect yet -- they still dispatch Research's
live-lookup tools for every format, which is harmless for `--format
bluepeak` (a graceful "not found" per lookup, same as any not-yet-scored
CVE) but does not yet give the agents path the same precision the
deterministic path gets from a pre-enriched source.

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

`rhino adapt list` / `rhino adapt probe <name>` are docs/adapter-generation
.md's Slice 6: tools for looking at a source nobody has written a mapping
for yet, ahead of Slice 8's not-yet-built phase-1 inference agent. `list`
scans `data/` for subdirectories that contain at least one `.csv` file and
names which, if any, already match a registered `--format`'s expected
filenames (`_discover_probe_sources`) -- purely a directory listing, no
file content is read. `probe <name>` resolves `<name>` exactly like `--data`
(`_resolve_data_dir`) and hands it to `adapters/probe.py`'s
`profile_source`, which reads every .csv file there in full and reports,
per column, how much of it is blank, how many distinct values it takes, and
which of a small set of code-owned patterns every non-blank value happens
to satisfy -- a hint for a human (or a future LLM) proposing a mapping,
never itself a mapping. Neither command makes an LLM call, needs an API
key, or writes anything; `adapters/probe.py`'s own module docstring has the
full design reasoning.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rhinosecure.agents.schema_inference import ProposeResult

from rhinosecure.adapters import (
    DEFAULT_FORMAT,
    FORMATS,
    get_adapter,
    load_config_adapter,
    resolve_config_path,
)
from rhinosecure.adapters.config_model import Contract
from rhinosecure.adapters.probe import ColumnProfile, FileProfile, ProbeError, profile_source
from rhinosecure.adapters.review import Measurement, ReviewError, ReviewOutcome, review_contract
from rhinosecure.enrich.attack import load_index as load_attack_index
from rhinosecure.enrich.cache import OfflineCacheMissError, SnapshotCache
from rhinosecure.enrich.kev import load_catalog as load_kev_catalog
from rhinosecure.ingest import (
    GapTally,
    IngestError,
    IngestReport,
    IngestStats,
    attach_source_enrichment,
    attach_threat_signals,
    load_batch,
)
from rhinosecure.schema import Asset, EnrichedFinding
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
    have any (empty for the native fixture).

    `contract` is the confirmed ingest contract behind a `--adapter-config`
    run (`ConfiguredAdapter.contract`), or `None` for a built-in `--format`
    -- `main` reads it to print which reviewed mapping produced this plan,
    above the exclusion report."""

    scored: list[ScoredFinding]
    assets: dict[str, Asset]
    not_collected_by_finding: dict[str, frozenset[str]]
    report: IngestReport
    contract: Contract | None = None


def run(
    data_dir: Path, seed: int, *, offline: bool = False, fmt: str = DEFAULT_FORMAT, adapter_config: str | None = None
) -> list[ScoredFinding]:
    """Ingest (via the `fmt` adapter, or `adapter_config` if given), enrich,
    score, rank. The list-returning form every existing caller uses; see
    run_with_report."""
    return run_with_report(data_dir, seed, offline=offline, fmt=fmt, adapter_config=adapter_config).scored


def run_with_report(
    data_dir: Path, seed: int, *, offline: bool = False, fmt: str = DEFAULT_FORMAT, adapter_config: str | None = None
) -> RunResult:
    # Scoring is fully deterministic (no sampling); the seed is accepted
    # now so the CLI contract does not change once Slice 4's ToT beam
    # search introduces anything seed-sensitive.
    random.seed(seed)

    # adapter_config, when given, wins outright -- cli.py's argparse group
    # already makes --format/--adapter-config mutually exclusive, so this
    # is never resolving a genuine conflict, just picking whichever path
    # supplied something. `fmt` is rebound to the resolved adapter's OWN
    # declared name afterward: a no-op for a built-in (`adapter.format ==
    # fmt` already), and correct for a contract, whose `format` need not
    # equal the --adapter-config argument itself (a path vs. the name the
    # contract declares) -- every print/report below reads `fmt`, not the
    # original argument, from this point on.
    adapter = load_config_adapter(adapter_config) if adapter_config else get_adapter(fmt)
    fmt = adapter.format
    contract = getattr(adapter, "contract", None)
    assets, enriched = load_batch(data_dir, adapter)

    if adapter.provides_enrichment:
        # This format's own export already carries CVSS/exploitation/ATT&CK
        # data per finding (Finding.source_enrichment) -- its CVE IDs
        # typically don't resolve at NVD/KEV/EPSS/ATT&CK anyway (see
        # adapters/bluepeak.py), so skip the live lookups, and the two bulk
        # KEV/ATT&CK loads below, entirely rather than spending them on
        # retries that would just find nothing.
        def enrich(e: EnrichedFinding) -> EnrichedFinding:
            return attach_source_enrichment(e)
    else:
        cache = SnapshotCache(offline=offline)
        kev_catalog = load_kev_catalog(cache)  # one bulk feed, loaded once for the whole run
        attack_index = load_attack_index(cache)  # same shape: one filtered bundle, loaded once

        def enrich(e: EnrichedFinding) -> EnrichedFinding:
            return attach_threat_signals(e, kev_catalog, attack_index, cache)

    tally = GapTally()
    scored: list[ScoredFinding] = []
    not_collected_by_finding: dict[str, frozenset[str]] = {}
    for e in enriched:  # still one lazy pass over the findings stream
        tally.observe(e.finding)
        if e.finding.not_collected:
            not_collected_by_finding[e.finding.finding_id] = e.finding.not_collected
        scored.append(score_finding(enrich(e)))
    return RunResult(
        scored=rank(scored),
        assets=assets,
        not_collected_by_finding=not_collected_by_finding,
        report=tally.report(fmt, assets, adapter.stats),
        contract=contract,
    )


def run_agents(
    data_dir: Path,
    seed: int,
    *,
    offline: bool = False,
    db_path: Path | str | None = None,
    fmt: str = DEFAULT_FORMAT,
    adapter_config: str | None = None,
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

    `adapter_config`, when given, resolves the ingest adapter the same way
    `run_with_report` does -- see its own comment for why `fmt` is rebound
    to the resolved adapter's own declared name afterward. `Coordinator`
    gets `ingest_format=adapter.run_label`, not the bare name: for a
    config-driven run that includes the confirmed revision
    (`"<format>@v<version>"`), so two runs against different revisions of
    the same contract are distinguishable in `memory.runs`, which a plain
    format name never was.
    """
    from rhinosecure.agents.coordinator import Coordinator
    from rhinosecure.memory import DEFAULT_DB_PATH, Memory

    random.seed(seed)  # see run()'s comment -- still a no-op for now
    adapter = load_config_adapter(adapter_config) if adapter_config else get_adapter(fmt)
    fmt = adapter.format
    assets, enriched = load_batch(data_dir, adapter)
    findings = list(enriched)
    _warn_of_exclusions(adapter.stats, fmt)
    memory = Memory(db_path if db_path is not None else DEFAULT_DB_PATH)
    coordinator = Coordinator(
        data_dir,
        cache=SnapshotCache(offline=offline),
        memory=memory,
        assets=assets,
        ingest_format=adapter.run_label,
        contract=getattr(adapter, "contract", None),
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
    adapter_config: str | None = None,
) -> ConstraintSubmissionResult | CapacitySubmissionResult:
    """CLI entry point for `rhino constraint add` -- the agent equivalent
    of `run`/`run_agents`, dispatching `agents/coordinator.py`'s
    `submit_constraint` against every finding in `data_dir`. Imports
    agents.*/memory lazily, same reason as `run_agents`.

    `fmt` selects the ingest adapter exactly as it does for `run`. This is
    the path that most needs a non-native format to work: a real scanner
    export carries no patch window, compensating control, or role (see
    adapters/base.py), and this command is how a human supplies them --
    `adapter_config` is how it does that for a config-driven contract, the
    same way `run_with_report`/`run_agents` resolve one."""
    from rhinosecure.agents.coordinator import Coordinator
    from rhinosecure.memory import DEFAULT_DB_PATH, Memory

    random.seed(seed)
    adapter = load_config_adapter(adapter_config) if adapter_config else get_adapter(fmt)
    fmt = adapter.format
    assets, enriched = load_batch(data_dir, adapter)
    findings = list(enriched)
    _warn_of_exclusions(adapter.stats, fmt)
    memory = Memory(db_path if db_path is not None else DEFAULT_DB_PATH)
    coordinator = Coordinator(
        data_dir,
        cache=SnapshotCache(offline=offline),
        memory=memory,
        assets=assets,
        ingest_format=adapter.run_label,
        contract=getattr(adapter, "contract", None),
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


def _print_adapter_config_banner(contract: Contract | None, report: IngestReport | None = None) -> None:
    """The provenance a config-driven run has that a built-in --format
    never does: which reviewed contract produced this plan, and which
    confirmed revision. Printed above _print_exclusions -- before any
    number a reader could otherwise form an impression from without
    knowing it came from a human-reviewed mapping rather than a built-in
    one. A no-op for a built-in --format run (contract is None there).

    When the contract carries a measurement from its own confirmation
    (`observed`, written by `rhino adapt confirm` -- adapters/review.py),
    this also compares what was signed against what just loaded. Nothing
    else in the codebase reads `observed` except V18, so without this a
    contract confirmed against a friendly six-row sample and then run
    against a six-million-row export is completely undetectable -- and the
    re-probe's own cost is exactly what pushes an operator toward the small
    sample. Stated as a notice, not enforced: there is no defensible
    threshold yet, and the point is to put the mismatch in front of a person
    at the moment it matters. Silent when the contract was confirmed before
    this existed (`observed` is null on both committed contracts today), so
    no existing output changes."""
    if contract is None:
        return
    print(
        f"Using adapter config {contract.format!r} v{contract.version}, confirmed "
        f"{contract.review.confirmed_at} by {contract.review.confirmed_by}"
    )
    observed = contract.observed or {}
    if report is None or not observed:
        return
    signed_assets, signed_findings = observed.get("assets_loaded"), observed.get("findings_loaded")
    if not isinstance(signed_assets, int) or not isinstance(signed_findings, int):
        return
    if (signed_assets, signed_findings) == (report.assets_total, report.findings_total):
        return
    print(
        _wrap(
            f"note: this mapping was confirmed against {signed_assets} asset(s) and "
            f"{signed_findings} finding(s); this run loaded {report.assets_total} and "
            f"{report.findings_total}. A signature covers the mapping, not this data -- "
            "re-review it (`rhino adapt rereview`) if the source has changed shape.",
            indent="  ",
            continuation_indent="  ",
        )
    )


def _print_exclusions(report: IngestReport) -> None:
    """Scope-boundary exclusions (adapters/base.py's `ProblemCollector
    .exclude` -- e.g. Defender's non-Windows `OSPlatform`, BluePeak's
    unmapped `Asset_Type`), printed BEFORE the table, unlike the gap
    report below: a plan that's silently missing part of a fleet must
    never look complete, so this cannot be a footnote after the numbers
    a reader has already formed an impression from. Prints nothing when
    there is nothing to report -- native, and any run with nothing
    excluded, stays exactly as before."""
    if not report.has_exclusions:
        return
    original_assets = report.assets_total + len(report.excluded_assets)
    original_findings = report.findings_total + len(report.excluded_findings)
    print(
        f"Excluded (--format {report.format}): {len(report.excluded_assets)}/{original_assets} asset(s), "
        f"{len(report.excluded_findings)}/{original_findings} finding(s) -- outside this project's declared "
        "scope, not a data-quality problem. The rest of the batch is scored below."
    )
    by_reason: dict[str, list[str]] = {}
    for asset_id, reason in report.excluded_assets.items():
        by_reason.setdefault(reason, []).append(asset_id)
    for reason, ids in sorted(by_reason.items()):
        label = "  asset(s)  "
        print(_wrap(f"{', '.join(sorted(ids))}: {reason}", indent=label, continuation_indent=" " * len(label)))
    for finding_id, reason in sorted(report.excluded_findings.items()):
        label = "  finding   "
        print(_wrap(f"{finding_id}: {reason}", indent=label, continuation_indent=" " * len(label)))
    print()


def _warn_of_exclusions(stats: IngestStats, fmt: str) -> None:
    """The `--agents`/`constraint add` paths' counterpart to
    `_print_exclusions` -- they don't build a full `IngestReport` (no
    `GapTally` pass over the enriched findings), so this is a shorter,
    stderr-only notice rather than the full grouped-by-reason breakdown,
    just enough that a shrunk batch is never silent on these paths either.
    `rhino run` (without --agents) is where the full breakdown lives."""
    total = len(stats.excluded_assets) + len(stats.excluded_findings)
    if total == 0:
        return
    print(
        f"Note: --format {fmt} excluded {len(stats.excluded_assets)} asset(s) and "
        f"{len(stats.excluded_findings)} finding(s) outside this project's declared scope "
        "(not a data-quality problem) -- run `rhino run` (without --agents) for the full "
        "breakdown of what and why.",
        file=sys.stderr,
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


@dataclass(frozen=True)
class ProbeSource:
    """One `data/` subdirectory `rhino adapt list` found -- a candidate
    argument for `rhino adapt probe`. `matches_format` names every
    registered `--format` whose expected filenames are all present here
    (a subset check: extra, unrelated CSVs alongside them don't disqualify
    a match) -- purely so a user isn't pointed at probing a source that
    already has a working, reviewed, built-in adapter."""

    name: str
    csv_files: tuple[str, ...]
    matches_format: tuple[str, ...]


def _discover_probe_sources() -> list[ProbeSource]:
    data_root = REPO_ROOT / "data"
    if not data_root.is_dir():
        return []
    sources: list[ProbeSource] = []
    for entry in sorted(data_root.iterdir(), key=lambda p: p.name):
        if not entry.is_dir():
            continue
        try:
            csv_files = sorted(p.name for p in entry.iterdir() if p.is_file() and p.suffix.lower() == ".csv")
        except OSError as exc:
            print(f"Note: could not list {entry} -- {exc}", file=sys.stderr)
            continue
        if not csv_files:
            continue
        csv_set = set(csv_files)
        matches = sorted(
            fmt for fmt, cls in FORMATS.items() if {cls.assets_filename, cls.findings_filename} <= csv_set
        )
        sources.append(ProbeSource(name=entry.name, csv_files=tuple(csv_files), matches_format=tuple(matches)))
    return sources


def _print_adapt_list(sources: list[ProbeSource]) -> None:
    if not sources:
        print(f"No candidate sources found under {REPO_ROOT / 'data'} (no subdirectory has a .csv file).")
        return
    headers = ("name", "files", "known format")
    rows = [
        (s.name, ", ".join(s.csv_files), ", ".join(s.matches_format) or "-- (rhino adapt probe candidate)")
        for s in sources
    ]
    _print_rows(headers, rows)


_PROBE_SAMPLE_CHARS = 24
_PROBE_SAMPLES_SHOWN = 3


def _column_row(col: ColumnProfile, row_count: int) -> tuple[str, str, str, str, str, str]:
    length = f"{col.min_length}-{col.max_length}" if col.min_length is not None else "--"
    distinct = f"{col.distinct_count}{'+' if col.distinct_overflow else ''}"
    shown = col.sample_values[:_PROBE_SAMPLES_SHOWN]
    samples = ", ".join(v if len(v) <= _PROBE_SAMPLE_CHARS else v[: _PROBE_SAMPLE_CHARS - 1] + "…" for v in shown)
    if col.distinct_count > len(shown) or col.distinct_overflow:
        samples = f"{samples}, ..." if samples else "..."
    return (
        col.name,
        f"{col.blank}/{row_count}",
        distinct,
        length,
        ", ".join(col.looks_like) or "--",
        samples or "--",
    )


def _print_probe_report(data_dir: Path, profiles: list[FileProfile]) -> None:
    print(f"Probing {data_dir} ({len(profiles)} file(s))")
    for profile in profiles:
        status = " -- STOPPED EARLY, see observations below" if profile.truncated else ""
        print(
            f"\n{profile.path.name} -- {profile.encoding}, {profile.row_count} row(s), "
            f"{len(profile.columns)} column(s){status}"
        )
        headers = ("column", "blank", "distinct", "len", "looks_like", "samples")
        rows = [_column_row(profile.columns[name], profile.row_count) for name in dict.fromkeys(profile.header)]
        _print_rows(headers, rows)
        if profile.problems:
            print(f"\n  {len(profile.problems)} observation(s) (not fatal):")
            for message in profile.problems:
                print(_wrap(message, indent="    - ", continuation_indent="      "))
        else:
            print("\n  No observations.")


def _describe_mapping(mapping) -> str:
    """One line per mapping kind, for the propose report's slot table --
    condensed, not the full `model_dump`; a human reading the table wants
    to scan 40-some rows at a glance, not re-parse JSON per row."""
    kind = mapping.kind
    if kind == "column":
        return f"column={mapping.column}"
    if kind == "vocabulary":
        return f"vocabulary={mapping.column} ({len(mapping.table)} token(s) proposed)"
    if kind == "parsed":
        return f"parsed={mapping.column} (parser={mapping.parser})"
    if kind == "literal":
        return f"literal={mapping.value!r}"
    if kind == "composed":
        return f"composed({len(mapping.parts)} part(s))"
    if kind == "not_collected":
        return "not_collected"
    if kind == "derived":
        return f"derived={mapping.from_}.{mapping.output}"
    if kind == "default_by":
        return f"default_by={mapping.table}"
    if kind == "content_address":
        return f"content_address({', '.join(mapping.columns)})"
    return kind


_PROPOSE_DETAIL_CHARS = 70


def _truncated(text: str, limit: int = _PROPOSE_DETAIL_CHARS) -> str:
    text = " ".join(text.split())  # collapse embedded newlines/whitespace to keep one table row one line
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _print_propose_slots(label: str, slots: dict) -> None:
    print(f"\nSlot mapping -- {label} ({len(slots)} target field(s)):")
    headers = ("field", "status", "detail", "conf")
    rows = []
    for target in sorted(slots):
        sp = slots[target]
        if sp.status == "mapped":
            rows.append((target, sp.status, _truncated(_describe_mapping(sp.mapping)), f"{sp.confidence:.2f}"))
        else:
            rows.append((target, sp.status, _truncated(sp.reason), "--"))
    _print_rows(headers, rows)


def _print_propose_grounding(grounding) -> None:
    """Caveats print FIRST and get their own labeled section -- a
    distinct_overflow caveat is the one case grounding is knowingly
    incomplete, and a human is being asked to cover for it by hand; it
    must never read as a trailing footnote under the pass/fail list."""
    print("\nEvidence grounding (LLM-free, checked against the real file):")
    if grounding.caveats:
        print(
            f"  ! {len(grounding.caveats)} caveat(s) -- grounding could not be exhaustive here; "
            "verify these by hand:"
        )
        for issue in grounding.caveats:
            print(_wrap(f"{issue.slot}: {issue.message}", indent="    ! ", continuation_indent="      "))
    if grounding.failures:
        print(f"  {len(grounding.failures)} failure(s):")
        for issue in grounding.failures:
            print(_wrap(f"{issue.slot}: {issue.message}", indent="    - ", continuation_indent="      "))
    if not grounding.caveats and not grounding.failures:
        print("  clean -- every cited column and table entry was verified against the real file.")


def _print_propose_report(data_dir: Path, name: str, result: "ProposeResult") -> None:
    from rhinosecure.agents.schema_inference import unresolved_slots

    proposal = result.proposal
    print(
        f"Proposing a contract for {name!r} from {data_dir} "
        f"({len(result.profiles)} file(s), {proposal.meta.source_layout})"
    )

    _print_propose_slots("asset", proposal.asset)
    _print_propose_slots("finding", proposal.finding)
    _print_propose_grounding(result.grounding)

    if proposal.unmapped_columns:
        print("\nColumns this proposal does not read:")
        for filename, entries in proposal.unmapped_columns.items():
            print(f"  {filename}")
            for column, entry in sorted(entries.items()):
                print(
                    _wrap(
                        f"[{entry.disposition}] {entry.reason}",
                        indent=f"    {column}: ", continuation_indent="        ",
                    )
                )

    unresolved = unresolved_slots(proposal)
    print()
    if result.contract is not None:
        print("Result: every slot mapped and grounded, every column accounted for.")
    else:
        blocking = sorted(set(unresolved) | result.grounding.failed_slots)
        print(
            f"Result: {len(unresolved)} slot(s) unresolved, "
            f"{len(result.grounding.failed_slots)} slot(s)/reference(s) failed grounding -- NOT written."
        )
        if blocking:
            print(_wrap(f"Blocking: {blocking}", indent="  ", continuation_indent="    "))
        if result.incomplete_reason:
            # Every slot was mapped and grounding was clean, but assembly's
            # own validate_contract safety net still refused (an illegal
            # vocabulary value, an illegal union_fields entry, etc.) --
            # blocking alone would print as empty here with no explanation.
            print(
                _wrap(
                    f"validate_contract refused the assembled contract: {result.incomplete_reason}",
                    indent="  ! ", continuation_indent="    ",
                )
            )

    g = result.generator
    print(
        f"\nGenerator: {g.model}, {g.attempts} attempt(s), ~{g.prompt_tokens:,} prompt + "
        f"{g.completion_tokens:,} completion tokens, est. ${g.estimated_cost_usd:.2f}"
    )


def _utc_now_iso() -> str:
    """The one place `rhino adapt confirm` reads the clock. `config_io.py`'s
    module docstring reserves this for the CLI on purpose ("The caller (a
    later slice's CLI) is where 'now' and 'who' actually get read"), so
    `adapters/review.py` stays clock-free and testable with a literal."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _print_review_header(outcome: ReviewOutcome, data_dir: Path) -> None:
    contract = outcome.contract
    print(f"Reviewing {contract.format!r} v{contract.version} ({outcome.path})")
    print(f"  source: {data_dir}")


def _print_measurement(m: Measurement) -> None:
    """What the mapping actually did, first -- before any of the contract's
    own claims about itself. A reviewer should form an impression from
    measurements, not from assurances."""
    print("\nMeasurement -- the real mapping, over the real files:")
    collapsed_a = f", {m.duplicate_assets_collapsed} repeated row(s) collapsed" if m.duplicate_assets_collapsed else ""
    collapsed_f = f", {m.duplicate_findings_collapsed} duplicate row(s) collapsed" if m.duplicate_findings_collapsed else ""
    print(f"  assets    {m.assets_loaded} loaded{collapsed_a}")
    print(f"  findings  {m.findings_loaded} loaded{collapsed_f}")
    if m.excluded_assets or m.excluded_findings:
        print(f"  excluded  {len(m.excluded_assets)} asset(s), {len(m.excluded_findings)} finding(s)")
        for asset_id, reason in sorted(m.excluded_assets.items()):
            print(_wrap(f"{asset_id}: {reason}", indent="    - ", continuation_indent="      "))
        for finding_id, reason in sorted(m.excluded_findings.items()):
            print(_wrap(f"{finding_id}: {reason}", indent="    - ", continuation_indent="      "))
    for notice in m.header_notices:
        print(_wrap(f"header: {notice}", indent="  ! ", continuation_indent="    "))


def _print_value_distribution(m: Measurement) -> None:
    """The values the mapping actually produced for the enumerated scoring
    inputs, beside how many of them are documented defaults rather than
    facts from the export. This is the line a claim-only review cannot
    produce: a mapping can run perfectly clean while every Impact input is
    fabricated, and that is exactly what this shows."""
    if not m.value_distribution:
        return
    print("\nValues produced for the scoring inputs (Impact axis):")
    rows = []
    for target, counts in m.value_distribution.items():
        head = list(counts.items())[:4]
        shown = ", ".join(f"{value} x{count}" for value, count in head)
        if len(counts) > len(head):
            shown += f", +{len(counts) - len(head)} more"
        gap = m.asset_gaps.get(target, 0)
        note = f"{gap}/{m.assets_loaded} not collected -- documented default" if gap else ""
        rows.append((target, shown, note))
    _print_rows(("field", "values produced", "provenance"), rows)


def _print_gaps(m: Measurement) -> None:
    if not m.asset_gaps and not m.finding_gaps:
        return
    print("\nFields no record carries (adapters/base.py's NOT_COLLECTED_DEFAULTS are in effect):")
    for kind, total, gaps in (("assets", m.assets_loaded, m.asset_gaps), ("findings", m.findings_loaded, m.finding_gaps)):
        by_count: dict[int, list[str]] = {}
        for name, count in gaps.items():
            by_count.setdefault(count, []).append(name)
        for count in sorted(by_count, reverse=True):
            label = f"  {kind:<8} {count}/{total}  "
            print(_wrap(", ".join(sorted(by_count[count])), indent=label, continuation_indent=" " * len(label)))


def _print_unmapped_profiles(m: Measurement) -> None:
    """Each column the contract declares it deliberately does not read, with
    its stated reason and its MEASURED shape side by side. `unmapped_columns`
    is a signed claim that nothing otherwise checks -- this is where a
    dismissed column that actually carries a patch window becomes visible."""
    if not m.unmapped_profiles:
        return
    print("\nColumns this contract declares it does not read:")
    by_file: dict[str, list[tuple[str, dict]]] = {}
    for key, p in sorted(m.unmapped_profiles.items()):
        filename, column = key.split(":", 1)
        by_file.setdefault(filename, []).append((column, p))
    for filename, entries in by_file.items():
        # Grouped by file, because the same column name can legitimately
        # appear in both of a two-file source (a denormalised copy) with a
        # different stated reason on each side.
        print(f"  {filename}")
        for column, p in entries:
            print(_wrap(f"[{p['disposition']}] {p['reason']}", indent=f"    {column}: ", continuation_indent="        "))
            looks = ", ".join(p["looks_like"]) or "--"
            samples = ", ".join(str(s)[:26] for s in p["samples"]) or "--"
            print(f"        measured: {p['blank']}/{p['rows']} blank, {p['distinct']} distinct, {looks}; e.g. {samples}"[:100])


def _print_contract_state(outcome: ReviewOutcome) -> None:
    drift, contract = outcome.drift, outcome.contract
    print("\nContract state:")
    if not drift.was_confirmed:
        print(f"  never confirmed (review.state={drift.state!r}) -- nothing to compare against yet")
    else:
        print(f"  confirmed {contract.review.confirmed_at} by {contract.review.confirmed_by}")
        if drift.content_matches and drift.decision_matches:
            print("  digests match -- the file has not been edited since it was signed")
        else:
            if not drift.decision_matches:
                print("  a MAPPING DECISION has changed since this was signed")
            elif not drift.content_matches:
                print("  edited since signing, but outside the mapping decisions (observed/provenance only)")
    slots = drift.slots
    if not slots.available:
        if drift.was_confirmed:
            print(
                _wrap(
                    "this contract recorded no slot_digests at confirmation time, so a re-review cannot "
                    "be proportional -- every slot is in scope. Re-confirming records them, so a "
                    "contract passes through this fallback at most once.",
                    indent="  ! ",
                    continuation_indent="    ",
                )
            )
    else:
        print(f"  slots: {len(slots.unchanged)} unchanged, {len(slots.changed)} changed, "
              f"{len(slots.new)} new, {len(slots.orphaned)} orphaned")
        for name in slots.moved:
            # `slot_digests` lives under `review`, which sits outside both
            # digests -- its keys are unsigned, so a hand-edited file can carry
            # a name in any shape. A printer must not raise on one.
            block, _dot, target = name.partition(".")
            node = (
                outcome.contract.asset.get(target)
                if block == "asset"
                else outcome.contract.finding.get(target) if block == "finding" else None
            )
            rendered = json.dumps(node.model_dump(mode="json", by_alias=True), sort_keys=True) if node else "(removed)"
            print(_wrap(f"{name} -> {rendered}", indent="    NEEDS REVIEW ", continuation_indent="      "))
        if slots.moved:
            print(_wrap(
                "a digest cannot reconstruct what it hashed -- the previous mapping for these is in "
                "git (`git show HEAD:<path>`), not here.", indent="    ", continuation_indent="    "))


def _print_attestations(outcome: ReviewOutcome) -> None:
    print("\nAttestations:")
    for item, reason in sorted(outcome.required.items()):
        print(_wrap(f"{item} -- required because {reason}", indent="  required: ", continuation_indent="    "))
    if not outcome.required:
        print("  none required by this contract's shape or this measurement")
    if outcome.still_missing:
        print(
            _wrap(
                f"MISSING {outcome.still_missing} -- `rhino adapt confirm` will refuse until each is "
                "supplied with --attest ITEM=\"...\". A requirement can appear without the contract "
                "changing at all: the source started excluding records.",
                indent="  ! ",
                continuation_indent="    ",
            )
        )
    for reason in outcome.attestations_dropped:
        print(_wrap(f"no longer carries forward -- {reason}", indent="  - ", continuation_indent="    "))
    for previous, new in outcome.attestations_replaced:
        print(_wrap(f"{new.item}: replacing the text recorded at {previous.at}", indent="  ! ", continuation_indent="    "))
    for attestation in outcome.attestations_added:
        print(_wrap(f"{attestation.item}: {attestation.text}", indent="  + ", continuation_indent="    "))


def _print_review_problems(m: Measurement) -> None:
    if m.fatal_problems:
        print(f"\n{len(m.fatal_problems)} problem(s) the mapping hit on this source:", file=sys.stderr)
        for message in m.fatal_problems:
            print(_wrap(message, indent="  - ", continuation_indent="    "), file=sys.stderr)
    if m.halted_by is not None:
        print(_wrap(
            f"the pass stopped here: {m.halted_by}", indent="\n  HALTED: ", continuation_indent="    "
        ), file=sys.stderr)


def _print_review(outcome: ReviewOutcome, data_dir: Path, *, verb: str) -> None:
    _print_review_header(outcome, data_dir)
    _print_measurement(outcome.measurement)
    _print_value_distribution(outcome.measurement)
    _print_gaps(outcome.measurement)
    _print_unmapped_profiles(outcome.measurement)
    _print_contract_state(outcome)
    _print_attestations(outcome)
    _print_review_problems(outcome.measurement)
    if outcome.written and outcome.signed is not None:
        review_block = outcome.signed.review
        print(
            f"\nSigned: {outcome.signed.format!r} v{outcome.signed.version} confirmed "
            f"{review_block.confirmed_at} by {review_block.confirmed_by}, "
            f"{len(review_block.slot_digests or {})} slot digest(s) recorded."
        )
        print(f"Wrote {outcome.path}")
        return
    if outcome.refusals:
        print(f"\n{verb} refused -- nothing was written:", file=sys.stderr)
        for refusal in outcome.refusals:
            print(_wrap(refusal, indent="  - ", continuation_indent="    "), file=sys.stderr)
        return
    if verb == "rereview":
        # Same property the exit code uses, so the line and the status can
        # never disagree -- see ReviewOutcome.rereview_clean.
        print(
            "\nNo drift and no problems."
            if outcome.rereview_clean
            else "\nReviewed. See above; nothing was written."
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
    run_format_group = run_parser.add_mutually_exclusive_group()
    run_format_group.add_argument(
        "--format",
        default=DEFAULT_FORMAT,
        choices=sorted(FORMATS),
        help=(
            "ingest adapter for --data's files (adapters/): native reads assets.csv + findings.csv; "
            "defender reads Microsoft Defender Vulnerability Management exports devices.csv "
            "(DeviceInfo) + vulnerabilities.csv (DeviceTvmSoftwareVulnerabilities); bluepeak reads a "
            "single pre-enriched synthetic_cve_inventory_50.csv, trusting its own CVSS/exploitation/"
            "ATT&CK fields instead of fetching (adapters/bluepeak.py)"
        ),
    )
    run_format_group.add_argument(
        "--adapter-config",
        default=None,
        metavar="NAME_OR_PATH",
        help=(
            "use a declarative, human-reviewed ingest contract instead of a built-in --format -- "
            "a bare name resolves to data/adapters/<name>.json, or pass a path directly. The "
            "contract must already be confirmed (adapters/config_io.py); mutually exclusive with "
            "--format"
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
    constraint_format_group = constraint_add_parser.add_mutually_exclusive_group()
    constraint_format_group.add_argument(
        "--format",
        default=DEFAULT_FORMAT,
        choices=sorted(FORMATS),
        help=(
            "ingest adapter for --data's files, same as `rhino run --format`. A real scanner "
            "export carries no patch window, compensating control, or role, so this is the "
            "command that supplies them"
        ),
    )
    constraint_format_group.add_argument(
        "--adapter-config",
        default=None,
        metavar="NAME_OR_PATH",
        help="use a declarative ingest contract instead of a built-in --format, same as `rhino run --adapter-config`",
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
    web_parser.add_argument(
        "--enable-jobs",
        action="store_true",
        help=(
            "opt-in write mode: mount POST /api/jobs so the browser can submit a constraint as a "
            "background job (agents/coordinator.py's submit_constraint, the same operation `rhino "
            "constraint add` runs). Off by default -- without this flag the server is byte-for-byte "
            "the read-only viewer described above, with zero import of rhinosecure.agents/memory/"
            "crewai. The flags below are only meaningful together with this one."
        ),
    )
    web_parser.add_argument(
        "--data", default="demo", help="dataset the job substrate reasons about (only with --enable-jobs)"
    )
    web_parser.add_argument("--seed", type=int, default=42, help="only meaningful with --enable-jobs")
    web_parser.add_argument(
        "--offline",
        action="store_true",
        help="forbid network fetches while seeding the job substrate's plan (only with --enable-jobs)",
    )
    web_parser.add_argument(
        "--db",
        default=None,
        help="path to the memory.py SQLite file for the job substrate (default: memory.DEFAULT_DB_PATH); "
        "only meaningful with --enable-jobs",
    )
    web_format_group = web_parser.add_mutually_exclusive_group()
    web_format_group.add_argument(
        "--format",
        default=DEFAULT_FORMAT,
        choices=sorted(FORMATS),
        help="ingest adapter for --data, same as `rhino run --format` (only with --enable-jobs)",
    )
    web_format_group.add_argument(
        "--adapter-config",
        default=None,
        metavar="NAME_OR_PATH",
        help="use a declarative ingest contract instead of a built-in --format (only with --enable-jobs)",
    )
    web_parser.add_argument(
        "--enable-chat",
        action="store_true",
        help=(
            "opt-in: mount POST /api/chat, a read-only, LLM-backed Q&A over the currently-served "
            "export file (agents/chat.py). Off by default -- without this flag the server never "
            "imports rhinosecure.agents.chat or crewai for this purpose. Independent of "
            "--enable-jobs: chat never writes to memory.py or re-plans anything, so it needs "
            "neither --data/--format/--seed/--db nor the job substrate's single-job-at-a-time "
            "lock -- every request just reads the export file already being served."
        ),
    )

    adapt_parser = subparsers.add_parser(
        "adapt", help="tools for building a declarative ingest contract for a new source (docs/adapter-generation.md)"
    )
    adapt_subparsers = adapt_parser.add_subparsers(dest="adapt_command", required=True)
    adapt_subparsers.add_parser("list", help="list data/ subdirectories that look like candidate sources to probe")
    adapt_probe_parser = adapt_subparsers.add_parser(
        "probe", help="profile every .csv file in a source, column by column -- no LLM, no key, writes nothing"
    )
    adapt_probe_parser.add_argument("name", help="dataset name under data/, or a path (same resolution as --data)")

    adapt_propose_parser = adapt_subparsers.add_parser(
        "propose",
        help="LLM-assisted: draft a candidate ingest contract for a new source (docs/adapter-generation.md Slice 8)",
    )
    adapt_propose_parser.add_argument(
        "name", help="the new contract's format name -- resolves the output to data/adapters/<name>.json"
    )
    adapt_propose_parser.add_argument(
        "--data", required=True, help="dataset name under data/, or a path, to profile and propose a mapping for"
    )
    adapt_propose_parser.add_argument(
        "--assets-file", default=None, metavar="NAME",
        help="which file is the asset side, when --data has more than one .csv (required together with --findings-file in that case)",
    )
    adapt_propose_parser.add_argument(
        "--findings-file", default=None, metavar="NAME",
        help="which file is the finding side, when --data has more than one .csv (required together with --assets-file in that case)",
    )
    adapt_propose_parser.add_argument(
        "--max-attempts", type=int, default=3,
        help="re-dispatch the model this many times if its output doesn't parse or disagrees with the requested facts (default: 3)",
    )
    adapt_propose_parser.add_argument(
        "--sample-rows", type=int, default=20,
        help="literal example rows shown to the model on top of the full-file column profile (default: 20)",
    )
    adapt_propose_parser.add_argument(
        "--from-proposal", default=None, metavar="PATH",
        help="skip the LLM call; re-run grounding and assembly on an already-produced (optionally hand-corrected) saved proposal file",
    )
    adapt_propose_parser.add_argument(
        "--report-out", default=None, metavar="PATH", help="also save the human-readable report here (always prints to stdout too)"
    )
    adapt_propose_parser.add_argument(
        "--overwrite-confirmed", action="store_true",
        help="required to re-run propose over a name whose data/adapters/<name>.json already holds a CONFIRMED contract",
    )

    adapt_confirm_parser = adapt_subparsers.add_parser(
        "confirm", help="measure a contract against real files, then sign it -- the only verb that writes"
    )
    adapt_rereview_parser = adapt_subparsers.add_parser(
        "rereview", help="measure a confirmed contract and report what has moved since it was signed; writes nothing"
    )
    for sub in (adapt_confirm_parser, adapt_rereview_parser):
        sub.add_argument(
            "config",
            metavar="NAME_OR_PATH",
            help="contract name (resolves to data/adapters/<name>.json) or a path to one",
        )
        sub.add_argument(
            "--data",
            required=True,
            help=(
                "dataset name under data/, or a path, to measure the mapping against. Required and "
                "never defaulted: a signature covers specific bytes, and it cannot inherit which ones"
            ),
        )
        sub.add_argument(
            "--attest",
            action="append",
            metavar="ITEM=TEXT",
            default=[],
            help=(
                "supply an attestation, repeatable. Nothing is auto-generated -- the value of the "
                "item is that a person wrote the sentence"
            ),
        )
    adapt_confirm_parser.add_argument(
        "--by",
        required=True,
        metavar="IDENTITY",
        help=(
            "who is signing. Required, and never inferred from $USER or git config: an inferred "
            "signature is a fabricated one"
        ),
    )
    adapt_confirm_parser.add_argument(
        "--reconfirm",
        action="store_true",
        help="required to re-sign a contract that is already confirmed, replacing that signature",
    )
    adapt_confirm_parser.add_argument(
        "--reset-identity",
        action="store_true",
        help=(
            "required to re-sign when finding.finding_id's recipe has changed -- it re-keys every "
            "decision memory.decisions has recorded for this format"
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
                coordinator = run_agents(
                    data_dir,
                    args.seed,
                    offline=args.offline,
                    db_path=args.db,
                    fmt=args.format,
                    adapter_config=args.adapter_config,
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

            _print_adapter_config_banner(coordinator.contract)
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
                        fmt=coordinator.contract.format if coordinator.contract else coordinator.ingest_format,
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
            result = run_with_report(
                data_dir, args.seed, offline=args.offline, fmt=args.format, adapter_config=args.adapter_config
            )
        except IngestError as exc:
            print(f"ingest error: {exc}", file=sys.stderr)
            return 1
        except OfflineCacheMissError as exc:
            print(f"offline error: {exc}", file=sys.stderr)
            return 1

        scored = result.scored
        _print_adapter_config_banner(result.contract, result.report)
        _print_exclusions(result.report)
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
                    fmt=result.report.format,
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
                args.text,
                data_dir,
                args.seed,
                offline=args.offline,
                db_path=args.db,
                fmt=args.format,
                adapter_config=args.adapter_config,
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

        job_config = None
        db_path = None
        if args.enable_jobs:
            from rhinosecure.memory import DEFAULT_DB_PATH
            from rhinosecure.web.jobs import JobConfig

            db_path = Path(args.db) if args.db else DEFAULT_DB_PATH
            job_config = JobConfig(
                data_dir=_resolve_data_dir(args.data),
                fmt=args.format,
                adapter_config=args.adapter_config,
                seed=args.seed,
                offline=args.offline,
                db_path=db_path,
            )

        app = create_app(
            args.export,
            jobs_enabled=args.enable_jobs,
            job_config=job_config,
            chat_enabled=args.enable_chat,
        )
        resolved = app.state.export_path
        if not resolved.exists():
            print(f"warning: export file does not exist yet: {resolved}", file=sys.stderr)
        print(f"RhinoSecure web viewer -- serving {resolved}")
        if args.enable_jobs:
            print(
                f"  write mode enabled -- jobs will run agent code (dataset: {job_config.data_dir}, "
                f"format: {job_config.fmt}) and persist to {db_path}"
            )
        if args.enable_chat:
            print("  chat enabled -- POST /api/chat calls the LLM seam per question (reads only, no writes)")
        print(f"  http://{args.host}:{args.port}/")
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    if args.command == "adapt" and args.adapt_command == "list":
        _print_adapt_list(_discover_probe_sources())
        return 0

    if args.command == "adapt" and args.adapt_command == "probe":
        data_dir = _resolve_data_dir(args.name)
        try:
            profiles = profile_source(data_dir)
        except ProbeError as exc:
            print(f"probe error: {exc}", file=sys.stderr)
            return 1
        _print_probe_report(data_dir, profiles)
        return 0

    if args.command == "adapt" and args.adapt_command == "propose":
        import contextlib
        import io

        from pydantic import ValidationError

        from rhinosecure.adapters.config_io import ContractIOError, read_contract, write_contract
        from rhinosecure.llm import LLMConfigError

        try:
            from rhinosecure.agents.schema_inference import (
                ProposalGenerationError,
                SavedProposal,
                SchemaInferenceError,
                dump_saved_proposal,
                load_saved_proposal,
                propose_contract,
            )
        except ImportError as exc:  # crewai only imports on the .venv312 interpreter -- CLAUDE.md Section 11
            print(f"propose error: this command needs the crewai-capable interpreter -- {exc}", file=sys.stderr)
            return 1

        data_dir = _resolve_data_dir(args.data)
        output_path = resolve_config_path(args.name)

        if output_path.exists() and not args.overwrite_confirmed:
            try:
                existing = read_contract(output_path)
            except (ContractIOError, IngestError, ValidationError):
                existing = None
            if existing is not None and existing.review.state == "confirmed":
                print(
                    f"propose refused: {output_path} already holds a CONFIRMED contract (signed "
                    f"{existing.review.confirmed_at} by {existing.review.confirmed_by}). Re-running propose "
                    "would silently overwrite that signature. Pass --overwrite-confirmed if you really mean "
                    "to replace it.",
                    file=sys.stderr,
                )
                return 1

        from_proposal = None
        if args.from_proposal:
            try:
                from_proposal = load_saved_proposal(Path(args.from_proposal))
            except SchemaInferenceError as exc:
                print(f"propose error: {exc}", file=sys.stderr)
                return 1

        try:
            result = propose_contract(
                data_dir,
                args.name,
                generated_at=_utc_now_iso(),
                assets_filename=args.assets_file,
                findings_filename=args.findings_file,
                max_attempts=args.max_attempts,
                sample_rows=args.sample_rows,
                from_proposal=from_proposal,
            )
        except ProbeError as exc:
            print(f"probe error: {exc}", file=sys.stderr)
            return 1
        except (SchemaInferenceError, ProposalGenerationError) as exc:
            print(f"propose error: {exc}", file=sys.stderr)
            return 1
        except LLMConfigError as exc:
            print(f"LLM config error: {exc}", file=sys.stderr)
            return 1

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_propose_report(data_dir, args.name, result)
        report_text = buf.getvalue()
        print(report_text, end="")
        if args.report_out:
            Path(args.report_out).write_text(report_text, encoding="utf-8")

        saved_path = REPO_ROOT / "out" / f"propose_{args.name}.json"
        saved_path.parent.mkdir(parents=True, exist_ok=True)
        saved_path.write_text(
            json.dumps(dump_saved_proposal(SavedProposal(result.proposal, result.generator)), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"Proposal saved to {saved_path} -- hand-correct it and re-run with --from-proposal if incomplete.")

        if result.contract is None:
            return 1

        written = write_contract(output_path, result.contract)
        print(f"Wrote {output_path} (v{written.version}, review.state=proposed).")
        print(f'Next: rhino adapt confirm {args.name} --data {args.data} --by "<you>"')
        return 0

    if args.command == "adapt" and args.adapt_command in ("confirm", "rereview"):
        from pydantic import ValidationError

        from rhinosecure.adapters.config_io import read_contract

        sign = args.adapt_command == "confirm"
        data_dir = _resolve_data_dir(args.data)
        config_path = resolve_config_path(args.config)
        try:
            contract = read_contract(config_path)
        except IngestError as exc:  # ContractIOError, an AdapterError, an IngestError
            print(f"contract error: {exc}", file=sys.stderr)
            return 1
        except ValidationError as exc:
            print(f"contract error: {config_path}: not a valid adapter config -- {exc}", file=sys.stderr)
            return 1

        try:
            outcome = review_contract(
                config_path,
                contract,
                data_dir,
                at=_utc_now_iso(),
                by=args.by if sign else None,
                attest=args.attest,
                sign=sign,
                reconfirm=getattr(args, "reconfirm", False),
                reset_identity=getattr(args, "reset_identity", False),
            )
        except ReviewError as exc:
            print(f"{args.adapt_command} refused: {exc}", file=sys.stderr)
            return 1
        except IngestError as exc:
            print(f"contract error: {exc}", file=sys.stderr)
            return 1

        _print_review(outcome, data_dir, verb=args.adapt_command)
        if sign:
            return 0 if outcome.written else 1
        return 0 if outcome.rereview_clean else 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
