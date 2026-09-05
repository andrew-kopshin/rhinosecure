"""Serialize one `rhino run` (deterministic or `--agents`) to a single JSON
file for the read-only web UI described alongside this module -- CLAUDE.md
Section 4's "every retrieved record carries a source and timestamp" and
Section 8's "cost/usage visibility" open item, made consumable outside the
terminal.

**Additive only.** This module reads `cli.RunResult` / `Coordinator.state` /
`Memory` after the fact -- it calls no new scoring, no new LLM, and mutates
nothing. `scoring.score_finding` is reused (never reimplemented) for the one
place a fresh number is actually computed: an asset-scoped constraint's
"before" score, exactly the same call `agents/coordinator.py`'s own
`submit_constraint` already makes for its diff. `scoring.py` stays the sole
owner of risk arithmetic, same as everywhere else in this codebase.

**Two independent shapes, one schema.** `write_run_export(agents=False,
result=...)` reads the plain `cli.RunResult`; `write_run_export(agents=True,
coordinator=...)` reads a `Coordinator` after `run()`/`replan()`. Fields that
only exist on one path (`threat_score`/`impact_score` on the deterministic
side; `verdict_summary`/`narrative`/`constraints_applied`/`cited_text`/ToT
results on the agents side) are `null`/`[]` on the other -- never fabricated,
never silently omitted, so a frontend built against one path's file never
has to guess whether a missing key means "empty" or "doesn't apply here."

**Why this needs `from __future__ import annotations` and a `TYPE_CHECKING`
guard for `Coordinator`, but imports `rhinosecure.memory`/`rhinosecure.cli`
directly.** `agents.coordinator` imports `crewai` at module level, which
does not import on Python 3.14 (CLAUDE.md Section 11) -- the same reason
`cli.py` itself defers that import to inside `run_agents()`/`main()`'s
`--agents` branch (see `cli.py`'s own module docstring). `Coordinator` is
therefore a type-only import here, real only under `TYPE_CHECKING`, the same
seam `ingest.py` already uses for `adapters.base.IngestAdapter`. `cli.py` and
`memory.py` carry no such constraint (neither imports `crewai` at module
level), so both import normally -- `write_run_export` runs on the
deterministic-only path too, and that path must keep working wherever the
rest of the deterministic pipeline does.

**Known, stated limitations, not silent gaps:**

- **Agents-path duplicate-row counts are unavailable.** `IngestReport.
  duplicate_assets_collapsed`/`duplicate_findings_collapsed` come from the
  `IngestAdapter.stats` object `ingest.load_batch` fills in as it streams --
  but `Coordinator` never retains the adapter instance that produced its
  inventory (`cli.run_agents()` builds one, hands `load_batch` its data, and
  lets it fall out of scope). `_build_agents_ingest_report` below rebuilds
  everything else `IngestReport` needs (per-field `not_collected` gap
  counts) from `Coordinator.state`/`_asset_index` directly, but has no way
  to recover a duplicate count that was never persisted anywhere -- so both
  fields read `0` on the agents path's `pipeline.ingest`/`summary.data_gaps`
  regardless of what was actually collapsed at ingest time. The deterministic
  path does not have this gap: `RunResult.report` already carries the real
  counts straight from `run_with_report`.
- **A failed ToT search's per-finding token spend is not attached to its
  `contested[]` entry.** `RunState.tot_failures` stores only the failure's
  string message (`agents/coordinator.py`'s `_dispatch_tot`) -- the
  `ToTDispatchError.usage` that message was built from is not itself
  retained anywhere `Coordinator` keeps around after the fact. A failed
  contested finding's `usage` field is therefore `null`, never a fabricated
  number; its real spend is still visible in the fleet-wide `usage.tot`
  total (`RunState.tot_usage`, which *does* fold in every failure's partial
  spend -- see `tot.py`'s and `_dispatch_tot`'s own docstrings), just not
  attributable to that one finding alone.
- **`memory=None` means an empty constraints section**, `{"asset_scoped":
  [], "capacity": []}` -- not an error. A caller that wants the constraints
  section populated must pass a real `Memory`; `cli.py` always does when
  `--export` is given (opening one read-only, at `--db` or the default
  path, is itself a new *first use* of `--db` on the deterministic branch --
  see that module's docstring -- but `Memory.__init__`'s `CREATE TABLE IF
  NOT EXISTS`/migration is idempotent and side-effect-free to open, per
  `memory.py`'s own docstring).

**Atomic write.** `_write_json_atomic` writes to a `.tmp` sibling and
`Path.replace`s it into place -- the same durability idiom `enrich/cache.py`'s
`SnapshotCache.write` already uses in this codebase, so a crash mid-write
never leaves a truncated export file for the server half of this feature to
choke on. Any `OSError` (bad path, permission failure, a path component that
is actually a file) propagates to the caller uncaught -- `cli.py` catches it
around each `write_run_export` call site and reports it after the run's own
console output has already printed, never hiding a successful run behind a
broken `--export` path.
"""

from __future__ import annotations

import json
import os
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.ingest import GapTally, IngestReport, IngestStats
from rhinosecure.memory import Memory
from rhinosecure.scoring import Bucket, contested_rate, score_finding

if TYPE_CHECKING:
    from rhinosecure.agents.coordinator import Coordinator
    from rhinosecure.cli import RunResult

EXPORT_SCHEMA_VERSION = "1.0.0"

# memory.list_runs()/Memory has no list_capacity_constraints()/all_runs()
# without a run_id -- reconstructing constraints.capacity (always
# historical, see _capacity_history) means paging through runs newest-first
# and stopping somewhere. This is that stated, real limit, not an unbounded
# scan; see this module's own docstring and _capacity_history below.
CAPACITY_HISTORY_RUN_LIMIT = 500


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _usage_dict(usage: Any) -> dict[str, Any] | None:
    return None if usage is None else usage.model_dump()


def _dedup_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _ingest_report_dict(report: IngestReport) -> dict[str, Any]:
    return {
        "format": report.format,
        "assets_total": report.assets_total,
        "findings_total": report.findings_total,
        "duplicate_assets_collapsed": report.duplicate_assets_collapsed,
        "duplicate_findings_collapsed": report.duplicate_findings_collapsed,
        "asset_gaps": dict(report.asset_gaps),
        "finding_gaps": dict(report.finding_gaps),
        # Scope-boundary exclusions (adapters/base.py's ProblemCollector
        # .exclude), not data-quality problems -- id -> reason, mirroring
        # cli.py's _print_exclusions so the web viewer can show the same
        # "excluded, and why" a terminal run already does, rather than
        # silently reporting a smaller-than-expected fleet with no
        # explanation.
        "excluded_assets": dict(report.excluded_assets),
        "excluded_findings": dict(report.excluded_findings),
    }


def _ingest_detail(report: IngestReport, fmt: str) -> str:
    total_dupes = report.duplicate_assets_collapsed + report.duplicate_findings_collapsed
    total_excluded = len(report.excluded_assets) + len(report.excluded_findings)
    excluded_note = f"; {total_excluded} record(s) excluded (scope boundary)" if total_excluded else ""
    return (
        f"{report.assets_total} asset(s), {report.findings_total} finding(s) loaded via "
        f"--format {fmt}; {total_dupes} duplicate row(s) collapsed{excluded_note}"
    )


def _bucket_distribution(buckets: list[str]) -> dict[str, int]:
    counts = Counter(buckets)
    return {b.value: counts.get(b.value, 0) for b in Bucket}


def _sources_for_cve(cache: SnapshotCache, cve_id: str) -> list[dict[str, Any]]:
    """Structured, source-plus-timestamp evidence for one CVE -- CLAUDE.md
    Section 4's own requirement, satisfied by re-reading the already-
    populated `SnapshotCache` (no new fetch: every one of these entries
    necessarily already exists, since scoring itself required the lookup to
    succeed). Identical on both paths -- `cache` differs (a fresh instance
    pointed at the default snapshot directory for the deterministic path,
    the real `Coordinator.cache` for the agents path) but the read
    mechanics do not."""
    entries: list[dict[str, Any]] = []
    nvd = cache.read("nvd", cve_id)
    if nvd is not None:
        entries.append({"source": "nvd", "key": cve_id, "retrieved_at": nvd.retrieved_at})
    kev = cache.read("kev", None)
    if kev is not None:
        entries.append({"source": "kev", "key": None, "retrieved_at": kev.retrieved_at})
    epss = cache.read("epss", cve_id)
    if epss is not None:
        entries.append({"source": "epss", "key": cve_id, "retrieved_at": epss.retrieved_at})
    attack = cache.read("attack", "enterprise-windows")
    if attack is not None:
        entries.append({"source": "attack", "key": "enterprise-windows", "retrieved_at": attack.retrieved_at})
    return entries


def _det_finding_entry(
    scored: Any,
    cache: SnapshotCache,
    assets: dict[str, Any],
    not_collected_by_finding: dict[str, frozenset[str]],
    contested_ids: set[str],
) -> dict[str, Any]:
    asset = assets[scored.asset_id]
    return {
        "finding_id": scored.finding_id,
        "cve_id": scored.cve_id,
        "asset_id": scored.asset_id,
        "hostname": scored.hostname,
        "bucket": scored.bucket.value,
        "risk_score": scored.risk_score,
        "threat_score": scored.threat_score,
        "impact_score": scored.impact_score,
        "rationale": list(scored.rationale),
        "verdict_summary": None,
        "narrative": None,
        "constraints_applied": [],
        "cited_text": [],
        "sources": _sources_for_cve(cache, scored.cve_id),
        "not_collected": sorted(not_collected_by_finding.get(scored.finding_id, frozenset())),
        "asset_not_collected": sorted(asset.not_collected),
        "has_tot": scored.finding_id in contested_ids,
    }


def _agents_finding_entry(
    recommendation: Any,
    cache: SnapshotCache,
    coordinator: Coordinator,
    contested_ids: set[str],
) -> dict[str, Any]:
    fid = recommendation.finding_id
    enriched = coordinator.state.enriched_by_id[fid]
    research = coordinator.state.research_by_id.get(fid)
    cited = _dedup_preserve_order([*(research.sources if research is not None else []), *recommendation.sources])
    return {
        "finding_id": fid,
        "cve_id": recommendation.cve_id,
        "asset_id": recommendation.asset_id,
        "hostname": recommendation.hostname,
        "bucket": recommendation.bucket,
        "risk_score": recommendation.risk_score,
        "threat_score": None,
        "impact_score": None,
        "rationale": list(recommendation.scoring_rationale),
        "verdict_summary": recommendation.verdict_summary,
        "narrative": recommendation.narrative,
        "constraints_applied": list(recommendation.constraints_applied),
        "cited_text": cited,
        "sources": _sources_for_cve(cache, recommendation.cve_id),
        "not_collected": sorted(enriched.finding.not_collected),
        "asset_not_collected": sorted(enriched.asset.not_collected),
        "has_tot": fid in contested_ids,
    }


def _thought_entry(thought: Any, result: Any) -> dict[str, Any]:
    is_winner = not result.near_tie and result.winner is not None and thought is result.winner
    critic = thought.critic
    return {
        "strategy": thought.strategy.value,
        "depth": thought.depth,
        "proposal": thought.proposal,
        "exhausted": thought.exhausted,
        "exhaustion_reason": thought.exhaustion_reason,
        "critic_scores": {
            "risk_reduction": critic.risk_reduction,
            "operational_cost": critic.operational_cost,
            "constraint_compliance": critic.constraint_compliance,
            "evidence_strength": critic.evidence_strength,
            "contradicting_evidence": critic.contradicting_evidence,
            "justification": critic.justification,
        },
        "aggregate_score": thought.score,
        "is_winner": is_winner,
    }


def _contested_entry(fid: str, state: Any) -> dict[str, Any]:
    """One `contested[]` element for `fid`, which must be a key of
    `state.tot_by_id` or `state.tot_failures` (never both, never neither --
    `_dispatch_tot` writes exactly one of the two per contested finding).
    `state.risk_by_id[fid]` is always present for either case: ToT is only
    ever dispatched for a finding whose Risk stage just succeeded with
    bucket="contested" (`_dispatch_tot`'s own gate), so cve_id/hostname are
    always real, sourced facts, never guessed."""
    rec = state.risk_by_id[fid]
    if fid in state.tot_by_id:
        result = state.tot_by_id[fid]
        return {
            "finding_id": fid,
            "cve_id": rec.cve_id,
            "hostname": rec.hostname,
            "status": "resolved",
            "failure_reason": None,
            "termination_reason": result.termination_reason,
            "depth_reached": result.depth_reached,
            "near_tie": result.near_tie,
            "winner_strategy": None if result.near_tie else result.winner.strategy.value,
            "branches": [_thought_entry(t, result) for t in result.candidates],
            "usage": result.usage.model_dump(),
        }
    return {
        "finding_id": fid,
        "cve_id": rec.cve_id,
        "hostname": rec.hostname,
        "status": "failed",
        "failure_reason": state.tot_failures[fid],
        "termination_reason": None,
        "depth_reached": None,
        "near_tie": None,
        "winner_strategy": None,
        "branches": [],
        # Known limitation -- see module docstring: the per-finding spend
        # behind this failure is not retained on RunState, only the
        # fleet-wide tot_usage total is. Never fabricated here.
        "usage": None,
    }


def _asset_constraint_deltas(coordinator: Coordinator, asset_id: str) -> list[dict[str, Any]]:
    """Live, in-process recomputation of one asset-scoped constraint's
    real effect on this run's own findings -- reuses
    `agents.coordinator._build_finding_delta` and
    `agents.risk.merge_research_into_enriched` directly (the exact
    functions `Coordinator.submit_constraint` already uses for its own
    diff) rather than reimplementing the comparison. Imported lazily: both
    live in modules that import `crewai` at module level, and this
    function only ever runs once a real `Coordinator` already exists (the
    agents path), so the import is safe here but must not leak onto the
    deterministic-only call path that never reaches this function at all.
    """
    from rhinosecure.agents.coordinator import _build_finding_delta
    from rhinosecure.agents.risk import merge_research_into_enriched

    state = coordinator.state
    deltas: list[dict[str, Any]] = []
    for fid, enriched in state.enriched_by_id.items():
        if enriched.asset.asset_id != asset_id:
            continue
        after = state.risk_by_id.get(fid)
        research = state.research_by_id.get(fid)
        if after is None or research is None:
            continue  # this finding failed upstream in the current run -- nothing to diff
        before = score_finding(merge_research_into_enriched(enriched, research))
        delta = _build_finding_delta(before, after)
        deltas.append(
            {
                "finding_id": delta.finding_id,
                "cve_id": delta.cve_id,
                "hostname": delta.hostname,
                "before_bucket": delta.before_bucket,
                "after_bucket": delta.after_bucket,
                "before_risk_score": delta.before_risk_score,
                "after_risk_score": delta.after_risk_score,
                "rationale_added": list(delta.rationale_added),
                "rationale_removed": list(delta.rationale_removed),
                "after_verdict_summary": delta.after_verdict_summary,
                "changed": delta.changed,
            }
        )
    return deltas


_DETERMINISTIC_NOTE = (
    "constraints are not applied on the deterministic path (memory.py is never touched there) -- "
    "run rhino run --agents to see live effect"
)
_NO_FINDINGS_NOTE = "no findings for this asset in the current dataset"


def _asset_scoped_constraints(
    memory: Memory, *, agents: bool, coordinator: Coordinator | None, current_asset_ids: set[str]
) -> list[dict[str, Any]]:
    entries = []
    for c in memory.all_active_constraints():
        applies = c.asset_id in current_asset_ids
        deltas: list[dict[str, Any]] = []
        note: str | None
        if not agents:
            note = _DETERMINISTIC_NOTE
        elif not applies:
            note = _NO_FINDINGS_NOTE
        else:
            note = None
            deltas = _asset_constraint_deltas(coordinator, c.asset_id)
        entries.append(
            {
                "constraint_id": c.id,
                "asset_id": c.asset_id,
                "constraint_text": c.constraint_text,
                "effect_kind": c.effect_kind,
                "effect_value": c.effect_value,
                "created_at": c.created_at,
                "active": c.active,
                "applies_to_current_run": applies,
                "deltas": deltas,
                "note": note,
            }
        )
    return entries


def _capacity_history(memory: Memory, *, data_dir: Path, fmt: str) -> list[dict[str, Any]]:
    """Always reconstructed read-only from `Memory` -- no `rhino run`
    invocation (deterministic or `--agents`) ever calls
    `scoring.apply_capacity_limit`; only `rhino constraint add` does, via
    `_submit_capacity_constraint`. `original_bucket` is not a stored
    column -- `apply_capacity_limit`'s own contract guarantees every
    finding in its pool started as `Bucket.NEXT_WINDOW`, so the literal
    string is a code-guaranteed fact here, not a guess."""
    current_data_dir = str(data_dir)
    entries: list[dict[str, Any]] = []
    for run in memory.list_runs(limit=CAPACITY_HISTORY_RUN_LIMIT):
        for cc in memory.capacity_constraints_for_run(run.id):
            decisions = sorted(
                (d for d in memory.decisions_for_run(run.id) if d.capacity_rank is not None),
                key=lambda d: d.capacity_rank,
            )
            entries.append(
                {
                    "capacity_constraint_id": cc.id,
                    "run_id": cc.run_id,
                    "raw_text": cc.raw_text,
                    "patch_limit": cc.patch_limit,
                    "pool_size": cc.pool_size,
                    "deferred_count": cc.deferred_count,
                    "created_at": cc.created_at,
                    "source_run": {
                        "data_dir": run.data_dir,
                        "ingest_format": run.ingest_format,
                        "seed": run.seed,
                        "started_at": run.started_at,
                    },
                    "stale": run.data_dir != current_data_dir or run.ingest_format != fmt,
                    "deltas": [
                        {
                            "finding_id": d.finding_id,
                            "cve_id": d.cve_id,
                            "asset_id": d.asset_id,
                            "hostname": d.hostname,
                            "risk_score": d.risk_score,
                            "original_bucket": Bucket.NEXT_WINDOW.value,
                            "effective_bucket": d.bucket,
                            "rank": d.capacity_rank,
                            "pool_size": d.capacity_pool_size,
                            "limit": d.capacity_limit,
                            "fits": d.capacity_rank <= d.capacity_limit,
                        }
                        for d in decisions
                    ],
                }
            )
    return entries


def _constraints_section(
    *,
    memory: Memory | None,
    data_dir: Path,
    fmt: str,
    agents: bool,
    coordinator: Coordinator | None,
    current_asset_ids: set[str],
) -> dict[str, Any]:
    if memory is None:
        return {"asset_scoped": [], "capacity": []}
    return {
        "asset_scoped": _asset_scoped_constraints(
            memory, agents=agents, coordinator=coordinator, current_asset_ids=current_asset_ids
        ),
        "capacity": _capacity_history(memory, data_dir=data_dir, fmt=fmt),
    }


def _pipeline_common(fmt: str, report: IngestReport, offline: bool) -> dict[str, Any]:
    return {
        "ingest": {"status": "completed", "detail": _ingest_detail(report, fmt)},
        "enrichment": {
            "status": "completed",
            "detail": (
                f"KEV/EPSS/NVD/ATT&CK attached via SnapshotCache for {report.findings_total} finding(s)"
                + (", offline mode" if offline else "")
            ),
        },
    }


def _build_deterministic_export(
    *, fmt: str, data_dir: Path, seed: int, offline: bool, result: RunResult, memory: Memory | None
) -> dict[str, Any]:
    scored = result.scored
    cache = SnapshotCache()
    contested_ids: set[str] = set()  # the deterministic path never dispatches ToT

    findings = [
        _det_finding_entry(s, cache, result.assets, result.not_collected_by_finding, contested_ids)
        for s in scored
    ]
    rate = contested_rate(s.bucket.value for s in scored)

    pipeline = _pipeline_common(fmt, result.report, offline)
    pipeline["scoring"] = {
        "status": "completed",
        "detail": f"{len(scored)} finding(s) scored via scoring.score_finding (deterministic, no LLM)",
    }
    pipeline["agents"] = {"status": "not_run", "detail": "run without --agents; deterministic pipeline only"}
    pipeline["tot"] = {"status": "not_run", "detail": "agents not dispatched"}

    constraints = _constraints_section(
        memory=memory,
        data_dir=data_dir,
        fmt=fmt,
        agents=False,
        coordinator=None,
        current_asset_ids={s.asset_id for s in scored},
    )

    return {
        "export_schema_version": EXPORT_SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "run": {"data_dir": str(data_dir), "format": fmt, "seed": seed, "offline": offline, "agents": False},
        "pipeline": pipeline,
        "summary": {
            "total_findings": len(scored),
            "bucket_distribution": _bucket_distribution([s.bucket.value for s in scored]),
            "contested_rate": {"contested": rate.contested, "total": rate.total, "pct": rate.pct},
            "data_gaps": _ingest_report_dict(result.report),
        },
        "findings": findings,
        "contested": [],
        "constraints": constraints,
        "usage": {"research": None, "environment": None, "risk": None, "tot": None},
    }


def _build_agents_ingest_report(fmt: str, coordinator: Coordinator) -> IngestReport:
    """Mirrors `run_with_report`'s own construction (`ingest.GapTally` over
    every ingested finding, plus the asset inventory) against state
    `run_agents()`/`Coordinator` already loaded -- pure and side-effect-
    free, no second ingest pass. `IngestStats()` (both fields 0) stands in
    for the real adapter stats -- see this module's own docstring for why
    the real duplicate-row counts are not recoverable here."""
    tally = GapTally()
    for enriched in coordinator.state.enriched_by_id.values():
        tally.observe(enriched.finding)
    return tally.report(fmt, coordinator._asset_index, IngestStats())


def _build_agents_export(
    *, fmt: str, data_dir: Path, seed: int, offline: bool, coordinator: Coordinator, memory: Memory | None
) -> dict[str, Any]:
    state = coordinator.state
    if state is None:
        raise ValueError("write_run_export(agents=True): coordinator has not run() yet")

    recommendations = coordinator.ranked()
    cache = coordinator.cache
    total = len(state.enriched_by_id)
    contested_ids = set(state.tot_by_id) | set(state.tot_failures)

    findings = [_agents_finding_entry(r, cache, coordinator, contested_ids) for r in recommendations]
    rate = contested_rate(r.bucket for r in recommendations)
    report = _build_agents_ingest_report(fmt, coordinator)

    tot_resolved, tot_failed = len(state.tot_by_id), len(state.tot_failures)
    if tot_resolved + tot_failed == 0:
        tot_stage = {"status": "skipped", "detail": "0 contested finding(s) in this run"}
    else:
        tot_stage = {
            "status": "completed",
            "detail": f"{tot_resolved} contested finding(s) resolved, {tot_failed} failed",
        }

    pipeline = _pipeline_common(fmt, report, offline)
    pipeline["enrichment"] = {
        "status": "completed",
        "detail": (
            f"{len(state.research_by_id)}/{total} finding(s) enriched by the Vulnerability Research agent, "
            f"{len(state.research_failures)} failed"
        ),
    }
    pipeline["scoring"] = {
        "status": "completed",
        "detail": (
            f"{len(state.risk_by_id)}/{total} finding(s) scored via the score_finding tool inside "
            f"Risk & Recommendation, {len(state.risk_failures)} failed"
        ),
    }
    pipeline["agents"] = {
        "status": "completed",
        "detail": (
            f"Research -> Environment -> Risk dispatched for {total} finding(s): "
            f"{len(state.risk_by_id)} succeeded, {len(state.risk_failures)} failed"
        ),
    }
    pipeline["tot"] = tot_stage

    contested = [_contested_entry(r.finding_id, state) for r in recommendations if r.finding_id in contested_ids]

    constraints = _constraints_section(
        memory=memory,
        data_dir=data_dir,
        fmt=fmt,
        agents=True,
        coordinator=coordinator,
        current_asset_ids={e.asset.asset_id for e in state.enriched_by_id.values()},
    )

    return {
        "export_schema_version": EXPORT_SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "run": {"data_dir": str(data_dir), "format": fmt, "seed": seed, "offline": offline, "agents": True},
        "pipeline": pipeline,
        "summary": {
            "total_findings": len(recommendations),
            "bucket_distribution": _bucket_distribution([r.bucket for r in recommendations]),
            "contested_rate": {"contested": rate.contested, "total": rate.total, "pct": rate.pct},
            "data_gaps": _ingest_report_dict(report),
        },
        "findings": findings,
        "contested": contested,
        "constraints": constraints,
        "usage": {
            "research": _usage_dict(state.research_usage),
            "environment": _usage_dict(state.environment_usage),
            "risk": _usage_dict(state.risk_usage),
            "tot": _usage_dict(state.tot_usage),
        },
    }


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Writes to a PID-and-random-suffixed sibling, then `Path.replace`s
    it into place -- not a bare `<path>.tmp`. Two writers targeting the
    same `path` at once (a live `rhino web --enable-jobs` job substrate
    plus a stray `rhino run --export <same path>` from another terminal,
    say) used to be able to collide on one shared tmp name; each writer
    now gets its own, so the only remaining race is over which finished
    `Path.replace` lands last -- an ordinary last-write-wins, not
    corruption from two processes writing the same file concurrently."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")
    tmp_path.replace(path)


def write_run_export(
    path: Path,
    *,
    fmt: str,
    data_dir: Path,
    seed: int,
    offline: bool,
    agents: bool,
    result: RunResult | None = None,
    coordinator: Coordinator | None = None,
    memory: Memory | None = None,
) -> None:
    """Write one run's full report as JSON to `path` -- the export contract
    described alongside this module. `agents` selects which of `result`
    (deterministic path, `cli.RunResult`) or `coordinator` (a `Coordinator`
    that has already run) is read; the other is ignored. `memory`, if
    given, populates the `constraints` section (empty otherwise -- see
    module docstring). Raises `ValueError` if the required companion
    object for `agents` is missing, and lets any `OSError` from the actual
    file write propagate to the caller (`cli.py` maps that to exit code 1
    after the run's own console output has already printed).
    """
    if agents:
        if coordinator is None:
            raise ValueError("write_run_export(agents=True) requires coordinator=")
        payload = _build_agents_export(
            fmt=fmt, data_dir=data_dir, seed=seed, offline=offline, coordinator=coordinator, memory=memory
        )
    else:
        if result is None:
            raise ValueError("write_run_export(agents=False) requires result=")
        payload = _build_deterministic_export(
            fmt=fmt, data_dir=data_dir, seed=seed, offline=offline, result=result, memory=memory
        )

    _write_json_atomic(path, payload)
