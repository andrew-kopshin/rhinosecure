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

**1.1.0: `is_kev` and a nested `asset` summary, added for the web UI's
scenario views** (bulk selection and a coverage summary by bucket, KEV
status, exposure, and asset role -- purely a client-side consumer of this
file, no new scoring). Both are facts already computed upstream of this
module; nothing here derives them. `asset` (`role`/`internet_exposed`/
`criticality`/`environment`/`data_sensitivity`) is free on the
deterministic path -- `_det_finding_entry` already holds the full `Asset`
object for `not_collected` -- and ground truth on the agents path too
(`enriched.asset`, never `EnvironmentAssessment`'s model-reconstructed
view, same "don't trust the agent's own facts" reasoning `merge_research_
into_enriched`'s docstring already gives). `is_kev` took an actual fix:
`cli.RunResult` didn't retain it at all (see its own docstring's
`is_kev_by_finding` note) on the deterministic path, and on the agents
path `coordinator.state.enriched_by_id[fid].is_kev` is always the
pre-Research default (`False`) -- Research's tool-based KEV lookup is
merged into a scoring input on demand (`merge_research_into_enriched`),
never written back onto `state.enriched_by_id`. The real, scored value is
`research.is_kev` (identical to what `merge_research_into_enriched` would
produce, without needing that merge just to read one field back off it).

**1.2.0: a top-level `provenance` key** -- adapter-generation Slice 9
(docs/adapter-generation.md), surfacing the confirmed-contract identity
behind a `--adapter-config` run on the one surface that never had it. The
`Contract` was already reaching this module on both paths
(`RunResult.contract`, `Coordinator.contract`) -- Slice 4's CLI banner
(`cli._print_adapter_config_banner`) already prints exactly these facts to
a terminal; this is that same, unchanged set of facts, extended to
`export.py`/`rhino web`. `None` for a built-in `--format` run, matching
every other path-conditional field's convention in this module (see above).
Deliberately excludes `Contract.generator` (the phase-1 LLM's model/token/
cost record) -- see `_provenance_dict`'s own docstring for why. Also fixes
a real, adjacent defect this key's own plumbing exposed: `_capacity_history`
compared a historical run's stored (possibly revision-qualified)
`ingest_format` against this run's bare `fmt`, so a config-driven run's own
capacity constraints always rendered a false "stale" pill in the web UI --
see `_current_run_label`.

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

from rhinosecure.adapters.config_model import Contract
from rhinosecure.adapters.review import is_provisional
from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.ingest import GapTally, IngestReport, IngestStats
from rhinosecure.memory import Memory
from rhinosecure.scoring import Bucket, contested_rate, score_finding

if TYPE_CHECKING:
    from rhinosecure.agents.coordinator import Coordinator
    from rhinosecure.cli import RunResult

EXPORT_SCHEMA_VERSION = "1.2.0"

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


def _ingest_flag(fmt: str, contract: Contract | None) -> str:
    """How this run's ingest source is actually invoked from the CLI --
    `--format X` for a built-in adapter, `--adapter-config X` for a
    confirmed contract. `fmt`/`report.format` never carries this
    distinction on its own (both name the same bare string either way), so
    every human-readable sentence that used to hardcode "--format" needs
    the contract in scope to name the right flag. Duplicated in `cli.py`
    rather than imported: a one-line formula, and the two modules
    deliberately don't import each other at module level (this module's
    own docstring)."""
    return f"--adapter-config {fmt}" if contract is not None else f"--format {fmt}"


def _current_run_label(fmt: str, contract: Contract | None) -> str:
    """The label `memory.runs.ingest_format` would hold for a run against
    this exact `(fmt, contract)` pair -- mirrors `adapters.configured
    .ConfiguredAdapter.run_label`'s own formula (`"<format>@v<version>"`)
    without importing it: this module has only the `Contract` by this
    point (`RunResult.contract` / `Coordinator.contract`), never the
    adapter object itself. Used only to compare against a *historical*
    run's stored `ingest_format` in `_capacity_history` -- never persisted
    here, since the deterministic path never writes a `runs` row at all
    (only `Coordinator` does, via `record_run`)."""
    return fmt if contract is None else f"{contract.format}@v{contract.version}"


def _provenance_dict(contract: Contract | None, report: IngestReport | None) -> dict[str, Any] | None:
    """The confirmed-mapping identity behind an `--adapter-config` run,
    mirroring exactly what `cli._print_adapter_config_banner` already
    prints to a terminal (Slice 4) -- extended to the export/web surface
    that never had it. `None` for a built-in `--format` run (`contract` is
    `None` there by construction), matching this module's own "absent on
    the path that doesn't apply, never fabricated" rule (see module
    docstring).

    Deliberately excludes `Contract.generator` (the phase-1 LLM's model/
    token/cost audit trail). Two of the three committed contracts
    (`bluepeak-gen`, `mdvm-gen`) are hand-authored but carry identical
    placeholder `generator` blocks -- the same fabricated token counts and
    cost on both, predating the phase-1 agent that would have produced a
    real one. Surfacing that data here would present invented numbers as a
    real fact about how the mapping was produced. "Provenance," in this
    codebase's own vocabulary, has always meant the four facts the Slice 4
    banner names plus proof the file has not been edited since signing --
    never the phase-1 cost accounting, which stays `rhino adapt propose`/
    `confirm`-only (`Contract.generator`'s own docstring: "audit trail, not
    input to any decision the engine makes" -- true of display too, not
    just scoring).

    `scale_drift` mirrors the banner's own signed-vs-loaded comparison:
    non-`None` only when the contract's `observed` measurement (written at
    `rhino adapt confirm` time) carries real asset/finding counts that
    disagree with what THIS run actually loaded. `None` (not just an
    absent key) is itself informative -- either nothing was signed
    (`observed` is `None` on both committed contracts today) or this run's
    counts match what was signed."""
    if contract is None:
        return None
    review = contract.review
    observed = contract.observed or {}
    signed_assets = observed.get("assets_loaded")
    signed_findings = observed.get("findings_loaded")
    scale_drift: dict[str, int] | None = None
    if (
        report is not None
        and isinstance(signed_assets, int)
        and isinstance(signed_findings, int)
        and (signed_assets, signed_findings) != (report.assets_total, report.findings_total)
    ):
        scale_drift = {
            "signed_assets": signed_assets,
            "signed_findings": signed_findings,
            "loaded_assets": report.assets_total,
            "loaded_findings": report.findings_total,
        }
    return {
        "format": contract.format,
        "version": contract.version,
        "confirmed_at": review.confirmed_at,
        "confirmed_by": review.confirmed_by,
        "content_digest": review.content_digest,
        "decision_digest": review.decision_digest,
        "scale_drift": scale_drift,
    }


def _ingest_detail(report: IngestReport, fmt: str, contract: Contract | None) -> str:
    total_dupes = report.duplicate_assets_collapsed + report.duplicate_findings_collapsed
    total_excluded = len(report.excluded_assets) + len(report.excluded_findings)
    excluded_note = f"; {total_excluded} record(s) excluded (scope boundary)" if total_excluded else ""
    return (
        f"{report.assets_total} asset(s), {report.findings_total} finding(s) loaded via "
        f"{_ingest_flag(fmt, contract)}; {total_dupes} duplicate row(s) collapsed{excluded_note}"
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


def _asset_summary(asset: Any) -> dict[str, Any]:
    """The Impact-axis facts (scoring.py) a finding's asset carries, in one
    nested object -- for the web UI's scenario views (bulk select / coverage
    by exposure, KEV status, and role) to filter and group by, without
    reaching for a second, asset-keyed section of the export. Never the
    operational fields (`patch_window`/`compensating_controls`/
    `patch_restrictions`) -- those are mutable via a constraint and already
    have their own representation (`constraints_applied`, the `constraints`
    section); these five are not: no format's fill-in path touches them
    (CLAUDE.md Section 3's own "Open items" note), so ground truth is always
    what scoring actually used, constraint or not."""
    return {
        "role": asset.role,
        "internet_exposed": asset.internet_exposed,
        "criticality": asset.criticality,
        "environment": asset.environment,
        "data_sensitivity": asset.data_sensitivity,
    }


def _decomposition_dict(d: Any) -> dict[str, Any]:
    """`scoring.ScoreDecomposition`, structured for the web UI's per-finding
    breakdown -- CLAUDE.md's "drop a CSV, get a plan" spec's own worked
    example ("Impact 4.1 (environment production, role domain-controller --
    criticality unavailable, excluded from calculation)"): the actual named
    components a reader can check the math on, not another prose sentence
    (`rationale`, above, already covers that). Every field here is already
    on `ScoreDecomposition` -- this is a plain field-for-field mirror, never
    a second computation of anything scoring.py itself computed."""
    return {
        "threat": {
            "severity_base": d.severity_base,
            "severity_source": d.severity_source,
            "internet_exposed": d.internet_exposed,
            "internet_exposed_neutralized": d.internet_exposed_neutralized,
            "epss": d.epss,
            "is_kev": d.is_kev,
            "likelihood_multiplier": d.likelihood_multiplier,
            "attack_prevalence": d.attack_prevalence,
        },
        "impact": {
            "criticality": d.criticality,
            "criticality_neutralized": d.criticality_neutralized,
            "environment": d.environment,
            "environment_neutralized": d.environment_neutralized,
            "data_sensitivity": d.data_sensitivity,
            "data_sensitivity_neutralized": d.data_sensitivity_neutralized,
            "role": d.role,
            "role_neutralized": d.role_neutralized,
            "composite": d.impact_composite,
            "compensating_controls": list(d.compensating_controls),
        },
    }


def _det_finding_entry(
    scored: Any,
    cache: SnapshotCache,
    assets: dict[str, Any],
    not_collected_by_finding: dict[str, frozenset[str]],
    is_kev_by_finding: dict[str, bool],
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
        "is_kev": is_kev_by_finding.get(scored.finding_id, False),
        "asset": _asset_summary(asset),
        "rationale": list(scored.rationale),
        "decomposition": _decomposition_dict(scored.decomposition),
        "verdict_summary": None,
        "narrative": None,
        "constraints_applied": [],
        "cited_text": [],
        "sources": _sources_for_cve(cache, scored.cve_id),
        "not_collected": sorted(not_collected_by_finding.get(scored.finding_id, frozenset())),
        "asset_not_collected": sorted(asset.not_collected),
        "has_tot": scored.finding_id in contested_ids,
    }


def _agents_decomposition(coordinator: Coordinator, enriched: Any, research: Any | None) -> dict[str, Any] | None:
    """Live recompute of one agents-path finding's `ScoreDecomposition` --
    mirrors `agents/risk.py`'s `score_finding_tool` EXACTLY: merge
    Research's enrichment signals into the ground-truth `EnrichedFinding`
    (`merge_research_into_enriched`), fold in any active constraint via
    `coordinator.memory` (identical `constraints_for_asset`/
    `apply_constraints` calls, same condition -- `if coordinator.memory is
    not None`), then `scoring.score_finding`.

    Deliberately NOT `_asset_constraint_deltas`'s constraint-free "before"
    pattern -- that pattern exists specifically to isolate a constraint's
    own effect for a diff, so reusing it here would silently disagree
    with the actual displayed `risk_score`/`bucket` whenever a real
    constraint is active on a confirmed run (a new bug this function must
    not introduce). For the provisional case this is moot either way --
    `coordinator.memory` is `None`, so the constraint branch below is
    always skipped, matching what `score_finding_tool` itself would have
    done had it been reachable at all.

    `None` when `research` is `None`: Research failed upstream for this
    finding, so `score_finding_tool` could never have been called for it
    either -- there is nothing honest to recompute, the same "absent, not
    fabricated" rule this module's docstring states for every other
    path-conditional field."""
    if research is None:
        return None
    from rhinosecure.agents.constraint_intake import apply_constraints
    from rhinosecure.agents.risk import merge_research_into_enriched

    merged = merge_research_into_enriched(enriched, research)
    if coordinator.memory is not None:
        active = coordinator.memory.constraints_for_asset(merged.asset.asset_id)
        if active:
            merged = merged.model_copy(update={"asset": apply_constraints(merged.asset, active)})
    return _decomposition_dict(score_finding(merged).decomposition)


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
        # research.is_kev, not enriched.is_kev -- see this module's own
        # docstring (the 1.1.0 note) for why enriched.is_kev is always the
        # pre-Research default here.
        "is_kev": research.is_kev if research is not None else False,
        "asset": _asset_summary(enriched.asset),
        "rationale": list(recommendation.scoring_rationale),
        # Closes a pre-existing gap unrelated to provisional-ness: before
        # this, the per-finding neutralized-axis UI note never rendered
        # for ANY agents-path finding, including a confirmed Defender run
        # -- see _agents_decomposition's own docstring for why this is a
        # live recompute, not a second copy of _det_finding_entry's
        # "already have a ScoredFinding" pattern (RiskRecommendation
        # carries no ScoreDecomposition of its own).
        "decomposition": _agents_decomposition(coordinator, enriched, research),
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
#: The agents-path analog of _DETERMINISTIC_NOTE, for a PROVISIONAL run
#: (CLAUDE.md's provisional-run entry) -- the 4-agent pipeline DID
#: dispatch, but its Coordinator was built with memory=None (point 5 of
#: that entry: nothing provisional writes durable state), so
#: agents/risk.py's score_finding_tool never queried a constraint either.
#: Without this, a memory-less coordinator's constraints section would
#: otherwise fall through to the "applies, deltas computed" branch below
#: and show a real constraint as live with a no-op delta -- misrepresenting
#: one that was never actually folded into what was scored.
_PROVISIONAL_NO_MEMORY_NOTE = (
    "this run used a provisional (unconfirmed) contract, whose Coordinator is never given a Memory "
    "instance (CLAUDE.md's provisional-run entry) -- constraints are not applied on a provisional run; "
    "confirm the contract, then re-run --agents to see live effect"
)
_NO_FINDINGS_NOTE = "no findings for this asset in the current dataset"


def _asset_scoped_constraints(
    memory: Memory,
    *,
    live: bool,
    not_live_note: str,
    coordinator: Coordinator | None,
    current_asset_ids: set[str],
) -> list[dict[str, Any]]:
    """`live` replaces the old blanket `agents: bool` -- a confirmed
    agents run and a PROVISIONAL agents run both have `agents=True` in
    the caller's own sense (the 4-agent pipeline really did dispatch),
    but only the confirmed one actually folded a constraint into scoring
    (`coordinator.memory is not None`). `not_live_note` lets each caller
    supply the honest reason ("deterministic path never touches memory.py
    at all" vs. "this run's Coordinator was never given one") instead of
    this function guessing which applies."""
    entries = []
    for c in memory.all_active_constraints():
        applies = c.asset_id in current_asset_ids
        deltas: list[dict[str, Any]] = []
        note: str | None
        if not live:
            note = not_live_note
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


def _capacity_history(memory: Memory, *, data_dir: Path, run_label: str) -> list[dict[str, Any]]:
    """Always reconstructed read-only from `Memory` -- no `rhino run`
    invocation (deterministic or `--agents`) ever calls
    `scoring.apply_capacity_limit`; only `rhino constraint add` does, via
    `_submit_capacity_constraint`. `original_bucket` is not a stored
    column -- `apply_capacity_limit`'s own contract guarantees every
    finding in its pool started as `Bucket.NEXT_WINDOW`, so the literal
    string is a code-guaranteed fact here, not a guess.

    `run_label` must be `_current_run_label(fmt, contract)`, not the bare
    `fmt` -- `memory.runs.ingest_format` stores the revision-qualified
    label for a config-driven run, and comparing that against a bare
    format name made every capacity constraint filed by a config-driven
    run compare unequal to itself (a real, verified defect this parameter
    rename exists to fix)."""
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
                    "stale": run.data_dir != current_data_dir or run.ingest_format != run_label,
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
    run_label: str,
    live: bool,
    not_live_note: str,
    coordinator: Coordinator | None,
    current_asset_ids: set[str],
) -> dict[str, Any]:
    if memory is None:
        return {"asset_scoped": [], "capacity": []}
    return {
        "asset_scoped": _asset_scoped_constraints(
            memory,
            live=live,
            not_live_note=not_live_note,
            coordinator=coordinator,
            current_asset_ids=current_asset_ids,
        ),
        "capacity": _capacity_history(memory, data_dir=data_dir, run_label=run_label),
    }


def _pipeline_common(fmt: str, report: IngestReport, offline: bool, contract: Contract | None) -> dict[str, Any]:
    return {
        "ingest": {"status": "completed", "detail": _ingest_detail(report, fmt, contract)},
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
    contract = result.contract
    run_label = _current_run_label(fmt, contract)

    findings = [
        _det_finding_entry(
            s, cache, result.assets, result.not_collected_by_finding, result.is_kev_by_finding, contested_ids
        )
        for s in scored
    ]
    rate = contested_rate(s.bucket.value for s in scored)

    pipeline = _pipeline_common(fmt, result.report, offline, contract)
    pipeline["scoring"] = {
        "status": "completed",
        "detail": f"{len(scored)} finding(s) scored via scoring.score_finding (deterministic, no LLM)",
    }
    pipeline["agents"] = {"status": "not_run", "detail": "run without --agents; deterministic pipeline only"}
    pipeline["tot"] = {"status": "not_run", "detail": "agents not dispatched"}

    constraints = _constraints_section(
        memory=memory,
        data_dir=data_dir,
        run_label=run_label,
        live=False,
        not_live_note=_DETERMINISTIC_NOTE,
        coordinator=None,
        current_asset_ids={s.asset_id for s in scored},
    )

    return {
        "export_schema_version": EXPORT_SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "run": {"data_dir": str(data_dir), "format": fmt, "seed": seed, "offline": offline, "agents": False},
        "provenance": _provenance_dict(contract, result.report),
        # True only for the provisional-run path (CLAUDE.md's "drop a CSV,
        # get a plan" spec). False (never absent) for a built-in --format
        # run (contract is None) and for a real --adapter-config run
        # against a genuinely confirmed contract. Deliberately NOT
        # `contract.review.state != "confirmed"` -- review._provisional
        # (which ConfiguredAdapter.__init__'s own assert_confirmed gate
        # requires to even construct) stamps state="confirmed" with a
        # sentinel identity on purpose; is_provisional checks THAT
        # identity, not the state, which the stamp deliberately fakes.
        "provisional": is_provisional(contract),
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
    contract = coordinator.contract
    run_label = _current_run_label(fmt, contract)

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

    pipeline = _pipeline_common(fmt, report, offline, contract)
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
        run_label=run_label,
        # A confirmed agents run and a PROVISIONAL one both dispatch the
        # full 4-agent pipeline, but only a confirmed run's Coordinator
        # was ever given a real Memory instance -- coordinator.memory is
        # the one honest signal for whether a constraint could have been
        # live during THIS run's own scoring, not the blanket "agents"
        # bool this used to be.
        live=coordinator.memory is not None,
        not_live_note=_PROVISIONAL_NO_MEMORY_NOTE,
        coordinator=coordinator,
        current_asset_ids={e.asset.asset_id for e in state.enriched_by_id.values()},
    )

    return {
        "export_schema_version": EXPORT_SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "run": {"data_dir": str(data_dir), "format": fmt, "seed": seed, "offline": offline, "agents": True},
        "provenance": _provenance_dict(contract, report),
        # No longer always False on this path -- web/jobs.py's
        # _run_run_agents now has its OWN provisional branch (CLAUDE.md's
        # provisional-run entry), mirroring run_deterministic's: an upload
        # whose contract exists but was never confirmed can reach the full
        # 4-agent pipeline too, via a Coordinator built with memory=None
        # and never committed as plan_state's current plan. `contract`
        # here is that branch's provisional-stamped contract
        # (`Coordinator.contract`, set from the adapter `_resolve_
        # provisional` builds), so `is_provisional` correctly reports True
        # for it -- exactly the same check the deterministic path already
        # relied on, extended to a second caller rather than duplicated.
        # Still False for every ordinary confirmed --adapter-config run
        # and every built-in --format run (contract is None there).
        "provisional": is_provisional(contract),
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
