"""Coordinator (CLAUDE.md Section 5): plans the run, dispatches Research,
Environment, and Risk in sequence, owns the shared state that threads
their structured payloads together, and owns the re-plan entry point.

Primary path, per Section 5's Flow: `Research -> Environment -> Risk`,
Coordinator dispatching each stage as its own CrewAI `Crew` and threading
each stage's real structured output into the next stage's task-builder as
an explicit Python object -- not CrewAI's own `context=[...]` task
chaining. This matches Research/Environment/Risk's own established
pattern (each `build_*_task` takes upstream payloads as parameters, not
implicit crew state) for the same reason: it stays unit-testable without
running a live crew, and it is what Section 5 means by "structured
payloads, not free conversation" -- the handoff is a concrete pydantic
object at every step, not something buried in CrewAI's internal task
graph.

**Coordinator is plain Python, not a CrewAI `Agent`.** Section 5 lists it
in the same responsibility table as the three LLM-backed roles, but none
of its four responsibilities -- planning the run, dispatching work, owning
shared state, owning the re-plan loop -- requires model reasoning at the
scope currently built. The primary path's sequencing is fixed, not
model-decided, and re-plan here (see `replan` below) is "re-run Environment
and Risk for these finding_ids," a mechanical re-dispatch.

**`submit_constraint` is constraint intake, now built -- the interpretation
step every prior commit in this repo named as the one unbuilt piece of
Slice 4's Coordinator-side wiring.** `interpret_constraint` dispatches
`agents/constraint_intake.py`'s Constraint Interpreter once, against the
fleet's current (deterministic, unenriched) scores for tool context, and
raises `ConstraintInterpretationError` if its response never parses --
unlike a single finding's Research/Environment/Risk/ToT failure (recorded
and skipped, the rest of the run continues), a constraint that can't be
interpreted at all has nothing to fall back to, so `submit_constraint`
aborts entirely rather than persisting or re-planning anything from a
response it can't trust. If the Interpreter itself resolves cleanly but
declines -- no single asset named, or no effect kind it recognizes (e.g.
Section 10's "only five patches fit this window", a fleet-wide capacity
statement with no one asset to resolve to; see `constraint_intake.py`'s
module docstring for why that's out of scope) -- `submit_constraint`
returns a normal (non-exception) result with `constraint_id=None` and the
Interpreter's own `rationale` explaining why, and persists and re-plans
nothing.

Once resolved, `submit_constraint`: persists via `self.memory.add_constraint`
*before* re-planning (Environment's and Risk's tools only ever see an
active constraint by querying `self.memory` themselves -- see
`_dispatch_environment`/`_dispatch_risk` below -- so the constraint has to
already be on file for the targeted `run()` that follows to pick it up);
re-plans only the resolved `affected_finding_ids` (a fresh, scoped `run()`,
not the whole fleet -- `rhino constraint add` stays cheap); computes a
per-finding diff against a "before" score computed from the exact same
Research-enriched inputs the targeted run itself produced, just without the
constraint overlay (`agents/risk.py`'s `merge_research_into_enriched` +
`scoring.score_finding` directly, no LLM call needed for "before" since
it's the same deterministic function Risk's own tool already trusts) --
so the diff isolates the constraint's own effect rather than conflating it
with enrichment that would happen regardless; and records the run,
each affected finding's new decision, and the constraint itself as
feedback, via `memory.py`'s existing `record_run`/`record_decision`/
`record_feedback` -- exercising all four Section 7 tables from this one
flow.

**`_dispatch_tot` is the gate CLAUDE.md Section 6 describes: every
finding whose Risk stage lands on `bucket="contested"` gets routed into a
`tot.run_tree_of_thought` root.** Called after `_dispatch_risk` in both
`run` and `replan` -- a replanned finding can end up contested (or stop
being contested) the same way any other finding can, so the gate has to
re-check every time Risk produces a fresh bucket, not just on the first
run. Like the three stages above it, one finding's ToT failure (raised
as `tot.ToTDispatchError` after `tot.py`'s own retry cap) is caught here,
recorded into `RunState.tot_failures`, and never allowed to block ToT for
any other contested finding in the same batch -- but unlike a
Research/Environment/Risk failure, it does NOT remove the finding from
`risk_by_id`: Risk already succeeded (that's *why* the finding reached
this gate at all), and a failed ToT elaboration doesn't retroactively
make that scoring result untrustworthy.

**A failed finding is recorded and skipped, never left to block the whole
run.** Incident (PROGRESS.md, this date): a 24-finding run hung on the
first finding, retrying an identical failure indefinitely, because the
model's answer for that finding was shaped as `{"finding": {...}}` instead
of the fields directly, and CrewAI's own structured-output conversion
re-raises that validation failure uncaught rather than recovering or
giving up (traced in `agents/parsing.py`'s docstring). Two changes follow
from that:

1. No Task built by `agents/research.py`, `environment.py`, or `risk.py`
   sets `output_pydantic` any more -- each stage's raw final-answer text
   is parsed by `agents.parsing.parse_structured_output`, which tolerates
   a single-key wrapper, so the exact incident shape now succeeds without
   needing a retry at all.
2. `_resolve_output` below is this module's own retry loop, capped at
   `max_parse_attempts` (default 3) fresh re-dispatches -- not CrewAI's.
   If a finding still won't parse (or, for Risk, still disagrees with
   `verify_scoring_matches_tool`) after the cap, it is recorded in the
   relevant `RunState.*_failures` dict and excluded from that stage's
   `*_by_id` -- never raised, never left retrying. A finding missing from
   an upstream stage (because it failed there) is skipped at every stage
   after that, recorded again at each one, rather than treated as a
   Coordinator misuse error.

`CoordinatorError` is reserved for actual misuse of this class (`replan`
before any `run`, or `replan` naming a finding_id `run` never saw) --
never for an individual finding's processing failure, which is what the
mechanism above exists to make survivable.

All LLM calls happen inside the agents this module dispatches -- this
module itself never constructs a provider client or calls `get_llm`.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TypeVar

from crewai import Agent, Crew, Process, Task
from crewai.types.usage_metrics import UsageMetrics
from pydantic import BaseModel

from rhinosecure.agents.constraint_intake import (
    ConstraintInterpretation,
    ConstraintInterpretationError,
    ConstraintKind,
    apply_constraints,
    build_constraint_agent,
    build_constraint_task,
    build_constraint_tools,
)
from rhinosecure.agents.environment import (
    EnvironmentAssessment,
    build_environment_agent,
    build_environment_task,
    build_environment_tools,
)
from rhinosecure.agents.parsing import AgentOutputParseError, parse_structured_output
from rhinosecure.agents.research import (
    ResearchFinding,
    build_research_agent,
    build_research_task,
    build_research_tools,
)
from rhinosecure.agents.risk import (
    RiskRecommendation,
    ScoringMismatchError,
    build_risk_agent,
    build_risk_task,
    build_risk_tools,
    merge_research_into_enriched,
    verify_scoring_matches_tool,
)
from rhinosecure.enrich.attack import load_index as load_attack_index
from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.enrich.kev import load_catalog as load_kev_catalog
from rhinosecure.ingest import attach_threat_signals, load_asset_index
from rhinosecure.memory import Memory
from rhinosecure.schema import EnrichedFinding
from rhinosecure.scoring import (
    Bucket,
    CapacityAllocation,
    RankableFinding,
    ScoredFinding,
    apply_capacity_limit,
    contested_rate,
    score_finding,
)
from rhinosecure.tot import (
    ToTDispatchError,
    ToTResult,
    ToTRoot,
    build_critic_agent,
    build_strategist_agent,
    run_tree_of_thought,
)

ModelT = TypeVar("ModelT", bound=BaseModel)

DEFAULT_MAX_PARSE_ATTEMPTS = 3


class CoordinatorError(RuntimeError):
    """Raised for misuse of this class -- `replan` before any `run`, or
    naming a finding_id `run` never saw. Never raised for one finding's
    processing failure; see the module docstring."""


@dataclass
class RunState:
    """Shared state Coordinator owns across the run -- CP4's "MCP correction"
    (CLAUDE.md Section 1): agent state lives here, not passed through MCP or
    left implicit in a CrewAI crew's internal history."""

    enriched_by_id: dict[str, EnrichedFinding]
    research_by_id: dict[str, ResearchFinding] = field(default_factory=dict)
    environment_by_id: dict[str, EnvironmentAssessment] = field(default_factory=dict)
    risk_by_id: dict[str, RiskRecommendation] = field(default_factory=dict)
    # Only populated for findings whose RiskRecommendation.bucket is
    # "contested" -- see _dispatch_tot. Never used to compute risk_score
    # or bucket for anything; scoring.py stays the sole owner of both.
    tot_by_id: dict[str, ToTResult] = field(default_factory=dict)
    research_call_log: list[dict[str, Any]] = field(default_factory=list)
    environment_call_log: list[dict[str, Any]] = field(default_factory=list)
    risk_call_log: list[dict[str, Any]] = field(default_factory=list)
    # Each stage's crewai UsageMetrics from its most recent dispatch --
    # token accounting for cost visibility, not anything scoring reads.
    # tot_usage is the sum across every contested finding _dispatch_tot
    # processed in that call (unlike the other three, one dispatch can
    # mean many Crews -- see tot.py's module docstring), including
    # whatever partial usage a finding accrued before its search failed.
    research_usage: Any = None
    environment_usage: Any = None
    risk_usage: Any = None
    tot_usage: UsageMetrics | None = None
    # finding_id -> why it has no result for that stage, whether it failed
    # there directly or was skipped because an earlier stage failed for it.
    research_failures: dict[str, str] = field(default_factory=dict)
    environment_failures: dict[str, str] = field(default_factory=dict)
    risk_failures: dict[str, str] = field(default_factory=dict)
    tot_failures: dict[str, str] = field(default_factory=dict)


_RATIONALE_TIE_TOLERANCE = 0.05  # risk_score is printed to 0.1 -- ignore float noise below that


@dataclass(frozen=True)
class FindingDelta:
    """One finding's before/after comparison from `submit_constraint`.
    `before_*` comes from `scoring.score_finding` run directly (no
    overlay); `after_*` from the targeted run's real `RiskRecommendation`
    (overlay applied). Both are computed from the same Research-enriched
    inputs -- see `submit_constraint`'s docstring -- so any difference
    here is the constraint's own effect, not enrichment noise."""

    finding_id: str
    cve_id: str
    hostname: str
    before_bucket: str
    after_bucket: str
    before_risk_score: float
    after_risk_score: float
    rationale_added: tuple[str, ...]
    rationale_removed: tuple[str, ...]
    # The "why" a caller (cli.py's diff output) can show without needing
    # separate access to Coordinator.state -- the agent's own narrative
    # already explains the constraint's effect (agents/risk.py's task
    # prompt tells it to, whenever constraints_applied is non-empty).
    after_verdict_summary: str
    after_constraints_applied: tuple[str, ...]

    @property
    def bucket_changed(self) -> bool:
        return self.before_bucket != self.after_bucket

    @property
    def risk_score_changed(self) -> bool:
        return not math.isclose(self.before_risk_score, self.after_risk_score, abs_tol=_RATIONALE_TIE_TOLERANCE)

    @property
    def changed(self) -> bool:
        return self.bucket_changed or self.risk_score_changed


def _build_finding_delta(before: ScoredFinding, after: RiskRecommendation) -> FindingDelta:
    before_rationale = set(before.rationale)
    after_rationale = set(after.scoring_rationale)
    return FindingDelta(
        finding_id=after.finding_id,
        cve_id=after.cve_id,
        hostname=after.hostname,
        before_bucket=before.bucket.value,
        after_bucket=after.bucket,
        after_verdict_summary=after.verdict_summary,
        after_constraints_applied=tuple(after.constraints_applied),
        before_risk_score=before.risk_score,
        after_risk_score=after.risk_score,
        rationale_added=tuple(sorted(after_rationale - before_rationale)),
        rationale_removed=tuple(sorted(before_rationale - after_rationale)),
    )


def _summarize_deltas(constraint_id: int, deltas: tuple[FindingDelta, ...]) -> str:
    changed = [d for d in deltas if d.changed]
    if not changed:
        return (
            f"constraint #{constraint_id}: re-evaluated {len(deltas)} finding(s), "
            "none changed bucket or risk score"
        )
    parts = [
        f"{d.finding_id}: {d.before_bucket}({d.before_risk_score:.1f}) -> "
        f"{d.after_bucket}({d.after_risk_score:.1f})"
        for d in changed
    ]
    return f"constraint #{constraint_id}: " + "; ".join(parts)


def _usage_dict(usage: UsageMetrics | None) -> dict[str, Any] | None:
    return None if usage is None else usage.model_dump()


@dataclass(frozen=True)
class ConstraintSubmissionResult:
    """The end-to-end outcome of `submit_constraint`. `constraint_id` and
    `run_id` are None together when the Interpreter couldn't resolve the
    constraint to one asset and effect, or resolved one but none of its
    `affected_finding_ids` actually matched a real finding on that asset
    -- nothing was persisted or re-planned in either case, and `deltas`
    is empty. `unresolved_finding_ids` names any finding_id the
    Interpreter listed that didn't survive that cross-check (a
    hallucinated or cross-asset id), even when others did and the
    constraint still went through."""

    interpretation: ConstraintInterpretation
    constraint_id: int | None
    run_id: int | None
    deltas: tuple[FindingDelta, ...]
    unresolved_finding_ids: tuple[str, ...] = ()

    @property
    def persisted(self) -> bool:
        return self.constraint_id is not None

    @property
    def changed_deltas(self) -> tuple[FindingDelta, ...]:
        return tuple(d for d in self.deltas if d.changed)


@dataclass(frozen=True)
class CapacityDelta:
    """One finding's outcome from a fleet-wide capacity reallocation
    (`_submit_capacity_constraint`) -- deliberately NOT a `FindingDelta`.
    Nothing about this finding's own risk_score or Research evidence
    changed (`scoring.apply_capacity_limit`'s own docstring: the whole
    point of "exempt by construction" is that the pool this operates
    over was already final) -- only its rank position relative to a
    fleet-wide limit did. Framing this as a risk_score before/after the
    way `FindingDelta` does would misrepresent what actually happened,
    which is why `risk_score` here is a single value, not a pair."""

    finding_id: str
    cve_id: str
    asset_id: str
    hostname: str
    risk_score: float
    original_bucket: str
    effective_bucket: str
    rank: int
    pool_size: int
    limit: int

    @property
    def fits(self) -> bool:
        return self.rank <= self.limit

    @property
    def changed(self) -> bool:
        return self.original_bucket != self.effective_bucket


def _capacity_verdict_summary(d: CapacityDelta) -> str:
    if d.fits:
        return (
            f"Fits within this cycle's capacity: ranked {d.rank} of {d.pool_size} "
            f"next_window candidate(s), limit {d.limit}."
        )
    return (
        f"Deferred to next cycle: ranked {d.rank} of {d.pool_size} next_window "
        f"candidate(s), exceeding this cycle's capacity of {d.limit}. risk_score is "
        "unchanged -- this finding lost a rank-position race, not a change in risk."
    )


def _capacity_rationale_line(d: CapacityDelta) -> str:
    return (
        f"capacity: ranked {d.rank} of {d.pool_size} next_window candidate(s) "
        f"against a cycle limit of {d.limit} -> "
        f"{'fits, stays next_window' if d.fits else 'deferred_capacity'}"
    )


def _summarize_capacity_deltas(capacity_constraint_id: int, deltas: tuple[CapacityDelta, ...]) -> str:
    deferred = [d for d in deltas if d.changed]
    if not deferred:
        return (
            f"capacity constraint #{capacity_constraint_id}: {len(deltas)} next_window "
            "candidate(s) evaluated, all fit within capacity"
        )
    parts = [f"{d.finding_id}: rank {d.rank}/{d.pool_size} -> deferred_capacity" for d in deferred]
    return f"capacity constraint #{capacity_constraint_id}: " + "; ".join(parts)


@dataclass(frozen=True)
class CapacitySubmissionResult:
    """The end-to-end outcome of a fleet-wide capacity constraint
    (`_submit_capacity_constraint`) -- CLAUDE.md Section 10's "only five
    patches fit this window". `capacity_constraint_id` and `run_id` are
    None together when the Interpreter recognized the statement as
    capacity-shaped but could not extract a usable limit -- nothing was
    computed or persisted in that case, and `deltas` is empty."""

    interpretation: ConstraintInterpretation
    capacity_constraint_id: int | None
    run_id: int | None
    deltas: tuple[CapacityDelta, ...]

    @property
    def persisted(self) -> bool:
        return self.capacity_constraint_id is not None

    @property
    def changed_deltas(self) -> tuple[CapacityDelta, ...]:
        return tuple(d for d in self.deltas if d.changed)


class Coordinator:
    def __init__(
        self,
        data_dir: Path,
        cache: SnapshotCache | None = None,
        *,
        memory: Memory | None = None,
        verbose: bool = False,
        max_parse_attempts: int = DEFAULT_MAX_PARSE_ATTEMPTS,
    ):
        self.data_dir = data_dir
        self.cache = cache or SnapshotCache()
        self.memory = memory
        self.verbose = verbose
        self.max_parse_attempts = max_parse_attempts
        self._asset_index = load_asset_index(data_dir / "assets.csv")
        self.state: RunState | None = None

    def run(self, findings: list[EnrichedFinding]) -> list[RiskRecommendation]:
        """Primary path: dispatch Research, then Environment, then Risk,
        for every finding in `findings`. Replaces any prior state -- this
        is a fresh run, not an incremental one; see `replan` for that."""
        self.state = RunState(enriched_by_id={e.finding.finding_id: e for e in findings})
        self._dispatch_research(findings)
        self._dispatch_environment(findings)
        self._dispatch_risk(findings)
        self._dispatch_tot(findings)
        return self.ranked()

    def replan(self, finding_ids: list[str]) -> list[RiskRecommendation]:
        """Re-plan path (Section 5's Flow: "Human submits a constraint ->
        Coordinator -> re-plan from Environment onward"). Re-dispatches
        Environment and Risk for `finding_ids` only, reusing the Research
        output already held in state -- Research is CVE-keyed and doesn't
        depend on operational constraints, so it has no reason to re-run.
        Requires a prior `run` -- there is no state to re-plan from otherwise.
        """
        if self.state is None:
            raise CoordinatorError("replan called with no prior run -- call run() first")
        missing = [fid for fid in finding_ids if fid not in self.state.enriched_by_id]
        if missing:
            raise CoordinatorError(f"replan: unknown finding_id(s) never seen by run(): {missing}")
        findings = [self.state.enriched_by_id[fid] for fid in finding_ids]
        self._dispatch_environment(findings)
        self._dispatch_risk(findings)
        self._dispatch_tot(findings)
        return self.ranked()

    def interpret_constraint(
        self, text: str, findings: list[EnrichedFinding]
    ) -> ConstraintInterpretation:
        """Dispatch the Constraint Interpreter once (agents/constraint_intake.py)
        against `findings`' current, deterministic, unenriched scores --
        context for the model's own reasoning, not an authoritative
        verdict (see that module's docstring). Does not require a prior
        `run` -- `findings` here is the ground-truth pool to search and
        list against, independent of any state `run`/`replan` may hold.

        Raises `ConstraintInterpretationError` if the response never
        parses within `max_parse_attempts` -- there is no per-finding
        skip-and-continue for a single constraint that can't be
        interpreted at all; see the module docstring.
        """
        scored_by_asset: dict[str, list[ScoredFinding]] = defaultdict(list)
        for e in findings:
            scored_by_asset[e.asset.asset_id].append(score_finding(e))

        call_log: list[dict[str, Any]] = []
        tools = build_constraint_tools(self._asset_index, scored_by_asset, call_log)
        agent = build_constraint_agent(tools)
        task = build_constraint_task(text, agent)
        Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=self.verbose).kickoff()

        last_error: Exception | None = None
        for attempt in range(1, self.max_parse_attempts + 1):
            try:
                return parse_structured_output(task.output.raw, ConstraintInterpretation)
            except AgentOutputParseError as exc:
                last_error = exc
                if attempt == self.max_parse_attempts:
                    break
                task = build_constraint_task(text, agent)
                Crew(
                    agents=[agent], tasks=[task], process=Process.sequential, verbose=self.verbose
                ).kickoff()
        raise ConstraintInterpretationError(
            f"gave up after {self.max_parse_attempts} attempt(s): {last_error}"
        )

    def submit_constraint(
        self, text: str, findings: list[EnrichedFinding], *, seed: int = 42
    ) -> ConstraintSubmissionResult | CapacitySubmissionResult:
        """The full "Human submits a constraint" flow (Section 5's Flow,
        Section 7's worked example): interpret, then dispatch to one of
        two entirely different mechanisms depending on
        `interpretation.constraint_kind`. Requires `self.memory` --
        construct `Coordinator(..., memory=Memory(...))`. See the module
        docstring for the asset-scoped mechanics; `_submit_capacity_constraint`
        below has the fleet-wide capacity mechanics
        (CLAUDE.md Section 10's "only five patches fit this window").
        `seed` is recorded on the resulting `runs` row only (scoring has
        no sampling to seed -- same no-op `cli.run` itself documents).
        """
        if self.memory is None:
            raise CoordinatorError(
                "submit_constraint requires a Memory instance -- construct "
                "Coordinator(..., memory=Memory(...))"
            )

        interpretation = self.interpret_constraint(text, findings)

        if interpretation.constraint_kind == ConstraintKind.CAPACITY.value:
            return self._submit_capacity_constraint(text, findings, interpretation, seed=seed)

        if interpretation.constraint_kind != ConstraintKind.ASSET.value or interpretation.asset_id is None:
            # A refusal (constraint_kind=None), or -- defensively -- any
            # inconsistent shape the schema shouldn't produce but this
            # doesn't trust blindly. Persists and re-plans nothing.
            return ConstraintSubmissionResult(
                interpretation=interpretation, constraint_id=None, run_id=None, deltas=()
            )

        by_id = {e.finding.finding_id: e for e in findings}
        requested = set(interpretation.affected_finding_ids)
        affected = [
            by_id[fid]
            for fid in interpretation.affected_finding_ids
            if fid in by_id and by_id[fid].asset.asset_id == interpretation.asset_id
        ]
        unresolved = tuple(sorted(requested - {e.finding.finding_id for e in affected}))
        if not affected:
            return ConstraintSubmissionResult(
                interpretation=interpretation,
                constraint_id=None,
                run_id=None,
                deltas=(),
                unresolved_finding_ids=unresolved,
            )

        constraint_id = self.memory.add_constraint(
            interpretation.asset_id,
            text,
            effect_kind=interpretation.effect_kind,
            effect_value=interpretation.effect_value,
        )

        # Fresh, scoped run -- Risk's score_finding tool applies the
        # constraint just persisted above by querying self.memory itself.
        self.run(affected)

        deltas = []
        for e in affected:
            fid = e.finding.finding_id
            after = self.state.risk_by_id.get(fid)
            if after is None:
                continue  # this finding failed during the targeted run; already in risk_failures
            research = self.state.research_by_id[fid]
            before = score_finding(merge_research_into_enriched(e, research))
            deltas.append(_build_finding_delta(before, after))
        deltas = tuple(deltas)

        run_id = self.memory.record_run(
            data_dir=str(self.data_dir),
            seed=seed,
            offline=self.cache.offline,
            agents=True,
            total_findings=len(affected),
            contested_count=sum(
                1 for r in self.state.risk_by_id.values() if r.bucket == Bucket.CONTESTED.value
            ),
            contested_total=len(self.state.risk_by_id),
            research_usage=_usage_dict(self.state.research_usage),
            environment_usage=_usage_dict(self.state.environment_usage),
            risk_usage=_usage_dict(self.state.risk_usage),
            tot_usage=_usage_dict(self.state.tot_usage),
        )
        for delta in deltas:
            recommendation = self.state.risk_by_id[delta.finding_id]
            self.memory.record_decision(
                run_id=run_id,
                finding_id=delta.finding_id,
                cve_id=delta.cve_id,
                asset_id=interpretation.asset_id,
                hostname=delta.hostname,
                risk_score=recommendation.risk_score,
                bucket=recommendation.bucket,
                rationale=list(recommendation.scoring_rationale),
                verdict_summary=recommendation.verdict_summary,
                narrative=recommendation.narrative,
            )
        self.memory.record_feedback(text, _summarize_deltas(constraint_id, deltas), run_id=run_id)

        return ConstraintSubmissionResult(
            interpretation=interpretation,
            constraint_id=constraint_id,
            run_id=run_id,
            deltas=deltas,
            unresolved_finding_ids=unresolved,
        )

    def _submit_capacity_constraint(
        self,
        text: str,
        findings: list[EnrichedFinding],
        interpretation: ConstraintInterpretation,
        *,
        seed: int,
    ) -> CapacitySubmissionResult:
        """CLAUDE.md Section 10's "only five patches fit this window" --
        fleet-wide, not asset-scoped, so there is no one asset's findings
        to target the way the asset flow above does. The competing pool
        is every finding currently in `Bucket.NEXT_WINDOW`, computed here,
        deterministically, from the whole fleet -- never from the
        Interpreter's own judgment (`interpretation.affected_finding_ids`
        is not read here; `constraint_intake.py`'s task prompt already
        instructs it to leave that empty for a capacity constraint).

        Entirely LLM-free past the one `interpret_constraint` call that
        already happened to extract `patch_limit` -- no Research/
        Environment/Risk/ToT dispatch. The real, current bucket for every
        finding comes from `ingest.attach_threat_signals` +
        `scoring.score_finding`, the exact same deterministic pipeline
        `cli.run()` uses, so "who's in next_window" reflects live KEV/
        EPSS/NVD/ATT&CK data, not a guess -- but the reallocation itself
        (`scoring.apply_capacity_limit`) stays a pure sort, matching
        "Keep the allocation deterministic and in the scoring path, not
        in an agent." `patch_now` and a contested finding whose ToT
        recommended `emergency_change` are both excluded from the
        competing pool by construction, not by an exemption list here --
        neither is ever `Bucket.NEXT_WINDOW` in the first place; see
        `apply_capacity_limit`'s own docstring.

        Any active asset-scoped constraint on file is folded in before
        scoring, the same way `agents/risk.py`'s `score_finding_tool`
        does for a live agents run -- otherwise "the real, current
        bucket" above would be a lie whenever an asset has a constraint
        (e.g. a `compensating_control` just added via a prior `rhino
        constraint add`) affecting `has_patch_window`/
        `has_compensating_controls`: a finding could wrongly compete for
        capacity (or wrongly be excluded, if a constraint moved it out of
        `contested`) against the fleet's raw, un-overlaid CSV state
        instead of what a person would actually see right now.
        """
        if interpretation.patch_limit is None:
            return CapacitySubmissionResult(
                interpretation=interpretation, capacity_constraint_id=None, run_id=None, deltas=()
            )

        kev_catalog = load_kev_catalog(self.cache)
        attack_index = load_attack_index(self.cache)
        scored = []
        for e in findings:
            active = self.memory.constraints_for_asset(e.asset.asset_id)
            if active:
                e = e.model_copy(update={"asset": apply_constraints(e.asset, active)})
            scored.append(score_finding(attach_threat_signals(e, kev_catalog, attack_index, self.cache)))
        scored_by_id = {s.finding_id: s for s in scored}
        asset_id_by_finding_id = {e.finding.finding_id: e.asset.asset_id for e in findings}

        rankable = [
            RankableFinding(finding_id=s.finding_id, risk_score=s.risk_score, bucket=s.bucket)
            for s in scored
        ]
        allocations = apply_capacity_limit(rankable, interpretation.patch_limit)

        deltas = tuple(
            CapacityDelta(
                finding_id=a.finding_id,
                cve_id=scored_by_id[a.finding_id].cve_id,
                asset_id=asset_id_by_finding_id[a.finding_id],
                hostname=scored_by_id[a.finding_id].hostname,
                risk_score=scored_by_id[a.finding_id].risk_score,
                original_bucket=a.original_bucket.value,
                effective_bucket=a.effective_bucket.value,
                rank=a.rank,
                pool_size=a.pool_size,
                limit=a.limit,
            )
            for a in allocations
        )
        deferred_count = sum(1 for d in deltas if d.changed)

        rate = contested_rate(s.bucket.value for s in scored)
        run_id = self.memory.record_run(
            data_dir=str(self.data_dir),
            seed=seed,
            offline=self.cache.offline,
            # agents=False: this run made no LLM calls beyond the one
            # Interpreter call already dispatched by interpret_constraint
            # -- the allocation itself is the deterministic pipeline, the
            # same shape as `rhino run` without --agents.
            agents=False,
            total_findings=len(findings),
            contested_count=rate.contested,
            contested_total=rate.total,
        )
        capacity_constraint_id = self.memory.record_capacity_constraint(
            run_id, text, interpretation.patch_limit, len(allocations), deferred_count
        )
        for d in deltas:
            self.memory.record_decision(
                run_id=run_id,
                finding_id=d.finding_id,
                cve_id=d.cve_id,
                asset_id=d.asset_id,
                hostname=d.hostname,
                risk_score=d.risk_score,
                bucket=d.effective_bucket,
                rationale=[*scored_by_id[d.finding_id].rationale, _capacity_rationale_line(d)],
                verdict_summary=_capacity_verdict_summary(d),
                narrative=_capacity_verdict_summary(d),
                capacity_rank=d.rank,
                capacity_pool_size=d.pool_size,
                capacity_limit=d.limit,
            )
        self.memory.record_feedback(
            text, _summarize_capacity_deltas(capacity_constraint_id, deltas), run_id=run_id
        )

        return CapacitySubmissionResult(
            interpretation=interpretation,
            capacity_constraint_id=capacity_constraint_id,
            run_id=run_id,
            deltas=deltas,
        )

    def ranked(self) -> list[RiskRecommendation]:
        """The current plan, sorted the same way `scoring.rank` sorts the
        deterministic pipeline's output -- descending risk, finding_id as
        the tiebreak. Findings recorded as failures are simply absent, not
        represented with a placeholder score."""
        if self.state is None:
            raise CoordinatorError("no run has been dispatched yet")
        return sorted(self.state.risk_by_id.values(), key=lambda r: (-r.risk_score, r.finding_id))

    def _resolve_output(
        self,
        finding_id: str,
        task: Task,
        model: type[ModelT],
        rebuild_task: Callable[[], Task],
        agent: Agent,
        failures: dict[str, str],
        *,
        extra_validate: Callable[[ModelT], None] | None = None,
    ) -> ModelT | None:
        """Parse `task`'s raw output into `model`, retrying with a fresh
        dispatch (via `rebuild_task`) up to `self.max_parse_attempts`
        total attempts if parsing -- or `extra_validate`, when given --
        fails. Records `finding_id` into `failures` and returns None if
        every attempt is exhausted; never raises for this reason. See the
        module docstring for why this exists instead of trusting CrewAI's
        own `output_pydantic` conversion."""
        last_error: Exception | None = None
        for attempt in range(1, self.max_parse_attempts + 1):
            try:
                result = parse_structured_output(task.output.raw, model)
                if extra_validate is not None:
                    extra_validate(result)
                return result
            except (AgentOutputParseError, ScoringMismatchError) as exc:
                last_error = exc
                if attempt == self.max_parse_attempts:
                    break
                task = rebuild_task()
                Crew(
                    agents=[agent], tasks=[task], process=Process.sequential, verbose=self.verbose
                ).kickoff()
        failures[finding_id] = (
            f"gave up after {self.max_parse_attempts} attempt(s): {last_error}"
        )
        return None

    def _dispatch_research(self, findings: list[EnrichedFinding]) -> None:
        tools = build_research_tools(self.cache, self.state.research_call_log)
        agent = build_research_agent(tools)
        tasks = [build_research_task(e, agent) for e in findings]
        crew = Crew(agents=[agent], tasks=tasks, process=Process.sequential, verbose=self.verbose)
        crew.kickoff()
        self.state.research_usage = crew.usage_metrics
        for finding, task in zip(findings, tasks):
            fid = finding.finding.finding_id
            result = self._resolve_output(
                fid,
                task,
                ResearchFinding,
                lambda e=finding, a=agent: build_research_task(e, a),
                agent,
                self.state.research_failures,
            )
            if result is not None:
                self.state.research_by_id[fid] = result

    def _dispatch_environment(self, findings: list[EnrichedFinding]) -> None:
        survivors = []
        for e in findings:
            fid = e.finding.finding_id
            if fid not in self.state.research_by_id:
                self.state.environment_failures[fid] = (
                    "skipped: no ResearchFinding (Research failed for this finding)"
                )
            else:
                survivors.append(e)
        if not survivors:
            return

        tools = build_environment_tools(self._asset_index, self.state.environment_call_log, self.memory)
        agent = build_environment_agent(tools)
        tasks = [
            build_environment_task(e, self.state.research_by_id[e.finding.finding_id], agent)
            for e in survivors
        ]
        crew = Crew(agents=[agent], tasks=tasks, process=Process.sequential, verbose=self.verbose)
        crew.kickoff()
        self.state.environment_usage = crew.usage_metrics
        for finding, task in zip(survivors, tasks):
            fid = finding.finding.finding_id
            research = self.state.research_by_id[fid]
            result = self._resolve_output(
                fid,
                task,
                EnvironmentAssessment,
                lambda e=finding, r=research, a=agent: build_environment_task(e, r, a),
                agent,
                self.state.environment_failures,
            )
            if result is not None:
                self.state.environment_by_id[fid] = result

    def _dispatch_risk(self, findings: list[EnrichedFinding]) -> None:
        survivors = []
        for e in findings:
            fid = e.finding.finding_id
            if fid not in self.state.research_by_id:
                self.state.risk_failures[fid] = (
                    "skipped: no ResearchFinding (Research failed for this finding)"
                )
            elif fid not in self.state.environment_by_id:
                self.state.risk_failures[fid] = (
                    "skipped: no EnvironmentAssessment (Environment failed for this finding)"
                )
            else:
                survivors.append(e)
        if not survivors:
            return

        tools = build_risk_tools(
            self.state.enriched_by_id, self.state.research_by_id, self.state.risk_call_log, self.memory
        )
        agent = build_risk_agent(tools)
        tasks = [
            build_risk_task(
                e,
                self.state.research_by_id[e.finding.finding_id],
                self.state.environment_by_id[e.finding.finding_id],
                agent,
            )
            for e in survivors
        ]
        crew = Crew(agents=[agent], tasks=tasks, process=Process.sequential, verbose=self.verbose)
        crew.kickoff()
        self.state.risk_usage = crew.usage_metrics
        for finding, task in zip(survivors, tasks):
            fid = finding.finding.finding_id
            research = self.state.research_by_id[fid]
            environment = self.state.environment_by_id[fid]
            result = self._resolve_output(
                fid,
                task,
                RiskRecommendation,
                lambda e=finding, r=research, env=environment, a=agent: build_risk_task(e, r, env, a),
                agent,
                self.state.risk_failures,
                extra_validate=lambda rec: verify_scoring_matches_tool(rec, self.state.risk_call_log),
            )
            if result is not None:
                self.state.risk_by_id[fid] = result

    def _dispatch_tot(self, findings: list[EnrichedFinding]) -> None:
        """CLAUDE.md Section 6's gate: any finding in `findings` whose
        just-dispatched RiskRecommendation is bucket="contested" gets a
        tot.ToTRoot built from this run's own Research/Environment/Risk
        state and routed into run_tree_of_thought. Findings that never
        reached Risk (upstream failure) or landed in a real bucket are
        silently skipped -- this only ever fires on contested findings.

        `self.state.tot_usage` is set to the sum of every contested
        finding's usage in THIS call (overwritten, not accumulated across
        calls -- same shape as research_usage/environment_usage/
        risk_usage, which likewise reflect their most recent dispatch,
        not a running session total). A finding that fails still
        contributes whatever it spent before giving up
        (ToTDispatchError.usage) -- real API calls happened either way."""
        contested = [
            e
            for e in findings
            if self.state.risk_by_id.get(e.finding.finding_id) is not None
            and self.state.risk_by_id[e.finding.finding_id].bucket == Bucket.CONTESTED.value
        ]
        if not contested:
            return

        strategist = build_strategist_agent()
        critic = build_critic_agent()
        total_usage = UsageMetrics()
        for e in contested:
            fid = e.finding.finding_id
            root = ToTRoot(
                enriched=e,
                research=self.state.research_by_id[fid],
                environment=self.state.environment_by_id[fid],
                risk=self.state.risk_by_id[fid],
            )
            try:
                result = run_tree_of_thought(
                    root,
                    strategist,
                    critic,
                    verbose=self.verbose,
                    max_parse_attempts=self.max_parse_attempts,
                )
                self.state.tot_by_id[fid] = result
                total_usage.add_usage_metrics(result.usage)
            except ToTDispatchError as exc:
                self.state.tot_failures[fid] = str(exc)
                total_usage.add_usage_metrics(exc.usage)
        self.state.tot_usage = total_usage
