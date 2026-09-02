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
and Risk for these finding_ids," a mechanical re-dispatch, not an
interpretation of free-form human constraint text -- that interpretation
step (Slice 4: constraint intake, ToT, `tot.py`) is genuinely LLM-shaped
work and is not built yet. If and when it is, it slots in ahead of
`replan`'s `finding_ids` argument, not inside this class.

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

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TypeVar

from crewai import Agent, Crew, Process, Task
from pydantic import BaseModel

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
    verify_scoring_matches_tool,
)
from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.ingest import load_asset_index
from rhinosecure.schema import EnrichedFinding

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
    research_call_log: list[dict[str, Any]] = field(default_factory=list)
    environment_call_log: list[dict[str, Any]] = field(default_factory=list)
    risk_call_log: list[dict[str, Any]] = field(default_factory=list)
    # Each stage's crewai UsageMetrics from its most recent dispatch --
    # token accounting for cost visibility, not anything scoring reads.
    research_usage: Any = None
    environment_usage: Any = None
    risk_usage: Any = None
    # finding_id -> why it has no result for that stage, whether it failed
    # there directly or was skipped because an earlier stage failed for it.
    research_failures: dict[str, str] = field(default_factory=dict)
    environment_failures: dict[str, str] = field(default_factory=dict)
    risk_failures: dict[str, str] = field(default_factory=dict)


class Coordinator:
    def __init__(
        self,
        data_dir: Path,
        cache: SnapshotCache | None = None,
        *,
        verbose: bool = False,
        max_parse_attempts: int = DEFAULT_MAX_PARSE_ATTEMPTS,
    ):
        self.data_dir = data_dir
        self.cache = cache or SnapshotCache()
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
        return self.ranked()

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

        tools = build_environment_tools(self._asset_index, self.state.environment_call_log)
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
            self.state.enriched_by_id, self.state.research_by_id, self.state.risk_call_log
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
