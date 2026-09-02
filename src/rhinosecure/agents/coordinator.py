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

**Grounding is enforced, not assumed.** After each Risk task completes,
`verify_scoring_matches_tool` (`agents/risk.py`) checks its risk_score/
bucket/rationale against what score_finding actually computed --
Coordinator raises rather than silently accepting a mismatch, which is
what "owns shared state" has to mean if the state is going to be trusted
by anything downstream.

All LLM calls happen inside the agents this module dispatches -- this
module itself never constructs a provider client or calls `get_llm`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from crewai import Crew, Process

from rhinosecure.agents.environment import (
    EnvironmentAssessment,
    build_environment_agent,
    build_environment_task,
    build_environment_tools,
)
from rhinosecure.agents.research import (
    ResearchFinding,
    build_research_agent,
    build_research_task,
    build_research_tools,
)
from rhinosecure.agents.risk import (
    RiskRecommendation,
    build_risk_agent,
    build_risk_task,
    build_risk_tools,
    verify_scoring_matches_tool,
)
from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.ingest import load_asset_index
from rhinosecure.schema import EnrichedFinding


class CoordinatorError(RuntimeError):
    """Raised when a stage is dispatched without the upstream state it
    depends on -- e.g. `replan` before any `run`, or Environment/Risk for a
    finding_id Research never produced output for."""


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


class Coordinator:
    def __init__(self, data_dir: Path, cache: SnapshotCache | None = None, *, verbose: bool = False):
        self.data_dir = data_dir
        self.cache = cache or SnapshotCache()
        self.verbose = verbose
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
        the tiebreak."""
        if self.state is None:
            raise CoordinatorError("no run has been dispatched yet")
        return sorted(self.state.risk_by_id.values(), key=lambda r: (-r.risk_score, r.finding_id))

    def _dispatch_research(self, findings: list[EnrichedFinding]) -> None:
        tools = build_research_tools(self.cache, self.state.research_call_log)
        agent = build_research_agent(tools)
        tasks = [build_research_task(e, agent) for e in findings]
        crew = Crew(agents=[agent], tasks=tasks, process=Process.sequential, verbose=self.verbose)
        crew.kickoff()
        self.state.research_usage = crew.usage_metrics
        for task in tasks:
            result: ResearchFinding = task.output.pydantic
            self.state.research_by_id[result.finding_id] = result

    def _dispatch_environment(self, findings: list[EnrichedFinding]) -> None:
        tools = build_environment_tools(self._asset_index, self.state.environment_call_log)
        agent = build_environment_agent(tools)
        tasks = []
        for e in findings:
            fid = e.finding.finding_id
            research = self.state.research_by_id.get(fid)
            if research is None:
                raise CoordinatorError(f"{fid}: no ResearchFinding in state -- run Research first")
            tasks.append(build_environment_task(e, research, agent))
        crew = Crew(agents=[agent], tasks=tasks, process=Process.sequential, verbose=self.verbose)
        crew.kickoff()
        self.state.environment_usage = crew.usage_metrics
        for task in tasks:
            result: EnvironmentAssessment = task.output.pydantic
            self.state.environment_by_id[result.finding_id] = result

    def _dispatch_risk(self, findings: list[EnrichedFinding]) -> None:
        tools = build_risk_tools(
            self.state.enriched_by_id, self.state.research_by_id, self.state.risk_call_log
        )
        agent = build_risk_agent(tools)
        tasks = []
        for e in findings:
            fid = e.finding.finding_id
            research = self.state.research_by_id.get(fid)
            environment = self.state.environment_by_id.get(fid)
            if research is None or environment is None:
                raise CoordinatorError(
                    f"{fid}: missing upstream research/environment output -- "
                    "run Research and Environment first"
                )
            tasks.append(build_risk_task(e, research, environment, agent))
        crew = Crew(agents=[agent], tasks=tasks, process=Process.sequential, verbose=self.verbose)
        crew.kickoff()
        self.state.risk_usage = crew.usage_metrics
        for task in tasks:
            result: RiskRecommendation = task.output.pydantic
            verify_scoring_matches_tool(result, self.state.risk_call_log)
            self.state.risk_by_id[result.finding_id] = result
