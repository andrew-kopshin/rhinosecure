"""Tree-of-Thought (CLAUDE.md Section 6): beam search over remediation
strategies for CONTESTED findings -- findings scoring.py's bucket_for
could not honestly place in any of the four real remediation buckets
(Section 3). A "thought" here is a remediation strategy, never an
explanation -- Section 6's own framing -- and this module never touches
risk_score or bucket: those stay scoring.py's sole, deterministic
property (Section 8 rule 2). ToT only decides HOW to remediate a finding
whose priority scoring.py already, correctly, refused to force into one
of the four ordinary categories.

**The canonical branch set does not apply to the only gate that exists
today.** Section 6's three canonical branches -- patch immediately /
compensating control + defer / accept and monitor -- assume a control
already exists to defer behind, and treat accept as viable. Neither
holds for bucket_for's contested case (Section 3, Section 6's "First
concrete gate"): a KEV-listed finding is disqualified from accept by
definition (bucket_for's own is_kev-disqualifies-accept rule), and by
construction has no compensating control to defer behind -- that
absence is *why* it's contested, not an incidental detail. Branches that
presuppose either one aren't just weaker for this case, they're
incoherent for it. This module uses a different, fixed three instead,
each viable regardless of whether a control or window currently exists:

- emergency_change -- patch now, through an expedited change process,
  outside any declared window (there isn't one)
- establish_window -- formally schedule a maintenance window for this
  asset going forward, and patch within it
- build_control -- implement a real compensating control before the
  next patch cycle

If a future contested case reaches ToT through a different bucket_for
rule (Section 6 notes these remain future work) where an existing
control or accept genuinely is on the table, that case may need its own
branch set -- this one is scoped to the gate that actually exists.

**Critic scoring is a deterministic aggregation over LLM-assessed axes,
not an LLM-computed number.** CritiqueOutput below has no total/aggregate
field at all -- the model is never asked to combine risk_reduction,
operational_cost, constraint_compliance, evidence_strength, and
contradicting_evidence into one score, so there is nothing for it to
mis-add. Same reason RiskRecommendation.risk_score can only ever be a
verbatim copy of score_finding's answer (agents/risk.py) -- only
CriticScores.aggregate, ordinary Python arithmetic, produces the number
beam pruning and clear-winner detection actually compare.

**Depth is refinement, not new branches.** ~3 initial thoughts are
proposed once, critiqued, and pruned to beam_width -- from there, each
surviving thought is the SAME strategy, strengthened round over round in
response to the critic's own feedback, not replaced by a different
strategy. A remediation-strategy space this small (three fixed, named
options) doesn't have enough genuinely distinct branches to explore
breadth-first past depth 1; what depth 2/3 buys is pressure-testing each
survivor against its own weakest point, which is also what makes
"exhausted evidence" (Section 6's third termination condition) a
coherent thing for the strategist to report: refinement, unlike
branching, can genuinely run out of runway.

All LLM calls route through `rhinosecure.llm.get_llm` -- this module
never constructs a provider client itself (Trust boundary section).
Tasks built here never set `output_pydantic`, for the same reason
research.py/environment.py/risk.py stopped (agents/parsing.py's module
docstring has the full incident) -- raw text is parsed by
`agents.parsing.parse_structured_output` and retried by this module's
own `_dispatch_batch`/`_resolve`, capped at `max_parse_attempts`. Unlike
agents/coordinator.py's per-finding skip-and-continue, a ToT parse
failure that survives the cap raises `ToTDispatchError` and aborts the
WHOLE tree for that one finding -- a beam search with one silently
missing branch is a different, unreported search, not a smaller version
of the same one. `agents/coordinator.py`'s `_dispatch_tot` catches that
per contested finding and records it into `RunState.tot_failures`, so
one finding's ToT failure still can't block the rest of the run -- the
same guarantee every other stage already gives, at the finding
granularity instead of the thought granularity.

Lives at the repository-layout-specified `rhinosecure/tot.py` (CLAUDE.md
Section 9), not under `agents/`, even though it imports crewai and the
other agents' output types the same way they import each other --
CLAUDE.md's layout treats this as a distinct reasoning mechanism (beam
search over thoughts), not one more agent role.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, TypeVar

from crewai import Agent, Crew, Process, Task
from crewai.llms.base_llm import BaseLLM
from pydantic import BaseModel, Field

from rhinosecure.agents.environment import EnvironmentAssessment
from rhinosecure.agents.parsing import AgentOutputParseError, parse_structured_output
from rhinosecure.agents.research import ResearchFinding
from rhinosecure.agents.risk import RiskRecommendation
from rhinosecure.llm import get_llm
from rhinosecure.schema import EnrichedFinding

ModelT = TypeVar("ModelT", bound=BaseModel)

STRATEGIST_ROLE = "Tree-of-Thought Strategist"
CRITIC_ROLE = "Tree-of-Thought Critic"

BEAM_WIDTH = 2
MAX_DEPTH = 3
# Mirrors agents/coordinator.py's DEFAULT_MAX_PARSE_ATTEMPTS -- not
# imported from there, to avoid a circular import (coordinator.py
# imports this module, not the other way around).
DEFAULT_MAX_PARSE_ATTEMPTS = 3
# Gap between the top two beam members' aggregate scores (0-10 scale)
# needed to call it a clear winner and stop before max_depth. 2.0 is a
# fifth of the full range -- enough that a couple tenths of scoring
# noise between rounds can't spuriously trigger it, small enough to
# resolve a genuinely one-sided case in fewer than 3 rounds.
CLEAR_WINNER_MARGIN = 2.0


class Strategy(str, Enum):
    EMERGENCY_CHANGE = "emergency_change"
    ESTABLISH_WINDOW = "establish_window"
    BUILD_CONTROL = "build_control"


STRATEGY_GUIDANCE: dict[Strategy, str] = {
    Strategy.EMERGENCY_CHANGE: (
        "Emergency change outside any window: patch this finding now, "
        "through an emergency/expedited change process, rather than "
        "waiting for a declared maintenance window -- there isn't one."
    ),
    Strategy.ESTABLISH_WINDOW: (
        "Establish a maintenance window for the asset: formally schedule "
        "and declare a patch window for this asset going forward, and "
        "patch within it."
    ),
    Strategy.BUILD_CONTROL: (
        "Build a compensating control before the next cycle: implement a "
        "concrete mitigating control (e.g. network isolation, WAF/IPS "
        "rule, access restriction) that reduces exposure until the asset "
        "can be patched on its next cycle."
    ),
}

# risk_reduction weighted highest: the reason a strategy exists at all is
# to reduce risk on a finding CISA has confirmed is being exploited.
# contradicting_evidence weighted second, and as a penalty: evidence that
# argues against a strategy should be able to overrule an otherwise
# appealing one -- the same "an observation should not be diluted by a
# disagreeing prediction" argument behind scoring.py's KEV floor, applied
# here to a strategy instead of a CVE. constraint_compliance next --
# CLAUDE.md's whole thesis is that operational constraints modulate a
# technical decision. evidence_strength next. operational_cost weighted
# lowest, deliberately: cost is real (it's why "establish a window" and
# "build a control" exist as branches at all, not just "always emergency
# patch") but must not be able to outweigh confirmed exploitation on its
# own -- the same reason is_kev disqualifies accept regardless of cost or
# convenience (scoring.py's bucket_for).
AGGREGATE_WEIGHTS: dict[str, float] = {
    "risk_reduction": 0.35,
    "contradicting_evidence": 0.25,
    "constraint_compliance": 0.20,
    "evidence_strength": 0.15,
    "operational_cost": 0.05,
}


@dataclass(frozen=True)
class CriticScores:
    """Five raw axis scores (0-10 each), from CritiqueOutput. `aggregate`
    is the only combination of them anywhere -- see module docstring for
    why the model itself is never asked to produce one."""

    risk_reduction: float
    operational_cost: float
    constraint_compliance: float
    evidence_strength: float
    contradicting_evidence: float
    justification: str

    @property
    def aggregate(self) -> float:
        return (
            AGGREGATE_WEIGHTS["risk_reduction"] * self.risk_reduction
            + AGGREGATE_WEIGHTS["constraint_compliance"] * self.constraint_compliance
            + AGGREGATE_WEIGHTS["evidence_strength"] * self.evidence_strength
            + AGGREGATE_WEIGHTS["operational_cost"] * (10 - self.operational_cost)
            + AGGREGATE_WEIGHTS["contradicting_evidence"] * (10 - self.contradicting_evidence)
        )


@dataclass(frozen=True)
class Thought:
    """One scored node in the search -- a remediation strategy at a given
    depth, never an explanation (Section 6). `exhausted` means the
    strategist found nothing left to strengthen as of this depth; its
    `critic` score in that case is carried forward from its own last
    depth unchanged, not re-scored (see run_tree_of_thought)."""

    strategy: Strategy
    depth: int
    proposal: str
    critic: CriticScores
    exhausted: bool = False
    exhaustion_reason: str = ""

    @property
    def score(self) -> float:
        return self.critic.aggregate


@dataclass(frozen=True)
class _RawThought:
    """A strategist response before it has been critiqued -- proposal
    text plus (from depth 2 on) whether the strategist reported nothing
    left to add. Never leaves this module."""

    strategy: Strategy
    depth: int
    proposal: str
    exhausted: bool = False
    exhaustion_reason: str = ""


@dataclass(frozen=True)
class ToTRoot:
    """The contested finding plus all gathered evidence (Section 6:
    "Root: the contested finding plus all gathered evidence") -- the
    fixed context every propose/critique/refine task is given. Building
    one at all is agents/coordinator.py's `_dispatch_tot`'s call to make
    (only for a finding whose RiskRecommendation.bucket is "contested");
    nothing in this module enforces that gate itself."""

    enriched: EnrichedFinding
    research: ResearchFinding
    environment: EnvironmentAssessment
    risk: RiskRecommendation


@dataclass(frozen=True)
class ToTResult:
    """One finding's beam search outcome. `winner` is set only when
    `near_tie` is False -- Section 6: "Near-tie -> surface both branches
    to the human. Do not force a single answer." `candidates` is always
    the final beam, ranked best-first (length == beam_width)."""

    finding_id: str
    winner: Thought | None
    near_tie: bool
    candidates: tuple[Thought, ...]
    termination_reason: str  # "clear_winner" | "depth_limit" | "exhausted_evidence"
    depth_reached: int


class ProposalOutput(BaseModel):
    strategy: str
    proposal: str


class CritiqueOutput(BaseModel):
    strategy: str
    risk_reduction: float = Field(ge=0, le=10)
    operational_cost: float = Field(ge=0, le=10)
    constraint_compliance: float = Field(ge=0, le=10)
    evidence_strength: float = Field(ge=0, le=10)
    contradicting_evidence: float = Field(ge=0, le=10)
    justification: str


class RefinementOutput(BaseModel):
    strategy: str
    proposal: str
    exhausted: bool
    exhaustion_reason: str = ""


class ToTDispatchError(RuntimeError):
    """Raised when a strategist/critic response for one thought never
    parses, or echoes the wrong strategy, within max_parse_attempts --
    see module docstring for why this aborts the whole tree rather than
    dropping the one thought."""


def build_strategist_agent(llm: BaseLLM | None = None) -> Agent:
    """`llm` defaults to the trust-boundary seam's `get_llm()` -- pass one
    explicitly (as tests do, with a throwaway key) to avoid depending on
    real `.env` state at construction time. No tools: unlike Research's
    external sources or Risk's score_finding, there is no deterministic
    fact source this role must be forced through -- its evidence is the
    ToTRoot text embedded directly in each task, the same way Risk embeds
    Research/Environment context as prose."""
    return Agent(
        role=STRATEGIST_ROLE,
        goal=(
            "Propose and refine one concrete remediation strategy at a "
            "time for a finding the deterministic scorer could not "
            "honestly bucket, using only the evidence given. Never invent "
            "a fact not present in that evidence, and never assign a risk "
            "score or bucket -- that stays scoring.py's job."
        ),
        backstory=(
            "A remediation planner who turns a contested finding's "
            "evidence into a concrete, executable plan for one specific "
            "strategy, and who says so plainly when a strategy has "
            "nothing left to strengthen rather than padding it with "
            "restatement."
        ),
        llm=llm or get_llm(),
        verbose=True,
    )


def build_critic_agent(llm: BaseLLM | None = None) -> Agent:
    """See build_strategist_agent's docstring for the no-tools rationale
    -- applies here too."""
    return Agent(
        role=CRITIC_ROLE,
        goal=(
            "Score one proposed remediation strategy, strictly from the "
            "evidence given, on risk reduction, operational cost, "
            "constraint compliance, evidence strength, and contradicting "
            "evidence. Score each strategy on its own merits, not by "
            "comparison to any other candidate."
        ),
        backstory=(
            "An independent reviewer who never authored the strategy "
            "being scored, and is exactly as willing to score one low as "
            "high when the evidence says so."
        ),
        llm=llm or get_llm(),
        verbose=True,
    )


def _describe_root(root: ToTRoot) -> str:
    finding = root.enriched.finding
    env = root.environment
    research = root.research
    kev_note = f" (added {research.kev_date_added})" if research.kev_date_added else ""
    rationale = "\n".join(f"  - {line}" for line in root.risk.scoring_rationale)
    return (
        f"Finding {finding.finding_id}: CVE {research.cve_id} on {env.hostname} "
        f"({env.asset_id}).\n"
        f"Research: NVD severity {research.nvd_severity or 'unknown'} (base score "
        f"{research.nvd_base_score}), KEV-listed: {research.is_kev}{kev_note}, EPSS: "
        f"{research.epss_score}. {research.exploitation_summary}\n"
        f"Environment: OS {env.os} (build {env.os_build}), role {env.role}, "
        f"environment {env.environment}, internet_exposed: {env.internet_exposed}, "
        f"compensating_controls: {env.compensating_controls or 'none'}, "
        f"has_patch_window: {env.has_patch_window} "
        f"({env.patch_window or 'none declared'}). {env.applicability_summary}\n"
        f"Deterministic scoring: risk_score={root.risk.risk_score:.1f}/100, "
        "bucket=contested. Rationale:\n"
        f"{rationale}"
    )


_EXPECTED_OUTPUT_PREFIX = (
    "Return ONLY a single JSON object, with these keys directly at the top "
    "level -- not wrapped in any container key, and no markdown code "
    "fences or prose before or after it: "
)


def _build_propose_task(root: ToTRoot, strategy: Strategy, agent: Agent) -> Task:
    return Task(
        description=(
            f"{_describe_root(root)}\n\n"
            "This finding has no honest bucket among the four standard "
            "remediation categories (patch_now/next_window/"
            "mitigate_monitor/accept) -- it is KEV-listed (confirmed "
            "exploited in the wild) with no compensating control and no "
            "patch window, so none of them are true. Propose ONE concrete "
            "remediation strategy for THIS specific finding and asset: "
            f"{STRATEGY_GUIDANCE[strategy]}\n\n"
            "Be concrete: state what would actually happen, who would be "
            "involved, and how it addresses the fact that this is a "
            "confirmed-exploited vulnerability. Do not introduce any fact "
            "not present in the evidence above."
        ),
        expected_output=(
            f"{_EXPECTED_OUTPUT_PREFIX}strategy (echo exactly the string "
            f'"{strategy.value}"), and proposal (a concrete paragraph '
            "describing this strategy for this specific finding)."
        ),
        agent=agent,
    )


def _build_critique_task(root: ToTRoot, thought: _RawThought, agent: Agent) -> Task:
    return Task(
        description=(
            f"{_describe_root(root)}\n\n"
            f"Proposed remediation strategy ({thought.strategy.value}): "
            f"{thought.proposal}\n\n"
            "Score this proposed strategy on five axes, each 0-10, on its "
            "own merits -- do not compare it to any other candidate "
            "strategy:\n"
            "- risk_reduction: how much this strategy actually reduces "
            "risk for a confirmed-exploited (KEV-listed) finding. 10 = "
            "closes the exposure fully and promptly, 0 = does nothing.\n"
            "- operational_cost: how disruptive or expensive this "
            "strategy is to execute. 10 = severe disruption or cost, 0 = "
            "negligible.\n"
            "- constraint_compliance: how well it respects this asset's "
            "declared operational constraints (patch_restrictions, "
            "business hours, etc). 10 = fully compliant, 0 = violates "
            "them.\n"
            "- evidence_strength: how well the evidence above actually "
            "supports this being workable for this specific asset. 10 = "
            "strongly supported, 0 = unsupported speculation.\n"
            "- contradicting_evidence: how much of the evidence above "
            "actively argues against this strategy. 10 = strong "
            "contradicting evidence, 0 = none.\n\n"
            "Then write a short justification citing which evidence "
            "drove each score."
        ),
        expected_output=(
            f"{_EXPECTED_OUTPUT_PREFIX}strategy (echo exactly the string "
            f'"{thought.strategy.value}"), risk_reduction, '
            "operational_cost, constraint_compliance, evidence_strength, "
            "and contradicting_evidence (each a number 0-10), and "
            "justification (a short paragraph)."
        ),
        agent=agent,
    )


def _build_refine_task(root: ToTRoot, thought: Thought, agent: Agent) -> Task:
    critic = thought.critic
    return Task(
        description=(
            f"{_describe_root(root)}\n\n"
            f"Your previously proposed strategy ({thought.strategy.value}): "
            f"{thought.proposal}\n\n"
            "A critic scored it: risk_reduction="
            f"{critic.risk_reduction}/10, operational_cost="
            f"{critic.operational_cost}/10, constraint_compliance="
            f"{critic.constraint_compliance}/10, evidence_strength="
            f"{critic.evidence_strength}/10, contradicting_evidence="
            f"{critic.contradicting_evidence}/10. Justification: "
            f"{critic.justification}\n\n"
            "Strengthen this SAME strategy (do not switch to a different "
            "strategy) to address its weakest point(s), using only the "
            "evidence already given above -- do not invent new facts. If "
            "there is genuinely nothing more to add given the evidence "
            "available -- you would just be restating the same proposal "
            "-- say so instead of padding it."
        ),
        expected_output=(
            f"{_EXPECTED_OUTPUT_PREFIX}strategy (echo exactly the string "
            f'"{thought.strategy.value}"), proposal (the strengthened '
            "paragraph, or the same proposal if unchanged), exhausted "
            "(true if there is nothing more to add given the evidence "
            "available, false if you strengthened it), and "
            "exhaustion_reason (a short string explaining why if "
            "exhausted is true, else an empty string)."
        ),
        agent=agent,
    )


def _parse_and_check_strategy(task: Task, model: type[ModelT], expected: Strategy) -> ModelT:
    result = parse_structured_output(task.output.raw, model)
    echoed = getattr(result, "strategy")
    if echoed != expected.value:
        raise AgentOutputParseError(
            f"expected strategy={expected.value!r}, agent echoed {echoed!r}"
        )
    return result


def _dispatch_batch(
    agent: Agent,
    build_task: Callable[[int], Task],
    count: int,
    parse_one: Callable[[Task, int], ModelT],
    *,
    max_parse_attempts: int,
    verbose: bool,
) -> list[ModelT]:
    """Batch `count` tasks onto one Crew, then resolve each independently
    -- a stuck task gets its own single-task retry Crew, the same shape
    as agents/coordinator.py's `_resolve_output`, without sharing code
    with it: failure here means abort the whole tree, not skip one of
    many findings (see module docstring)."""
    tasks = [build_task(i) for i in range(count)]
    Crew(agents=[agent], tasks=tasks, process=Process.sequential, verbose=verbose).kickoff()
    return [
        _resolve(
            agent,
            task,
            lambda i=i: build_task(i),
            lambda t, i=i: parse_one(t, i),
            max_parse_attempts,
            verbose,
        )
        for i, task in enumerate(tasks)
    ]


def _resolve(
    agent: Agent,
    task: Task,
    rebuild: Callable[[], Task],
    parse_task: Callable[[Task], ModelT],
    max_parse_attempts: int,
    verbose: bool,
) -> ModelT:
    last_error: Exception | None = None
    for attempt in range(1, max_parse_attempts + 1):
        try:
            return parse_task(task)
        except AgentOutputParseError as exc:
            last_error = exc
            if attempt == max_parse_attempts:
                break
            task = rebuild()
            Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=verbose).kickoff()
    raise ToTDispatchError(f"gave up after {max_parse_attempts} attempt(s): {last_error}")


def _propose_initial(
    root: ToTRoot, agent: Agent, *, max_parse_attempts: int, verbose: bool
) -> list[_RawThought]:
    strategies = list(Strategy)
    outputs = _dispatch_batch(
        agent,
        lambda i: _build_propose_task(root, strategies[i], agent),
        len(strategies),
        lambda task, i: _parse_and_check_strategy(task, ProposalOutput, strategies[i]),
        max_parse_attempts=max_parse_attempts,
        verbose=verbose,
    )
    return [
        _RawThought(strategy=s, depth=1, proposal=o.proposal) for s, o in zip(strategies, outputs)
    ]


def _critique(
    raw_thoughts: list[_RawThought],
    root: ToTRoot,
    agent: Agent,
    *,
    max_parse_attempts: int,
    verbose: bool,
) -> list[Thought]:
    outputs = _dispatch_batch(
        agent,
        lambda i: _build_critique_task(root, raw_thoughts[i], agent),
        len(raw_thoughts),
        lambda task, i: _parse_and_check_strategy(task, CritiqueOutput, raw_thoughts[i].strategy),
        max_parse_attempts=max_parse_attempts,
        verbose=verbose,
    )
    return [
        Thought(
            strategy=t.strategy,
            depth=t.depth,
            proposal=t.proposal,
            exhausted=t.exhausted,
            exhaustion_reason=t.exhaustion_reason,
            critic=CriticScores(
                risk_reduction=o.risk_reduction,
                operational_cost=o.operational_cost,
                constraint_compliance=o.constraint_compliance,
                evidence_strength=o.evidence_strength,
                contradicting_evidence=o.contradicting_evidence,
                justification=o.justification,
            ),
        )
        for t, o in zip(raw_thoughts, outputs)
    ]


def _refine(
    beam: list[Thought],
    root: ToTRoot,
    agent: Agent,
    depth: int,
    *,
    max_parse_attempts: int,
    verbose: bool,
) -> list[_RawThought]:
    outputs = _dispatch_batch(
        agent,
        lambda i: _build_refine_task(root, beam[i], agent),
        len(beam),
        lambda task, i: _parse_and_check_strategy(task, RefinementOutput, beam[i].strategy),
        max_parse_attempts=max_parse_attempts,
        verbose=verbose,
    )
    return [
        _RawThought(
            strategy=b.strategy,
            depth=depth,
            proposal=o.proposal,
            exhausted=o.exhausted,
            exhaustion_reason=o.exhaustion_reason,
        )
        for b, o in zip(beam, outputs)
    ]


def _carry_forward(raw: _RawThought, parent: Thought) -> Thought:
    """An exhausted refinement keeps its parent's critic score rather
    than being re-critiqued on unchanged (or near-unchanged) content --
    see module docstring."""
    return Thought(
        strategy=raw.strategy,
        depth=raw.depth,
        proposal=raw.proposal,
        exhausted=raw.exhausted,
        exhaustion_reason=raw.exhaustion_reason,
        critic=parent.critic,
    )


def _prune(thoughts: list[Thought], beam_width: int) -> list[Thought]:
    return sorted(thoughts, key=lambda t: -t.score)[:beam_width]


def _score_gap(beam: list[Thought]) -> float:
    ranked = sorted(beam, key=lambda t: -t.score)
    if len(ranked) < 2:
        return float("inf")
    return ranked[0].score - ranked[1].score


def run_tree_of_thought(
    root: ToTRoot,
    strategist: Agent,
    critic: Agent,
    *,
    max_depth: int = MAX_DEPTH,
    beam_width: int = BEAM_WIDTH,
    max_parse_attempts: int = DEFAULT_MAX_PARSE_ATTEMPTS,
    verbose: bool = False,
) -> ToTResult:
    """Section 6's beam search over remediation strategies for one
    contested finding. ~3 initial thoughts (Strategy's fixed members),
    critiqued and pruned to `beam_width`; each survivor then refines in
    place (same strategy, strengthened) for up to `max_depth` rounds
    total. Stops early on a clear winner (score gap >=
    CLEAR_WINNER_MARGIN) or when every active beam member reports
    nothing left to add (exhausted evidence); otherwise runs out the
    full depth. The final beam's top two are always what
    `near_tie`/`winner`/`candidates` are computed from, regardless of
    which of the three reasons stopped the loop -- see ToTResult and the
    module docstring.
    """
    raw = _propose_initial(root, strategist, max_parse_attempts=max_parse_attempts, verbose=verbose)
    beam = _prune(
        _critique(raw, root, critic, max_parse_attempts=max_parse_attempts, verbose=verbose),
        beam_width,
    )

    depth = 1
    termination_reason = "depth_limit"
    while depth < max_depth:
        if _score_gap(beam) >= CLEAR_WINNER_MARGIN:
            termination_reason = "clear_winner"
            break
        # Only beam members that are NOT yet exhausted get refined this
        # round -- one that already reported nothing left to add stays
        # frozen (same Thought, same score) for every remaining round
        # rather than being re-dispatched to say so again.
        active_idx = [i for i, t in enumerate(beam) if not t.exhausted]
        if not active_idx:
            termination_reason = "exhausted_evidence"
            break
        depth += 1
        refined = _refine(
            [beam[i] for i in active_idx],
            root, strategist, depth, max_parse_attempts=max_parse_attempts, verbose=verbose,
        )
        refined_by_idx = dict(zip(active_idx, refined))
        still_active_raw = [r for r in refined if not r.exhausted]
        scored = (
            iter(_critique(still_active_raw, root, critic, max_parse_attempts=max_parse_attempts, verbose=verbose))
            if still_active_raw
            else iter(())
        )
        beam = [
            t if i not in refined_by_idx
            else (next(scored) if not refined_by_idx[i].exhausted else _carry_forward(refined_by_idx[i], t))
            for i, t in enumerate(beam)
        ]

    ranked = sorted(beam, key=lambda t: -t.score)
    near_tie = _score_gap(ranked) < CLEAR_WINNER_MARGIN
    return ToTResult(
        finding_id=root.enriched.finding.finding_id,
        winner=None if near_tie else ranked[0],
        near_tie=near_tie,
        candidates=tuple(ranked),
        termination_reason=termination_reason,
        depth_reached=depth,
    )
