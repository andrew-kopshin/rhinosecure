import json
from types import SimpleNamespace

import pytest
from crewai.types.usage_metrics import UsageMetrics

from rhinosecure.agents.environment import EnvironmentAssessment
from rhinosecure.agents.parsing import AgentOutputParseError
from rhinosecure.agents.research import ResearchFinding
from rhinosecure.agents.risk import RiskRecommendation
from rhinosecure.llm import LLMConfig, get_llm
from rhinosecure.schema import Asset, EnrichedFinding, Finding
from rhinosecure import tot as tot_module
from rhinosecure.tot import (
    AGGREGATE_WEIGHTS,
    CLEAR_WINNER_MARGIN,
    CriticScores,
    ProposalOutput,
    Strategy,
    Thought,
    ToTDispatchError,
    ToTRoot,
    _build_critique_task,
    _build_propose_task,
    _build_refine_task,
    _parse_and_check_strategy,
    _prune,
    _score_gap,
    build_critic_agent,
    build_strategist_agent,
    run_tree_of_thought,
)

# --- fixtures: the real F14 shape (KEV, no control, no window) --------------

ASSET = Asset(
    asset_id="A09",
    hostname="WKS-FIN12",
    os="Windows 10",
    os_build="19045",
    role="workstation",
    business_function="Finance workstation",
    criticality=3,
    internet_exposed=False,
    environment="prod",
    data_sensitivity="confidential",
    patch_window="",
    patch_restrictions="",
    compensating_controls="",
    owner="finance-it",
)

FINDING = Finding(
    finding_id="F14",
    asset_id="A09",
    cve_id="CVE-2023-23397",
    scanner_severity="low",
    product="Microsoft Outlook",
    version="365",
    evidence="Reminder task triggers NTLM hash leak via crafted appointment",
)

ENRICHED = EnrichedFinding(finding=FINDING, asset=ASSET)

RESEARCH = ResearchFinding(
    finding_id="F14",
    cve_id="CVE-2023-23397",
    scanner_severity="low",
    nvd_base_score=9.8,
    nvd_severity="critical",
    severity_disagreement=True,
    is_kev=True,
    kev_date_added="2023-03-14",
    epss_score=0.94,
    epss_percentile=0.99,
    attack_techniques=[],
    exploitation_summary="KEV-listed, high EPSS; NVD rates this critical though the scanner called it low.",
    sources=["nvd", "kev", "epss"],
)

ENVIRONMENT = EnvironmentAssessment(
    finding_id="F14",
    cve_id="CVE-2023-23397",
    asset_id="A09",
    hostname="WKS-FIN12",
    os="Windows 10",
    os_build="19045",
    os_build_consistent=True,
    role="workstation",
    environment="prod",
    internet_exposed=False,
    compensating_controls=[],
    has_patch_window=False,
    patch_window="",
    patch_restrictions="",
    applicability_summary="Outlook 365 is consistent with this workstation.",
    sources=["lookup_asset_context(asset_id=A09)"],
)

RISK = RiskRecommendation(
    finding_id="F14",
    cve_id="CVE-2023-23397",
    asset_id="A09",
    hostname="WKS-FIN12",
    risk_score=30.62,
    bucket="contested",
    scoring_rationale=[
        "scanner_severity='low' vs NVD CVSS 9.8 (critical) -- disagreement: NVD is authoritative",
        "bucket=contested: is_kev=True with no compensating control and no patch window -- "
        "not accept, not mitigate_monitor, not next_window.",
    ],
    verdict_summary="Contested: confirmed KEV exploitation with no control or window to lean on.",
    narrative="fake narrative",
    sources=["Vulnerability Research", "Environment Analysis", "score_finding"],
)

ROOT = ToTRoot(enriched=ENRICHED, research=RESEARCH, environment=ENVIRONMENT, risk=RISK)


def _fake_llm():
    return get_llm(LLMConfig(model="claude-sonnet-5", api_key="sk-test-key"))


# --- CriticScores.aggregate ---------------------------------------------------


def test_aggregate_weights_sum_to_one():
    assert sum(AGGREGATE_WEIGHTS.values()) == pytest.approx(1.0)


def test_aggregate_is_ten_when_every_axis_is_maximally_favorable():
    c = CriticScores(
        risk_reduction=10,
        operational_cost=0,
        constraint_compliance=10,
        evidence_strength=10,
        contradicting_evidence=0,
        justification="",
    )
    assert c.aggregate == pytest.approx(10.0)


def test_aggregate_is_zero_when_every_axis_is_maximally_unfavorable():
    c = CriticScores(
        risk_reduction=0,
        operational_cost=10,
        constraint_compliance=0,
        evidence_strength=0,
        contradicting_evidence=10,
        justification="",
    )
    assert c.aggregate == pytest.approx(0.0)


def test_aggregate_matches_a_hand_computed_example():
    # 0.35*9 + 0.20*8 + 0.15*8 + 0.05*(10-3) + 0.25*(10-1) = 8.55
    c = CriticScores(
        risk_reduction=9,
        operational_cost=3,
        constraint_compliance=8,
        evidence_strength=8,
        contradicting_evidence=1,
        justification="j",
    )
    assert c.aggregate == pytest.approx(8.55)


def test_aggregate_cannot_be_influenced_by_the_model_directly():
    """CritiqueOutput (the LLM-parsed schema) has no aggregate/total field
    -- the only way to get one is CriticScores.aggregate's own arithmetic,
    the same "model never computes the number" property score_finding's
    tool gives risk_score (agents/risk.py)."""
    from rhinosecure.tot import CritiqueOutput

    assert "aggregate" not in CritiqueOutput.model_fields
    assert "total" not in CritiqueOutput.model_fields


# --- Strategy: the substituted branch set, not the canonical one ------------


def test_strategy_is_exactly_the_three_substituted_branches():
    """CLAUDE.md Section 6's canonical three (patch immediately /
    compensating control + defer / accept and monitor) don't apply to the
    only gate that exists (KEV + no control + no window: accept is
    disqualified, and there is no control to defer behind). These three
    are the substitute, each viable regardless of whether a control or
    window currently exists."""
    assert list(Strategy) == [Strategy.EMERGENCY_CHANGE, Strategy.ESTABLISH_WINDOW, Strategy.BUILD_CONTROL]
    assert Strategy.EMERGENCY_CHANGE.value == "emergency_change"
    assert Strategy.ESTABLISH_WINDOW.value == "establish_window"
    assert Strategy.BUILD_CONTROL.value == "build_control"


# --- _prune / _score_gap ------------------------------------------------------


def _thought(strategy: Strategy, **scores) -> Thought:
    return Thought(
        strategy=strategy, depth=1, proposal="p", critic=CriticScores(justification="j", **scores)
    )


def test_prune_keeps_top_beam_width_by_aggregate_score():
    thoughts = [
        _thought(  # aggregate 8.55
            Strategy.EMERGENCY_CHANGE,
            risk_reduction=9, operational_cost=3, constraint_compliance=8,
            evidence_strength=8, contradicting_evidence=1,
        ),
        _thought(  # aggregate 3.55
            Strategy.ESTABLISH_WINDOW,
            risk_reduction=3, operational_cost=5, constraint_compliance=4,
            evidence_strength=3, contradicting_evidence=6,
        ),
        _thought(  # aggregate 2.55 -- lowest, must be dropped
            Strategy.BUILD_CONTROL,
            risk_reduction=2, operational_cost=6, constraint_compliance=3,
            evidence_strength=2, contradicting_evidence=7,
        ),
    ]
    pruned = _prune(thoughts, 2)
    assert [t.strategy for t in pruned] == [Strategy.EMERGENCY_CHANGE, Strategy.ESTABLISH_WINDOW]


def test_score_gap_is_infinite_with_fewer_than_two_thoughts():
    assert _score_gap([_thought(Strategy.BUILD_CONTROL, risk_reduction=5, operational_cost=5,
                                 constraint_compliance=5, evidence_strength=5, contradicting_evidence=5)]) == float("inf")


# --- _parse_and_check_strategy (the grounding cross-check) ------------------


def test_parse_and_check_strategy_succeeds_when_echoed_strategy_matches():
    task = SimpleNamespace(output=SimpleNamespace(raw=json.dumps({"strategy": "build_control", "proposal": "x"})))
    result = _parse_and_check_strategy(task, ProposalOutput, Strategy.BUILD_CONTROL)
    assert result.proposal == "x"


def test_parse_and_check_strategy_raises_when_echoed_strategy_is_wrong():
    raw = json.dumps({"strategy": "build_control", "proposal": "x"})
    task = SimpleNamespace(output=SimpleNamespace(raw=raw))
    with pytest.raises(AgentOutputParseError) as exc_info:
        _parse_and_check_strategy(task, ProposalOutput, Strategy.EMERGENCY_CHANGE)
    assert exc_info.value.raw == raw  # available for --verbose even on a grounding mismatch


# --- ToTDispatchError.usage / .raw ---------------------------------------------


def test_tot_dispatch_error_defaults_to_empty_usage_not_none():
    exc = ToTDispatchError("gave up")
    assert exc.usage == UsageMetrics()


def test_tot_dispatch_error_carries_the_usage_it_was_given():
    usage = UsageMetrics(total_tokens=42, successful_requests=3)
    exc = ToTDispatchError("gave up", usage=usage)
    assert exc.usage is usage


def test_tot_dispatch_error_defaults_raw_to_none():
    exc = ToTDispatchError("gave up")
    assert exc.raw is None


def test_tot_dispatch_error_carries_the_raw_output_it_was_given():
    exc = ToTDispatchError("gave up", raw="not json at all")
    assert exc.raw == "not json at all"


# --- agent/task construction (no network, no LLM call) -----------------------


def test_build_strategist_agent_has_role_and_no_tools():
    from rhinosecure.agents.limits import MAX_AGENT_EXECUTION_SECONDS

    agent = build_strategist_agent(llm=_fake_llm())
    assert agent.role == "Tree-of-Thought Strategist"
    assert not agent.tools
    assert agent.max_execution_time == MAX_AGENT_EXECUTION_SECONDS


def test_build_critic_agent_has_role_and_no_tools():
    from rhinosecure.agents.limits import MAX_AGENT_EXECUTION_SECONDS

    agent = build_critic_agent(llm=_fake_llm())
    assert agent.role == "Tree-of-Thought Critic"
    assert not agent.tools
    assert agent.max_execution_time == MAX_AGENT_EXECUTION_SECONDS


def test_build_propose_task_embeds_root_evidence_and_strategy_guidance():
    agent = build_strategist_agent(llm=_fake_llm())
    task = _build_propose_task(ROOT, Strategy.BUILD_CONTROL, agent)

    assert task.output_pydantic is None  # own parsing, not CrewAI's converter -- see module docstring
    assert "F14" in task.description
    assert "CVE-2023-23397" in task.description
    assert "WKS-FIN12" in task.description
    assert "KEV-listed: True" in task.description
    assert "Build a compensating control before the next cycle" in task.description
    assert "not wrapped in any container key" in task.expected_output
    assert '"build_control"' in task.expected_output


def test_build_critique_task_embeds_the_proposal_and_five_axes():
    agent = build_critic_agent(llm=_fake_llm())
    raw = tot_module._RawThought(strategy=Strategy.EMERGENCY_CHANGE, depth=1, proposal="Patch WKS-FIN12 tonight.")
    task = _build_critique_task(ROOT, raw, agent)

    assert task.output_pydantic is None
    assert "Patch WKS-FIN12 tonight." in task.description
    assert "risk_reduction" in task.description
    assert "operational_cost" in task.description
    assert "constraint_compliance" in task.description
    assert "evidence_strength" in task.description
    assert "contradicting_evidence" in task.description
    assert '"emergency_change"' in task.expected_output


def test_build_refine_task_embeds_prior_proposal_and_critic_feedback():
    agent = build_strategist_agent(llm=_fake_llm())
    thought = Thought(
        strategy=Strategy.ESTABLISH_WINDOW,
        depth=1,
        proposal="Establish a Sunday window.",
        critic=CriticScores(
            risk_reduction=6, operational_cost=3, constraint_compliance=8,
            evidence_strength=6, contradicting_evidence=3, justification="Reasonable but slow.",
        ),
    )
    task = _build_refine_task(ROOT, thought, agent)

    assert "Establish a Sunday window." in task.description
    assert "Reasonable but slow." in task.description
    assert "exhausted" in task.expected_output
    assert '"establish_window"' in task.expected_output


# --- run_tree_of_thought: full beam search, fake Crew -----------------------


class _QueuedFakeCrew:
    """Stands in for crewai.Crew -- pops one raw JSON text string per task
    off a shared queue, in dispatch order, exactly like
    test_coordinator.py's _QueuedFakeCrew (no tools here, so no
    score_finding special-casing is needed). usage_metrics scales with
    task count (1 "request" per task) so accumulation across multiple
    Crew instantiations is predictable to assert on."""

    queue: list = []
    instantiations: int = 0

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.tasks = tasks
        type(self).instantiations += 1
        self.usage_metrics = UsageMetrics(
            total_tokens=100 * len(tasks),
            prompt_tokens=80 * len(tasks),
            completion_tokens=20 * len(tasks),
            successful_requests=len(tasks),
        )

    def kickoff(self):
        for task in self.tasks:
            task.output = SimpleNamespace(raw=_QueuedFakeCrew.queue.pop(0))
        return None


@pytest.fixture(autouse=True)
def fake_crew(monkeypatch):
    _QueuedFakeCrew.queue = []
    _QueuedFakeCrew.instantiations = 0
    monkeypatch.setattr(tot_module, "Crew", _QueuedFakeCrew)
    return _QueuedFakeCrew


UNPARSEABLE = "this is not json and will never parse, no matter how many times you ask"


def _proposal(strategy: Strategy, proposal: str) -> str:
    return json.dumps({"strategy": strategy.value, "proposal": proposal})


def _critique(strategy: Strategy, **scores) -> str:
    return json.dumps({"strategy": strategy.value, "justification": "fake justification", **scores})


def _refinement(strategy: Strategy, proposal: str, *, exhausted: bool, reason: str = "") -> str:
    return json.dumps(
        {"strategy": strategy.value, "proposal": proposal, "exhausted": exhausted, "exhaustion_reason": reason}
    )


STRATEGIST = None
CRITIC = None


@pytest.fixture(autouse=True)
def agents():
    global STRATEGIST, CRITIC
    STRATEGIST = build_strategist_agent(llm=_fake_llm())
    CRITIC = build_critic_agent(llm=_fake_llm())


def test_clear_winner_terminates_at_depth_one_without_any_refinement():
    _QueuedFakeCrew.queue = [
        # depth-1 propose, one per Strategy, in enum order
        _proposal(Strategy.EMERGENCY_CHANGE, "Patch tonight via emergency change."),
        _proposal(Strategy.ESTABLISH_WINDOW, "Schedule a Sunday window."),
        _proposal(Strategy.BUILD_CONTROL, "Isolate the host on the network."),
        # depth-1 critique, same order -- emergency_change dominates (8.55 vs 3.55 vs 2.55)
        _critique(Strategy.EMERGENCY_CHANGE, risk_reduction=9, operational_cost=3,
                  constraint_compliance=8, evidence_strength=8, contradicting_evidence=1),
        _critique(Strategy.ESTABLISH_WINDOW, risk_reduction=3, operational_cost=5,
                  constraint_compliance=4, evidence_strength=3, contradicting_evidence=6),
        _critique(Strategy.BUILD_CONTROL, risk_reduction=2, operational_cost=6,
                  constraint_compliance=3, evidence_strength=2, contradicting_evidence=7),
    ]

    result = run_tree_of_thought(ROOT, STRATEGIST, CRITIC)

    assert result.termination_reason == "clear_winner"
    assert result.depth_reached == 1
    assert result.near_tie is False
    assert result.winner is not None
    assert result.winner.strategy == Strategy.EMERGENCY_CHANGE
    assert result.winner.score == pytest.approx(8.55)
    assert len(result.candidates) == 2  # beam_width, even though a winner was picked
    assert _QueuedFakeCrew.instantiations == 2  # one propose batch, one critique batch -- no refinement
    # usage sums both Crews' fake metrics: propose (3 tasks) + critique (3 tasks) = 6 "requests".
    assert result.usage.successful_requests == 6
    assert result.usage.total_tokens == 600


def test_depth_limit_with_close_scores_produces_a_near_tie_not_a_forced_winner():
    """Section 6: 'Near-tie -> surface both branches to the human. Do not
    force a single answer.' Scores stay within CLEAR_WINNER_MARGIN through
    all 3 rounds -- winner must be None, both final candidates returned."""
    _QueuedFakeCrew.queue = [
        # depth 1
        _proposal(Strategy.EMERGENCY_CHANGE, "Patch tonight."),
        _proposal(Strategy.ESTABLISH_WINDOW, "Schedule a window."),
        _proposal(Strategy.BUILD_CONTROL, "Add a control."),
        _critique(Strategy.EMERGENCY_CHANGE, risk_reduction=8, operational_cost=6,
                  constraint_compliance=7, evidence_strength=7, contradicting_evidence=2),  # 7.45
        _critique(Strategy.ESTABLISH_WINDOW, risk_reduction=6, operational_cost=3,
                  constraint_compliance=8, evidence_strength=6, contradicting_evidence=3),  # 6.70
        _critique(Strategy.BUILD_CONTROL, risk_reduction=5, operational_cost=4,
                  constraint_compliance=7, evidence_strength=5, contradicting_evidence=4),  # 5.70 -- pruned
        # depth 2: refine the surviving two (emergency_change, establish_window)
        _refinement(Strategy.EMERGENCY_CHANGE, "Patch tonight, refined.", exhausted=False),
        _refinement(Strategy.ESTABLISH_WINDOW, "Schedule a window, refined.", exhausted=False),
        _critique(Strategy.EMERGENCY_CHANGE, risk_reduction=8.5, operational_cost=6,
                  constraint_compliance=7.5, evidence_strength=7.5, contradicting_evidence=2),  # 7.80
        _critique(Strategy.ESTABLISH_WINDOW, risk_reduction=6.5, operational_cost=3,
                  constraint_compliance=8.5, evidence_strength=6.5, contradicting_evidence=2.5),  # 7.175
        # depth 3: refine again
        _refinement(Strategy.EMERGENCY_CHANGE, "Patch tonight, refined again.", exhausted=False),
        _refinement(Strategy.ESTABLISH_WINDOW, "Schedule a window, refined again.", exhausted=False),
        _critique(Strategy.EMERGENCY_CHANGE, risk_reduction=9, operational_cost=6,
                  constraint_compliance=8, evidence_strength=8, contradicting_evidence=2),  # 8.15
        _critique(Strategy.ESTABLISH_WINDOW, risk_reduction=7, operational_cost=3,
                  constraint_compliance=9, evidence_strength=7, contradicting_evidence=2),  # 7.65
    ]

    result = run_tree_of_thought(ROOT, STRATEGIST, CRITIC)

    assert result.termination_reason == "depth_limit"
    assert result.depth_reached == 3
    assert result.near_tie is True
    assert result.winner is None
    assert {c.strategy for c in result.candidates} == {Strategy.EMERGENCY_CHANGE, Strategy.ESTABLISH_WINDOW}
    assert result.candidates[0].score == pytest.approx(8.15)
    assert result.candidates[1].score == pytest.approx(7.65)
    assert _QueuedFakeCrew.instantiations == 6  # 3 propose/critique pairs
    # propose(3) + critique(3) + refine_d2(2) + critique_d2(2) + refine_d3(2) + critique_d3(2) = 14 tasks.
    assert result.usage.successful_requests == 14
    assert result.usage.total_tokens == 1400


def test_all_beam_members_exhausted_stops_early_and_carries_forward_the_score():
    _QueuedFakeCrew.queue = [
        _proposal(Strategy.EMERGENCY_CHANGE, "Patch tonight."),
        _proposal(Strategy.ESTABLISH_WINDOW, "Schedule a window."),
        _proposal(Strategy.BUILD_CONTROL, "Add a control."),
        _critique(Strategy.EMERGENCY_CHANGE, risk_reduction=8, operational_cost=6,
                  constraint_compliance=7, evidence_strength=7, contradicting_evidence=2),  # 7.45
        _critique(Strategy.ESTABLISH_WINDOW, risk_reduction=6, operational_cost=3,
                  constraint_compliance=8, evidence_strength=6, contradicting_evidence=3),  # 6.70
        _critique(Strategy.BUILD_CONTROL, risk_reduction=5, operational_cost=4,
                  constraint_compliance=7, evidence_strength=5, contradicting_evidence=4),  # 5.70 -- pruned
        # depth 2: BOTH survivors report nothing left to add
        _refinement(Strategy.EMERGENCY_CHANGE, "Patch tonight.", exhausted=True, reason="Nothing left to add."),
        _refinement(Strategy.ESTABLISH_WINDOW, "Schedule a window.", exhausted=True, reason="Nothing left to add."),
        # no critique tasks queued for depth 2 -- none should be dispatched
    ]

    result = run_tree_of_thought(ROOT, STRATEGIST, CRITIC)

    assert result.termination_reason == "exhausted_evidence"
    assert result.depth_reached == 2
    # scores carried forward unchanged from depth 1 -- not re-critiqued
    assert result.candidates[0].score == pytest.approx(7.45)
    assert result.candidates[1].score == pytest.approx(6.70)
    assert all(c.exhausted for c in result.candidates)
    assert _QueuedFakeCrew.instantiations == 3  # propose, critique(depth1), refine(depth2) -- no critique(depth2)


def test_partial_exhaustion_only_recritiques_the_still_active_thought():
    """emergency_change reports exhausted at depth 2 and must NOT be
    re-dispatched for a depth-3 refinement -- only establish_window (the
    still-active one) gets refined and re-critiqued again."""
    _QueuedFakeCrew.queue = [
        _proposal(Strategy.EMERGENCY_CHANGE, "Patch tonight."),
        _proposal(Strategy.ESTABLISH_WINDOW, "Schedule a window."),
        _proposal(Strategy.BUILD_CONTROL, "Add a control."),
        _critique(Strategy.EMERGENCY_CHANGE, risk_reduction=8, operational_cost=6,
                  constraint_compliance=7, evidence_strength=7, contradicting_evidence=2),  # 7.45
        _critique(Strategy.ESTABLISH_WINDOW, risk_reduction=6, operational_cost=3,
                  constraint_compliance=8, evidence_strength=6, contradicting_evidence=3),  # 6.70
        _critique(Strategy.BUILD_CONTROL, risk_reduction=5, operational_cost=4,
                  constraint_compliance=7, evidence_strength=5, contradicting_evidence=4),  # pruned
        # depth 2: only establish_window has anything left to add
        _refinement(Strategy.EMERGENCY_CHANGE, "Patch tonight.", exhausted=True, reason="Nothing left."),
        _refinement(Strategy.ESTABLISH_WINDOW, "Schedule a window, refined.", exhausted=False),
        _critique(Strategy.ESTABLISH_WINDOW, risk_reduction=10, operational_cost=0,
                  constraint_compliance=10, evidence_strength=10, contradicting_evidence=0),  # 10.0
        # If emergency_change were wrongly re-dispatched at depth 3, the
        # queue would be empty here and the fake Crew would raise --
        # nothing is queued past this point on purpose.
    ]

    result = run_tree_of_thought(ROOT, STRATEGIST, CRITIC)

    # establish_window's fresh depth-2 critique (10.0) clears the margin
    # over emergency_change's frozen, carried-forward depth-1 score
    # (7.45) -- gap 2.55 >= 2.0 -- so the search stops right there, one
    # round short of max_depth, instead of needlessly re-refining a
    # strategy that already said it had nothing left.
    assert result.termination_reason == "clear_winner"
    assert result.depth_reached == 2
    assert result.near_tie is False
    assert result.winner.strategy == Strategy.ESTABLISH_WINDOW
    assert result.winner.score == pytest.approx(10.0)
    by_strategy = {c.strategy: c for c in result.candidates}
    assert by_strategy[Strategy.EMERGENCY_CHANGE].score == pytest.approx(7.45)
    assert by_strategy[Strategy.EMERGENCY_CHANGE].exhausted is True
    assert by_strategy[Strategy.ESTABLISH_WINDOW].exhausted is False
    # 3 propose + 3 critique(depth1) + 2 refine(depth2) + 1 critique(depth2, one task) = 4 Crews total
    assert _QueuedFakeCrew.instantiations == 4


def test_persistently_unparseable_response_raises_tot_dispatch_error():
    _QueuedFakeCrew.queue = [
        _proposal(Strategy.EMERGENCY_CHANGE, "Patch tonight."),
        _proposal(Strategy.ESTABLISH_WINDOW, "Schedule a window."),
        UNPARSEABLE,  # build_control's initial attempt
        UNPARSEABLE,  # build_control's one retry (max_parse_attempts=2)
    ]

    with pytest.raises(ToTDispatchError, match="gave up after 2 attempt") as exc_info:
        run_tree_of_thought(ROOT, STRATEGIST, CRITIC, max_parse_attempts=2)

    assert _QueuedFakeCrew.instantiations == 2  # batched propose crew + one single-task retry crew
    # Real API calls happened on the way to giving up -- the exception
    # must carry that spend rather than silently dropping it (module
    # docstring). Batched propose (3 tasks) + one retry (1 task) = 4.
    assert exc_info.value.usage.successful_requests == 4
    assert exc_info.value.usage.total_tokens == 400
    # The last attempt's raw output survives onto the exception too --
    # available for --verbose, never baked into the short message above.
    assert exc_info.value.raw == UNPARSEABLE
    assert UNPARSEABLE not in str(exc_info.value)


def test_a_wrong_echoed_strategy_is_retried_and_recovers():
    _QueuedFakeCrew.queue = [
        _proposal(Strategy.EMERGENCY_CHANGE, "Patch tonight."),
        _proposal(Strategy.ESTABLISH_WINDOW, "Schedule a window."),
        json.dumps({"strategy": "establish_window", "proposal": "wrong strategy echoed"}),  # build_control's slot
        _proposal(Strategy.BUILD_CONTROL, "Add a control, corrected."),  # its retry
        _critique(Strategy.EMERGENCY_CHANGE, risk_reduction=9, operational_cost=3,
                  constraint_compliance=8, evidence_strength=8, contradicting_evidence=1),
        _critique(Strategy.ESTABLISH_WINDOW, risk_reduction=3, operational_cost=5,
                  constraint_compliance=4, evidence_strength=3, contradicting_evidence=6),
        _critique(Strategy.BUILD_CONTROL, risk_reduction=2, operational_cost=6,
                  constraint_compliance=3, evidence_strength=2, contradicting_evidence=7),
    ]

    result = run_tree_of_thought(ROOT, STRATEGIST, CRITIC, max_parse_attempts=2)

    assert result.winner.strategy == Strategy.EMERGENCY_CHANGE  # unaffected by the retried slot
