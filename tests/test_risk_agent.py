import json

import pytest
from crewai import Task

from rhinosecure.agents.environment import EnvironmentAssessment
from rhinosecure.agents.research import AttackTechniqueSummary, ResearchFinding
from rhinosecure.agents.risk import (
    RiskRecommendation,
    ScoringMismatchError,
    build_risk_agent,
    build_risk_task,
    build_risk_tools,
    verify_scoring_matches_tool,
)
from rhinosecure.llm import LLMConfig, get_llm
from rhinosecure.schema import Asset, AttackTechniqueRef, EnrichedFinding, Finding
from rhinosecure.scoring import score_finding

ASSET = Asset(
    asset_id="A02",
    hostname="EXCH01",
    os="Windows Server 2019",
    os_build="17763",
    role="exchange",
    business_function="Primary mail server",
    criticality=5,
    internet_exposed=True,
    environment="prod",
    data_sensitivity="confidential",
    patch_window="Sun 02:00-06:00",
    patch_restrictions="no reboot during business hours",
    compensating_controls="",
    owner="messaging-team",
)

FINDING = Finding(
    finding_id="F01",
    asset_id="A02",
    cve_id="CVE-2021-26855",
    scanner_severity="critical",
    product="Microsoft Exchange Server",
    version="2016 CU19",
    evidence="OWA endpoint vulnerable to pre-auth SSRF chain (ProxyLogon)",
)

ENRICHED = EnrichedFinding(finding=FINDING, asset=ASSET)

RESEARCH = ResearchFinding(
    finding_id="F01",
    cve_id="CVE-2021-26855",
    scanner_severity="critical",
    nvd_base_score=9.8,
    nvd_severity="critical",
    severity_disagreement=False,
    is_kev=True,
    kev_date_added="2021-11-03",
    epss_score=0.99996,
    epss_percentile=0.99988,
    attack_techniques=[
        AttackTechniqueSummary(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            confidence="confirmed",
            prevalence=0.97,
        )
    ],
    exploitation_summary="Confirmed KEV-listed, near-maximal EPSS, confirmed ATT&CK match.",
    sources=["nvd", "kev", "epss", "attack"],
)

ENVIRONMENT = EnvironmentAssessment(
    finding_id="F01",
    cve_id="CVE-2021-26855",
    asset_id="A02",
    hostname="EXCH01",
    os="Windows Server 2019",
    os_build="17763",
    os_build_consistent=True,
    role="exchange",
    environment="prod",
    internet_exposed=True,
    compensating_controls=[],
    has_patch_window=True,
    patch_window="Sun 02:00-06:00",
    patch_restrictions="no reboot during business hours",
    applicability_summary="Exchange 2016 CU19 is consistent with Windows Server 2019.",
    sources=["lookup_asset_context(asset_id=A02)"],
)


def _tools():
    call_log: list[dict] = []
    tools = build_risk_tools({"F01": ENRICHED}, {"F01": RESEARCH}, call_log)
    return {t.name: t for t in tools}, call_log


def test_returns_the_score_finding_tool():
    tools, _ = _tools()
    assert set(tools) == {"score_finding"}


def test_score_finding_tool_matches_calling_scoring_directly_with_research_signals_merged():
    tools, call_log = _tools()

    result = json.loads(tools["score_finding"].run(finding_id="F01"))

    expected = score_finding(
        ENRICHED.model_copy(
            update={
                "is_kev": True,
                "epss": 0.99996,
                "nvd_base_score": 9.8,
                "nvd_severity": "critical",
                "attack_techniques": (
                    AttackTechniqueRef(
                        technique_id="T1190",
                        name="Exploit Public-Facing Application",
                        confidence="confirmed",
                    ),
                ),
                "attack_prevalence": 0.97,
            }
        )
    )
    assert result["risk_score"] == pytest.approx(expected.risk_score)
    assert result["bucket"] == expected.bucket.value
    assert result["rationale"] == list(expected.rationale)
    assert result["finding_id"] == "F01"
    assert result["asset_id"] == "A02"
    assert result["hostname"] == "EXCH01"

    assert len(call_log) == 1
    assert call_log[0]["tool"] == "score_finding"
    assert call_log[0]["args"] == {"finding_id": "F01"}
    assert call_log[0]["result"] == result
    assert result["constraints_applied"] == []


# --- constraint overlay (agents/constraint_intake.py's apply_constraints) ---


def test_without_memory_scoring_is_unaffected_and_constraints_applied_is_empty(tmp_path):
    """The default (memory=None) reproduces the exact prior behavior --
    every call site before constraints existed."""
    call_log: list[dict] = []
    tools = {
        t.name: t for t in build_risk_tools({"F01": ENRICHED}, {"F01": RESEARCH}, call_log)
    }
    result = json.loads(tools["score_finding"].run(finding_id="F01"))
    assert result["constraints_applied"] == []


def test_with_memory_but_no_active_constraints_scoring_is_unaffected(tmp_path):
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    call_log: list[dict] = []
    tools = {
        t.name: t
        for t in build_risk_tools({"F01": ENRICHED}, {"F01": RESEARCH}, call_log, memory)
    }
    result = json.loads(tools["score_finding"].run(finding_id="F01"))
    assert result["constraints_applied"] == []


def test_an_active_compensating_control_constraint_changes_the_score_and_is_reported(tmp_path):
    """ASSET (module-level) has compensating_controls="" -- adding one via
    a constraint must change score_finding's own risk_score/rationale
    (scoring.py's compensating-control decay applies) and be reported
    separately in constraints_applied, not silently folded into
    rationale's existing text."""
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    memory.add_constraint(
        "A02", "now sits behind the new WAF rule",
        effect_kind="compensating_control", effect_value="WAF rule enabled",
    )
    call_log: list[dict] = []
    tools = {
        t.name: t
        for t in build_risk_tools({"F01": ENRICHED}, {"F01": RESEARCH}, call_log, memory)
    }

    without_constraint = json.loads(_tools()[0]["score_finding"].run(finding_id="F01"))
    with_constraint = json.loads(tools["score_finding"].run(finding_id="F01"))

    assert with_constraint["constraints_applied"] == ["now sits behind the new WAF rule"]
    assert with_constraint["risk_score"] < without_constraint["risk_score"]
    assert with_constraint["rationale"] != without_constraint["rationale"]


def test_the_overlay_never_mutates_the_ground_truth_asset(tmp_path):
    """ENRICHED.asset must be byte-identical after a scored call with an
    active constraint -- the overlay is a fresh, throwaway Asset.model_copy,
    never written back to enriched_by_id (module docstring)."""
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    memory.add_constraint(
        "A02", "now sits behind the new WAF rule",
        effect_kind="compensating_control", effect_value="WAF rule enabled",
    )
    enriched_by_id = {"F01": ENRICHED}
    tools = {
        t.name: t
        for t in build_risk_tools(enriched_by_id, {"F01": RESEARCH}, [], memory)
    }
    tools["score_finding"].run(finding_id="F01")

    assert enriched_by_id["F01"] is ENRICHED
    assert enriched_by_id["F01"].asset.compensating_controls == ""


def test_score_finding_ignores_environment_analysis_asset_data_uses_ground_truth():
    """The tool must reconstruct scoring input from the ground-truth Asset
    (criticality=5, prod, confidential, exchange -- ENRICHED above), not
    from anything EnvironmentAssessment says, since Risk's tools are never
    even given an EnvironmentAssessment object -- only research_by_id,
    the ground-truth enriched_by_id, and (optionally) memory for the
    constraint overlay. This test is really just documenting that
    contract: build_risk_tools's signature has no environment parameter
    at all.
    """
    import inspect

    sig = inspect.signature(build_risk_tools)
    assert list(sig.parameters) == ["enriched_by_id", "research_by_id", "call_log", "memory"]


# --- agent/task construction (no network, no LLM call) ----------------------


def _fake_llm():
    return get_llm(LLMConfig(model="claude-sonnet-5", api_key="sk-test-key"))


def test_build_risk_agent_has_role_and_the_tool():
    tools = build_risk_tools({"F01": ENRICHED}, {"F01": RESEARCH}, [])
    agent = build_risk_agent(tools, llm=_fake_llm())

    assert agent.role == "Risk & Recommendation"
    assert {t.name for t in agent.tools} == {"score_finding"}


def test_build_risk_task_embeds_finding_research_and_environment_context():
    tools = build_risk_tools({"F01": ENRICHED}, {"F01": RESEARCH}, [])
    agent = build_risk_agent(tools, llm=_fake_llm())

    task = build_risk_task(ENRICHED, RESEARCH, ENVIRONMENT, agent)

    assert isinstance(task, Task)
    # No output_pydantic: CrewAI's own conversion caused an unbounded retry
    # loop on a malformed response (PROGRESS.md) -- parsing is now this
    # project's own code (agents/parsing.py), not CrewAI's.
    assert task.output_pydantic is None
    assert task.agent is agent
    assert "F01" in task.description
    assert "CVE-2021-26855" in task.description
    assert "not wrapped in any container key" in task.expected_output
    assert "EXCH01" in task.description
    assert "KEV-listed: True" in task.description
    assert "Confirmed KEV-listed, near-maximal EPSS" in task.description
    assert "Exchange 2016 CU19 is consistent with Windows Server 2019." in task.description
    assert "score_finding" in task.description
    assert "verdict_summary" in task.description
    assert "exactly two sentences" in task.description
    assert "verdict_summary" in task.expected_output
    assert "constraints_applied" in task.description
    assert "constraints_applied" in task.expected_output


# --- verify_scoring_matches_tool ---------------------------------------------


def _matching_recommendation_and_log():
    tools, call_log = _tools()
    tool_result = json.loads(tools["score_finding"].run(finding_id="F01"))
    recommendation = RiskRecommendation(
        finding_id="F01",
        cve_id="CVE-2021-26855",
        asset_id="A02",
        hostname="EXCH01",
        risk_score=tool_result["risk_score"],
        bucket=tool_result["bucket"],
        scoring_rationale=tool_result["rationale"],
        verdict_summary="Patch now: confirmed KEV on an exposed Exchange server.",
        narrative="Patch now: confirmed KEV, exposed Exchange server.",
        sources=["Vulnerability Research", "Environment Analysis", "score_finding"],
    )
    return recommendation, call_log


def test_verify_passes_when_recommendation_matches_the_tool_result():
    recommendation, call_log = _matching_recommendation_and_log()
    verify_scoring_matches_tool(recommendation, call_log)  # must not raise


def test_verify_raises_on_mismatched_risk_score():
    recommendation, call_log = _matching_recommendation_and_log()
    bad = recommendation.model_copy(update={"risk_score": recommendation.risk_score + 5})
    with pytest.raises(ScoringMismatchError):
        verify_scoring_matches_tool(bad, call_log)


def test_verify_raises_on_mismatched_bucket():
    recommendation, call_log = _matching_recommendation_and_log()
    bad = recommendation.model_copy(update={"bucket": "accept"})
    assert bad.bucket != recommendation.bucket
    with pytest.raises(ScoringMismatchError):
        verify_scoring_matches_tool(bad, call_log)


def test_verify_raises_on_mismatched_rationale():
    recommendation, call_log = _matching_recommendation_and_log()
    bad = recommendation.model_copy(update={"scoring_rationale": ["a made-up rationale line"]})
    with pytest.raises(ScoringMismatchError):
        verify_scoring_matches_tool(bad, call_log)


def test_verify_raises_on_mismatched_constraints_applied():
    recommendation, call_log = _matching_recommendation_and_log()
    bad = recommendation.model_copy(update={"constraints_applied": ["a constraint the tool never applied"]})
    with pytest.raises(ScoringMismatchError):
        verify_scoring_matches_tool(bad, call_log)


def test_verify_raises_when_no_matching_call_logged():
    recommendation, _ = _matching_recommendation_and_log()
    with pytest.raises(ScoringMismatchError):
        verify_scoring_matches_tool(recommendation, [])
