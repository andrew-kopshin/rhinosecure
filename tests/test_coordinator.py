import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from rhinosecure.agents import coordinator as coordinator_module
from rhinosecure.agents.coordinator import Coordinator, CoordinatorError
from rhinosecure.agents.environment import EnvironmentAssessment
from rhinosecure.agents.research import ResearchFinding
from rhinosecure.agents.risk import RiskRecommendation, ScoringMismatchError
from rhinosecure.ingest import join_findings
from rhinosecure.scoring import score_finding

ASSETS_CSV = """asset_id,hostname,os,os_build,role,business_function,criticality,internet_exposed,environment,data_sensitivity,patch_window,patch_restrictions,compensating_controls,owner
A01,EXCH01,Windows Server 2019,17763,exchange,Mail server,5,True,prod,confidential,Sun 02:00-06:00,,,messaging-team
A02,WKS01,Windows 10,19045,workstation,Finance workstation,2,False,prod,confidential,,,,it-helpdesk
"""

FINDINGS_CSV = """finding_id,asset_id,cve_id,detected_date,scanner_severity,product,version,port,service,evidence
F01,A01,CVE-2021-26855,2026-08-01,critical,Microsoft Exchange Server,2016 CU19,443,https,OWA SSRF chain
F02,A02,CVE-2018-8410,2026-08-08,high,Microsoft OLE DB Driver,18.2,1433,mssql,Outdated OLE DB provider
"""


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    (tmp_path / "assets.csv").write_text(ASSETS_CSV, encoding="utf-8")
    (tmp_path / "findings.csv").write_text(FINDINGS_CSV, encoding="utf-8")
    return tmp_path


@pytest.fixture
def findings(data_dir: Path):
    return list(join_findings(data_dir / "findings.csv", data_dir / "assets.csv"))


def _research(fid: str, cve_id: str) -> ResearchFinding:
    return ResearchFinding(
        finding_id=fid,
        cve_id=cve_id,
        scanner_severity="high",
        is_kev=False,
        exploitation_summary="fake research summary",
        sources=["fake"],
    )


def _environment(fid: str, cve_id: str, asset_id: str, hostname: str) -> EnvironmentAssessment:
    return EnvironmentAssessment(
        finding_id=fid,
        cve_id=cve_id,
        asset_id=asset_id,
        hostname=hostname,
        os="Windows Server 2019",
        os_build="17763",
        os_build_consistent=True,
        role="exchange",
        environment="prod",
        internet_exposed=True,
        compensating_controls=[],
        has_patch_window=True,
        patch_window="Sun 02:00-06:00",
        patch_restrictions="",
        applicability_summary="fake environment summary",
        sources=["fake"],
    )


class _QueuedFakeCrew:
    """Stands in for crewai.Crew.

    Research/Environment stages: kickoff() pops a pre-queued fake payload
    per task, in order -- no real tool call, since nothing downstream
    checks those against a call log.

    Risk stage (detected by the presence of the score_finding tool):
    kickoff() pops a finding_id and calls the REAL score_finding tool for
    it -- score_finding is pure deterministic Python, not an LLM call, so
    this gives verify_scoring_matches_tool a genuine call_log entry to
    check, and the synthesized RiskRecommendation copies that real result.
    `corrupt_finding_id`, if set, reports a deliberately wrong risk_score
    for that one finding while still logging the real tool call -- an LLM
    that called the tool correctly but misreported the number in its final
    answer, exactly what verify_scoring_matches_tool exists to catch.
    """

    queue: list = []
    instantiations: int = 0
    corrupt_finding_id: str | None = None

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.tasks = tasks
        self.agent = agents[0]
        self.usage_metrics = None
        type(self).instantiations += 1

    def kickoff(self):
        is_risk_stage = any(t.name == "score_finding" for t in self.agent.tools)
        for task in self.tasks:
            if is_risk_stage:
                finding_id = _QueuedFakeCrew.queue.pop(0)
                tool_result = json.loads(self.agent.tools[0].run(finding_id=finding_id))
                risk_score = tool_result["risk_score"]
                if finding_id == _QueuedFakeCrew.corrupt_finding_id:
                    risk_score += 500  # deliberately disagrees with the logged call
                output = RiskRecommendation(
                    finding_id=tool_result["finding_id"],
                    cve_id=tool_result["cve_id"],
                    asset_id=tool_result["asset_id"],
                    hostname=tool_result["hostname"],
                    risk_score=risk_score,
                    bucket=tool_result["bucket"],
                    scoring_rationale=tool_result["rationale"],
                    narrative="fake narrative",
                    sources=["fake"],
                )
            else:
                output = _QueuedFakeCrew.queue.pop(0)
            task.output = SimpleNamespace(pydantic=output)
        return None


@pytest.fixture(autouse=True)
def fake_crew(monkeypatch):
    _QueuedFakeCrew.queue = []
    _QueuedFakeCrew.instantiations = 0
    _QueuedFakeCrew.corrupt_finding_id = None
    monkeypatch.setattr(coordinator_module, "Crew", _QueuedFakeCrew)
    return _QueuedFakeCrew


def _queue_happy_path(finding_ids_for_risk):
    _QueuedFakeCrew.queue = [
        _research("F01", "CVE-2021-26855"),
        _research("F02", "CVE-2018-8410"),
        _environment("F01", "CVE-2021-26855", "A01", "EXCH01"),
        _environment("F02", "CVE-2018-8410", "A02", "WKS01"),
        *finding_ids_for_risk,
    ]


def test_run_threads_state_through_all_three_stages_and_returns_ranked_list(data_dir, findings):
    _queue_happy_path(["F01", "F02"])

    coordinator = Coordinator(data_dir)
    ranked = coordinator.run(findings)

    findings_by_id = {e.finding.finding_id: e for e in findings}
    expected_f01 = score_finding(findings_by_id["F01"].model_copy(update={"is_kev": False}))
    expected_f02 = score_finding(findings_by_id["F02"].model_copy(update={"is_kev": False}))

    assert coordinator.state.research_by_id["F01"].cve_id == "CVE-2021-26855"
    assert coordinator.state.environment_by_id["F02"].hostname == "WKS01"
    assert coordinator.state.risk_by_id["F01"].risk_score == pytest.approx(expected_f01.risk_score)
    assert coordinator.state.risk_by_id["F02"].risk_score == pytest.approx(expected_f02.risk_score)
    assert [r.finding_id for r in ranked] == sorted(
        ["F01", "F02"], key=lambda fid: -coordinator.state.risk_by_id[fid].risk_score
    )
    assert _QueuedFakeCrew.instantiations == 3  # one Crew per stage


def test_replan_reuses_research_and_only_redispatches_environment_and_risk(data_dir, findings, monkeypatch):
    _queue_happy_path(["F01", "F02"])
    coordinator = Coordinator(data_dir)
    coordinator.run(findings)
    original_f02_risk = coordinator.state.risk_by_id["F02"].risk_score

    research_called = {"count": 0}
    monkeypatch.setattr(
        coordinator,
        "_dispatch_research",
        lambda *a, **k: research_called.__setitem__("count", research_called["count"] + 1),
    )

    _QueuedFakeCrew.queue = [
        _environment("F01", "CVE-2021-26855", "A01", "EXCH01"),
        "F01",
    ]
    _QueuedFakeCrew.instantiations = 0  # isolate the count to just this replan() call
    ranked = coordinator.replan(["F01"])

    assert research_called["count"] == 0
    assert coordinator.state.risk_by_id["F02"].risk_score == original_f02_risk  # untouched
    assert [r.finding_id for r in ranked] == ["F01", "F02"]
    assert _QueuedFakeCrew.instantiations == 2  # only environment + risk this time


def test_replan_without_prior_run_raises(data_dir):
    coordinator = Coordinator(data_dir)
    with pytest.raises(CoordinatorError):
        coordinator.replan(["F01"])


def test_replan_unknown_finding_id_raises(data_dir, findings):
    _queue_happy_path(["F01", "F02"])
    coordinator = Coordinator(data_dir)
    coordinator.run(findings)

    with pytest.raises(CoordinatorError):
        coordinator.replan(["F99"])


def test_ranked_before_any_run_raises(data_dir):
    coordinator = Coordinator(data_dir)
    with pytest.raises(CoordinatorError):
        coordinator.ranked()


def test_run_raises_scoring_mismatch_when_risk_output_disagrees_with_tool(data_dir, findings):
    _queue_happy_path(["F01", "F02"])
    _QueuedFakeCrew.corrupt_finding_id = "F01"

    coordinator = Coordinator(data_dir)
    with pytest.raises(ScoringMismatchError):
        coordinator.run(findings)
