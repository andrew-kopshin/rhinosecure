import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from rhinosecure.agents import coordinator as coordinator_module
from rhinosecure.agents.coordinator import Coordinator, CoordinatorError
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


def _research_json(fid: str, cve_id: str, *, wrapped: bool = False) -> str:
    payload = {
        "finding_id": fid,
        "cve_id": cve_id,
        "scanner_severity": "high",
        "is_kev": False,
        "exploitation_summary": "fake research summary",
        "sources": ["fake"],
    }
    return json.dumps({"finding": payload} if wrapped else payload)


def _environment_json(fid: str, cve_id: str, asset_id: str, hostname: str, *, wrapped: bool = False) -> str:
    payload = {
        "finding_id": fid,
        "cve_id": cve_id,
        "asset_id": asset_id,
        "hostname": hostname,
        "os": "Windows Server 2019",
        "os_build": "17763",
        "os_build_consistent": True,
        "os_build_consistent_provenance": "model_judgment",
        "role": "exchange",
        "environment": "prod",
        "internet_exposed": True,
        "compensating_controls": [],
        "has_patch_window": True,
        "patch_window": "Sun 02:00-06:00",
        "patch_restrictions": "",
        "applicability_summary": "fake environment summary",
        "sources": ["fake"],
    }
    return json.dumps({"assessment": payload} if wrapped else payload)


UNPARSEABLE = "this is not json and will never parse, no matter how many times you ask"


class _QueuedFakeCrew:
    """Stands in for crewai.Crew.

    Research/Environment stages: kickoff() pops a pre-queued RAW JSON TEXT
    string per task and sets task.output.raw to it -- this exercises the
    real parse_structured_output path inside Coordinator (including its
    single-key-wrapper tolerance), not a bypass of it, so these tests cover
    the actual incident fix rather than assuming it works.

    Risk stage (detected by the presence of the score_finding tool):
    kickoff() pops a finding_id and calls the REAL score_finding tool for
    it -- score_finding is pure deterministic Python, not an LLM call -- so
    verify_scoring_matches_tool has a genuine call_log entry to check.
    `corrupt_finding_id`, if set, reports a deliberately wrong risk_score
    in the JSON text for that one finding while still logging the real
    tool call underneath -- an LLM that called the tool correctly but
    misreported the number in its final answer.
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
                raw = json.dumps(
                    {
                        "finding_id": tool_result["finding_id"],
                        "cve_id": tool_result["cve_id"],
                        "asset_id": tool_result["asset_id"],
                        "hostname": tool_result["hostname"],
                        "risk_score": risk_score,
                        "bucket": tool_result["bucket"],
                        "scoring_rationale": tool_result["rationale"],
                        "verdict_summary": "fake verdict summary.",
                        "narrative": "fake narrative",
                        "sources": ["fake"],
                    }
                )
            else:
                raw = _QueuedFakeCrew.queue.pop(0)
            task.output = SimpleNamespace(raw=raw)
        return None


@pytest.fixture(autouse=True)
def fake_crew(monkeypatch):
    _QueuedFakeCrew.queue = []
    _QueuedFakeCrew.instantiations = 0
    _QueuedFakeCrew.corrupt_finding_id = None
    monkeypatch.setattr(coordinator_module, "Crew", _QueuedFakeCrew)
    return _QueuedFakeCrew


def _queue_happy_path(risk_finding_ids):
    _QueuedFakeCrew.queue = [
        _research_json("F01", "CVE-2021-26855"),
        _research_json("F02", "CVE-2018-8410"),
        _environment_json("F01", "CVE-2021-26855", "A01", "EXCH01"),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        *risk_finding_ids,
    ]


def test_run_threads_state_through_all_three_stages_and_returns_ranked_list(data_dir, findings):
    _queue_happy_path(["F01", "F02"])

    coordinator = Coordinator(data_dir)
    ranked = coordinator.run(findings)

    findings_by_id = {e.finding.finding_id: e for e in findings}
    expected_f01 = score_finding(findings_by_id["F01"])
    expected_f02 = score_finding(findings_by_id["F02"])

    assert coordinator.state.research_by_id["F01"].cve_id == "CVE-2021-26855"
    assert coordinator.state.environment_by_id["F02"].hostname == "WKS01"
    assert coordinator.state.risk_by_id["F01"].risk_score == pytest.approx(expected_f01.risk_score)
    assert coordinator.state.risk_by_id["F02"].risk_score == pytest.approx(expected_f02.risk_score)
    assert [r.finding_id for r in ranked] == sorted(
        ["F01", "F02"], key=lambda fid: -coordinator.state.risk_by_id[fid].risk_score
    )
    assert coordinator.state.research_failures == {}
    assert coordinator.state.environment_failures == {}
    assert coordinator.state.risk_failures == {}
    assert _QueuedFakeCrew.instantiations == 3  # one Crew per stage, no retries needed


# --- single-key wrapper tolerance (the incident) -----------------------------


def test_a_single_key_wrapped_response_succeeds_without_any_retry(data_dir, findings):
    """The exact incident shape: F01's ResearchFinding comes back as
    {"finding": {...}} instead of the fields directly. Must resolve to a
    correct ResearchFinding on the FIRST attempt -- no extra Crew
    dispatch, since parse_structured_output already tolerates this."""
    _QueuedFakeCrew.queue = [
        _research_json("F01", "CVE-2021-26855", wrapped=True),
        _research_json("F02", "CVE-2018-8410"),
        _environment_json("F01", "CVE-2021-26855", "A01", "EXCH01"),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        "F01",
        "F02",
    ]

    coordinator = Coordinator(data_dir)
    coordinator.run(findings)

    assert coordinator.state.research_by_id["F01"].cve_id == "CVE-2021-26855"
    assert coordinator.state.research_failures == {}
    assert _QueuedFakeCrew.instantiations == 3  # still just one Crew per stage


# --- retry cap and skip-and-record -------------------------------------------


def test_persistently_unparseable_finding_is_recorded_and_skipped_not_blocking(data_dir, findings):
    """F01's research answer never parses, no matter how many times it's
    retried. After the cap, F01 must be recorded as a research failure and
    excluded from research_by_id -- and the run must still complete for
    F02, and for Environment/Risk on F02, rather than blocking or raising."""
    max_attempts = 2
    # Order: [F01 initial, F02 initial] (the batched research Crew), then
    # F01's (max_attempts - 1) retry attempts (each its own single-task
    # Crew), then Environment and Risk for F02 only -- F01 never reaches
    # either, since it never produced a usable ResearchFinding.
    _QueuedFakeCrew.queue = (
        [UNPARSEABLE, _research_json("F02", "CVE-2018-8410")]
        + [UNPARSEABLE] * (max_attempts - 1)  # F01's retries (single-task crews)
        + [
            _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
            "F02",
        ]
    )

    coordinator = Coordinator(data_dir, max_parse_attempts=max_attempts)
    ranked = coordinator.run(findings)

    assert "F01" not in coordinator.state.research_by_id
    assert "F01" in coordinator.state.research_failures
    assert f"gave up after {max_attempts} attempt(s)" in coordinator.state.research_failures["F01"]

    # F01 is skipped downstream too, recorded at each stage it never reached.
    assert "F01" in coordinator.state.environment_failures
    assert "Research failed" in coordinator.state.environment_failures["F01"]
    assert "F01" in coordinator.state.risk_failures
    assert "Research failed" in coordinator.state.risk_failures["F01"]

    # F02 is unaffected -- the run completed instead of blocking on F01.
    assert coordinator.state.risk_by_id["F02"].cve_id == "CVE-2018-8410"
    assert [r.finding_id for r in ranked] == ["F02"]


def test_retry_cap_is_respected_exactly(data_dir, findings):
    """With max_parse_attempts=2, an always-unparseable finding must be
    retried exactly once (2 total attempts: 1 initial + 1 retry) and no
    more -- confirmed by counting Crew instantiations precisely."""
    max_attempts = 2
    _QueuedFakeCrew.queue = [
        UNPARSEABLE,  # F01's initial attempt (part of the batched research Crew)
        _research_json("F02", "CVE-2018-8410"),
        UNPARSEABLE,  # F01's one retry attempt (its own single-task Crew)
    ]

    coordinator = Coordinator(data_dir, max_parse_attempts=max_attempts)
    findings_subset = [e for e in findings if e.finding.finding_id in ("F01", "F02")]
    # Only dispatch research directly to isolate the count to this one stage.
    coordinator.state = coordinator_module.RunState(
        enriched_by_id={e.finding.finding_id: e for e in findings_subset}
    )
    coordinator._dispatch_research(findings_subset)

    # 1 batched Crew (both findings) + 1 retry Crew for F01 alone = 2.
    assert _QueuedFakeCrew.instantiations == 2
    assert "F01" in coordinator.state.research_failures
    assert "F02" in coordinator.state.research_by_id


def test_environment_failure_does_not_block_risk_for_other_findings(data_dir, findings):
    """Same skip-and-continue guarantee, one stage later: F01's Environment
    answer never parses; Risk must still run for F02."""
    max_attempts = 1  # fail fast: no retries needed to prove the point
    _QueuedFakeCrew.queue = [
        _research_json("F01", "CVE-2021-26855"),
        _research_json("F02", "CVE-2018-8410"),
        UNPARSEABLE,  # F01's environment answer
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        "F02",
    ]

    coordinator = Coordinator(data_dir, max_parse_attempts=max_attempts)
    ranked = coordinator.run(findings)

    assert "F01" not in coordinator.state.environment_by_id
    assert "F01" in coordinator.state.environment_failures
    assert "F01" in coordinator.state.risk_failures
    assert "no EnvironmentAssessment" in coordinator.state.risk_failures["F01"]
    assert [r.finding_id for r in ranked] == ["F02"]


def test_scoring_mismatch_is_recorded_and_skipped_not_raised(data_dir, findings):
    """A Risk answer that disagrees with the tool's own logged result must
    be treated like a parse failure -- recorded and skipped -- not left to
    raise ScoringMismatchError out of run() and abort everything."""
    _queue_happy_path(["F01", "F02"])
    _QueuedFakeCrew.corrupt_finding_id = "F01"

    coordinator = Coordinator(data_dir, max_parse_attempts=1)
    ranked = coordinator.run(findings)

    assert "F01" not in coordinator.state.risk_by_id
    assert "F01" in coordinator.state.risk_failures
    assert coordinator.state.risk_by_id["F02"].cve_id == "CVE-2018-8410"
    assert [r.finding_id for r in ranked] == ["F02"]


# --- replan and misuse errors -------------------------------------------------


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
        _environment_json("F01", "CVE-2021-26855", "A01", "EXCH01"),
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
