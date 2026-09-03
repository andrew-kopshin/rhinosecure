import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from rhinosecure import tot as tot_module
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


def _research_json(fid: str, cve_id: str, *, wrapped: bool = False, is_kev: bool = False) -> str:
    payload = {
        "finding_id": fid,
        "cve_id": cve_id,
        "scanner_severity": "high",
        "is_kev": is_kev,
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


# --- ToT gate (_dispatch_tot) -------------------------------------------------
#
# The beam-search mechanics (branches, critic scoring, termination, near-tie
# surfacing) are covered in test_tot.py; these only check that Coordinator
# routes a contested finding into it, records a failure without blocking the
# run, and leaves everything else untouched.


class _QueuedFakeTotCrew:
    """Stands in for tot.py's own Crew reference -- separate from
    coordinator_module.Crew above, since run_tree_of_thought (tot.py)
    never goes through Coordinator's Crew binding. Same pop-one-per-task
    contract."""

    queue: list = []
    instantiations: int = 0

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.tasks = tasks
        type(self).instantiations += 1

    def kickoff(self):
        for task in self.tasks:
            task.output = SimpleNamespace(raw=_QueuedFakeTotCrew.queue.pop(0))
        return None


@pytest.fixture(autouse=True)
def fake_tot_crew(monkeypatch):
    _QueuedFakeTotCrew.queue = []
    _QueuedFakeTotCrew.instantiations = 0
    monkeypatch.setattr(tot_module, "Crew", _QueuedFakeTotCrew)
    return _QueuedFakeTotCrew


def _tot_proposal(strategy: str, text: str) -> str:
    return json.dumps({"strategy": strategy, "proposal": text})


def _tot_critique(strategy: str, **scores) -> str:
    return json.dumps({"strategy": strategy, "justification": "fake", **scores})


def _tot_clear_winner_queue() -> list:
    """A minimal, complete ToT response sequence -- 3 proposals then 3
    critiques, emergency_change scored high enough to terminate at depth
    1. Only exists to give _dispatch_tot something real to parse; the
    beam-search behavior itself is test_tot.py's job."""
    return [
        _tot_proposal("emergency_change", "Patch now."),
        _tot_proposal("establish_window", "Schedule a window."),
        _tot_proposal("build_control", "Add a control."),
        _tot_critique("emergency_change", risk_reduction=9, operational_cost=3,
                      constraint_compliance=8, evidence_strength=8, contradicting_evidence=1),
        _tot_critique("establish_window", risk_reduction=3, operational_cost=5,
                      constraint_compliance=4, evidence_strength=3, contradicting_evidence=6),
        _tot_critique("build_control", risk_reduction=2, operational_cost=6,
                      constraint_compliance=3, evidence_strength=2, contradicting_evidence=7),
    ]


def test_a_contested_finding_is_routed_into_tot_and_recorded(data_dir, findings):
    """F02 sits on A02, which has neither a compensating control nor a
    patch window (ASSETS_CSV above) -- is_kev=True is enough on its own
    to make bucket_for return contested for it (scoring.py). F01 (A01,
    which DOES have a patch window) stays out of contested and must never
    reach ToT at all."""
    _QueuedFakeCrew.queue = [
        _research_json("F01", "CVE-2021-26855"),
        _research_json("F02", "CVE-2018-8410", is_kev=True),
        _environment_json("F01", "CVE-2021-26855", "A01", "EXCH01"),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        "F01",
        "F02",
    ]
    _QueuedFakeTotCrew.queue = _tot_clear_winner_queue()

    coordinator = Coordinator(data_dir)
    coordinator.run(findings)

    assert coordinator.state.risk_by_id["F02"].bucket == "contested"
    assert "F02" in coordinator.state.tot_by_id
    result = coordinator.state.tot_by_id["F02"]
    assert result.finding_id == "F02"
    assert result.winner.strategy.value == "emergency_change"
    assert "F01" not in coordinator.state.tot_by_id
    assert coordinator.state.tot_failures == {}


def test_a_run_with_no_contested_findings_never_touches_tot_crew(data_dir, findings):
    _queue_happy_path(["F01", "F02"])

    coordinator = Coordinator(data_dir)
    coordinator.run(findings)

    assert coordinator.state.tot_by_id == {}
    assert _QueuedFakeTotCrew.instantiations == 0


def test_tot_failure_is_recorded_and_does_not_remove_the_finding_from_risk_by_id(data_dir, findings):
    """A finding that reaches the gate but whose strategist responses
    never parse must be recorded in tot_failures, never raised -- and,
    unlike a Research/Environment/Risk failure, must NOT be removed from
    risk_by_id: Risk already succeeded for it (that's why it reached this
    gate at all) -- see agents/coordinator.py's _dispatch_tot docstring."""
    _QueuedFakeCrew.queue = [
        _research_json("F01", "CVE-2021-26855"),
        _research_json("F02", "CVE-2018-8410", is_kev=True),
        _environment_json("F01", "CVE-2021-26855", "A01", "EXCH01"),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        "F01",
        "F02",
    ]
    _QueuedFakeTotCrew.queue = [UNPARSEABLE, UNPARSEABLE, UNPARSEABLE]  # F02's 3 initial proposals

    coordinator = Coordinator(data_dir, max_parse_attempts=1)
    ranked = coordinator.run(findings)

    assert "F02" in coordinator.state.tot_failures
    assert "gave up after 1 attempt(s)" in coordinator.state.tot_failures["F02"]
    assert "F02" not in coordinator.state.tot_by_id
    assert coordinator.state.risk_by_id["F02"].bucket == "contested"  # untouched
    assert {r.finding_id for r in ranked} == {"F01", "F02"}  # both still in the plan


def test_replan_also_dispatches_tot_for_a_newly_contested_finding(data_dir, findings, monkeypatch):
    _queue_happy_path(["F01", "F02"])
    coordinator = Coordinator(data_dir)
    coordinator.run(findings)
    assert coordinator.state.tot_by_id == {}  # nothing contested on the first run

    research_called = {"count": 0}
    monkeypatch.setattr(
        coordinator,
        "_dispatch_research",
        lambda *a, **k: research_called.__setitem__("count", research_called["count"] + 1),
    )
    # Simulates F02's research turning up is_kev=True on re-enrichment --
    # constraint-driven re-enrichment itself isn't built yet (Slice 4's
    # remaining piece); this only confirms replan's _dispatch_tot wiring.
    coordinator.state.research_by_id["F02"] = coordinator.state.research_by_id["F02"].model_copy(
        update={"is_kev": True}
    )

    _QueuedFakeCrew.queue = [
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        "F02",
    ]
    _QueuedFakeTotCrew.queue = _tot_clear_winner_queue()

    coordinator.replan(["F02"])

    assert research_called["count"] == 0  # confirms replan, not a fresh run, drove this
    assert "F02" in coordinator.state.tot_by_id
