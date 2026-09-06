import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from crewai.types.usage_metrics import UsageMetrics

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


def _constraint_interpretation_json(
    *,
    asset_id: str | None,
    effect_kind: str | None = None,
    effect_value: str | None = None,
    affected_finding_ids: list[str] | None = None,
    rationale: str = "fake rationale",
    constraint_kind: str | None = "asset",
    patch_limit: int | None = None,
) -> str:
    return json.dumps(
        {
            "constraint_kind": constraint_kind,
            "asset_id": asset_id,
            "effect_kind": effect_kind,
            "effect_value": effect_value,
            "patch_limit": patch_limit,
            "affected_finding_ids": affected_finding_ids or [],
            "rationale": rationale,
            "sources": ["fake"],
        }
    )


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
                        "constraints_applied": tool_result["constraints_applied"],
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
    # The raw output is kept out of the short failure message (never a
    # multi-line UNPARSEABLE dump in research_failures itself)...
    assert UNPARSEABLE not in coordinator.state.research_failures["F01"]
    # ...but is still recorded, separately, for a caller to show under --verbose.
    assert coordinator.state.last_raw_output["F01"] == UNPARSEABLE

    # F01 is skipped downstream too, recorded at each stage it never reached.
    assert "F01" in coordinator.state.environment_failures
    assert "Research failed" in coordinator.state.environment_failures["F01"]
    assert "F01" in coordinator.state.risk_failures
    assert "Research failed" in coordinator.state.risk_failures["F01"]
    # Neither downstream skip ever attempted a dispatch, so neither wrote
    # its own entry -- last_raw_output holds only the real failure above.
    assert coordinator.state.last_raw_output == {"F01": UNPARSEABLE}

    # F02 is unaffected -- the run completed instead of blocking on F01.
    assert coordinator.state.risk_by_id["F02"].cve_id == "CVE-2018-8410"
    assert [r.finding_id for r in ranked] == ["F02"]


def test_kickoff_batch_records_only_the_finding_whose_task_never_completed(data_dir, findings):
    """A batched Crew's kickoff() raising PARTWAY through (simulated by an
    empty queue after F01's task already got its output) is caught by
    `_kickoff_batch`: F01, whose `task.output` was already set before the
    exception, is NOT treated as failed -- only F02, whose task never got
    output at all, is recorded. Before `_kickoff_batch` existed, the
    IndexError would have propagated straight out of `_dispatch_research`
    uncaught, losing F01's already-produced result along with F02's, and
    aborting `run()` entirely."""
    _QueuedFakeCrew.queue = [_research_json("F01", "CVE-2021-26855")]
    # Nothing queued for F02's task -- the fake crew's second .pop(0) call,
    # inside the SAME kickoff(), raises IndexError.

    coordinator = Coordinator(data_dir)
    coordinator.state = coordinator_module.RunState(
        enriched_by_id={e.finding.finding_id: e for e in findings}
    )
    coordinator._dispatch_research(findings)

    assert "F01" in coordinator.state.research_by_id
    assert "F02" not in coordinator.state.research_by_id
    assert "F02" in coordinator.state.research_failures
    assert "did not complete" in coordinator.state.research_failures["F02"]


def test_bulk_enrichment_fetch_failure_fails_every_finding_gracefully_not_a_crash(
    data_dir, findings, monkeypatch
):
    """load_kev_catalog/load_attack_index (build_research_tools) run ONCE
    per dispatch, before any Crew exists at all -- previously, a failure
    there propagated straight out of run()/replan() uncaught (a real gap:
    this is a categorically different, MORE fragile failure mode than a
    per-CVE tool-call failure, since it happens outside any per-finding
    boundary). Now every finding in the dispatch is recorded as a research
    failure instead, and run() completes (nothing ranked) rather than
    raising."""
    def _raise(cache, call_log):
        raise ConnectionError("simulated KEV/ATT&CK bulk fetch failure")

    monkeypatch.setattr(coordinator_module, "build_research_tools", _raise)

    coordinator = Coordinator(data_dir)
    ranked = coordinator.run(findings)  # must not raise

    assert ranked == []
    for e in findings:
        fid = e.finding.finding_id
        assert fid in coordinator.state.research_failures
        assert "bulk KEV/ATT&CK" in coordinator.state.research_failures[fid]
        assert "simulated KEV/ATT&CK bulk fetch failure" in coordinator.state.research_failures[fid]


def test_dispatch_risk_clears_a_stale_prior_result_when_skipped_this_time(data_dir, findings):
    """A finding with a STALE risk_by_id entry from an earlier successful
    dispatch must not silently keep answering with it if THIS dispatch
    can't even attempt it (no EnvironmentAssessment on file this time,
    simulating a redispatch whose Environment stage just failed). Without
    the fix, `after = self.state.risk_by_id.get(fid)` in
    `submit_constraint`'s delta-building loop would read this stale value
    back as if it reflected the current attempt -- exactly the bug a
    passing-but-wrong `test_a_replan_dispatch_failure_...` integration
    test surfaced while building the retry-cap fix."""
    from rhinosecure.agents.research import ResearchFinding
    from rhinosecure.agents.risk import RiskRecommendation

    coordinator = Coordinator(data_dir)
    coordinator.state = coordinator_module.RunState(
        enriched_by_id={e.finding.finding_id: e for e in findings}
    )
    coordinator.state.research_by_id["F02"] = ResearchFinding(
        finding_id="F02", cve_id="CVE-2018-8410", scanner_severity="high",
        exploitation_summary="fake", sources=["fake"],
    )
    coordinator.state.risk_by_id["F02"] = RiskRecommendation(
        finding_id="F02", cve_id="CVE-2018-8410", asset_id="A02", hostname="WKS01",
        risk_score=9.5, bucket="accept", scoring_rationale=["fake"],
        verdict_summary="fake", narrative="fake", sources=["fake"],
    )
    # environment_by_id deliberately left empty for F02 -- this dispatch's
    # Environment stage is being simulated as already having failed.

    coordinator._dispatch_risk(findings)

    assert "F02" not in coordinator.state.risk_by_id
    assert "F02" in coordinator.state.risk_failures
    assert "no EnvironmentAssessment" in coordinator.state.risk_failures["F02"]


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
    contract. `kickoff()` increments the REAL agent's `agent.llm`'s own
    cumulative usage counter (`_track_token_usage_internal`), one call per
    task, matching test_tot.py's own fake and the reason it needs this:
    production code (`tot._UsageTracker`) reads per-call usage via
    `agent.llm.get_token_usage_summary().delta_since(baseline)`, never
    `crew.usage_metrics` directly, since `_dispatch_tot` builds
    `strategist`/`critic` once and reuses them across every contested
    finding in a batch -- exactly what `test_a_contested_finding_is_routed
    _into_tot_and_recorded` and its multi-finding sibling below exercise."""

    queue: list = []
    instantiations: int = 0

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.agents = agents
        self.tasks = tasks
        type(self).instantiations += 1
        self.usage_metrics = UsageMetrics(
            total_tokens=100 * len(tasks),
            successful_requests=len(tasks),
        )

    def kickoff(self):
        for agent in self.agents:
            for _ in self.tasks:
                agent.llm._track_token_usage_internal({"total_tokens": 100, "prompt_tokens": 80, "completion_tokens": 20})
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
    # 3 propose + 3 critique tasks, each "costing" 1 request in the fake.
    assert coordinator.state.tot_usage.successful_requests == 6


def test_a_run_with_no_contested_findings_never_touches_tot_crew(data_dir, findings):
    _queue_happy_path(["F01", "F02"])

    coordinator = Coordinator(data_dir)
    coordinator.run(findings)

    assert coordinator.state.tot_by_id == {}
    assert _QueuedFakeTotCrew.instantiations == 0
    assert coordinator.state.tot_usage is None  # never set -- _dispatch_tot returned before touching it


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
    assert UNPARSEABLE not in coordinator.state.tot_failures["F02"]  # short message only
    assert coordinator.state.last_raw_output["F02"] == UNPARSEABLE  # available for --verbose
    assert "F02" not in coordinator.state.tot_by_id
    assert coordinator.state.risk_by_id["F02"].bucket == "contested"  # untouched
    assert {r.finding_id for r in ranked} == {"F01", "F02"}  # both still in the plan
    # Real requests happened on the way to giving up (max_parse_attempts=1,
    # so no retry -- just the batched 3-task propose crew) -- that spend
    # must still land in tot_usage, not be dropped because the search failed.
    assert coordinator.state.tot_usage.successful_requests == 3


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


# --- constraint intake (interpret_constraint / submit_constraint) -----------


def test_interpret_constraint_resolves_asset_and_affected_findings(data_dir, findings):
    _QueuedFakeCrew.queue = [
        _constraint_interpretation_json(
            asset_id="A02", effect_kind="compensating_control", effect_value="WAF rule enabled",
            affected_finding_ids=["F02"], rationale="matched A02 via business_function",
        ),
    ]

    coordinator = Coordinator(data_dir)
    interpretation = coordinator.interpret_constraint(
        "the finance workstation now sits behind a WAF", findings
    )

    assert interpretation.asset_id == "A02"
    assert interpretation.effect_kind == "compensating_control"
    assert interpretation.effect_value == "WAF rule enabled"
    assert interpretation.affected_finding_ids == ["F02"]
    assert interpretation.rationale == "matched A02 via business_function"
    assert coordinator.state is None  # interpret_constraint alone never dispatches run()
    assert _QueuedFakeCrew.instantiations == 1  # one batched (single-task) crew, no retries needed


def test_interpret_constraint_raises_after_persistent_parse_failure(data_dir, findings):
    max_attempts = 2
    _QueuedFakeCrew.queue = [UNPARSEABLE, UNPARSEABLE]

    coordinator = Coordinator(data_dir, max_parse_attempts=max_attempts)
    with pytest.raises(coordinator_module.ConstraintInterpretationError, match="gave up after 2 attempt") as exc_info:
        coordinator.interpret_constraint("nonsense", findings)

    # The short message never embeds the raw output (untrusted, unbounded
    # model text) -- it survives only as __cause__.raw, chained on
    # purpose so a caller (cli.py, --verbose) can still reach it.
    assert UNPARSEABLE not in str(exc_info.value)
    from rhinosecure.agents.parsing import AgentOutputParseError

    assert isinstance(exc_info.value.__cause__, AgentOutputParseError)
    assert exc_info.value.__cause__.raw == UNPARSEABLE


def test_submit_constraint_without_memory_raises(data_dir, findings):
    coordinator = Coordinator(data_dir)  # no memory= given
    with pytest.raises(CoordinatorError, match="requires a Memory instance"):
        coordinator.submit_constraint("the finance workstation now sits behind a WAF", findings)


def test_submit_constraint_happy_path_persists_replans_and_diffs(data_dir, findings, tmp_path):
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    _QueuedFakeCrew.queue = [
        _constraint_interpretation_json(
            asset_id="A02", effect_kind="compensating_control", effect_value="WAF rule enabled",
            affected_finding_ids=["F02"],
        ),
        _research_json("F02", "CVE-2018-8410"),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        "F02",
    ]

    coordinator = Coordinator(data_dir, memory=memory)
    result = coordinator.submit_constraint(
        "the finance workstation now sits behind a WAF", findings
    )

    assert result.persisted is True
    assert result.constraint_id is not None
    assert result.run_id is not None
    assert result.unresolved_finding_ids == ()

    # Persisted via memory.py, asset-scoped, structured effect included.
    [stored] = memory.constraints_for_asset("A02")
    assert stored.constraint_text == "the finance workstation now sits behind a WAF"
    assert stored.effect_kind == "compensating_control"
    assert stored.effect_value == "WAF rule enabled"

    # Diff: A02 had zero compensating controls before -- adding one must
    # lower F02's risk_score (scoring.py's decay), a real, non-trivial delta.
    assert len(result.deltas) == 1
    delta = result.deltas[0]
    assert delta.finding_id == "F02"
    assert delta.after_risk_score < delta.before_risk_score
    assert delta.risk_score_changed is True
    assert delta.changed is True
    assert delta.after_verdict_summary == "fake verdict summary."
    assert delta.after_constraints_applied == ("the finance workstation now sits behind a WAF",)

    # runs/decisions/feedback all populated -- all four Section 7 tables exercised.
    run = memory.get_run(result.run_id)
    assert run.data_dir == str(data_dir)
    assert run.total_findings == 1
    decisions = memory.decisions_for_run(result.run_id)
    assert [d.finding_id for d in decisions] == ["F02"]
    [feedback] = memory.list_feedback()
    assert feedback.raw_input == "the finance workstation now sits behind a WAF"
    assert feedback.run_id == result.run_id
    assert "F02" in feedback.change_description


def test_submit_constraint_replans_in_place_when_a_full_plan_already_exists(data_dir, findings, tmp_path):
    """If this Coordinator already holds a full-fleet plan (the shape a
    long-lived, per-plan Coordinator produces -- e.g. the web job
    substrate, which seeds one via `run()` once and then submits
    constraints against it repeatedly), submit_constraint must preserve
    every OTHER finding's state via `replan()` rather than collapsing to
    just the affected finding via `run()`. The CLI's own Coordinator never
    exercises this branch -- it always starts `state=None` (see
    test_submit_constraint_happy_path_persists_replans_and_diffs above),
    so `self.run(affected)` there is unchanged."""
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    coordinator = Coordinator(data_dir, memory=memory)

    # Phase 1: a real, full-fleet run over both findings.
    _queue_happy_path(["F01", "F02"])
    coordinator.run(findings)
    original_f01 = coordinator.state.risk_by_id["F01"]
    assert set(coordinator.state.enriched_by_id) == {"F01", "F02"}

    # Phase 2: a constraint targeting only F02's asset (A02). If this used
    # `run(affected)` instead of `replan`, F01 would vanish from state
    # entirely and the queue below (which has no F01 research/environment
    # entries) would starve on the wrong stage.
    _QueuedFakeCrew.queue = [
        _constraint_interpretation_json(
            asset_id="A02", effect_kind="compensating_control", effect_value="WAF rule enabled",
            affected_finding_ids=["F02"],
        ),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        "F02",
    ]
    stages_seen = []
    result = coordinator.submit_constraint(
        "the finance workstation now sits behind a WAF", findings, on_stage=stages_seen.append
    )

    assert result.persisted is True
    assert len(result.deltas) == 1
    assert result.deltas[0].finding_id == "F02"
    assert stages_seen == ["interpreting", "persisting", "environment", "risk"]

    # replan(), not run(): F01's state survives untouched, by identity --
    # nothing re-dispatched a Crew for it in phase 2 (the queue above has
    # no F01 entries at all, so a stray dispatch would raise IndexError).
    assert set(coordinator.state.enriched_by_id) == {"F01", "F02"}
    assert coordinator.state.risk_by_id["F01"] is original_f01

    # The persisted runs row is scoped to the AFFECTED finding only, never
    # to self.state.risk_by_id wholesale (which now holds both F01 and
    # F02) -- the contested_count/contested_total bug this branch could
    # otherwise reintroduce if it read the whole-plan state directly.
    run = memory.get_run(result.run_id)
    assert run.total_findings == 1
    assert run.contested_total == 1
    assert run.contested_count == 0


def test_a_replan_dispatch_failure_is_recorded_per_finding_not_raised(
    data_dir, findings, tmp_path
):
    """A transport-level failure during the targeted replan (simulated
    here by leaving the targeted run's Crew queue empty, so its first
    kickoff() raises IndexError) is now caught by `_kickoff_batch`
    (agents/coordinator.py) at the point `crew.kickoff()` actually raises
    -- the same "record and skip" contract every other per-finding
    failure in this module already gets. It no longer escapes `replan()`
    uncaught, so `submit_constraint` no longer needs to wrap it into
    `ConstraintReplanFailedError` -- that exception's own docstring
    originally cited exactly this scenario as its motivating example; see
    its updated docstring for why that's no longer the live path. The
    constraint is still persisted (no rollback either way); the affected
    finding just ends up with no delta because this Coordinator has no
    prior `run()`, so `submit_constraint` takes the "fresh, scoped run"
    branch (`self.run(affected)`), and Research -- dispatched first --
    never produced output for it."""
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    _QueuedFakeCrew.queue = [
        _constraint_interpretation_json(
            asset_id="A02", effect_kind="compensating_control", effect_value="WAF rule enabled",
            affected_finding_ids=["F02"],
        ),
        # Nothing queued for the targeted run that follows -- its first
        # Crew.kickoff() (Research) pops from an empty queue and raises
        # IndexError, now caught by _kickoff_batch rather than escaping.
    ]

    coordinator = Coordinator(data_dir, memory=memory)
    result = coordinator.submit_constraint("the finance workstation now sits behind a WAF", findings)

    assert result.persisted is True
    assert result.deltas == ()
    assert "F02" in coordinator.state.research_failures
    assert "did not complete" in coordinator.state.research_failures["F02"]

    [stored] = memory.constraints_for_asset("A02")
    assert stored.id == result.constraint_id
    assert stored.constraint_text == "the finance workstation now sits behind a WAF"


def test_submit_constraint_when_interpreter_declines_persists_nothing(data_dir, findings, tmp_path):
    """A statement that is neither asset-scoped nor capacity-shaped (e.g.
    ungrounded or unrelated to any asset/window) -- the Interpreter is
    instructed to refuse rather than guess (constraint_intake.py's module
    docstring). A genuine fleet-wide capacity statement like Section 10's
    "only five patches fit this window" now resolves to constraint_kind=
    "capacity" instead -- see the capacity tests below."""
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    _QueuedFakeCrew.queue = [
        _constraint_interpretation_json(
            asset_id=None, rationale="statement names no asset and no recognizable capacity limit",
            constraint_kind=None,
        ),
    ]

    coordinator = Coordinator(data_dir, memory=memory)
    result = coordinator.submit_constraint("please prioritize things better", findings)

    assert result.persisted is False
    assert result.constraint_id is None
    assert result.run_id is None
    assert result.deltas == ()
    assert memory.all_active_constraints() == []
    assert _QueuedFakeCrew.instantiations == 1  # interpretation only -- no replan was ever dispatched


def test_submit_constraint_filters_out_a_hallucinated_finding_id(data_dir, findings, tmp_path):
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    _QueuedFakeCrew.queue = [
        _constraint_interpretation_json(
            asset_id="A02", effect_kind="patch_restriction", effect_value="no reboots during business hours",
            affected_finding_ids=["F02", "F99"],  # F99 does not exist
        ),
        _research_json("F02", "CVE-2018-8410"),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        "F02",
    ]

    coordinator = Coordinator(data_dir, memory=memory)
    result = coordinator.submit_constraint("no reboots during business hours on the finance box", findings)

    assert result.persisted is True
    assert result.unresolved_finding_ids == ("F99",)
    assert [d.finding_id for d in result.deltas] == ["F02"]


# --- fleet-wide capacity constraint (_submit_capacity_constraint) -----------
#
# CLAUDE.md Section 10's "only five patches fit this window". Unlike the
# asset-scoped flow above, this path is entirely LLM-free past the one
# interpret_constraint call -- it re-scores every finding through the exact
# same deterministic pipeline cli.run() uses (ingest.attach_threat_signals +
# scoring.score_finding), so these tests fake attach_threat_signals/
# load_kev_catalog/load_attack_index to a pure identity (no network, no
# snapshot files needed) rather than faking a Crew -- there is no second
# Crew dispatch for this path to fake in the first place.

CAPACITY_ASSETS_CSV = """asset_id,hostname,os,os_build,role,business_function,criticality,internet_exposed,environment,data_sensitivity,patch_window,patch_restrictions,compensating_controls,owner
A00,DC01,Windows Server 2022,20348,dc,Domain controller,5,True,prod,regulated,,,,it-infra
A01,H1,Windows 10,19045,workstation,Engineering workstation,5,True,prod,confidential,Sun 02:00-06:00,,,it-helpdesk
A06,H6,Windows 10,19045,workstation,Engineering workstation,3,True,prod,confidential,Sun 02:00-06:00,,,it-helpdesk
A07,H7,Windows 10,19045,workstation,Engineering workstation,4,True,prod,confidential,Sun 02:00-06:00,,,it-helpdesk
A04,H4,Windows 10,19045,workstation,Engineering workstation,2,True,prod,confidential,Sun 02:00-06:00,,,it-helpdesk
A02,H2,Windows 10,19045,workstation,Finance workstation,4,False,prod,confidential,Sun 02:00-06:00,,,it-helpdesk
"""

CAPACITY_FINDINGS_CSV = """finding_id,asset_id,cve_id,detected_date,scanner_severity,product,version,port,service,evidence
F00,A00,CVE-2020-1472,2026-08-01,critical,Netlogon,x,445,smb,Zerologon
F01,A01,CVE-2021-26855,2026-08-01,critical,Microsoft Exchange Server,2016 CU19,443,https,OWA SSRF chain
F06,A06,CVE-2024-0006,2026-08-01,critical,Fake Product,1.0,0,x,fake
F07,A07,CVE-2024-0007,2026-08-01,high,Fake Product,1.0,0,x,fake
F04,A04,CVE-2024-0004,2026-08-01,high,Fake Product,1.0,0,x,fake
F02,A02,CVE-2024-0002,2026-08-01,critical,Fake Product,1.0,0,x,fake
"""

# A separate, isolated fixture for the constraint-overlay regression test below --
# deliberately NOT added to CAPACITY_ASSETS_CSV/CAPACITY_FINDINGS_CSV above, since
# adding a finding there would change every other capacity test's pool_size/rank
# assertions for no reason relevant to what they're each testing.
CAPACITY_OVERLAY_ASSETS_CSV = """asset_id,hostname,os,os_build,role,business_function,criticality,internet_exposed,environment,data_sensitivity,patch_window,patch_restrictions,compensating_controls,owner
A08,H8,Windows 10,19045,workstation,Engineering workstation,3,True,prod,confidential,,,,it-helpdesk
"""

CAPACITY_OVERLAY_FINDINGS_CSV = """finding_id,asset_id,cve_id,detected_date,scanner_severity,product,version,port,service,evidence
F08,A08,CVE-2024-0008,2026-08-01,critical,Fake Product,1.0,0,x,fake
"""


@pytest.fixture
def capacity_data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "capacity"
    d.mkdir()
    (d / "assets.csv").write_text(CAPACITY_ASSETS_CSV, encoding="utf-8")
    (d / "findings.csv").write_text(CAPACITY_FINDINGS_CSV, encoding="utf-8")
    return d


@pytest.fixture
def capacity_findings(capacity_data_dir: Path):
    """F00 -> patch_now (epss bumped so it clears the 70 threshold -- proves
    patch_now is excluded from the pool by construction, not by an
    exemption list). F01(36.4) > F06(31.7) > F07(21.2) > F04(18.3) all land
    in next_window -- a real, distinct rank ordering to allocate against.
    F02 lands in accept -- proves that bucket is excluded too."""
    all_findings = list(join_findings(capacity_data_dir / "findings.csv", capacity_data_dir / "assets.csv"))
    return [
        e.model_copy(update={"epss": 0.9}) if e.finding.finding_id == "F00" else e
        for e in all_findings
    ]


@pytest.fixture(autouse=True)
def fake_capacity_enrichment(monkeypatch):
    """Identity attach_threat_signals + inert bulk loaders -- the capacity
    flow's real enrichment call, with no network/snapshot dependency. Only
    the capacity tests below rely on this; every other test in this file
    never reaches _submit_capacity_constraint at all."""
    monkeypatch.setattr(coordinator_module, "attach_threat_signals", lambda e, kev, attack, cache: e)
    monkeypatch.setattr(coordinator_module, "load_kev_catalog", lambda cache: None)
    monkeypatch.setattr(coordinator_module, "load_attack_index", lambda cache: None)


def _capacity_interpretation_json(patch_limit: int | None) -> str:
    return _constraint_interpretation_json(
        asset_id=None,
        constraint_kind="capacity",
        patch_limit=patch_limit,
        rationale="fleet-wide capacity statement",
    )


def test_submit_constraint_routes_a_capacity_kind_to_the_capacity_flow_with_no_extra_crew(
    capacity_data_dir, capacity_findings, tmp_path
):
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    _QueuedFakeCrew.queue = [_capacity_interpretation_json(2)]

    coordinator = Coordinator(capacity_data_dir, memory=memory)
    result = coordinator.submit_constraint("only two patches fit this window", capacity_findings)

    from rhinosecure.agents.coordinator import CapacitySubmissionResult

    assert isinstance(result, CapacitySubmissionResult)
    # Interpretation only -- _submit_capacity_constraint dispatches no
    # Research/Environment/Risk Crew at all.
    assert _QueuedFakeCrew.instantiations == 1


def test_submit_capacity_constraint_ranks_and_defers_by_limit(capacity_data_dir, capacity_findings, tmp_path):
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    _QueuedFakeCrew.queue = [_capacity_interpretation_json(2)]

    coordinator = Coordinator(capacity_data_dir, memory=memory)
    result = coordinator.submit_constraint("only two patches fit this window", capacity_findings)

    assert result.persisted is True
    assert result.capacity_constraint_id is not None
    assert result.run_id is not None

    # Only the 4 next_window findings ever get a delta -- F00 (patch_now)
    # and F02 (accept) are absent entirely, not present with fits=True.
    assert {d.finding_id for d in result.deltas} == {"F01", "F06", "F07", "F04"}
    by_id = {d.finding_id: d for d in result.deltas}
    assert all(d.pool_size == 4 and d.limit == 2 for d in result.deltas)

    # Rank order matches risk_score descending, tie-break irrelevant here
    # since all 4 scores are distinct.
    assert by_id["F01"].rank == 1 and by_id["F01"].fits and not by_id["F01"].changed
    assert by_id["F06"].rank == 2 and by_id["F06"].fits and not by_id["F06"].changed
    assert by_id["F07"].rank == 3 and not by_id["F07"].fits
    assert by_id["F04"].rank == 4 and not by_id["F04"].fits

    # The deferred pair actually changed bucket; risk_score is untouched --
    # this is a rank-position loss, not a change in risk (CapacityDelta's
    # own contract).
    for fid in ("F07", "F04"):
        d = by_id[fid]
        assert d.original_bucket == "next_window"
        assert d.effective_bucket == "deferred_capacity"
        assert d.changed is True
    for fid in ("F01", "F06"):
        d = by_id[fid]
        assert d.original_bucket == d.effective_bucket == "next_window"

    assert result.changed_deltas and {d.finding_id for d in result.changed_deltas} == {"F07", "F04"}

    # Memory: capacity_constraints, decisions (one per pool member, with the
    # capacity_* columns populated), and feedback all written.
    [stored] = memory.capacity_constraints_for_run(result.run_id)
    assert stored.raw_text == "only two patches fit this window"
    assert stored.patch_limit == 2
    assert stored.pool_size == 4
    assert stored.deferred_count == 2

    decisions = memory.decisions_for_run(result.run_id)
    assert {d.finding_id for d in decisions} == {"F01", "F06", "F07", "F04"}
    decisions_by_id = {d.finding_id: d for d in decisions}
    assert decisions_by_id["F07"].bucket == "deferred_capacity"
    assert decisions_by_id["F07"].capacity_rank == 3
    assert decisions_by_id["F07"].capacity_pool_size == 4
    assert decisions_by_id["F07"].capacity_limit == 2
    assert decisions_by_id["F01"].bucket == "next_window"
    assert decisions_by_id["F01"].capacity_rank == 1

    [feedback] = memory.list_feedback()
    assert feedback.raw_input == "only two patches fit this window"
    assert feedback.run_id == result.run_id
    assert "F07" in feedback.change_description
    assert "F04" in feedback.change_description
    assert "F01" not in feedback.change_description  # only the deferred pair is called out


def test_submit_capacity_constraint_limit_covers_the_full_pool_none_deferred(
    capacity_data_dir, capacity_findings, tmp_path
):
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    _QueuedFakeCrew.queue = [_capacity_interpretation_json(10)]

    coordinator = Coordinator(capacity_data_dir, memory=memory)
    result = coordinator.submit_constraint("ten patches fit this window", capacity_findings)

    assert len(result.deltas) == 4
    assert all(d.fits and not d.changed for d in result.deltas)
    assert result.changed_deltas == ()

    [stored] = memory.capacity_constraints_for_run(result.run_id)
    assert stored.deferred_count == 0

    [feedback] = memory.list_feedback()
    assert "all fit within capacity" in feedback.change_description


def test_submit_capacity_constraint_when_patch_limit_is_missing_persists_nothing(
    capacity_data_dir, capacity_findings, tmp_path
):
    """The Interpreter recognized a capacity-shaped statement but couldn't
    extract a usable integer -- nothing computed, nothing persisted."""
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    _QueuedFakeCrew.queue = [_capacity_interpretation_json(None)]

    coordinator = Coordinator(capacity_data_dir, memory=memory)
    result = coordinator.submit_constraint("we don't have much bandwidth this week", capacity_findings)

    assert result.persisted is False
    assert result.capacity_constraint_id is None
    assert result.run_id is None
    assert result.deltas == ()
    assert memory.list_runs() == []


def test_submit_capacity_constraint_applies_an_active_asset_constraint_before_ranking(tmp_path):
    """A08/F08 has no declared patch_window and no compensating_controls in
    assets.csv, so it lands in next_window by default (bucket_for's "no
    control, no window" fallback). An active compensating_control
    constraint on A08 -- persisted earlier via the asset-scoped flow, the
    same way a real prior `rhino constraint add` would -- flips it to
    mitigate_monitor (control + no window). The capacity pool must reflect
    that overlaid state, not assets.csv's raw, un-overlaid facts: F08 must
    be entirely absent from the pool, not present and merely deprioritized.
    This is the regression test for the gap an adversarial review caught --
    _submit_capacity_constraint originally re-scored straight from
    ground-truth assets.csv, skipping the same constraint overlay
    agents/risk.py's score_finding_tool already applies."""
    from rhinosecure.memory import Memory

    data_dir = tmp_path / "overlay"
    data_dir.mkdir()
    (data_dir / "assets.csv").write_text(CAPACITY_OVERLAY_ASSETS_CSV, encoding="utf-8")
    (data_dir / "findings.csv").write_text(CAPACITY_OVERLAY_FINDINGS_CSV, encoding="utf-8")
    findings = list(join_findings(data_dir / "findings.csv", data_dir / "assets.csv"))

    memory = Memory(tmp_path / "mem.db")
    memory.add_constraint("A08", "A08 now sits behind a new WAF rule", effect_kind="compensating_control",
                           effect_value="WAF rule enabled")
    _QueuedFakeCrew.queue = [_capacity_interpretation_json(5)]

    coordinator = Coordinator(data_dir, memory=memory)
    result = coordinator.submit_constraint("five patches fit this window", findings)

    assert result.persisted is True
    assert result.deltas == ()  # F08 is mitigate_monitor once overlaid -- never enters the pool


def test_submit_capacity_constraint_limit_zero_is_a_real_limit_not_a_decline(
    capacity_data_dir, capacity_findings, tmp_path
):
    """coordinator.py's own guard is `if interpretation.patch_limit is
    None`, deliberately not a truthiness check -- 0 ("zero patches fit
    this window") is a real, meaningful limit distinct from None ("the
    Interpreter couldn't extract a number"). `0` is falsy in Python, so a
    regression to `if not interpretation.patch_limit` would silently
    misroute this into the decline branch; this test only passes if the
    real `is None` check is what's actually running."""
    from rhinosecure.memory import Memory

    memory = Memory(tmp_path / "mem.db")
    _QueuedFakeCrew.queue = [_capacity_interpretation_json(0)]

    coordinator = Coordinator(capacity_data_dir, memory=memory)
    result = coordinator.submit_constraint("zero patches fit this window", capacity_findings)

    assert result.persisted is True
    assert result.capacity_constraint_id is not None
    assert len(result.deltas) == 4  # every next_window finding deferred, none fits
    assert all(not d.fits and d.changed for d in result.deltas)
    [stored] = memory.capacity_constraints_for_run(result.run_id)
    assert stored.patch_limit == 0
    assert stored.deferred_count == 4


# --- inventory injection: a non-native format has no assets.csv -------------
#
# Coordinator used to read <data_dir>/assets.csv itself, which made every
# --format other than native impossible on the agents and constraint
# paths. It now takes the already-loaded, already-validated inventory.


def _defender_asset():
    from rhinosecure.schema import Asset

    return Asset(
        asset_id="1a" * 20,
        hostname="dc01.corp.example.com",
        os="Windows Server 2019",
        os_build="17763",
        role="file",
        criticality=3,
        internet_exposed=False,
        environment="prod",
        data_sensitivity="internal",
        not_collected=frozenset({"role", "patch_window", "compensating_controls"}),
    )


def test_accepts_an_inventory_and_never_reads_assets_csv(tmp_path: Path):
    """tmp_path deliberately has no assets.csv -- a Defender export ships
    devices.csv instead, so reading the native filename would fail."""
    asset = _defender_asset()
    assert not (tmp_path / "assets.csv").exists()

    coordinator = Coordinator(tmp_path, assets={asset.asset_id: asset}, ingest_format="defender")

    assert coordinator._asset_index == {asset.asset_id: asset}
    assert coordinator.ingest_format == "defender"


def test_without_an_inventory_it_still_loads_the_native_assets_csv(data_dir: Path):
    """Every native caller omits assets= -- that path must be unchanged."""
    coordinator = Coordinator(data_dir)
    assert set(coordinator._asset_index) == {"A01", "A02"}
    assert coordinator.ingest_format == "native"


def test_without_an_inventory_and_without_assets_csv_it_fails_loudly(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        Coordinator(tmp_path)


def test_the_injected_inventory_reaches_the_environment_and_constraint_tools(tmp_path: Path):
    """The inventory is not just stored -- it is what Environment's
    lookup_asset_context and the Interpreter's search_assets read."""
    from rhinosecure.agents.constraint_intake import build_constraint_tools
    from rhinosecure.agents.environment import build_environment_tools

    asset = _defender_asset()
    coordinator = Coordinator(tmp_path, assets={asset.asset_id: asset}, ingest_format="defender")

    env = {t.name: t for t in build_environment_tools(coordinator._asset_index, [])}
    looked_up = json.loads(env["lookup_asset_context"].run(asset_id=asset.asset_id))
    assert looked_up["found"] is True
    assert looked_up["hostname"] == "dc01.corp.example.com"
    assert "patch_window" in looked_up["not_collected"]

    search = {t.name: t for t in build_constraint_tools(coordinator._asset_index, {}, [])}
    matches = json.loads(search["search_assets"].run(query="dc01"))["matches"]
    assert [m["asset_id"] for m in matches] == [asset.asset_id]


def test_ingest_format_is_recorded_on_the_runs_row(tmp_path: Path, monkeypatch):
    """A stored decision should say which adapter produced the inventory
    behind it. Checked through the capacity path, which is LLM-free past
    the one interpretation call this stubs out."""
    from rhinosecure.agents.constraint_intake import ConstraintInterpretation
    from rhinosecure.memory import Memory

    (tmp_path / "assets.csv").write_text(ASSETS_CSV, encoding="utf-8")
    (tmp_path / "findings.csv").write_text(FINDINGS_CSV, encoding="utf-8")
    findings = list(join_findings(tmp_path / "findings.csv", tmp_path / "assets.csv"))

    memory = Memory(tmp_path / "m.db")
    coordinator = Coordinator(tmp_path, memory=memory, ingest_format="defender")
    monkeypatch.setattr(
        Coordinator,
        "interpret_constraint",
        lambda self, text, f: ConstraintInterpretation(
            constraint_kind="capacity", asset_id=None, effect_kind=None, effect_value=None,
            patch_limit=1, affected_finding_ids=[], rationale="fake", sources=[],
        ),
    )

    result = coordinator.submit_constraint("only one patch fits this window", findings)

    assert memory.get_run(result.run_id).ingest_format == "defender"
    memory.close()
