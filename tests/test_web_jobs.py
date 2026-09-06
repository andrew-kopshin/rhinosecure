"""Coverage for the job substrate (`web/jobs.py`), mounted via
`create_app(jobs_enabled=True, ...)`.

The `JobRegistry` tests are pure Python -- no HTTP, no threading, no
Coordinator -- and cover the single-job-at-a-time guard and bounded
history deterministically, without timing tricks.

The HTTP-level tests exercise the real `Coordinator`/`Memory`/native
adapter/`export.write_run_export` machinery end to end, with only the LLM
dispatch faked (the same `_QueuedFakeCrew` pattern `test_coordinator.py`
uses for the same reason -- these tests cover the actual integration
point, not a mocked-out approximation of it). Duplicated here rather than
imported from `test_coordinator.py`, matching this suite's existing
convention of each test file owning its own fixtures.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from rhinosecure.agents import coordinator as coordinator_module
from rhinosecure.web import jobs as jobs_module
from rhinosecure.web.jobs import JobConfig, JobRegistry
from rhinosecure.web.server import create_app

ASSETS_CSV = """asset_id,hostname,os,os_build,role,business_function,criticality,internet_exposed,environment,data_sensitivity,patch_window,patch_restrictions,compensating_controls,owner
A01,EXCH01,Windows Server 2019,17763,exchange,Mail server,5,True,prod,confidential,Sun 02:00-06:00,,,messaging-team
A02,WKS01,Windows 10,19045,workstation,Finance workstation,2,False,prod,confidential,,,,it-helpdesk
"""

FINDINGS_CSV = """finding_id,asset_id,cve_id,detected_date,scanner_severity,product,version,port,service,evidence
F01,A01,CVE-2021-26855,2026-08-01,critical,Microsoft Exchange Server,2016 CU19,443,https,OWA SSRF chain
F02,A02,CVE-2018-8410,2026-08-08,high,Microsoft OLE DB Driver,18.2,1433,mssql,Outdated OLE DB provider
"""

UNPARSEABLE = "this is not json and will never parse, no matter how many times you ask"


class _QueuedFakeCrew:
    """Trimmed-down stand-in for crewai.Crew -- see test_coordinator.py's
    fuller original. Research/Environment: pops one raw JSON string per
    task. Risk (detected by the score_finding tool): pops a finding_id
    and calls the REAL score_finding tool for it."""

    queue: list = []

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.tasks = tasks
        self.agent = agents[0]
        self.usage_metrics = None

    def kickoff(self):
        is_risk_stage = any(t.name == "score_finding" for t in self.agent.tools)
        for task in self.tasks:
            if is_risk_stage:
                finding_id = _QueuedFakeCrew.queue.pop(0)
                tool_result = json.loads(self.agent.tools[0].run(finding_id=finding_id))
                raw = json.dumps(
                    {
                        "finding_id": tool_result["finding_id"],
                        "cve_id": tool_result["cve_id"],
                        "asset_id": tool_result["asset_id"],
                        "hostname": tool_result["hostname"],
                        "risk_score": tool_result["risk_score"],
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


def _research_json(fid: str, cve_id: str) -> str:
    return json.dumps(
        {
            "finding_id": fid,
            "cve_id": cve_id,
            "scanner_severity": "high",
            "is_kev": False,
            "exploitation_summary": "fake research summary",
            "sources": ["fake"],
        }
    )


def _environment_json(fid: str, cve_id: str, asset_id: str, hostname: str) -> str:
    return json.dumps(
        {
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
    )


def _constraint_interpretation_json(
    *,
    asset_id: str | None,
    effect_kind: str | None = None,
    effect_value: str | None = None,
    affected_finding_ids: list[str] | None = None,
    constraint_kind: str | None = "asset",
) -> str:
    return json.dumps(
        {
            "constraint_kind": constraint_kind,
            "asset_id": asset_id,
            "effect_kind": effect_kind,
            "effect_value": effect_value,
            "patch_limit": None,
            "affected_finding_ids": affected_finding_ids or [],
            "rationale": "fake rationale",
            "sources": ["fake"],
        }
    )


def _queue_full_seed_run() -> None:
    _QueuedFakeCrew.queue = [
        _research_json("F01", "CVE-2021-26855"),
        _research_json("F02", "CVE-2018-8410"),
        _environment_json("F01", "CVE-2021-26855", "A01", "EXCH01"),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        "F01",
        "F02",
    ]


@pytest.fixture(autouse=True)
def fake_crew(monkeypatch):
    _QueuedFakeCrew.queue = []
    monkeypatch.setattr(coordinator_module, "Crew", _QueuedFakeCrew)


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    (d / "assets.csv").write_text(ASSETS_CSV, encoding="utf-8")
    (d / "findings.csv").write_text(FINDINGS_CSV, encoding="utf-8")
    return d


@pytest.fixture
def app_and_client(data_dir: Path, tmp_path: Path):
    export_path = tmp_path / "export.json"
    config = JobConfig(data_dir=data_dir, db_path=tmp_path / "mem.db")
    app = create_app(export_path, jobs_enabled=True, job_config=config)
    return app, TestClient(app), export_path


def _wait_for_terminal(client: TestClient, job_id: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    body = None
    while time.monotonic() < deadline:
        body = client.get(f"/api/jobs/{job_id}").json()
        if body["status"] in ("succeeded", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not reach a terminal state within {timeout}s: {body}")


# --- JobRegistry: pure Python, deterministic, no HTTP/threading -------------


def test_registry_enforces_one_job_at_a_time():
    registry = JobRegistry()
    job1 = registry.create_and_start("constraint_submit", {"text": "a"})
    assert job1 is not None
    assert job1.status == "running"
    assert job1.started_at is not None

    job2 = registry.create_and_start("constraint_submit", {"text": "b"})
    assert job2 is None  # rejected -- no job record created for it
    assert registry.list_recent() == [job1]

    registry.finish(job1.id, status="succeeded", result={"ok": True})
    job3 = registry.create_and_start("constraint_submit", {"text": "c"})
    assert job3 is not None  # slot freed once job1 finished


def test_registry_bounds_job_history():
    registry = JobRegistry(max_history=3)
    ids = []
    for i in range(5):
        job = registry.create_and_start("constraint_submit", {"n": i})
        assert job is not None
        registry.finish(job.id, status="succeeded")
        ids.append(job.id)

    assert len(registry.list_recent(limit=10)) == 3
    assert registry.get(ids[0]) is None  # evicted, oldest first
    assert registry.get(ids[1]) is None
    assert registry.get(ids[-1]) is not None


def test_set_stage_on_an_unknown_job_id_is_a_silent_no_op():
    registry = JobRegistry()
    registry.set_stage("does-not-exist", "research")  # must not raise


# --- Route-level: default app never mounts these (covered in test_web_server.py) ---


def test_default_app_rejects_a_running_job_check_gracefully(tmp_path):
    """Sanity check that create_app(jobs_enabled=True) requires job_config."""
    with pytest.raises(ValueError, match="requires job_config"):
        create_app(tmp_path / "export.json", jobs_enabled=True)


# --- Full lifecycle, real Coordinator/Memory/adapter, faked Crew ------------


def test_health_reports_jobs_enabled(app_and_client):
    _, client, _ = app_and_client
    assert client.get("/api/health").json()["jobs_enabled"] is True


def test_unknown_job_kind_is_a_400(app_and_client):
    _, client, _ = app_and_client
    resp = client.post("/api/jobs", json={"kind": "not_a_real_kind", "input": {}})
    assert resp.status_code == 400


def test_constraint_submit_requires_non_empty_text(app_and_client):
    _, client, _ = app_and_client
    resp = client.post("/api/jobs", json={"kind": "constraint_submit", "input": {"text": "   "}})
    assert resp.status_code == 400


def test_a_job_already_running_is_a_409(app_and_client):
    app, client, _ = app_and_client
    app.state.job_registry.create_and_start("constraint_submit", {"text": "already running"})
    resp = client.post("/api/jobs", json={"kind": "constraint_submit", "input": {"text": "another one"}})
    assert resp.status_code == 409


def test_unknown_job_id_is_a_404(app_and_client):
    _, client, _ = app_and_client
    assert client.get("/api/jobs/does-not-exist").status_code == 404


def test_happy_path_seeds_the_plan_submits_and_refreshes_the_whole_fleet_export(app_and_client):
    _, client, export_path = app_and_client
    assert not export_path.exists()

    _queue_full_seed_run()
    _QueuedFakeCrew.queue += [
        _constraint_interpretation_json(
            asset_id="A02",
            effect_kind="compensating_control",
            effect_value="WAF rule enabled",
            affected_finding_ids=["F02"],
        ),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        "F02",
    ]

    resp = client.post(
        "/api/jobs",
        json={
            "kind": "constraint_submit",
            "input": {"text": "the finance workstation now sits behind a WAF"},
        },
    )
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]
    assert resp.json()["status"] == "running"

    body = _wait_for_terminal(client, job_id)
    assert body["status"] == "succeeded"
    assert body["error"] is None
    assert body["result"]["kind"] == "asset"
    assert body["result"]["persisted"] is True
    assert len(body["result"]["deltas"]) == 1
    assert body["result"]["deltas"][0]["finding_id"] == "F02"
    assert body["export_written"] is True
    assert body["export_warning"] is None

    # The refreshed export reflects the WHOLE fleet (F01 and F02), not
    # just the affected finding -- the replan branch, not run(affected).
    export_body = client.get("/api/export").json()
    assert {f["finding_id"] for f in export_body["findings"]} == {"F01", "F02"}
    assert export_path.exists()

    # A second, independent job (no plan re-seed needed) still works.
    _QueuedFakeCrew.queue = [
        _constraint_interpretation_json(asset_id=None, constraint_kind=None),
    ]
    resp2 = client.post(
        "/api/jobs", json={"kind": "constraint_submit", "input": {"text": "please prioritize better"}}
    )
    body2 = _wait_for_terminal(client, resp2.json()["job_id"])
    assert body2["status"] == "succeeded"
    assert body2["result"]["persisted"] is False


def test_a_refused_interpretation_is_not_a_failure(app_and_client):
    _, client, export_path = app_and_client
    _queue_full_seed_run()
    _QueuedFakeCrew.queue.append(
        _constraint_interpretation_json(
            asset_id=None, constraint_kind=None,
        )
    )

    resp = client.post(
        "/api/jobs", json={"kind": "constraint_submit", "input": {"text": "please prioritize better"}}
    )
    body = _wait_for_terminal(client, resp.json()["job_id"])

    assert body["status"] == "succeeded"
    assert body["result"]["persisted"] is False
    assert body["export_written"] is False
    assert not export_path.exists()  # nothing to refresh -- never attempted


def test_interpretation_that_never_parses_fails_with_nothing_persisted(app_and_client):
    app, client, export_path = app_and_client
    _queue_full_seed_run()
    _QueuedFakeCrew.queue += [UNPARSEABLE] * 3  # DEFAULT_MAX_PARSE_ATTEMPTS

    resp = client.post(
        "/api/jobs", json={"kind": "constraint_submit", "input": {"text": "gibberish constraint"}}
    )
    body = _wait_for_terminal(client, resp.json()["job_id"])

    assert body["status"] == "failed"
    assert body["error"]["stage"] == "interpreting"
    assert body["error"]["type"] == "ConstraintInterpretationError"
    assert not export_path.exists()
    assert app.state.plan_state.memory.all_active_constraints() == []


def test_a_replan_dispatch_failure_still_persists_the_constraint_and_succeeds(app_and_client):
    """A transport-level failure during the targeted replan (simulated by
    an empty Crew queue, so its first kickoff() raises IndexError) is now
    caught inside `agents/coordinator.py`'s `_kickoff_batch` at the point
    `crew.kickoff()` actually raises -- the same "record and skip"
    contract every other per-finding failure already gets, rather than
    escaping `replan()` uncaught and getting wrapped into
    `ConstraintReplanFailedError` (this test's own prior name for itself).
    The job now succeeds: the constraint is persisted and the export is
    written normally; the affected finding just has no delta, since
    Environment -- dispatched first by `replan()` -- never produced
    output for it (see `test_coordinator.py`'s own direct test of that
    per-finding failure recording)."""
    app, client, export_path = app_and_client
    _queue_full_seed_run()
    _QueuedFakeCrew.queue.append(
        _constraint_interpretation_json(
            asset_id="A02",
            effect_kind="compensating_control",
            effect_value="WAF rule enabled",
            affected_finding_ids=["F02"],
        )
    )
    # Nothing queued for the targeted replan that follows -- its first
    # Crew.kickoff() (Environment) pops from an empty queue and raises
    # IndexError, now caught by _kickoff_batch rather than escaping.

    resp = client.post(
        "/api/jobs",
        json={"kind": "constraint_submit", "input": {"text": "the finance workstation now sits behind a WAF"}},
    )
    body = _wait_for_terminal(client, resp.json()["job_id"])

    assert body["status"] == "succeeded"
    assert body["export_written"] is True
    assert body["result"]["deltas"] == []
    assert export_path.exists()

    # Persisted regardless -- unaffected by the dispatch failure either way.
    [stored] = app.state.plan_state.memory.constraints_for_asset("A02")
    assert stored.constraint_text == "the finance workstation now sits behind a WAF"


def test_export_write_failure_is_a_warning_not_an_error(app_and_client, monkeypatch):
    """The constraint applied and the decisions are real -- only the file
    refresh failed. Distinct from `error`, since collapsing the two would
    misreport a working constraint as a failed submission."""
    _, client, export_path = app_and_client
    _queue_full_seed_run()
    _QueuedFakeCrew.queue += [
        _constraint_interpretation_json(
            asset_id="A02",
            effect_kind="compensating_control",
            effect_value="WAF rule enabled",
            affected_finding_ids=["F02"],
        ),
        _environment_json("F02", "CVE-2018-8410", "A02", "WKS01"),
        "F02",
    ]

    def _boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(jobs_module.export, "write_run_export", _boom)

    resp = client.post(
        "/api/jobs",
        json={"kind": "constraint_submit", "input": {"text": "the finance workstation now sits behind a WAF"}},
    )
    body = _wait_for_terminal(client, resp.json()["job_id"])

    assert body["status"] == "succeeded"
    assert body["error"] is None
    assert body["result"]["persisted"] is True
    assert body["export_written"] is False
    assert "disk full" in body["export_warning"]
    assert not export_path.exists()
