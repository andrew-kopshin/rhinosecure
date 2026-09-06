"""Coverage for the dispatcher (`web/route.py`): `RoutePlan`/
`RoutePlanRegistry`, `assert_step_approved`/`edit_step` (the per-step
human-approval gate), `_view_scenario`, and the HTTP wiring end to end.

HTTP-level tests monkeypatch `route_module.route_message` directly rather
than faking `agents.router`'s own `Crew` -- `agents/router.py`'s own test
suite (`tests/test_router.py`) already covers the Router's own grounding/
retry behavior in depth; these tests are about what happens to a decision
ONCE this module has one, not about re-deriving it from a fake LLM
response. A live, real-Router end-to-end check is done separately (see
PROGRESS.md), not duplicated here as a slow, non-deterministic unit test.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from rhinosecure.agents.router import (
    OperationKind,
    RouterGroundingIssue,
    RouterGroundingResult,
    RouterOperation,
)
from rhinosecure.web import route as route_module
from rhinosecure.web import uploads as uploads_module
from rhinosecure.web.jobs import JobConfig, JobRegistry, PlanState, ResolvedSource
from rhinosecure.web.route import (
    RouteApprovalError,
    RoutePlan,
    RoutePlanRegistry,
    RouteStep,
    _view_scenario,
    assert_step_approved,
    claim_step,
    edit_step,
    execute_step,
)
from rhinosecure.web.server import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]


def _step(op: OperationKind, params: dict, *, approved=False, status="pending", **overrides) -> RouteStep:
    return RouteStep(op=op.value, params=params, summary="do it", approved=approved, status=status, **overrides)


# ---------------- assert_step_approved ----------------


def test_assert_step_approved_rejects_an_out_of_range_index():
    plan = RoutePlan(id="r1", message="m", steps=[])
    with pytest.raises(RouteApprovalError, match="does not exist"):
        assert_step_approved(plan, 0)


def test_assert_step_approved_requires_every_earlier_step_to_have_succeeded():
    plan = RoutePlan(
        id="r1", message="m",
        steps=[_step(OperationKind.VIEW_SCENARIO, {}, status="pending"), _step(OperationKind.VIEW_SCENARIO, {}, approved=True)],
    )
    with pytest.raises(RouteApprovalError, match="has not succeeded"):
        assert_step_approved(plan, 1)


def test_assert_step_approved_requires_the_step_itself_to_be_approved():
    plan = RoutePlan(id="r1", message="m", steps=[_step(OperationKind.VIEW_SCENARIO, {}, approved=False)])
    with pytest.raises(RouteApprovalError, match="has not been approved"):
        assert_step_approved(plan, 0)


def test_assert_step_approved_rejects_a_step_that_already_ran():
    plan = RoutePlan(id="r1", message="m", steps=[_step(OperationKind.VIEW_SCENARIO, {}, approved=True, status="succeeded")])
    with pytest.raises(RouteApprovalError, match="already"):
        assert_step_approved(plan, 0)


def test_assert_step_approved_returns_the_step_on_success():
    step = _step(OperationKind.VIEW_SCENARIO, {}, approved=True)
    plan = RoutePlan(id="r1", message="m", steps=[step])
    assert assert_step_approved(plan, 0) is step


# ---------------- claim_step ----------------


def test_claim_step_marks_the_step_running_and_returns_it():
    step = _step(OperationKind.VIEW_SCENARIO, {}, approved=True)
    plan = RoutePlan(id="r1", message="m", steps=[step])
    claimed = claim_step(plan, 0)
    assert claimed is step
    assert step.status == "running"


def test_claim_step_is_atomic_under_concurrent_approval():
    """Two threads racing to claim the SAME step: `plan.lock` guarantees
    exactly one wins (transitions it to "running") and the other is
    refused with RouteApprovalError -- closing a race an adversarial
    review found in the original unlocked "check, then separately set
    status" sequence, which could let a synchronous step (view_scenario/
    qa_question, which never touches JobRegistry's own single-slot
    guard) run twice."""
    step = _step(OperationKind.VIEW_SCENARIO, {"mode": "recommended"}, approved=True)
    plan = RoutePlan(id="r1", message="m", steps=[step])

    results: list[str] = []
    barrier = threading.Barrier(2)

    def _claim():
        barrier.wait()
        try:
            claim_step(plan, 0)
            results.append("ok")
        except RouteApprovalError:
            results.append("refused")

    threads = [threading.Thread(target=_claim) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results) == ["ok", "refused"]
    assert step.status == "running"


# ---------------- edit_step ----------------


def test_edit_step_updates_params_and_clears_its_own_approval():
    step = _step(OperationKind.CONSTRAINT_SUBMIT, {"raw_text": "old"}, approved=True)
    plan = RoutePlan(id="r1", message="m", steps=[step])
    edit_step(plan, 0, {"raw_text": "new"})
    assert step.params == {"raw_text": "new"}
    assert step.approved is False


def test_edit_step_clears_approval_on_every_later_step_too():
    step0 = _step(OperationKind.VIEW_SCENARIO, {"mode": "recommended"}, approved=True)
    step1 = _step(OperationKind.VIEW_SCENARIO, {"mode": "recommended"}, approved=True)
    plan = RoutePlan(id="r1", message="m", steps=[step0, step1])
    edit_step(plan, 0, {"mode": "selection"})
    assert step0.approved is False
    assert step1.approved is False


def test_edit_step_refuses_extra_fields_not_in_the_ops_fixed_shape():
    step = _step(OperationKind.CONSTRAINT_SUBMIT, {"raw_text": "old"})
    plan = RoutePlan(id="r1", message="m", steps=[step])
    with pytest.raises(RouteApprovalError, match="do not match the fixed shape"):
        edit_step(plan, 0, {"raw_text": "new", "asset_id": "A01"})
    assert step.params == {"raw_text": "old"}  # unchanged on refusal


def test_edit_step_refuses_a_step_that_already_ran():
    step = _step(OperationKind.VIEW_SCENARIO, {"mode": "recommended"}, status="succeeded")
    plan = RoutePlan(id="r1", message="m", steps=[step])
    with pytest.raises(RouteApprovalError, match="no longer be edited"):
        edit_step(plan, 0, {"mode": "selection"})


def test_edit_step_accepts_a_failed_step_and_resets_it_to_a_clean_pending_slate():
    """The one recovery path for a step that was approved and claimed but
    then failed downstream (validate_job_input, or the job itself) --
    without this, the only option would be abandoning the whole plan."""
    step = _step(
        OperationKind.REMEDIATION_MARK,
        {"finding_id": "F01", "status": "bogus", "note": None},
        status="failed",
        error={"stage": "validating input", "type": "HTTPException", "message": "bad status"},
        job_id="some-job-id",
        export_written=True,
    )
    plan = RoutePlan(id="r1", message="m", steps=[step])
    edit_step(plan, 0, {"finding_id": "F01", "status": "remediated", "note": None})
    assert step.status == "pending"
    assert step.error is None
    assert step.job_id is None
    assert step.export_written is False
    assert step.approved is False
    assert step.params == {"finding_id": "F01", "status": "remediated", "note": None}


def test_edit_step_rejects_an_out_of_range_index():
    plan = RoutePlan(id="r1", message="m", steps=[])
    with pytest.raises(RouteApprovalError, match="does not exist"):
        edit_step(plan, 0, {})


def test_edit_step_cannot_race_a_concurrent_dispatch_once_the_step_is_claimed():
    """A TOCTOU an adversarial review found in the pre-`claim_step` code:
    a step used to stay `"pending"` for the ENTIRE window between its
    approval check and `dispatch_job` actually being called, so a
    concurrent `edit_step` could rewrite `params` after the approval
    check passed but before the (stale) params were read for dispatch --
    reporting a successful edit that never actually affected what ran.
    `claim_step` closes this by moving the pending->running transition to
    BEFORE dispatch is ever attempted, atomically with the approval
    check -- so by the time a concurrent edit could arrive, the step is
    already `"running"`, and `edit_step`'s own precondition refuses it."""
    step = _step(OperationKind.CONSTRAINT_SUBMIT, {"raw_text": "original"}, approved=True)
    plan = RoutePlan(id="r1", message="m", steps=[step])
    claim_step(plan, 0)  # simulates a concurrent request that already claimed this step for dispatch
    assert step.status == "running"

    with pytest.raises(RouteApprovalError, match="no longer be edited"):
        edit_step(plan, 0, {"raw_text": "rewritten-after-claim"})
    assert step.params == {"raw_text": "original"}  # untouched -- the edit never got a chance to land


# ---------------- _sync_step_from_job ----------------


def test_sync_step_from_job_marks_a_step_failed_once_its_job_ages_out_of_history():
    """A step's Job can finish and then be evicted from JobRegistry's own
    bounded history before this ever polls it (a burst of other jobs
    running in between). An adversarial review found the original code
    silently returned in that case, leaving the step reporting "running"
    forever with no way for a client to ever learn what happened."""
    registry = JobRegistry(max_history=1)
    job = registry.create_and_start("remediation_mark", {"finding_id": "F00", "status": "remediated"})
    registry.finish(job.id, status="succeeded", result={"transition": "x"})
    # A second job pushes the first out of the bounded (max_history=1) history.
    job2 = registry.create_and_start("remediation_mark", {"finding_id": "F01", "status": "remediated"})
    registry.finish(job2.id, status="succeeded", result={"transition": "y"})
    assert registry.get(job.id) is None  # sanity: really evicted

    step = _step(OperationKind.REMEDIATION_MARK, {}, status="running", job_id=job.id)
    route_module._sync_step_from_job(step, registry)
    assert step.status == "failed"
    assert step.error["type"] == "JobHistoryEvictedError"


def test_sync_step_from_job_leaves_a_step_alone_once_it_is_no_longer_running():
    step = _step(OperationKind.REMEDIATION_MARK, {}, status="succeeded", result={"transition": "x"})
    registry = JobRegistry()
    route_module._sync_step_from_job(step, registry)  # no job_id, not "running" -- must be a no-op
    assert step.status == "succeeded"
    assert step.result == {"transition": "x"}


# ---------------- _context_note ----------------


def _upload_registry(tmp_path: Path) -> uploads_module.UploadRegistry:
    return uploads_module.UploadRegistry(tmp_path / "uploads")


def test_context_note_names_a_ready_uploads_id_and_its_known_format_match(tmp_path: Path):
    """Previously ungrounded: every route.py test monkeypatches route_
    message wholesale, so _context_note ran but its real return value
    was always discarded by the fake's **kw catch-all -- an adversarial
    review found no test ever actually read this string."""
    registry = _upload_registry(tmp_path)
    upload = registry.create_set()
    registry.record_file(upload.id, "assets.csv", 100)
    registry.record_file(upload.id, "findings.csv", 200)
    registry.set_label(upload.id, "assets.csv", "inventory")
    registry.set_label(upload.id, "findings.csv", "findings")

    plan_state = PlanState(JobConfig(data_dir=None, db_path=tmp_path / "mem.db"), export_path=tmp_path / "export.json")
    note = route_module._context_note(registry, plan_state)
    assert upload.id in note
    assert "already matches the built-in" in note  # assets.csv+findings.csv is the native format
    assert "No plan has been run yet" not in note  # superseded by the "no default source" branch below
    assert "empty workspace" in note


def test_context_note_flags_an_unlabeled_upload_as_not_ready(tmp_path: Path):
    registry = _upload_registry(tmp_path)
    upload = registry.create_set()
    registry.record_file(upload.id, "mystery.csv", 50)
    registry.record_file(upload.id, "other.csv", 60)  # two files, neither labeled -- not ready

    plan_state = PlanState(JobConfig(data_dir=None, db_path=tmp_path / "mem.db"), export_path=tmp_path / "export.json")
    note = route_module._context_note(registry, plan_state)
    assert "still need labeling" in note
    assert upload.id not in note  # a not-ready upload is never offered as a usable source_ref


def test_context_note_reports_an_existing_plan_by_its_active_source(tmp_path: Path):
    registry = _upload_registry(tmp_path)
    plan_state = PlanState(JobConfig(data_dir=None, db_path=tmp_path / "mem.db"), export_path=tmp_path / "export.json")
    plan_state.coordinator = object()  # _context_note only checks "is not None", never calls into it
    plan_state.active_source = ResolvedSource(data_dir=tmp_path / "some-source", fmt="native", adapter_config=None)

    note = route_module._context_note(registry, plan_state)
    assert "A plan already exists" in note
    assert str(tmp_path / "some-source") in note


def test_context_note_names_the_configured_default_source_when_no_plan_has_run_yet(tmp_path: Path):
    registry = _upload_registry(tmp_path)
    plan_state = PlanState(JobConfig(data_dir=tmp_path / "demo", db_path=tmp_path / "mem.db"), export_path=tmp_path / "export.json")

    note = route_module._context_note(registry, plan_state)
    assert "No plan has been run yet" in note
    assert repr(str(tmp_path / "demo")) in note  # the note repr()s the path, escaping backslashes on Windows


def test_context_note_reports_a_true_empty_workspace(tmp_path: Path):
    registry = _upload_registry(tmp_path)
    plan_state = PlanState(JobConfig(data_dir=None, db_path=tmp_path / "mem.db"), export_path=tmp_path / "export.json")

    note = route_module._context_note(registry, plan_state)
    assert "empty workspace" in note
    assert "No plan exists yet" in note


# ---------------- RoutePlanRegistry ----------------


def test_route_plan_registry_bounds_history():
    registry = RoutePlanRegistry(max_history=2)
    plans = [RoutePlan(id=str(i), message="m", steps=[]) for i in range(3)]
    for p in plans:
        registry.add(p)
    assert registry.get("0") is None  # evicted, oldest first
    assert registry.get("1") is not None
    assert registry.get("2") is not None
    assert [p.id for p in registry.list_recent()] == ["1", "2"]


# ---------------- _view_scenario ----------------


_EXPORT_DATA = {
    "findings": [
        {"finding_id": "F01", "bucket": "patch_now"},
        {"finding_id": "F02", "bucket": "accept"},
        {"finding_id": "F03", "bucket": "contested"},
        {"finding_id": "F04", "bucket": "next_window"},
    ]
}


def test_view_scenario_recommended_filters_to_patch_now_and_contested():
    result = _view_scenario(_EXPORT_DATA, {"mode": "recommended"})
    assert result["total"] == 4
    assert {f["finding_id"] for f in result["findings"]} == {"F01", "F03"}
    assert result["matched"] == 2


def test_view_scenario_selection_returns_everything_unfiltered():
    result = _view_scenario(_EXPORT_DATA, {"mode": "selection"})
    assert result["matched"] == result["total"] == 4


def test_view_scenario_defaults_to_recommended_when_mode_is_absent():
    result = _view_scenario(_EXPORT_DATA, {})
    assert result["mode"] == "recommended"


# ---------------- HTTP wiring ----------------


@pytest.fixture(autouse=True)
def isolated_uploads_dir(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(uploads_module, "DEFAULT_UPLOADS_DIR", tmp_path / "uploads")


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    config = JobConfig(data_dir=None, db_path=tmp_path / "mem.db")
    app = create_app(tmp_path / "export.json", jobs_enabled=True, job_config=config, chat_enabled=True)
    return TestClient(app)


def _fake_route_message(**canned):
    def _fn(message, history=None, *, registered_ops, known_upload_ids=frozenset(), known_finding_ids=frozenset(), context_note="", **kw):
        return RouterGroundingResult(**canned)
    return _fn


def _wait_for_step_terminal(client: TestClient, route_id: str, index: int, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    body = None
    while time.monotonic() < deadline:
        body = client.get(f"/api/route/{route_id}").json()
        if body["steps"][index]["status"] in ("succeeded", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError(f"step {index} of route {route_id} did not reach a terminal state within {timeout}s: {body}")


def test_propose_route_creates_a_plan_from_the_groundingresult(client: TestClient, monkeypatch):
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[RouterOperation(op=OperationKind.VIEW_SCENARIO, params={"mode": "recommended"}, summary="show it")],
            issues=[], clarify=None,
        ),
    )
    resp = client.post("/api/route", json={"message": "show me what needs patching"})
    assert resp.status_code == 201
    body = resp.json()
    assert len(body["steps"]) == 1
    assert body["steps"][0]["op"] == "view_scenario"
    assert body["steps"][0]["approved"] is False
    assert body["steps"][0]["status"] == "pending"
    assert body["clarify"] is None
    assert body["issues"] == []


def test_propose_route_surfaces_clarify_and_issues(client: TestClient, monkeypatch):
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[], issues=[RouterGroundingIssue(step_index=0, message="op not registered")],
            clarify="Which source did you mean?",
        ),
    )
    resp = client.post("/api/route", json={"message": "do something"})
    body = resp.json()
    assert body["steps"] == []
    assert body["clarify"] == "Which source did you mean?"
    assert body["issues"] == [{"step_index": 0, "message": "op not registered"}]


def test_propose_route_passes_chat_enabled_into_registered_ops(client: TestClient, monkeypatch):
    captured = {}

    def _fn(message, history=None, *, registered_ops, **kw):
        captured["registered_ops"] = registered_ops
        return RouterGroundingResult(grounded_operations=[], issues=[], clarify=None)

    monkeypatch.setattr(route_module, "route_message", _fn)
    client.post("/api/route", json={"message": "hi"})
    assert "qa_question" in captured["registered_ops"]
    assert "view_scenario" in captured["registered_ops"]
    assert "run_agents" in captured["registered_ops"]


def test_get_unknown_route_id_is_404(client: TestClient):
    assert client.get("/api/route/does-not-exist").status_code == 404


def test_approving_a_view_scenario_step_runs_it_synchronously(client: TestClient, monkeypatch, tmp_path):
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[RouterOperation(op=OperationKind.VIEW_SCENARIO, params={"mode": "recommended"}, summary="show it")],
            issues=[], clarify=None,
        ),
    )
    export_path = tmp_path / "export.json"
    export_path.write_text('{"findings": [{"finding_id": "F01", "bucket": "patch_now"}]}', encoding="utf-8")

    route_id = client.post("/api/route", json={"message": "show me the plan"}).json()["route_id"]
    resp = client.post(f"/api/route/{route_id}/steps/0/approve")
    assert resp.status_code == 200
    body = resp.json()
    assert body["steps"][0]["status"] == "succeeded"
    assert body["steps"][0]["approved"] is True
    assert body["steps"][0]["result"]["matched"] == 1


def test_approving_a_view_scenario_step_before_an_export_exists_fails_cleanly(client: TestClient, monkeypatch):
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[RouterOperation(op=OperationKind.VIEW_SCENARIO, params={"mode": "recommended"}, summary="show it")],
            issues=[], clarify=None,
        ),
    )
    route_id = client.post("/api/route", json={"message": "show me the plan"}).json()["route_id"]
    resp = client.post(f"/api/route/{route_id}/steps/0/approve")
    body = resp.json()
    assert body["steps"][0]["status"] == "failed"
    assert body["steps"][0]["error"]["stage"] == "reading export"


def test_approving_a_job_backed_step_dispatches_a_real_job(client: TestClient, monkeypatch):
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[
                RouterOperation(
                    op=OperationKind.REMEDIATION_MARK,
                    params={"finding_id": "F01", "status": "remediated", "note": None},
                    summary="mark F01 remediated",
                )
            ],
            issues=[], clarify=None,
        ),
    )
    route_id = client.post("/api/route", json={"message": "mark F01 remediated"}).json()["route_id"]
    resp = client.post(f"/api/route/{route_id}/steps/0/approve")
    assert resp.status_code == 202  # job-backed and still running -- see route.py's approve_step
    assert resp.json()["steps"][0]["status"] == "running"
    assert resp.json()["steps"][0]["job_id"] is not None

    body = _wait_for_step_terminal(client, route_id, 0)
    assert body["steps"][0]["status"] == "succeeded"
    assert body["steps"][0]["result"]["transition"] == "(untracked) -> remediated"
    assert body["steps"][0]["export_written"] is False  # remediation_mark never writes an export


def test_approving_a_qa_question_step_runs_it_synchronously(client: TestClient, monkeypatch, tmp_path):
    """qa_question is the other synchronous op (alongside view_scenario)
    -- never job-backed (module docstring: forcing it through JobRegistry
    would let a long run_agents job block a simple question). Previously
    untested at the route-dispatch layer."""
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[RouterOperation(op=OperationKind.QA_QUESTION, params={"question": "how many are contested?"}, summary="answer it")],
            issues=[], clarify=None,
        ),
    )
    monkeypatch.setattr(
        "rhinosecure.agents.chat.answer_question",
        lambda export_data, message, history=None, **kw: {"answer": "3 findings are contested.", "citations": []},
    )
    export_path = tmp_path / "export.json"
    export_path.write_text('{"findings": []}', encoding="utf-8")

    route_id = client.post("/api/route", json={"message": "how many are contested?"}).json()["route_id"]
    resp = client.post(f"/api/route/{route_id}/steps/0/approve")
    assert resp.status_code == 200  # synchronous op, already terminal by the time this returns
    body = resp.json()
    assert body["steps"][0]["status"] == "succeeded"
    assert body["steps"][0]["job_id"] is None
    assert body["steps"][0]["result"]["answer"] == "3 findings are contested."


def test_a_step_rejected_by_validate_job_input_fails_cleanly_and_can_be_recovered_via_edit(client: TestClient, monkeypatch):
    """remediation_mark's `status` is a bare `str` in the Router's own
    fixed pydantic shape (RemediationMarkParams) -- an invalid value
    passes that shape and must be caught by validate_job_input instead,
    which an adversarial review found this dispatch path used to skip
    entirely, letting it claim (and waste) the single global job slot
    before failing deep inside the job itself."""
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[
                RouterOperation(
                    op=OperationKind.REMEDIATION_MARK,
                    params={"finding_id": "F01", "status": "not_a_real_status", "note": None},
                    summary="mark F01 with a bogus status",
                )
            ],
            issues=[], clarify=None,
        ),
    )
    route_id = client.post("/api/route", json={"message": "mark F01 bogus"}).json()["route_id"]
    resp = client.post(f"/api/route/{route_id}/steps/0/approve")
    assert resp.status_code == 200  # a terminal failure, not a claim in flight and not a 409
    body = resp.json()
    assert body["steps"][0]["status"] == "failed"
    assert body["steps"][0]["error"]["stage"] == "validating input"
    assert body["steps"][0]["job_id"] is None  # never actually claimed a job slot

    # The recovery path: edit the failed step with valid params, then re-approve.
    edit_resp = client.post(
        f"/api/route/{route_id}/steps/0",
        json={"params": {"finding_id": "F01", "status": "remediated", "note": None}},
    )
    assert edit_resp.status_code == 200
    edited = edit_resp.json()["steps"][0]
    assert edited["status"] == "pending"
    assert edited["error"] is None

    approve_resp = client.post(f"/api/route/{route_id}/steps/0/approve")
    assert approve_resp.status_code == 202
    final = _wait_for_step_terminal(client, route_id, 0)
    assert final["steps"][0]["status"] == "succeeded"


def test_dispatching_while_another_job_holds_the_slot_reverts_to_pending_and_raises(tmp_path: Path):
    """The functional shape of "two route plans racing for the same job
    slot": JobRegistry's single-job-at-a-time guard is process-wide, not
    per-plan, so a job-backed step from ANY source (a bare POST
    /api/jobs, or a different RoutePlan's step) can already hold it.
    Exercised directly against execute_step/JobRegistry -- deterministic,
    unlike racing two real HTTP jobs against a fixture-sized run that
    might finish before the second request lands."""
    registry = JobRegistry()
    occupying = registry.create_and_start("remediation_mark", {"finding_id": "F00", "status": "remediated"})
    assert occupying is not None  # sanity: the slot is genuinely held

    plan_state = PlanState(JobConfig(data_dir=None, db_path=tmp_path / "mem.db"), export_path=tmp_path / "export.json")
    step = _step(
        OperationKind.REMEDIATION_MARK,
        {"finding_id": "F01", "status": "remediated", "note": None},
        approved=True,
    )
    plan = RoutePlan(id="r1", message="m", steps=[step])

    with pytest.raises(RouteApprovalError, match="another job is already running"):
        execute_step(plan, 0, registry=registry, plan_state=plan_state)
    assert step.status == "pending"  # reverted -- transient, not a property of this step's params
    assert step.job_id is None


def test_approve_step_does_not_roll_back_approval_when_a_concurrent_request_already_claimed_it(client: TestClient, monkeypatch):
    """Simulates the exact race claim_step's lock exists to prevent: by
    the time THIS request's execute_step call fails, the step is no
    longer "pending" -- it's "running", because a concurrent request
    already won the claim. An adversarial review found approve_step used
    to roll `approved` back to False unconditionally on any
    RouteApprovalError, which would have misreported a step that's
    genuinely in flight (thanks to the other request) as never having
    been approved at all."""
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[RouterOperation(op=OperationKind.VIEW_SCENARIO, params={"mode": "recommended"}, summary="a")],
            issues=[], clarify=None,
        ),
    )
    route_id = client.post("/api/route", json={"message": "one step"}).json()["route_id"]
    plan = client.app.state.route_plan_registry.get(route_id)
    plan.steps[0].approved = True
    claim_step(plan, 0)  # simulate a concurrent request that already won the race
    assert plan.steps[0].status == "running"

    resp = client.post(f"/api/route/{route_id}/steps/0/approve")
    assert resp.status_code == 409
    assert plan.steps[0].approved is True  # NOT rolled back -- the step really is in flight
    assert plan.steps[0].status == "running"  # untouched by the losing request


def test_a_dispatched_jobs_real_failure_propagates_onto_the_step_via_polling(client: TestClient, monkeypatch):
    """Distinct from the validate_job_input case above: this step DOES
    pass validate_job_input and DOES get dispatched (a real job_id is
    set) -- the failure happens deeper, inside the job itself, after a
    background thread already started. No test previously drove a
    dispatched job-backed step all the way to a real failure and checked
    that `_sync_step_from_job` (invoked on every `GET /api/route/{id}`)
    actually surfaces it -- every prior job-backed test only covered the
    success path."""
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[
                RouterOperation(
                    op=OperationKind.RUN_DETERMINISTIC,
                    params={"source_ref": "totally-bogus-source-that-does-not-exist"},
                    summary="run a source that doesn't exist",
                )
            ],
            issues=[], clarify=None,
        ),
    )
    route_id = client.post("/api/route", json={"message": "run it"}).json()["route_id"]
    resp = client.post(f"/api/route/{route_id}/steps/0/approve")
    assert resp.status_code == 202
    assert resp.json()["steps"][0]["job_id"] is not None  # really dispatched, unlike the pre-check-rejected case

    body = _wait_for_step_terminal(client, route_id, 0)
    assert body["steps"][0]["status"] == "failed"
    assert "no such" in body["steps"][0]["error"]["message"].lower()


def test_export_written_propagates_from_the_underlying_job_to_the_step(tmp_path: Path, monkeypatch):
    """Uses the real, frozen data/demo fixture with offline=True (the
    repo's own committed snapshots -- no network) to prove a job-backed
    step's export_written flag really reflects the underlying Job's,
    not just a hardcoded default."""
    config = JobConfig(data_dir=None, db_path=tmp_path / "mem.db", offline=True)
    app = create_app(tmp_path / "export.json", jobs_enabled=True, job_config=config)
    client = TestClient(app)
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[RouterOperation(op=OperationKind.RUN_DETERMINISTIC, params={"source_ref": "demo"}, summary="run demo")],
            issues=[], clarify=None,
        ),
    )
    route_id = client.post("/api/route", json={"message": "run demo"}).json()["route_id"]
    client.post(f"/api/route/{route_id}/steps/0/approve")
    body = _wait_for_step_terminal(client, route_id, 0, timeout=20.0)
    assert body["steps"][0]["status"] == "succeeded", body["steps"][0].get("error")
    assert body["steps"][0]["export_written"] is True


def test_approving_step_1_before_step_0_succeeds_is_refused(client: TestClient, monkeypatch):
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[
                RouterOperation(op=OperationKind.VIEW_SCENARIO, params={"mode": "recommended"}, summary="a"),
                RouterOperation(op=OperationKind.VIEW_SCENARIO, params={"mode": "recommended"}, summary="b", depends_on=0),
            ],
            issues=[], clarify=None,
        ),
    )
    route_id = client.post("/api/route", json={"message": "two steps"}).json()["route_id"]
    resp = client.post(f"/api/route/{route_id}/steps/1/approve")
    assert resp.status_code == 409
    assert client.get(f"/api/route/{route_id}").json()["steps"][1]["approved"] is False  # rolled back


def test_editing_a_step_via_http_clears_its_approval(client: TestClient, monkeypatch):
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(
            grounded_operations=[RouterOperation(op=OperationKind.VIEW_SCENARIO, params={"mode": "recommended"}, summary="a")],
            issues=[], clarify=None,
        ),
    )
    route_id = client.post("/api/route", json={"message": "one step"}).json()["route_id"]
    resp = client.post(f"/api/route/{route_id}/steps/0", json={"params": {"mode": "selection"}})
    assert resp.status_code == 200
    step = resp.json()["steps"][0]
    assert step["params"] == {"mode": "selection"}
    assert step["approved"] is False


def test_editing_an_unknown_step_index_is_404(client: TestClient, monkeypatch):
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(grounded_operations=[], issues=[], clarify=None),
    )
    route_id = client.post("/api/route", json={"message": "nothing"}).json()["route_id"]
    resp = client.post(f"/api/route/{route_id}/steps/0", json={"params": {}})
    assert resp.status_code == 404


def test_approving_an_unknown_step_index_is_404(client: TestClient, monkeypatch):
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(grounded_operations=[], issues=[], clarify=None),
    )
    route_id = client.post("/api/route", json={"message": "nothing"}).json()["route_id"]
    resp = client.post(f"/api/route/{route_id}/steps/0/approve")
    assert resp.status_code == 404


def test_list_routes_returns_recent_plans(client: TestClient, monkeypatch):
    monkeypatch.setattr(
        route_module, "route_message",
        _fake_route_message(grounded_operations=[], issues=[], clarify=None),
    )
    client.post("/api/route", json={"message": "one"})
    client.post("/api/route", json={"message": "two"})
    resp = client.get("/api/route")
    assert len(resp.json()) == 2


def test_default_app_never_mounts_route(tmp_path: Path):
    app = create_app(tmp_path / "export.json")
    client = TestClient(app)
    assert client.post("/api/route", json={"message": "x"}).status_code == 404
