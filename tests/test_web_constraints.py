"""Coverage for `POST /api/constraints/{id}/retract` (web/jobs.py), the web
parity for `rhino constraint retract` -- docs/handoff-2026-09-20.md section 5:
"the web Constraints tab has no remove control (the CLI has `retract`)."

Deliberately lightweight, unlike test_web_jobs.py's crew-mocked integration
suite: this route never touches Coordinator/Crew at all, only `Memory`
(`plan_state.memory` when a plan has been seeded, or a throwaway `Memory`
over the same db_path otherwise -- the same fallback three other jobs.py
handlers already use). Constraints are seeded directly via `Memory.
add_constraint` against the exact db file `JobConfig.db_path` points at,
with `data_dir=None` (no plan run at all) confirming the route needs no
seeded plan, matching the CLI's own retract command.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from rhinosecure.memory import Memory
from rhinosecure.web.jobs import JobConfig
from rhinosecure.web.server import create_app


@pytest.fixture
def app_and_db(tmp_path: Path):
    db_path = tmp_path / "test.db"
    config = JobConfig(data_dir=None, db_path=db_path)
    app = create_app(jobs_enabled=True, job_config=config)
    return app, TestClient(app), db_path


def test_retract_deactivates_an_active_constraint(app_and_db):
    _, client, db_path = app_and_db
    constraint_id = Memory(db_path).add_constraint("A02", "payroll server only reboots on Sundays")

    resp = client.post(f"/api/constraints/{constraint_id}/retract")
    assert resp.status_code == 200
    body = resp.json()
    assert body["constraint_id"] == constraint_id
    assert body["retracted"] is True
    assert "inactive" in body["note"]

    with Memory(db_path) as memory:
        assert memory.constraints_for_asset("A02", active_only=True) == []
        assert len(memory.constraints_for_asset("A02", active_only=False)) == 1  # soft-delete, not gone


def test_retract_is_a_soft_delete_the_record_survives_and_stays_inactive(app_and_db):
    """CLI parity, not just the same status code -- the record must stay
    on file (memory.py's own docstring: "retracted constraints stay in the
    table... so the historical record survives"), never removed."""
    _, client, db_path = app_and_db
    constraint_id = Memory(db_path).add_constraint("A01", "no patching during business hours")

    client.post(f"/api/constraints/{constraint_id}/retract")

    with Memory(db_path) as memory:
        [record] = memory.constraints_for_asset("A01", active_only=False)
        assert record.id == constraint_id
        assert record.active is False
        assert record.constraint_text == "no patching during business hours"


def test_retract_an_unknown_id_is_refused_not_silently_accepted(app_and_db):
    _, client, _ = app_and_db
    resp = client.post("/api/constraints/999999/retract")
    assert resp.status_code == 404
    assert "no active constraint with id 999999" in resp.json()["detail"]


def test_retract_an_already_retracted_id_is_refused_the_second_time(app_and_db):
    """Mirrors the CLI's own message ("an already-retracted one cannot be
    retracted again") -- a second retract of the same id must not succeed
    a second time, or silently no-op with a 200."""
    _, client, db_path = app_and_db
    constraint_id = Memory(db_path).add_constraint("A01", "no patching during business hours")

    first = client.post(f"/api/constraints/{constraint_id}/retract")
    assert first.status_code == 200

    second = client.post(f"/api/constraints/{constraint_id}/retract")
    assert second.status_code == 404
    assert f"no active constraint with id {constraint_id}" in second.json()["detail"]


def test_retract_needs_no_seeded_plan(app_and_db):
    """`data_dir=None` (the empty-workspace start, no run_deterministic/
    run_agents job ever dispatched) must not block retraction -- `rhino
    constraint retract` itself has no such requirement, and this route
    falls back to a throwaway Memory(db_path) exactly like the other
    handlers in this module already do when plan_state.memory is None."""
    app, client, db_path = app_and_db
    assert app.state.plan_state.memory is None  # confirms the no-plan-seeded state this test targets

    constraint_id = Memory(db_path).add_constraint("A03", "SQL server: no reboot without change ticket")
    resp = client.post(f"/api/constraints/{constraint_id}/retract")
    assert resp.status_code == 200


def test_retract_only_affects_the_named_constraint(app_and_db):
    _, client, db_path = app_and_db
    keep_id = Memory(db_path).add_constraint("A01", "keep me active")
    retract_id = Memory(db_path).add_constraint("A02", "retract me")

    client.post(f"/api/constraints/{retract_id}/retract")

    with Memory(db_path) as memory:
        assert len(memory.constraints_for_asset("A01", active_only=True)) == 1
        [kept] = memory.constraints_for_asset("A01", active_only=True)
        assert kept.id == keep_id
        assert memory.constraints_for_asset("A02", active_only=True) == []
