import sqlite3
from pathlib import Path

import pytest

from rhinosecure.memory import DEFAULT_DB_PATH, Memory, REPO_ROOT


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "rhinosecure.db"


# --- construction / schema ----------------------------------------------


def test_default_db_path_is_repo_root_local_file():
    """Section 7: "SQLite, local file." Not asserted by constructing a
    Memory there (that would touch the real repo's database) -- just
    that the constant points at one, sitting next to pyproject.toml."""
    assert DEFAULT_DB_PATH.parent == REPO_ROOT
    assert DEFAULT_DB_PATH.name == "rhinosecure.db"
    assert (REPO_ROOT / "pyproject.toml").exists()


def test_opening_the_same_file_twice_is_safe(db_path: Path):
    """Schema creation is CREATE TABLE IF NOT EXISTS, run on every
    construction -- this is also literally how cross-session persistence
    gets exercised below, not a special "first run" path."""
    with Memory(db_path) as db1:
        db1.add_constraint("A12", "no reboots outside Sunday window")

    with Memory(db_path) as db2:
        assert len(db2.constraints_for_asset("A12")) == 1


def test_creates_parent_directories(tmp_path: Path):
    nested = tmp_path / "nested" / "dir" / "mem.db"
    with Memory(nested) as db:
        db.add_constraint("A01", "x")
    assert nested.exists()


# --- constraints ----------------------------------------------------------


def test_add_constraint_returns_an_id_and_is_retrievable(db_path: Path):
    with Memory(db_path) as db:
        constraint_id = db.add_constraint("A12", "payroll server only reboots on Sundays")

        [constraint] = db.constraints_for_asset("A12")
        assert constraint.id == constraint_id
        assert constraint.asset_id == "A12"
        assert constraint.constraint_text == "payroll server only reboots on Sundays"
        assert constraint.active is True
        assert constraint.created_at  # non-empty timestamp


def test_constraints_for_asset_does_not_leak_across_assets(db_path: Path):
    with Memory(db_path) as db:
        db.add_constraint("A12", "payroll: Sundays only")
        db.add_constraint("A09", "finance workstation: business hours only")

        assert [c.constraint_text for c in db.constraints_for_asset("A12")] == ["payroll: Sundays only"]
        assert [c.constraint_text for c in db.constraints_for_asset("A09")] == [
            "finance workstation: business hours only"
        ]
        assert db.constraints_for_asset("A99") == []  # no constraints, not an error


def test_constraints_for_asset_returns_oldest_first(db_path: Path):
    with Memory(db_path) as db:
        db.add_constraint("A12", "first")
        db.add_constraint("A12", "second")
        db.add_constraint("A12", "third")

        assert [c.constraint_text for c in db.constraints_for_asset("A12")] == [
            "first", "second", "third",
        ]


def test_deactivate_constraint_excludes_it_from_active_only_but_keeps_the_row(db_path: Path):
    """Soft-delete, not delete -- the retracted constraint stays in the
    historical record (module docstring)."""
    with Memory(db_path) as db:
        constraint_id = db.add_constraint("A12", "payroll: Sundays only")
        db.deactivate_constraint(constraint_id)

        assert db.constraints_for_asset("A12") == []  # active_only=True default
        [retracted] = db.constraints_for_asset("A12", active_only=False)
        assert retracted.active is False
        assert retracted.constraint_text == "payroll: Sundays only"


def test_all_active_constraints_spans_assets_and_excludes_retracted(db_path: Path):
    with Memory(db_path) as db:
        db.add_constraint("A12", "payroll: Sundays only")
        db.add_constraint("A09", "finance workstation: business hours only")
        retract_id = db.add_constraint("A03", "retracted later")
        db.deactivate_constraint(retract_id)

        active = db.all_active_constraints()
        assert {(c.asset_id, c.constraint_text) for c in active} == {
            ("A12", "payroll: Sundays only"),
            ("A09", "finance workstation: business hours only"),
        }
        assert all(c.active for c in active)


def test_the_claude_md_worked_example_survives_a_new_session(db_path: Path):
    """Section 7's worked example, verbatim: "the user states the payroll
    server only reboots on Sundays. That constraint persists and is
    applied automatically on the next run without being restated." This
    module's part of that promise is retrieval being correct after a
    real process boundary -- simulated here by closing one Memory and
    opening an entirely new one against the same file, the same way a
    second `rhino run` invocation would."""
    with Memory(db_path) as session_one:
        session_one.add_constraint("A_PAYROLL", "only reboots on Sundays")

    # session_one is closed; nothing keeps this file open in memory.
    session_two = Memory(db_path)
    try:
        [constraint] = session_two.constraints_for_asset("A_PAYROLL")
        assert constraint.constraint_text == "only reboots on Sundays"
        assert constraint.active is True
    finally:
        session_two.close()


# --- runs -------------------------------------------------------------------


def test_record_run_round_trips_every_field(db_path: Path):
    with Memory(db_path) as db:
        run_id = db.record_run(
            data_dir="demo",
            seed=42,
            offline=True,
            agents=True,
            total_findings=24,
            contested_count=3,
            contested_total=24,
            snapshot_versions={"kev": 3, "nvd:CVE-2021-26855": 1},
            research_usage={"total_tokens": 23408, "successful_requests": 6},
            environment_usage={"total_tokens": 14881, "successful_requests": 6},
            risk_usage={"total_tokens": 32838, "successful_requests": 6},
            tot_usage={"total_tokens": 5000, "successful_requests": 39},
        )

        run = db.get_run(run_id)
        assert run.id == run_id
        assert run.data_dir == "demo"
        assert run.seed == 42
        assert run.offline is True
        assert run.agents is True
        assert run.total_findings == 24
        assert run.contested_count == 3
        assert run.contested_total == 24
        assert run.contested_pct == pytest.approx(12.5)
        assert run.snapshot_versions == {"kev": 3, "nvd:CVE-2021-26855": 1}
        assert run.research_usage == {"total_tokens": 23408, "successful_requests": 6}
        assert run.tot_usage == {"total_tokens": 5000, "successful_requests": 39}
        assert run.started_at  # non-empty timestamp


def test_record_run_leaves_usage_and_snapshot_fields_none_when_not_given(db_path: Path):
    """The deterministic path makes no LLM calls at all -- usage fields
    must round-trip as None, not as an empty-but-present JSON blob."""
    with Memory(db_path) as db:
        run_id = db.record_run(
            data_dir="demo", seed=42, offline=True, agents=False,
            total_findings=24, contested_count=3, contested_total=24,
        )

        run = db.get_run(run_id)
        assert run.snapshot_versions is None
        assert run.research_usage is None
        assert run.environment_usage is None
        assert run.risk_usage is None
        assert run.tot_usage is None


def test_contested_pct_is_zero_not_a_division_error_when_total_is_zero(db_path: Path):
    with Memory(db_path) as db:
        run_id = db.record_run(
            data_dir="demo", seed=42, offline=True, agents=False,
            total_findings=0, contested_count=0, contested_total=0,
        )
        assert db.get_run(run_id).contested_pct == 0.0


def test_get_run_for_unknown_id_returns_none(db_path: Path):
    with Memory(db_path) as db:
        assert db.get_run(999) is None


def test_list_runs_returns_newest_first_and_respects_limit(db_path: Path):
    with Memory(db_path) as db:
        ids = [
            db.record_run(
                data_dir="demo", seed=s, offline=True, agents=False,
                total_findings=24, contested_count=3, contested_total=24,
            )
            for s in (1, 2, 3)
        ]

        assert [r.id for r in db.list_runs()] == list(reversed(ids))
        assert [r.id for r in db.list_runs(limit=2)] == list(reversed(ids))[:2]


# --- decisions ----------------------------------------------------------


def _record_demo_run(db: Memory) -> int:
    return db.record_run(
        data_dir="demo", seed=42, offline=True, agents=True,
        total_findings=24, contested_count=3, contested_total=24,
    )


def test_record_decision_round_trips_every_field_including_tot_summary(db_path: Path):
    with Memory(db_path) as db:
        run_id = _record_demo_run(db)
        decision_id = db.record_decision(
            run_id=run_id,
            finding_id="F14",
            cve_id="CVE-2023-23397",
            asset_id="A09",
            hostname="WKS-FIN12",
            risk_score=25.5,
            bucket="contested",
            rationale=["scanner_severity='low' vs NVD CVSS 9.8", "bucket=contested: ..."],
            verdict_summary="Contested: confirmed KEV exploitation with no control or window.",
            narrative="Full narrative text.",
            tot_winner_strategy="emergency_change",
            tot_near_tie=False,
            tot_termination_reason="depth_limit",
        )

        decision = db.decisions_for_run(run_id)[0]
        assert decision.id == decision_id
        assert decision.run_id == run_id
        assert decision.finding_id == "F14"
        assert decision.cve_id == "CVE-2023-23397"
        assert decision.risk_score == pytest.approx(25.5)
        assert decision.bucket == "contested"
        assert decision.rationale == ("scanner_severity='low' vs NVD CVSS 9.8", "bucket=contested: ...")
        assert decision.tot_winner_strategy == "emergency_change"
        assert decision.tot_near_tie is False
        assert decision.tot_termination_reason == "depth_limit"
        assert decision.decided_at


def test_record_decision_tot_fields_default_to_none_for_a_non_contested_finding(db_path: Path):
    with Memory(db_path) as db:
        run_id = _record_demo_run(db)
        db.record_decision(
            run_id=run_id, finding_id="F19", cve_id="CVE-2018-8410", asset_id="A07",
            hostname="SQL01", risk_score=8.6, bucket="accept",
            rationale=["risk_score=8.6/100"], verdict_summary="Accepted.", narrative="...",
        )

        decision = db.decisions_for_run(run_id)[0]
        assert decision.tot_winner_strategy is None
        assert decision.tot_near_tie is None
        assert decision.tot_termination_reason is None


def test_record_decision_with_unknown_run_id_raises_integrity_error(db_path: Path):
    """Foreign-keyed to runs and enforced by SQLite (PRAGMA
    foreign_keys=ON) -- not re-checked in Python."""
    with Memory(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.record_decision(
                run_id=999, finding_id="F01", cve_id="CVE-0000-0000", asset_id="A01",
                hostname="H1", risk_score=1.0, bucket="accept",
                rationale=[], verdict_summary="x", narrative="x",
            )


def test_decisions_for_run_is_scoped_to_that_run_only(db_path: Path):
    with Memory(db_path) as db:
        run1 = _record_demo_run(db)
        run2 = _record_demo_run(db)
        db.record_decision(
            run_id=run1, finding_id="F01", cve_id="CVE-A", asset_id="A01", hostname="H1",
            risk_score=1.0, bucket="accept", rationale=[], verdict_summary="x", narrative="x",
        )
        db.record_decision(
            run_id=run2, finding_id="F02", cve_id="CVE-B", asset_id="A02", hostname="H2",
            risk_score=2.0, bucket="accept", rationale=[], verdict_summary="x", narrative="x",
        )

        assert [d.finding_id for d in db.decisions_for_run(run1)] == ["F01"]
        assert [d.finding_id for d in db.decisions_for_run(run2)] == ["F02"]


def test_decisions_for_finding_spans_runs_oldest_first(db_path: Path):
    """The same finding re-scored across two runs -- decisions_for_finding
    is how a human would see "prior remediation verdicts" for one
    finding over time, not just within one run."""
    with Memory(db_path) as db:
        run1 = _record_demo_run(db)
        run2 = _record_demo_run(db)
        db.record_decision(
            run_id=run1, finding_id="F14", cve_id="CVE-2023-23397", asset_id="A09",
            hostname="WKS-FIN12", risk_score=25.5, bucket="contested",
            rationale=[], verdict_summary="first pass", narrative="x",
        )
        db.record_decision(
            run_id=run2, finding_id="F14", cve_id="CVE-2023-23397", asset_id="A09",
            hostname="WKS-FIN12", risk_score=25.5, bucket="contested",
            rationale=[], verdict_summary="second pass", narrative="x",
        )

        history = db.decisions_for_finding("F14")
        assert [d.verdict_summary for d in history] == ["first pass", "second pass"]
        assert db.decisions_for_finding("F99") == []


def test_latest_decision_for_finding_returns_the_most_recent(db_path: Path):
    with Memory(db_path) as db:
        run1 = _record_demo_run(db)
        run2 = _record_demo_run(db)
        db.record_decision(
            run_id=run1, finding_id="F14", cve_id="CVE-2023-23397", asset_id="A09",
            hostname="WKS-FIN12", risk_score=25.5, bucket="contested",
            rationale=[], verdict_summary="first pass", narrative="x",
        )
        db.record_decision(
            run_id=run2, finding_id="F14", cve_id="CVE-2023-23397", asset_id="A09",
            hostname="WKS-FIN12", risk_score=25.5, bucket="contested",
            rationale=[], verdict_summary="second pass", narrative="x",
        )

        assert db.latest_decision_for_finding("F14").verdict_summary == "second pass"
        assert db.latest_decision_for_finding("F99") is None


# --- feedback ----------------------------------------------------------


def test_record_feedback_round_trips_with_no_run_id(db_path: Path):
    with Memory(db_path) as db:
        feedback_id = db.record_feedback(
            "only five patches fit this window",
            "no re-plan has happened yet -- constraint intake is not wired",
        )

        [feedback] = db.list_feedback()
        assert feedback.id == feedback_id
        assert feedback.raw_input == "only five patches fit this window"
        assert feedback.run_id is None
        assert feedback.recorded_at


def test_record_feedback_can_reference_the_run_it_produced(db_path: Path):
    with Memory(db_path) as db:
        run_id = _record_demo_run(db)
        db.record_feedback(
            "the payroll server only reboots on Sundays",
            f"added constraint for A12; replanned into run {run_id}",
            run_id=run_id,
        )

        [feedback] = db.list_feedback()
        assert feedback.run_id == run_id


def test_record_feedback_with_unknown_run_id_raises_integrity_error(db_path: Path):
    with Memory(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.record_feedback("x", "y", run_id=999)


def test_list_feedback_returns_newest_first_and_respects_limit(db_path: Path):
    with Memory(db_path) as db:
        db.record_feedback("first", "x")
        db.record_feedback("second", "x")
        db.record_feedback("third", "x")

        assert [f.raw_input for f in db.list_feedback()] == ["third", "second", "first"]
        assert [f.raw_input for f in db.list_feedback(limit=2)] == ["third", "second"]
