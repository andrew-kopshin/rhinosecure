from datetime import date

import pytest

from rhinosecure.memory import RemediationEvent
from rhinosecure.remediation import (
    REMEDIATION_STATUSES,
    Contradiction,
    Overdue,
    TrackedFinding,
    UndocumentedAcceptance,
    classify_remediation,
    note_required_for_transition,
)

TODAY = date(2026, 9, 5)


def _event(status: str, *, note: str | None = None, recorded_at: str = "2026-01-01T00:00:00+00:00") -> RemediationEvent:
    return RemediationEvent(
        id=1, finding_id="F01", status=status, note=note, source="human",
        source_detail=None, run_id=None, recorded_at=recorded_at,
    )


def _finding(finding_id="F01", cve_id="CVE-0000-0001", hostname="H1", is_kev=False, kev_due_date=None) -> TrackedFinding:
    return TrackedFinding(finding_id=finding_id, cve_id=cve_id, hostname=hostname, is_kev=is_kev, kev_due_date=kev_due_date)


# --- note_required_for_transition -------------------------------------------


@pytest.mark.parametrize(
    "previous,new,expected",
    [
        ("remediated", "open", True),
        (None, "open", False),
        ("accepted", "open", False),
        ("deferred", "open", False),
        ("remediated", "accepted", False),
        ("remediated", "deferred", False),
        ("remediated", "remediated", False),
        ("open", "open", False),
    ],
)
def test_note_required_for_transition(previous, new, expected):
    assert note_required_for_transition(previous, new) is expected


# --- classify_remediation: basic counts -------------------------------------


def test_classify_remediation_with_no_findings():
    summary = classify_remediation([], {}, today=TODAY)
    assert summary.total == 0
    assert summary.untracked_count == 0
    assert summary.status_counts == {s: 0 for s in REMEDIATION_STATUSES}
    assert summary.contradictions == ()
    assert summary.overdue == ()
    assert summary.accepted_without_note == ()


def test_classify_remediation_untracked_finding_has_no_status():
    summary = classify_remediation([_finding("F01")], {}, today=TODAY)
    assert summary.total == 1
    assert summary.untracked_count == 1
    assert summary.status_counts["open"] == 0


def test_classify_remediation_counts_each_status_from_latest_events():
    findings = [_finding("F01"), _finding("F02"), _finding("F03"), _finding("F04"), _finding("F05")]
    latest = {
        "F01": _event("open"),
        "F02": _event("deferred", note="later"),
        "F03": _event("accepted", note="risk accepted"),
        "F04": _event("remediated", note="fixed"),
        # F05 untracked
    }
    summary = classify_remediation(findings, latest, today=TODAY)
    assert summary.total == 5
    assert summary.untracked_count == 1
    assert summary.status_counts == {"open": 1, "deferred": 1, "accepted": 1, "remediated": 1}


def test_classify_remediation_ignores_history_for_a_finding_absent_from_the_current_scan():
    """A finding with remediation history that simply isn't in this run's
    findings contributes nothing -- neither to total, nor to any category.
    This is the "actually fixed and no longer detected" case."""
    latest = {"GONE": _event("remediated", note="fixed")}
    summary = classify_remediation([_finding("F01")], latest, today=TODAY)
    assert summary.total == 1
    assert summary.contradictions == ()
    assert summary.status_counts["remediated"] == 0


# --- contradictions (reappearance after remediated) -------------------------


def test_a_remediated_finding_still_present_is_a_contradiction():
    event = _event("remediated", note="patched via WSUS")
    summary = classify_remediation([_finding("F01", cve_id="CVE-1", hostname="H1")], {"F01": event}, today=TODAY)
    assert summary.contradictions == (Contradiction("F01", "CVE-1", "H1", event),)
    # still counted in status_counts too -- a contradiction doesn't remove
    # the finding from the ordinary tally, it's an additional flag on top
    assert summary.status_counts["remediated"] == 1


def test_a_reopened_finding_is_not_a_contradiction():
    """Latest status is 'open' (a human explicitly walked it back), not
    'remediated' -- no contradiction, even though an earlier event was
    'remediated'. classify_remediation only ever sees the latest event."""
    summary = classify_remediation([_finding("F01")], {"F01": _event("open", note="regressed")}, today=TODAY)
    assert summary.contradictions == ()


@pytest.mark.parametrize("status", ["open", "accepted", "deferred"])
def test_only_remediated_status_ever_produces_a_contradiction(status):
    summary = classify_remediation([_finding("F01")], {"F01": _event(status)}, today=TODAY)
    assert summary.contradictions == ()


# --- accepted without documentation -----------------------------------------


def test_accepted_with_no_note_is_flagged():
    summary = classify_remediation([_finding("F01", cve_id="CVE-1", hostname="H1")], {"F01": _event("accepted")}, today=TODAY)
    assert len(summary.accepted_without_note) == 1
    assert summary.accepted_without_note[0].finding_id == "F01"


@pytest.mark.parametrize("note", [None, "", "   "])
def test_accepted_with_blank_or_whitespace_note_is_still_flagged(note):
    summary = classify_remediation([_finding("F01")], {"F01": _event("accepted", note=note)}, today=TODAY)
    assert len(summary.accepted_without_note) == 1


def test_accepted_with_a_real_note_is_not_flagged():
    summary = classify_remediation([_finding("F01")], {"F01": _event("accepted", note="board-approved risk acceptance")}, today=TODAY)
    assert summary.accepted_without_note == ()


@pytest.mark.parametrize("status", ["open", "deferred", "remediated"])
def test_only_accepted_status_is_checked_for_documentation(status):
    """A missing note on any other status is not this check's concern --
    only 'accepted' carries the "documented risk decision" expectation."""
    summary = classify_remediation([_finding("F01")], {"F01": _event(status)}, today=TODAY)
    assert summary.accepted_without_note == ()


# --- overdue past KEV due date ------------------------------------------


def test_overdue_kev_untracked_finding_is_flagged_with_status_untracked():
    finding = _finding("F01", cve_id="CVE-1", hostname="H1", is_kev=True, kev_due_date="2020-01-01")
    summary = classify_remediation([finding], {}, today=TODAY)
    assert summary.overdue == (Overdue("F01", "CVE-1", "H1", "2020-01-01", "untracked"),)


@pytest.mark.parametrize("status", ["open", "deferred", "accepted"])
def test_overdue_kev_tracked_finding_reports_its_real_status(status):
    finding = _finding("F01", is_kev=True, kev_due_date="2020-01-01")
    summary = classify_remediation([finding], {"F01": _event(status, note="x")}, today=TODAY)
    assert len(summary.overdue) == 1
    assert summary.overdue[0].status == status


def test_overdue_kev_marked_remediated_is_not_flagged():
    """The finding is contradicted (still detected despite 'remediated'),
    which is its own, more specific signal -- overdue would be a second,
    redundant flag for the same underlying fact."""
    finding = _finding("F01", is_kev=True, kev_due_date="2020-01-01")
    summary = classify_remediation([finding], {"F01": _event("remediated", note="fixed")}, today=TODAY)
    assert summary.overdue == ()
    assert len(summary.contradictions) == 1


def test_not_overdue_when_due_date_is_in_the_future():
    finding = _finding("F01", is_kev=True, kev_due_date="2099-01-01")
    summary = classify_remediation([finding], {}, today=TODAY)
    assert summary.overdue == ()


def test_not_overdue_when_not_kev():
    finding = _finding("F01", is_kev=False, kev_due_date="2020-01-01")
    summary = classify_remediation([finding], {}, today=TODAY)
    assert summary.overdue == ()


def test_not_overdue_when_kev_but_no_due_date_recorded():
    finding = _finding("F01", is_kev=True, kev_due_date=None)
    summary = classify_remediation([finding], {}, today=TODAY)
    assert summary.overdue == ()


def test_a_malformed_due_date_is_never_evaluated_as_overdue_or_raised():
    """An external feed's malformed value is treated as 'cannot evaluate',
    not silently 'not overdue' by coincidence and never a crash."""
    finding = _finding("F01", is_kev=True, kev_due_date="not-a-date")
    summary = classify_remediation([finding], {}, today=TODAY)  # must not raise
    assert summary.overdue == ()


def test_due_date_exactly_today_is_not_yet_overdue():
    finding = _finding("F01", is_kev=True, kev_due_date=TODAY.isoformat())
    summary = classify_remediation([finding], {}, today=TODAY)
    assert summary.overdue == ()


def test_classify_remediation_defaults_today_to_the_real_clock_when_omitted():
    """Not pinned to a specific date -- just confirms the default path
    (today=None) runs at all and produces a sane result for a date safely
    in the past relative to any real clock."""
    finding = _finding("F01", is_kev=True, kev_due_date="2000-01-01")
    summary = classify_remediation([finding], {})
    assert len(summary.overdue) == 1
