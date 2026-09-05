"""Remediation tracking: pure computation over already-persisted
`memory.RemediationEvent` rows and a run's current findings. No I/O, no
LLM, no dependency on `crewai` or anything under `agents/` -- the same
import-boundary discipline `scoring.py` and `memory.py` already hold
themselves to, so this module is importable from the deterministic path,
the agents path, and `export.py` alike without dragging any of them in.

**What this tracks, and why it's an event log read as "latest wins."**
`memory.py`'s `remediation_events` table is append-only -- an operator's
mark and a future execution outcome are the same kind of write, only the
`source` differs (CLAUDE.md's "Future direction: remediation execution":
"an execution result is another way a finding's status changes"). A
finding's CURRENT status is never stored; it is always the most recent
event for that finding_id, exactly the same "derived, never stored"
discipline `memory.RunRecord.contested_pct` already uses for itself.

**The one thing this module refuses to do: feed back into scoring.py.**
Remediation status answers "have we already dealt with this," which is a
different question from "how risky is this" -- `scoring.risk_score` and
`bucket` are computed with zero knowledge that this module exists, before
and after. This is the same "additive only" boundary `export.py` holds
itself to, applied to a second downstream consumer.

**Four statuses, not three.** CLAUDE.md's remediation-tracking design
names three human dispositions -- remediated, accepted, deferred -- but a
fourth, `open`, is also assertable: a human explicitly walking a finding
back to "needs attention" (from `accepted`, from `deferred`, or -- the one
transition that REQUIRES a note, see `note_required_for_transition` --
from `remediated`). `open` is distinct from "never tracked at all": both
currently read as "not resolved," but only one has a note explaining why
someone changed their mind. `classify_remediation` keeps them separate
(`RemediationSummary.untracked_count` vs. `status_counts["open"]`) so
nothing downstream has to guess which one a finding actually is; `cli.py`
prints them combined under one "N open" line by default, since the
distinction mostly matters when reading one finding's own history
(`rhino remediation log`), not the fleet-wide count.

**Contradiction, not silent trust.** If the LATEST recorded status for a
finding_id is `remediated`, but that finding_id is present in the CURRENT
scan being classified, that is a contradiction -- the belief that it was
fixed was wrong, or it regressed, or the scanner mismatched something.
`classify_remediation` never resolves this on its own (it has no evidence
to decide which of those is true); it only ever surfaces it, the same
"escalate rather than force a verdict" instinct `scoring.bucket_for`
already applies to a KEV finding with no honest bucket (CLAUDE.md Section
6). Nothing here writes a new event to "fix" the contradiction -- only a
human (or a future execution outcome) recording a new one does that.

**Overdue is evaluated against every currently-scanned finding, not just
tracked ones.** A finding nobody has ever marked at all is just as overdue
past its KEV due date as one explicitly marked `deferred` -- the check is
"does this still need attention past a federal remediation deadline," and
"untracked" is itself a kind of still-needing-attention. `Overdue.status`
records which of the two it actually was (`"untracked"` or one of the real
status strings) so the two cases stay distinguishable in the printed
detail, never flattened into one undifferentiated list.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from rhinosecure.memory import RemediationEvent

# The closed set `rhino remediation mark`'s CLI validates against
# (argparse `choices=`) -- memory.py itself validates nothing (Constraint
# .effect_kind's own precedent: persistence, not interpretation), so this
# is the one place the four real values are named as code, not prose.
REMEDIATION_STATUSES: tuple[str, ...] = ("open", "remediated", "accepted", "deferred")


def note_required_for_transition(previous_status: str | None, new_status: str) -> bool:
    """The one transition CLAUDE.md's remediation-tracking design singles
    out: walking a finding back to `open` from `remediated` is the
    transition where the reason (a failed patch? a regression? the wrong
    finding_id?) matters most. Every other transition -- including into
    `open` from anything else, or between accepted/deferred/remediated --
    stays optional. `previous_status=None` (never tracked before) is never
    "remediated", so it can never trigger this."""
    return previous_status == "remediated" and new_status == "open"


@dataclass(frozen=True)
class TrackedFinding:
    """The minimal per-finding facts `classify_remediation` needs, kept
    independent of `ScoredFinding`/`RiskRecommendation` so this module has
    no dependency on `scoring.py` or `agents/` -- a caller on either path
    builds this from whatever it already has."""

    finding_id: str
    cve_id: str
    hostname: str
    is_kev: bool
    kev_due_date: str | None


@dataclass(frozen=True)
class Contradiction:
    finding_id: str
    cve_id: str
    hostname: str
    event: "RemediationEvent"  # the stale 'remediated' event this scan contradicts


@dataclass(frozen=True)
class Overdue:
    finding_id: str
    cve_id: str
    hostname: str
    due_date: str
    status: str  # "untracked", or one of REMEDIATION_STATUSES -- never "remediated", see classify_remediation


@dataclass(frozen=True)
class UndocumentedAcceptance:
    finding_id: str
    cve_id: str
    hostname: str
    recorded_at: str


@dataclass(frozen=True)
class RemediationSummary:
    total: int
    untracked_count: int
    status_counts: dict[str, int]  # keys: REMEDIATION_STATUSES, values: current-scan counts with an explicit event
    contradictions: tuple[Contradiction, ...]
    overdue: tuple[Overdue, ...]
    accepted_without_note: tuple[UndocumentedAcceptance, ...]


def _parse_due_date(value: str) -> date | None:
    """CISA's KEV `dueDate` is `YYYY-MM-DD` (confirmed against the real
    committed snapshot, data/snapshots/kev.json) -- never guessed at, and
    never allowed to crash a run over a malformed value from an external
    feed: an unparseable date is treated as "cannot evaluate," not as
    "not overdue" (silently false) or a raised exception."""
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def classify_remediation(
    findings: Iterable[TrackedFinding],
    latest_events: dict[str, "RemediationEvent"],
    *,
    today: date | None = None,
) -> RemediationSummary:
    """Pure: no I/O, no clock read unless `today` is omitted (tests always
    pass one explicitly). `findings` is this run's CURRENT scan -- a
    finding with remediation history but absent from `findings` (the
    ordinary, hoped-for case: it was actually fixed and the scanner no
    longer detects it) contributes nothing here, on either side; this
    function only ever reasons about what's in front of it right now."""
    today = today or date.today()
    status_counts = {s: 0 for s in REMEDIATION_STATUSES}
    untracked = 0
    contradictions: list[Contradiction] = []
    overdue: list[Overdue] = []
    accepted_without_note: list[UndocumentedAcceptance] = []
    total = 0

    for f in findings:
        total += 1
        event = latest_events.get(f.finding_id)
        if event is None:
            untracked += 1
            current_status: str | None = None
        else:
            current_status = event.status
            status_counts[current_status] = status_counts.get(current_status, 0) + 1
            if current_status == "remediated":
                contradictions.append(Contradiction(f.finding_id, f.cve_id, f.hostname, event))
            elif current_status == "accepted" and not (event.note or "").strip():
                accepted_without_note.append(
                    UndocumentedAcceptance(f.finding_id, f.cve_id, f.hostname, event.recorded_at)
                )

        if f.is_kev and f.kev_due_date and current_status != "remediated":
            due = _parse_due_date(f.kev_due_date)
            if due is not None and due < today:
                overdue.append(
                    Overdue(f.finding_id, f.cve_id, f.hostname, f.kev_due_date, current_status or "untracked")
                )

    return RemediationSummary(
        total=total,
        untracked_count=untracked,
        status_counts=status_counts,
        contradictions=tuple(contradictions),
        overdue=tuple(overdue),
        accepted_without_note=tuple(accepted_without_note),
    )
