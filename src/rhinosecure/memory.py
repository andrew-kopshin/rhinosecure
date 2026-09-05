"""SQLite persistence (CLAUDE.md Section 7): constraints, decisions,
feedback, runs. Restored from CP2, where it was committed and then
dropped from CP3 onward.

`sqlite3` from the standard library, one local file -- no new dependency
(Section 11 already notes this: "sqlite3 is standard library -- no
install"). No LLM calls, no network access, no dependency on `crewai` or
anything under `agents/` -- this module is meant to be importable from
both the deterministic path and the agents path without pulling either
one in, the same reason `scoring.contested_rate` moved out of `tot.py`
(see that module's own commit history). Record types (`RunRecord`,
`Decision`, etc.) take and return plain, JSON-serializable values --
`UsageMetrics`/`ContestedRate`/`ToTResult` objects are never imported
here; a caller extracts primitive fields from those before calling in.

**Scope: persistence only.** This module makes constraints, decisions,
and feedback durable and queryable across process restarts. It does NOT
interpret free-form human text into a constraint (that is "constraint
intake," Section 5/6's still-unbuilt LLM-shaped work: deciding which
finding_ids a stated constraint should trigger a `Coordinator.replan`
for), and nothing here calls into `Coordinator` or modifies a run's
behavior based on what is stored. `add_constraint` takes the constraint
already reduced to `(asset_id, text)` -- turning "the payroll server only
reboots on Sundays" into that pair is a future caller's job, same as
turning a stored constraint back into a `bucket_for` input (Environment
Analysis's `has_patch_window`/`compensating_controls`) once retrieved.
This module's job is only to make sure that once a constraint exists in
this shape, it survives a restart and comes back out asset-scoped and in
insertion order -- CLAUDE.md's worked example ("that constraint persists
and is applied automatically on the next run without being restated")
is a requirement on retrieval being cheap and correct, not a requirement
that this module do the applying.

**Four tables, matching Section 7 exactly:**
- `constraints` -- asset-scoped, free-text, with a soft-delete `active`
  flag (`deactivate_constraint`) rather than an update-in-place, so a
  retracted constraint stays in the historical record instead of being
  overwritten -- the same append-only instinct as this project's own
  PROGRESS.md.
- `runs` -- one row per `rhino run` invocation: seed, snapshot versions,
  contested rate, and per-stage token usage, exactly the four things
  this module was asked to capture. `snapshot_versions` is a JSON object
  keyed by `"source"` or `"source:key"` (mirroring
  `enrich/cache.py`'s `SnapshotEntry.source`/`.key`/`.version`) rather
  than a normalized child table -- a run can touch dozens of
  (source, key) pairs (one NVD + one EPSS snapshot per unique CVE), and
  nothing here needs to query across runs by individual snapshot
  version, only read a whole run's provenance back out at once. The
  four `*_usage` columns are nullable: the deterministic path makes no
  LLM calls at all, and a `--agents` run without any contested findings
  never touches `tot_usage`.
- `decisions` -- one row per finding per run: the `RiskRecommendation`
  fields that constitute the actual verdict (risk_score, bucket,
  rationale, verdict_summary, narrative), plus nullable ToT summary
  columns (`tot_winner_strategy`/`tot_near_tie`/`tot_termination_reason`)
  for whichever of them were contested -- a decision record for a
  contested finding that omitted what ToT recommended wouldn't actually
  capture what was decided. Foreign-keyed to `runs`.
- `feedback` -- raw human input and what it changed, per Section 7's own
  description verbatim. `run_id` is nullable: feedback can be recorded
  before -- or without -- a replan resulting from it (again, no replan
  wiring lives here).

**A sixth table, beyond Section 7 and beyond `capacity_constraints`:**
`remediation_events` -- what actually happened to a finding, as opposed to
`decisions`' record of what a run recommended. Append-only, like every
other table here: a status is never updated in place, it is recorded
again, so `record_remediation_event` never overwrites a prior row. This is
deliberate, not just consistent -- CLAUDE.md's "Future direction:
remediation execution" names a future execution outcome as "another way a
finding's status changes," the same kind of write a human's own mark
already is, just a different `source`. An append-only log is what lets
both write the identical shape without the schema needing to change when
execution exists. `remediation.py` (a new, equally I/O-free module) is
where the read side's actual logic lives -- computing a fleet's current
status, detecting a finding that reappeared after being marked
`remediated`, and flagging one open past its CISA KEV due date -- exactly
the same split `scoring.py`/this module already draw: pure computation in
one place, pure persistence in the other, neither depending on the other's
internals.

Timestamps are UTC ISO 8601 strings (`datetime.now(timezone.utc)
.isoformat()`), the same format `enrich/cache.py`'s `SnapshotEntry
.retrieved_at` already uses, for the same reason: sortable as plain text,
unambiguous across machines.

Inspect the resulting file with DB Browser for SQLite (sqlitebrowser.org)
-- Section 7's own suggestion.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = REPO_ROOT / "rhinosecure.db"

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS constraints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT NOT NULL,
    constraint_text TEXT NOT NULL,
    effect_kind TEXT,
    effect_value TEXT,
    created_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_constraints_asset_id ON constraints (asset_id);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    data_dir TEXT NOT NULL,
    -- Which ingest adapter read data_dir (adapters/, CLAUDE.md Section 1).
    -- Nullable: rows written before --format existed have no answer, and
    -- inventing "native" for them would assert something never recorded.
    ingest_format TEXT,
    seed INTEGER NOT NULL,
    offline INTEGER NOT NULL,
    agents INTEGER NOT NULL,
    total_findings INTEGER NOT NULL,
    contested_count INTEGER NOT NULL,
    contested_total INTEGER NOT NULL,
    snapshot_versions TEXT,
    research_usage TEXT,
    environment_usage TEXT,
    risk_usage TEXT,
    tot_usage TEXT
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs (id),
    finding_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    risk_score REAL NOT NULL,
    bucket TEXT NOT NULL,
    rationale TEXT NOT NULL,
    verdict_summary TEXT NOT NULL,
    narrative TEXT NOT NULL,
    tot_winner_strategy TEXT,
    tot_near_tie INTEGER,
    tot_termination_reason TEXT,
    capacity_rank INTEGER,
    capacity_pool_size INTEGER,
    capacity_limit INTEGER,
    decided_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_run_id ON decisions (run_id);
CREATE INDEX IF NOT EXISTS idx_decisions_finding_id ON decisions (finding_id);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_input TEXT NOT NULL,
    change_description TEXT NOT NULL,
    run_id INTEGER REFERENCES runs (id),
    recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feedback_run_id ON feedback (run_id);

CREATE TABLE IF NOT EXISTS capacity_constraints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs (id),
    raw_text TEXT NOT NULL,
    patch_limit INTEGER NOT NULL,
    pool_size INTEGER NOT NULL,
    deferred_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_capacity_constraints_run_id ON capacity_constraints (run_id);

CREATE TABLE IF NOT EXISTS remediation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    status TEXT NOT NULL,
    note TEXT,
    source TEXT NOT NULL,
    source_detail TEXT,
    run_id INTEGER REFERENCES runs (id),
    recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remediation_events_finding_id ON remediation_events (finding_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Constraint:
    id: int
    asset_id: str
    constraint_text: str
    created_at: str
    active: bool
    # Structured effect -- nullable: a constraint can be recorded before
    # (or without) ever being interpreted into one of these. Populated by
    # agents/constraint_intake.py's ConstraintInterpretation once that
    # exists; this module doesn't know that type and only stores whatever
    # strings it's given. See agents/constraint_intake.py's module
    # docstring for what "effect_kind" values mean and how they're
    # applied.
    effect_kind: str | None = None
    effect_value: str | None = None


@dataclass(frozen=True)
class RunRecord:
    id: int
    started_at: str
    data_dir: str
    ingest_format: str | None
    seed: int
    offline: bool
    agents: bool
    total_findings: int
    contested_count: int
    contested_total: int
    snapshot_versions: dict[str, int] | None
    research_usage: dict[str, Any] | None
    environment_usage: dict[str, Any] | None
    risk_usage: dict[str, Any] | None
    tot_usage: dict[str, Any] | None

    @property
    def contested_pct(self) -> float:
        """Mirrors scoring.ContestedRate.pct -- derived, not stored, so
        it can never drift from contested_count/contested_total."""
        return 100.0 * self.contested_count / self.contested_total if self.contested_total else 0.0


@dataclass(frozen=True)
class Decision:
    id: int
    run_id: int
    finding_id: str
    cve_id: str
    asset_id: str
    hostname: str
    risk_score: float
    bucket: str
    rationale: tuple[str, ...]
    verdict_summary: str
    narrative: str
    tot_winner_strategy: str | None
    tot_near_tie: bool | None
    tot_termination_reason: str | None
    decided_at: str
    capacity_rank: int | None = None
    capacity_pool_size: int | None = None
    capacity_limit: int | None = None


@dataclass(frozen=True)
class Feedback:
    id: int
    raw_input: str
    change_description: str
    run_id: int | None
    recorded_at: str


@dataclass(frozen=True)
class RemediationEvent:
    """One recorded status change for one finding_id -- append-only, so
    this is a row in the historical log, never "the" current record.
    `status` is an unvalidated string, same as `Constraint.effect_kind`:
    this module persists, it does not interpret -- the closed set
    (`remediation.REMEDIATION_STATUSES`) is validated at the CLI layer.
    `source` is `"human"` for every event recorded so far; `"execution"`
    is reserved for the not-yet-built execution phase (CLAUDE.md's "Future
    direction: remediation execution") -- an execution outcome is another
    way this same table gets a new row, not a different mechanism.
    `source_detail` is free text whose meaning depends on `source`; always
    `None` today. `run_id` is nullable, provenance only, same shape as
    `Feedback.run_id` -- a mark made outside any run (the ordinary case:
    `rhino remediation mark` doesn't construct one) simply has none."""

    id: int
    finding_id: str
    status: str
    note: str | None
    source: str
    source_detail: str | None
    run_id: int | None
    recorded_at: str


@dataclass(frozen=True)
class CapacityConstraint:
    """One change cycle's declared patch bandwidth -- CLAUDE.md Section
    10's "only five patches fit this window" example. Cycle-scoped, not
    standing: unlike `Constraint` (asset-scoped, true until retracted),
    a capacity constraint describes exactly one run's available
    bandwidth and is foreign-keyed to that run. There is no
    active/deactivate lifecycle here -- see record_capacity_constraint's
    docstring for why."""

    id: int
    run_id: int
    raw_text: str
    patch_limit: int
    pool_size: int
    deferred_count: int
    created_at: str


def _json_or_none(value: str | None) -> Any:
    return None if value is None else json.loads(value)


def _dump_or_none(value: Any) -> str | None:
    return None if value is None else json.dumps(value)


def _optional_bool(value: int | None) -> bool | None:
    return None if value is None else bool(value)


def _constraint_from_row(row: sqlite3.Row) -> Constraint:
    return Constraint(
        id=row["id"],
        asset_id=row["asset_id"],
        constraint_text=row["constraint_text"],
        created_at=row["created_at"],
        active=bool(row["active"]),
        effect_kind=row["effect_kind"],
        effect_value=row["effect_value"],
    )


def _run_from_row(row: sqlite3.Row) -> RunRecord:
    return RunRecord(
        id=row["id"],
        started_at=row["started_at"],
        data_dir=row["data_dir"],
        ingest_format=row["ingest_format"],
        seed=row["seed"],
        offline=bool(row["offline"]),
        agents=bool(row["agents"]),
        total_findings=row["total_findings"],
        contested_count=row["contested_count"],
        contested_total=row["contested_total"],
        snapshot_versions=_json_or_none(row["snapshot_versions"]),
        research_usage=_json_or_none(row["research_usage"]),
        environment_usage=_json_or_none(row["environment_usage"]),
        risk_usage=_json_or_none(row["risk_usage"]),
        tot_usage=_json_or_none(row["tot_usage"]),
    )


def _decision_from_row(row: sqlite3.Row) -> Decision:
    return Decision(
        id=row["id"],
        run_id=row["run_id"],
        finding_id=row["finding_id"],
        cve_id=row["cve_id"],
        asset_id=row["asset_id"],
        hostname=row["hostname"],
        risk_score=row["risk_score"],
        bucket=row["bucket"],
        rationale=tuple(json.loads(row["rationale"])),
        verdict_summary=row["verdict_summary"],
        narrative=row["narrative"],
        tot_winner_strategy=row["tot_winner_strategy"],
        tot_near_tie=_optional_bool(row["tot_near_tie"]),
        tot_termination_reason=row["tot_termination_reason"],
        decided_at=row["decided_at"],
        capacity_rank=row["capacity_rank"],
        capacity_pool_size=row["capacity_pool_size"],
        capacity_limit=row["capacity_limit"],
    )


def _feedback_from_row(row: sqlite3.Row) -> Feedback:
    return Feedback(
        id=row["id"],
        raw_input=row["raw_input"],
        change_description=row["change_description"],
        run_id=row["run_id"],
        recorded_at=row["recorded_at"],
    )


def _remediation_event_from_row(row: sqlite3.Row) -> RemediationEvent:
    return RemediationEvent(
        id=row["id"],
        finding_id=row["finding_id"],
        status=row["status"],
        note=row["note"],
        source=row["source"],
        source_detail=row["source_detail"],
        run_id=row["run_id"],
        recorded_at=row["recorded_at"],
    )


def _capacity_constraint_from_row(row: sqlite3.Row) -> CapacityConstraint:
    return CapacityConstraint(
        id=row["id"],
        run_id=row["run_id"],
        raw_text=row["raw_text"],
        patch_limit=row["patch_limit"],
        pool_size=row["pool_size"],
        deferred_count=row["deferred_count"],
        created_at=row["created_at"],
    )


class Memory:
    """One connection, held open for this instance's lifetime -- close()
    or use as a context manager. Schema creation (`CREATE TABLE IF NOT
    EXISTS`) runs on every construction, so opening the same file twice,
    in the same or a different process, is always safe -- this is how
    cross-session persistence is exercised in practice, not a special
    "first run" code path.

    `check_same_thread=False` plus `self._lock` around every method body
    below: a `Memory` instance is routinely handed to `Coordinator` and
    from there into `agents/environment.py`'s `lookup_asset_context` and
    `agents/risk.py`'s `score_finding_tool`, both of which call
    `constraints_for_asset` unconditionally whenever `memory is not None`
    -- not only when a constraint actually exists. CrewAI executes tool
    calls from a worker thread, not the thread that constructed this
    `Memory`, and sqlite3's default `check_same_thread=True` raises
    `ProgrammingError` ("SQLite objects created in a thread can only be
    used in that same thread") the instant that happens -- confirmed
    directly: a real (non-mocked-Crew) agents run against a constraint on
    an asset failed exactly this way on every `lookup_asset_context`
    call, cascading into the whole Environment task exhausting its
    retries. One shared `sqlite3.Connection` is not itself safe for
    concurrent use from multiple threads (unlike, say, opening a fresh
    connection per thread), so allowing cross-thread access on its own
    isn't enough -- `self._lock` serializes every operation on it, which
    is sufficient here since nothing in this module holds the connection
    open across an actual concurrent read+write; each method acquires the
    lock, does its one query or write, and releases it."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA_SQL)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created.

        `CREATE TABLE IF NOT EXISTS` is a no-op on an existing file, so a
        column added to `_SCHEMA_SQL` never reaches a database someone
        already has -- the next INSERT would fail with "no such column"
        against their real run history. Each entry here is an idempotent
        ALTER, applied only when PRAGMA table_info says the column is
        genuinely absent. New columns must be nullable: there is no
        truthful value to backfill onto rows written before the column
        existed.
        """
        added: list[tuple[str, str, str]] = [
            ("runs", "ingest_format", "TEXT"),
        ]
        for table, column, decl in added:
            existing = {row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})")}
            if column not in existing:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> Memory:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # --- constraints ----------------------------------------------------

    def add_constraint(
        self,
        asset_id: str,
        constraint_text: str,
        *,
        effect_kind: str | None = None,
        effect_value: str | None = None,
    ) -> int:
        """`effect_kind`/`effect_value` are optional and independent of
        each other's presence -- this module doesn't validate them
        against anything (no dependency on agents/constraint_intake.py's
        ConstraintEffectKind enum). Omit both to record a constraint
        that hasn't been interpreted into a structured effect yet."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO constraints (asset_id, constraint_text, effect_kind, effect_value, "
                "created_at, active) VALUES (?, ?, ?, ?, ?, 1)",
                (asset_id, constraint_text, effect_kind, effect_value, _now()),
            )
            self._conn.commit()
            return cur.lastrowid

    def deactivate_constraint(self, constraint_id: int) -> None:
        """Soft-delete: retracted constraints stay in the table (active=0)
        rather than being removed, so the historical record survives."""
        with self._lock:
            self._conn.execute("UPDATE constraints SET active = 0 WHERE id = ?", (constraint_id,))
            self._conn.commit()

    def constraints_for_asset(self, asset_id: str, *, active_only: bool = True) -> list[Constraint]:
        """What CLAUDE.md's worked example describes retrieving: every
        constraint on file for one asset, oldest first, so a future
        caller can fold them into that asset's applicability check the
        same way a declared patch_window already is. active_only=True
        (the default) excludes retracted constraints."""
        query = "SELECT * FROM constraints WHERE asset_id = ?"
        params: tuple[Any, ...] = (asset_id,)
        if active_only:
            query += " AND active = 1"
        query += " ORDER BY created_at, id"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [_constraint_from_row(r) for r in rows]

    def all_active_constraints(self) -> list[Constraint]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM constraints WHERE active = 1 ORDER BY asset_id, created_at, id"
            ).fetchall()
        return [_constraint_from_row(r) for r in rows]

    # --- runs -------------------------------------------------------------

    def record_run(
        self,
        *,
        data_dir: str,
        seed: int,
        offline: bool,
        agents: bool,
        total_findings: int,
        contested_count: int,
        contested_total: int,
        ingest_format: str | None = None,
        snapshot_versions: dict[str, int] | None = None,
        research_usage: dict[str, Any] | None = None,
        environment_usage: dict[str, Any] | None = None,
        risk_usage: dict[str, Any] | None = None,
        tot_usage: dict[str, Any] | None = None,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO runs (
                    started_at, data_dir, ingest_format, seed, offline, agents, total_findings,
                    contested_count, contested_total, snapshot_versions,
                    research_usage, environment_usage, risk_usage, tot_usage
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    _now(),
                    data_dir,
                    ingest_format,
                    seed,
                    int(offline),
                    int(agents),
                    total_findings,
                    contested_count,
                    contested_total,
                    _dump_or_none(snapshot_versions),
                    _dump_or_none(research_usage),
                    _dump_or_none(environment_usage),
                    _dump_or_none(risk_usage),
                    _dump_or_none(tot_usage),
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_run(self, run_id: int) -> RunRecord | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return _run_from_row(row) if row is not None else None

    def list_runs(self, limit: int = 50) -> list[RunRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_run_from_row(r) for r in rows]

    # --- decisions ----------------------------------------------------

    def record_decision(
        self,
        *,
        run_id: int,
        finding_id: str,
        cve_id: str,
        asset_id: str,
        hostname: str,
        risk_score: float,
        bucket: str,
        rationale: list[str],
        verdict_summary: str,
        narrative: str,
        tot_winner_strategy: str | None = None,
        tot_near_tie: bool | None = None,
        tot_termination_reason: str | None = None,
        capacity_rank: int | None = None,
        capacity_pool_size: int | None = None,
        capacity_limit: int | None = None,
    ) -> int:
        """`run_id` must name a row already written by record_run --
        enforced by SQLite itself (PRAGMA foreign_keys=ON), not
        re-checked here; an unknown run_id raises sqlite3.IntegrityError.

        `capacity_rank`/`capacity_pool_size`/`capacity_limit` are
        optional, like the `tot_*` fields above -- most decisions have
        nothing to do with a capacity reallocation. Populate them when a
        decision results from one (CLAUDE.md Section 10's "only five
        patches fit this window" example) so the decision record carries
        why it landed where it did."""
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO decisions (
                    run_id, finding_id, cve_id, asset_id, hostname, risk_score, bucket,
                    rationale, verdict_summary, narrative,
                    tot_winner_strategy, tot_near_tie, tot_termination_reason,
                    capacity_rank, capacity_pool_size, capacity_limit, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    finding_id,
                    cve_id,
                    asset_id,
                    hostname,
                    risk_score,
                    bucket,
                    json.dumps(list(rationale)),
                    verdict_summary,
                    narrative,
                    tot_winner_strategy,
                    None if tot_near_tie is None else int(tot_near_tie),
                    tot_termination_reason,
                    capacity_rank,
                    capacity_pool_size,
                    capacity_limit,
                    _now(),
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def decisions_for_run(self, run_id: int) -> list[Decision]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM decisions WHERE run_id = ? ORDER BY id", (run_id,)
            ).fetchall()
        return [_decision_from_row(r) for r in rows]

    def decisions_for_finding(self, finding_id: str) -> list[Decision]:
        """Every prior decision for one finding, oldest first, across
        every run that ever scored it -- the "prior remediation verdicts"
        Section 7 describes this table as holding."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM decisions WHERE finding_id = ? ORDER BY id", (finding_id,)
            ).fetchall()
        return [_decision_from_row(r) for r in rows]

    def latest_decision_for_finding(self, finding_id: str) -> Decision | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM decisions WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
                (finding_id,),
            ).fetchone()
        return _decision_from_row(row) if row is not None else None

    # --- feedback ----------------------------------------------------

    def record_feedback(
        self, raw_input: str, change_description: str, run_id: int | None = None
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO feedback (raw_input, change_description, run_id, recorded_at) "
                "VALUES (?, ?, ?, ?)",
                (raw_input, change_description, run_id, _now()),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_feedback(self, limit: int = 50) -> list[Feedback]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM feedback ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_feedback_from_row(r) for r in rows]

    # --- capacity constraints -------------------------------------------

    def record_capacity_constraint(
        self,
        run_id: int,
        raw_text: str,
        patch_limit: int,
        pool_size: int,
        deferred_count: int,
    ) -> int:
        """Cycle-scoped, unlike `add_constraint`: a capacity constraint
        ("only five patches fit this window") describes exactly one
        change cycle's bandwidth, tied to the run it was applied within.
        There is no active/deactivate concept here, unlike `constraints`'
        soft-delete lifecycle -- a capacity constraint isn't a standing
        fact that can later be retracted while remaining true or false
        about some other, unrelated run; it has nothing to "still be
        true" on a later run the way an asset-scoped constraint does. It
        is scoped, recorded, and done."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO capacity_constraints (run_id, raw_text, patch_limit, pool_size, "
                "deferred_count, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, raw_text, patch_limit, pool_size, deferred_count, _now()),
            )
            self._conn.commit()
            return cur.lastrowid

    def capacity_constraints_for_run(self, run_id: int) -> list[CapacityConstraint]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM capacity_constraints WHERE run_id = ? ORDER BY id", (run_id,)
            ).fetchall()
        return [_capacity_constraint_from_row(r) for r in rows]

    # --- remediation events ---------------------------------------------

    def record_remediation_event(
        self,
        finding_id: str,
        status: str,
        *,
        note: str | None = None,
        source: str = "human",
        source_detail: str | None = None,
        run_id: int | None = None,
    ) -> int:
        """Appends one row -- never updates or replaces a prior event for
        this finding_id, the same append-only discipline every other table
        here follows. `status`/`source` are not validated against
        anything (this module persists, it does not interpret -- see the
        module docstring and `Constraint.effect_kind`'s identical
        precedent); the closed status vocabulary lives in
        `remediation.REMEDIATION_STATUSES`, checked by the CLI before this
        is ever called."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO remediation_events (finding_id, status, note, source, source_detail, "
                "run_id, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (finding_id, status, note, source, source_detail, run_id, _now()),
            )
            self._conn.commit()
            return cur.lastrowid

    def remediation_events_for_finding(self, finding_id: str) -> list[RemediationEvent]:
        """Full history for one finding, oldest first -- what `rhino
        remediation log` reads."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM remediation_events WHERE finding_id = ? ORDER BY id", (finding_id,)
            ).fetchall()
        return [_remediation_event_from_row(r) for r in rows]

    def latest_remediation_event_for_finding(self, finding_id: str) -> RemediationEvent | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM remediation_events WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
                (finding_id,),
            ).fetchone()
        return _remediation_event_from_row(row) if row is not None else None

    def latest_remediation_events(self) -> dict[str, RemediationEvent]:
        """Every tracked finding_id's current status in one query -- the
        bulk read `rhino run --track-remediation` needs at fleet scale
        (CLAUDE.md's own "no interface may assume demo scale" rule): one
        query plus a join, not one `latest_remediation_event_for_finding`
        call per finding. The join picks, per finding_id, the row whose id
        equals that finding_id's own max id -- the same "latest row per
        group" shape `decisions_for_finding`/`latest_decision_for_finding`
        already establish, just computed for every finding_id at once."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT re.* FROM remediation_events re
                INNER JOIN (
                    SELECT finding_id, MAX(id) AS max_id FROM remediation_events GROUP BY finding_id
                ) latest ON re.finding_id = latest.finding_id AND re.id = latest.max_id
                """
            ).fetchall()
        return {row["finding_id"]: _remediation_event_from_row(row) for row in rows}
