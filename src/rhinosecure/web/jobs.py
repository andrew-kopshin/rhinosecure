"""Write-capable job substrate for the web UI -- the one module `web/server
.py` is allowed to reach for anything beyond serving a static export file,
and only when an operator explicitly starts `rhino web --enable-jobs`.
`create_app()` imports this module conditionally, inside its own body, only
when `jobs_enabled=True` -- never at `web/server.py`'s module level. That is
what keeps the read-only claim in that module's own docstring true by
construction rather than by convention: a default `rhino web` invocation
never imports `rhinosecure.agents`, `rhinosecure.memory`, or `crewai` at all,
the exact same guarantee it already has today.

**What a job is.** A `Job` (below) is a small, typed record: id, kind,
status (`pending` -> `running` -> `succeeded`/`failed`), a `stage` string
whose vocabulary is kind-specific, typed `input`/`result`/`error` dicts, and
whether it refreshed the export file. Generality lives in exactly one place,
`JOB_HANDLERS` -- a `kind -> handler` dispatch table. Today it has one entry,
`"constraint_submit"` (the CLI's `rhino constraint add`, made async with
progress). A later `"agent_run"` handler (a full `--agents` run) is a few
lines reusing the same `PlanState.coordinator.run(...)`/export-write tail
this module already has -- zero changes to the registry, the routes, or the
locking below.

**One current plan per server process.** `PlanState` holds one long-lived
`Coordinator` + `Memory` pair -- mirroring `web/server.py`'s own "one export
file per server process" precedent -- seeded lazily on the FIRST job (not at
server startup, so `rhino web --enable-jobs` starts instantly; the one-time
full-fleet-run cost is instead surfaced through the ordinary job/progress
mechanism as a `"seeding"` stage). This is what makes a *targeted* constraint
submission able to refresh a *whole-fleet* export afterward: `Coordinator
.submit_constraint` (agents/coordinator.py) uses `replan()`, not `run()`,
whenever a full plan already exists on the instance -- exactly the shape
this module's long-lived `PlanState.coordinator` produces (see that method's
own docstring for the CLI-vs-here distinction, which never applies to a
brand-new, per-invocation Coordinator).

**Concurrency: at most one job in flight, server-wide.** `Coordinator`/
`RunState` (agents/coordinator.py) have no lock of their own -- unlike
`memory.py`, which does, because CrewAI already dispatches tool calls from
its own worker thread. Running two jobs against the same `PlanState
.coordinator` concurrently would be a real, unguarded data race on
`RunState`'s dicts. `JobRegistry.create_and_start` enforces the limit
atomically; a second submission while one is running is a plain 409, not
queued -- queuing is a reasonable later extension this shape doesn't
foreclose, just not built here.

**Hard rule, stated once so it can't be reintroduced accidentally: nothing
outside a job's own background thread may read `PlanState.coordinator.state`
directly.** The `on_stage` callback threaded into `Coordinator.run`/
`.replan`/`.submit_constraint` copies a short string into the lock-protected
`Job` object via `JobRegistry.set_stage` -- that copy, not a live peek at
`RunState`, is the entire progress-reporting surface. `GET /api/jobs/{id}`
only ever reads a `Job` object through `JobRegistry.get`.

**Failure taxonomy**, matched to what actually happened, not collapsed into
one "failed" bucket:

- Interpreted but nothing actionable resolved (no asset/effect, or no
  affected finding survived cross-checking) -- NOT a failure. `status=
  "succeeded"`, `result["persisted"] is False`.
- The Interpreter's own response never parsed (`ConstraintInterpretationError`)
  -- nothing was persisted anywhere. `status="failed"`, `error["stage"] ==
  "interpreting"`.
- The constraint *was* persisted, then the re-plan that followed raised
  (`agents.coordinator.ConstraintReplanFailedError` -- no rollback, by
  that exception's own design) -- `status="failed"`, and `error` names the
  real `constraint_id`/`asset_id` so a human isn't left guessing what's
  already on file.
- Everything succeeded, but writing the export file itself raised `OSError`
  -- `status="succeeded"` (the constraint *did* apply), with a distinct,
  non-null `export_warning` rather than `error` -- a different failure
  domain, and conflating the two would misreport a working constraint as a
  failed one.
"""

from __future__ import annotations

import random
import sys
import threading
import uuid
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from rhinosecure import export
from rhinosecure.adapters import DEFAULT_FORMAT, get_adapter, load_config_adapter
from rhinosecure.agents.constraint_intake import ConstraintInterpretationError
from rhinosecure.agents.coordinator import Coordinator, CoordinatorError, ConstraintReplanFailedError
from rhinosecure.enrich.cache import OfflineCacheMissError, SnapshotCache
from rhinosecure.ingest import IngestError, load_batch
from rhinosecure.llm import LLMConfigError
from rhinosecure.memory import Memory

if TYPE_CHECKING:
    from rhinosecure.schema import Asset, EnrichedFinding

MAX_JOB_HISTORY = 50


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class JobConfig:
    """What a `constraint_submit` (and later `agent_run`) job needs to
    load and reason about a fleet -- the same inputs `cli.py`'s
    `run_agents`/`submit_constraint` helpers take, resolved once by
    `rhino web --enable-jobs` at startup rather than per job. `db_path`
    is always a resolved `Path` here (never `None`) -- the caller
    (`cli.py`) resolves `memory.DEFAULT_DB_PATH` itself, the same
    defaulting `run_agents`/`submit_constraint` already do inline."""

    data_dir: Path
    fmt: str = DEFAULT_FORMAT
    adapter_config: str | None = None
    seed: int = 42
    offline: bool = False
    db_path: Path = field(default_factory=lambda: Path("rhinosecure.db"))


@dataclass
class JobOutcome:
    """What a job handler returns on success. Handlers never write to a
    `Job` object directly -- see the module docstring's hard rule; this is
    the value `_execute_job` hands to `JobRegistry.finish`."""

    result: dict[str, Any] | None = None
    export_written: bool = False
    export_warning: str | None = None


@dataclass
class Job:
    id: str
    kind: str
    status: str = "pending"  # pending | running | succeeded | failed
    stage: str | None = None
    created_at: str = field(default_factory=_now)
    started_at: str | None = None
    finished_at: str | None = None
    input: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    export_written: bool = False
    export_warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.id,
            "kind": self.kind,
            "status": self.status,
            "stage": self.stage,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "input": self.input,
            "result": self.result,
            "error": self.error,
            "export_written": self.export_written,
            "export_warning": self.export_warning,
        }


class JobRegistry:
    """In-memory, bounded job history plus a single-job-at-a-time guard.
    Storage cardinality and the concurrency limit are deliberately
    separate: this can hold many finished jobs regardless of how many may
    run concurrently (today: exactly one) -- relaxing that limit later
    touches only `create_and_start`, never this class's shape or the
    routes built on it.

    Every method locks its whole body -- mirroring `memory.py`'s own
    proven pattern (one lock, one long-lived registry, no per-field
    atomicity assumptions) -- since a `Job`'s fields are written from the
    background job thread and read from whichever HTTP request thread
    handles `GET /api/jobs/{id}`."""

    def __init__(self, max_history: int = MAX_JOB_HISTORY):
        self._lock = threading.Lock()
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._max_history = max_history
        self._running_job_id: str | None = None

    def create_and_start(self, kind: str, input: dict[str, Any]) -> Job | None:
        """Atomically creates a job and claims the single running slot,
        or returns None -- creating nothing -- if another job is already
        running. One operation, not create-then-claim, so a rejected
        submission never leaves an orphan job record and there is no
        window for two concurrent submissions to both believe they won."""
        with self._lock:
            if self._running_job_id is not None:
                return None
            job = Job(id=uuid.uuid4().hex, kind=kind, input=input, status="running", started_at=_now())
            self._jobs[job.id] = job
            while len(self._jobs) > self._max_history:
                self._jobs.popitem(last=False)
            self._running_job_id = job.id
            return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list_recent(self, limit: int = MAX_JOB_HISTORY) -> list[Job]:
        with self._lock:
            return list(self._jobs.values())[-limit:]

    def set_stage(self, job_id: str, stage: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.stage = stage

    def finish(
        self,
        job_id: str,
        *,
        status: str,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
        export_written: bool = False,
        export_warning: str | None = None,
    ) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.status = status
            job.finished_at = _now()
            job.result = result
            job.error = error
            job.export_written = export_written
            job.export_warning = export_warning
            if self._running_job_id == job_id:
                self._running_job_id = None


class PlanState:
    """One server process's one live plan: a long-lived `Coordinator` +
    `Memory` pair, seeded lazily on the first job rather than at server
    startup. `export_path` is always the SAME path `web/server.py`'s read
    routes serve (`app.state.export_path`) -- passed in explicitly by
    `mount_job_routes` rather than duplicated on `JobConfig`, so a job can
    never be misconfigured to write somewhere the read routes don't look."""

    def __init__(self, config: JobConfig, export_path: Path):
        self.config = config
        self.export_path = export_path
        self.coordinator: Coordinator | None = None
        self.memory: Memory | None = None
        self.findings: list[EnrichedFinding] | None = None

    def seed(self, on_stage: Callable[[str], None] | None = None) -> None:
        """Loads the fleet and runs the full agent pipeline once. A no-op
        if already seeded. Left at `coordinator=None` if this raises, so
        the next job attempt retries seeding cleanly rather than working
        from a half-built plan -- `run()` itself never partially persists
        anything (only `submit_constraint`/`_submit_capacity_constraint`
        touch `memory.py`), so there is nothing to roll back here."""
        if self.coordinator is not None:
            return
        if on_stage is not None:
            on_stage("seeding")
        random.seed(self.config.seed)
        adapter = (
            load_config_adapter(self.config.adapter_config)
            if self.config.adapter_config
            else get_adapter(self.config.fmt)
        )
        assets, enriched = load_batch(self.config.data_dir, adapter)
        findings = list(enriched)
        _log_exclusions(adapter, adapter.format)

        memory = Memory(self.config.db_path)
        coordinator = Coordinator(
            self.config.data_dir,
            cache=SnapshotCache(offline=self.config.offline),
            memory=memory,
            assets=assets,
            ingest_format=adapter.run_label,
            contract=getattr(adapter, "contract", None),
        )
        coordinator.run(findings, on_stage=on_stage)

        self.memory = memory
        self.findings = findings
        self.coordinator = coordinator  # set last: see the "left at None" note above


def _log_exclusions(adapter: Any, fmt: str) -> None:
    """Server-log equivalent of `cli.py`'s `_warn_of_exclusions` -- not
    imported from there, since `cli.py` is deliberately not a dependency
    of this module (see the module docstring's import-boundary rationale
    for `web/server.py`, which this module was written to respect too,
    even though nothing requires it of `web/jobs.py` specifically)."""
    stats = adapter.stats
    total = len(stats.excluded_assets) + len(stats.excluded_findings)
    if total == 0:
        return
    print(
        f"Note: --format {fmt} excluded {len(stats.excluded_assets)} asset(s) and "
        f"{len(stats.excluded_findings)} finding(s) outside this project's declared scope "
        "(not a data-quality problem) while seeding the web job substrate's plan.",
        file=sys.stderr,
    )


def _serialize_submission_result(result: Any) -> dict[str, Any]:
    """`ConstraintSubmissionResult` and `CapacitySubmissionResult`
    (agents/coordinator.py) have different shapes past `interpretation`/
    `persisted`/`run_id` -- `hasattr(result, "constraint_id")` is how
    `Coordinator.submit_constraint` itself tells them apart at the type
    level (an `isinstance` check would need importing both dataclasses
    just for this), so this mirrors that rather than inventing a second
    way to distinguish them."""
    base: dict[str, Any] = {
        "interpretation": result.interpretation.model_dump(),
        "persisted": result.persisted,
        "run_id": result.run_id,
    }
    if hasattr(result, "constraint_id"):
        base["kind"] = "asset"
        base["constraint_id"] = result.constraint_id
        base["unresolved_finding_ids"] = list(result.unresolved_finding_ids)
        base["deltas"] = [{**asdict(d), "changed": d.changed} for d in result.deltas]
    else:
        base["kind"] = "capacity"
        base["capacity_constraint_id"] = result.capacity_constraint_id
        base["deltas"] = [{**asdict(d), "fits": d.fits, "changed": d.changed} for d in result.deltas]
    return base


def _run_constraint_submit(job: Job, plan_state: PlanState, on_stage: Callable[[str], None]) -> JobOutcome:
    """The one job kind built so far -- `rhino constraint add`, made
    async. Handles whichever `ConstraintKind` the Interpreter resolves to
    (asset-scoped or fleet-wide capacity) internally, the same way
    `Coordinator.submit_constraint` itself branches -- a human's free
    text doesn't pre-declare its kind, so this isn't two job kinds."""
    text = job.input.get("text") or ""

    plan_state.seed(on_stage=on_stage)
    coordinator = plan_state.coordinator
    assert coordinator is not None  # seed() either sets this or raises

    result = coordinator.submit_constraint(
        text, plan_state.findings, seed=plan_state.config.seed, on_stage=on_stage
    )
    result_dict = _serialize_submission_result(result)

    if not result.persisted:
        return JobOutcome(result=result_dict)  # refused -- interpreted, but nothing to apply

    on_stage("exporting")
    try:
        export.write_run_export(
            plan_state.export_path,
            fmt=coordinator.contract.format if coordinator.contract else coordinator.ingest_format,
            data_dir=plan_state.config.data_dir,
            seed=plan_state.config.seed,
            offline=plan_state.config.offline,
            agents=True,
            coordinator=coordinator,
            memory=plan_state.memory,
        )
    except OSError as exc:
        return JobOutcome(
            result=result_dict,
            export_warning=(
                "the constraint was applied, but the export file could not be refreshed: "
                f"{exc}"
            ),
        )
    return JobOutcome(result=result_dict, export_written=True)


JOB_HANDLERS: dict[str, Callable[[Job, PlanState, Callable[[str], None]], JobOutcome]] = {
    "constraint_submit": _run_constraint_submit,
    # "agent_run": _run_agent_run,  # added later -- zero changes needed
    # below this line: same registry, same routes, same locking.
}


def _execute_job(job: Job, registry: JobRegistry, plan_state: PlanState) -> None:
    """Runs on its own background thread, one at a time (enforced by
    `JobRegistry.create_and_start`, not by anything here). Never mutates
    `job` directly -- every state change goes through `registry`, so
    `Job` has exactly one writer path regardless of which thread is
    running. See the module docstring's failure taxonomy for why each
    exception below lands where it does."""

    def on_stage(stage: str) -> None:
        registry.set_stage(job.id, stage)

    handler = JOB_HANDLERS[job.kind]
    try:
        outcome = handler(job, plan_state, on_stage)
    except ConstraintInterpretationError as exc:
        registry.finish(
            job.id,
            status="failed",
            error={"stage": "interpreting", "type": type(exc).__name__, "message": str(exc)},
        )
        return
    except ConstraintReplanFailedError as exc:
        registry.finish(
            job.id,
            status="failed",
            error={
                "stage": "replanning",
                "type": type(exc).__name__,
                "message": str(exc),
                "constraint_id": exc.constraint_id,
                "asset_id": exc.asset_id,
            },
        )
        return
    except (CoordinatorError, IngestError, OfflineCacheMissError, LLMConfigError) as exc:
        registry.finish(
            job.id,
            status="failed",
            error={"stage": job.stage, "type": type(exc).__name__, "message": str(exc)},
        )
        return
    except Exception as exc:  # a background thread must never die silently
        registry.finish(
            job.id,
            status="failed",
            error={"stage": job.stage, "type": type(exc).__name__, "message": str(exc)},
        )
        return

    registry.finish(
        job.id,
        status="succeeded",
        result=outcome.result,
        export_written=outcome.export_written,
        export_warning=outcome.export_warning,
    )


class SubmitJobRequest(BaseModel):
    """`input` is a free-form, kind-specific dict, deliberately not typed
    per-field here -- it becomes `Job.input` verbatim, and each handler
    validates what it needs (see `_run_constraint_submit`'s `text`
    lookup). Adding a job kind never requires touching this model."""

    kind: str
    input: dict[str, Any] = {}


def mount_job_routes(app: FastAPI, job_config: JobConfig) -> None:
    """Called by `create_app()` only when `jobs_enabled=True`. Builds this
    process's one `JobRegistry`/`PlanState` pair and registers the three
    write-capable routes. Never called, and nothing this module imports
    is ever touched, unless an operator explicitly passed
    `--enable-jobs` to `rhino web`."""
    registry = JobRegistry()
    plan_state = PlanState(job_config, export_path=app.state.export_path)
    app.state.job_registry = registry
    app.state.plan_state = plan_state

    @app.post("/api/jobs", status_code=202)
    def submit_job(body: SubmitJobRequest) -> dict[str, Any]:
        if body.kind not in JOB_HANDLERS:
            raise HTTPException(400, f"unknown job kind: {body.kind!r}")
        if body.kind == "constraint_submit" and not str(body.input.get("text") or "").strip():
            raise HTTPException(400, "constraint_submit requires non-empty input.text")

        job = registry.create_and_start(body.kind, body.input)
        if job is None:
            raise HTTPException(409, "another job is already running -- try again once it finishes")

        threading.Thread(target=_execute_job, args=(job, registry, plan_state), daemon=True).start()
        return job.to_dict()

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str) -> dict[str, Any]:
        job = registry.get(job_id)
        if job is None:
            raise HTTPException(404, f"no such job: {job_id}")
        return job.to_dict()

    @app.get("/api/jobs")
    def list_jobs() -> list[dict[str, Any]]:
        return [j.to_dict() for j in registry.list_recent()]
