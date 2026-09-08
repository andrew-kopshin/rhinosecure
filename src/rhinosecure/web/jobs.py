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
`JOB_HANDLERS` -- a `kind -> handler` dispatch table. Five entries today,
all matching `agents/router.py`'s `OperationKind` names exactly (the Router's
entire callable surface, per CLAUDE.md's own framing, IS this table plus two
non-job actions -- `view_scenario`/`qa_question` -- neither of which is a
`JOB_HANDLERS` entry, on purpose; see `web/route.py`):
`"constraint_submit"` (the CLI's `rhino constraint add`, made async with
progress), `"ingest_propose"` (phase 1 of LLM-assisted adapter generation,
`schema_inference.propose_contract`, dispatched over an uploaded source --
`web/uploads.py`'s conversational-front-end mechanics -- instead of a
`--data` directory named on argv; see `_run_ingest_propose`'s own docstring),
`"run_deterministic"`/`"run_agents"` (the two ingest-and-score pipelines,
dispatched over a Router-resolved `source_ref` -- see `resolve_source_ref`
and each handler's own docstring), and `"remediation_mark"` (mirrors `rhino
remediation mark`, the cheapest handler here: no ingest, no LLM, no export
write).

**One CURRENT plan per server process -- "current" can change over the
server's lifetime, not fixed at startup.** `PlanState` holds one long-lived
`Coordinator` + `Memory` pair -- mirroring `web/server.py`'s own "one export
file per server process" precedent -- seeded lazily on the FIRST job that
needs one (not at server startup, so `rhino web --enable-jobs` starts
instantly). The conversational front end's empty-workspace design
(CLAUDE.md) means there may be NO source at startup at all (`JobConfig
.data_dir=None`) -- the first `run_deterministic`/`run_agents` job to name a
real `source_ref` is what establishes (or replaces) "the current plan," via
`PlanState.run_agents_pipeline`/`resolve_source_ref`, not necessarily the
server's own startup flags. This is what makes a *targeted* constraint
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
- `ingest_propose` has its own third category, distinct from both: a
  proposal that leaves a slot unresolved or fails grounding is NOT a
  failure -- `status="succeeded"`, `result["contract_written"] is False`,
  with `unresolved_slots`/`grounding` naming exactly what a human still
  needs to fix by hand (mirrors `rhino adapt propose`'s own "NOT written"
  outcome, never an exception). Only an unreadable/empty source, an
  ambiguous two-file layout, or the model's output never parsing raises
  -- `status="failed"`, `error["stage"] == "proposing"`.
- `run_deterministic`/`run_agents` raise `IngestError` (caught generically,
  `error["stage"]` reflects whatever `on_stage` last set) when `source_ref`
  cannot be resolved at all -- an unknown upload, an upload with a
  proposed-but-unconfirmed contract (naming the exact `rhino adapt confirm`
  command that would finish it), or a bare `--data` name that doesn't
  exist. There is no "partially resolved" state to report as a success.
- `remediation_mark` raises `IngestError` for the same two CLI-mirrored
  reasons `rhino remediation mark` exits 1 for: an unrecognized `status`,
  or a missing `note` on the one transition (`remediated` -> `open`) where
  it's required. A `finding_id` no scored run has ever seen is NOT a
  failure -- recorded anyway, with `result["seen_before_in_a_scored_run"]
  is False` naming the gap, mirroring the CLI's own warn-not-refuse choice.
"""

from __future__ import annotations

import json
import random
import re
import sys
import threading
import uuid
from collections import Counter, OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from rhinosecure import export
from rhinosecure.adapters import (
    DEFAULT_FORMAT,
    FORMATS,
    REPO_ROOT,
    get_adapter,
    load_config_adapter,
    resolve_config_path,
)
from rhinosecure.adapters.config_io import read_contract, write_contract
from rhinosecure.adapters.config_model import SCORING_ENUM_TARGETS, Attestation, Contract, missing_attestations
from rhinosecure.adapters.configured import ConfiguredAdapter
from rhinosecure.adapters.review import _provisional as provisional_stamp
from rhinosecure.agents.constraint_intake import ConstraintInterpretationError
from rhinosecure.agents.coordinator import Coordinator, CoordinatorError, ConstraintReplanFailedError
from rhinosecure.agents.schema_inference import (
    DEFAULT_MAX_ATTEMPTS as PROPOSE_DEFAULT_MAX_ATTEMPTS,
    DEFAULT_SAMPLE_ROWS,
    ProposalGenerationError,
    SchemaInferenceError,
    SavedProposal,
    assemble_provisional_contract,
    dump_saved_proposal,
    propose_contract,
    saved_proposal_from_dict,
    unresolved_slots,
)
from rhinosecure.enrich.cache import OfflineCacheMissError, SnapshotCache
from rhinosecure.ingest import IngestError, load_batch
from rhinosecure.llm import LLMConfigError
from rhinosecure.memory import Memory
from rhinosecure.remediation import REMEDIATION_STATUSES, note_required_for_transition
from rhinosecure.web import uploads as uploads_module

if TYPE_CHECKING:
    from rhinosecure.schema import Asset, EnrichedFinding

MAX_JOB_HISTORY = 50


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class JobConfig:
    """What a `constraint_submit` job needs to load and reason about a
    fleet by default -- the same inputs `cli.py`'s `run_agents`/
    `submit_constraint` helpers take, resolved once by `rhino web
    --enable-jobs` at startup rather than per job. `db_path` is always a
    resolved `Path` here (never `None`) -- the caller (`cli.py`) resolves
    `memory.DEFAULT_DB_PATH` itself, the same defaulting `run_agents`/
    `submit_constraint` already do inline.

    `data_dir=None` is the conversational-front-end's "empty workspace"
    starting point (CLAUDE.md) -- `rhino web --enable-jobs` with no
    `--data` given. Nothing seeds a plan at startup in that case;
    `PlanState.seed()` raises a clear, actionable error if `constraint_
    submit` is dispatched before ANY `run_deterministic`/`run_agents` job
    has resolved a real source. Passing an actual `--data` name (the
    pre-front-end default, `"demo"`) keeps the original "a plan already
    exists the moment jobs are enabled" behavior working unchanged."""

    data_dir: Path | None = None
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


class PlanNotSeededError(RuntimeError):
    """Raised by `PlanState.seed()` when no plan exists yet AND the
    server was started with no default `--data` source (the empty-
    workspace case, `JobConfig.data_dir is None`) -- there is nothing
    honest to seed from. `constraint_submit` has no fallback for this;
    a `run_deterministic`/`run_agents` job naming a real `source_ref`
    has to run first."""


@dataclass(frozen=True)
class ResolvedSource:
    """What `resolve_source_ref` turns a Router-supplied (or CLI-supplied)
    `source_ref` into: a real directory plus the `fmt`/`adapter_config`
    STRING pair every existing ingest entry point (`Coordinator`, `cli.
    run_with_report`/`run_agents`) already takes -- deliberately not a
    pre-resolved adapter INSTANCE, so this stays a drop-in for those
    existing call sites rather than a third, parallel convention for
    passing an adapter around. Re-resolving the adapter from these two
    strings inside each caller (as `run_with_report`/`Coordinator`
    already do internally) costs a cheap re-parse of a small CSV/JSON
    file, not a second live decision -- `resolve_source_ref` already made
    the one real decision (which format/contract this source is)."""

    data_dir: Path
    fmt: str
    adapter_config: str | None


#: uuid.uuid4().hex is always exactly 32 hex characters -- the same shape
#: web/uploads.py's own upload_id always has (see that module's
#: docstring). Case-insensitive on purpose (an adversarial review found
#: a real upload_id re-cased by a client -- copy/paste autocapitalization,
#: say -- used to silently miss this pattern and fall through to a
#: confusing "no such data set" error instead). Used only to DECIDE
#: whether a source_ref names an upload; never to validate or trust
#: anything about the upload's CONTENTS.
_UPLOAD_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)

#: web/uploads.py's own UploadSet.to_dict()["relative_data_dir"] -- and
#: this module's own `next_step` hint text for a proposed contract --
#: both hand back a source_ref of exactly this shape, `f"uploads/{id}"`,
#: not the bare id. A previous version of this module recognized only
#: the bare id, so a caller that faithfully echoed either of those two
#: strings back as `source_ref` silently fell through to the bare
#: `--data <name>` branch below instead -- an adversarial review found
#: this resolves (data/uploads/<id> really is a directory) with `fmt`
#: hardcoded to "native" and NO format detection at all, a real
#: wrong-but-plausible-scoring risk. Stripped here so both shapes always
#: reach the exact same upload resolution logic.
_UPLOAD_SOURCE_REF_PREFIX = "uploads/"

#: Written by `_run_ingest_propose` next to an upload's own files
#: whenever it produces a real contract, naming exactly that contract --
#: `resolve_source_ref` checks this BEFORE the auto-generated default
#: name, so a contract proposed under an operator-chosen `name` (a real,
#: intentionally exposed `ingest_propose` input) is still found later,
#: not just one that happened to keep the default. Best-effort: a
#: missing or unreadable marker never blocks resolution, it just means
#: only the default-name convention gets tried.
_CONTRACT_NAME_MARKER = ".rhino_contract_name"


def _record_upload_contract_name(upload_dir: Path, name: str) -> None:
    try:
        (upload_dir / _CONTRACT_NAME_MARKER).write_text(name, encoding="utf-8")
    except OSError:
        pass  # a convenience marker, never load-bearing -- the default-name path still works without it


def _upload_id_from_source_ref(source_ref: str) -> str | None:
    """Returns the lowercase, canonical upload_id if `source_ref` names
    an upload (bare, or prefixed `uploads/`) by SHAPE alone -- does not
    check whether that upload actually exists; see `resolve_source_ref`
    for what happens when it doesn't (a real, plausible non-upload
    directory can also happen to be 32 hex characters -- this function
    only recognizes the SHAPE, never commits to "this must be an
    upload")."""
    candidate = source_ref[len(_UPLOAD_SOURCE_REF_PREFIX) :] if source_ref.startswith(_UPLOAD_SOURCE_REF_PREFIX) else source_ref
    return candidate.lower() if _UPLOAD_ID_PATTERN.match(candidate) else None


def _find_upload_contract(upload_id: str, data_dir: Path) -> tuple[Path, Contract] | None:
    """The contract-lookup half of `_resolve_upload_source` -- factored out
    so a caller that needs to know "is there ANY contract at all, confirmed
    or not" (`_resolve_provisional`, shared by `_run_run_deterministic` and
    `_run_run_agents`) doesn't duplicate the candidate-name search, and
    `_resolve_upload_source`'s own refusal wording for an unconfirmed
    contract stays in exactly one place. `None` means nothing has ever been
    proposed for this upload -- not an error; every caller decides what
    that means for itself."""
    candidate_names = list(
        dict.fromkeys(
            n
            for n in (_read_upload_contract_marker(data_dir), _default_propose_name(upload_id))
            if n
        )
    )
    for name in candidate_names:
        candidate = resolve_config_path(name)
        if not candidate.is_file():
            continue
        try:
            return candidate, read_contract(candidate)
        except Exception as exc:
            raise IngestError(
                f"upload {upload_id!r} has a contract at {candidate}, but it could not be read: {exc}"
            ) from exc
    return None


def _resolve_upload_source(upload_id: str, data_dir: Path) -> ResolvedSource:
    filenames = sorted(p.name for p in data_dir.iterdir() if p.is_file())
    matched_format = known_format_match(filenames)
    if matched_format is not None:
        return ResolvedSource(data_dir=data_dir, fmt=matched_format, adapter_config=None)

    found = _find_upload_contract(upload_id, data_dir)
    if found is not None:
        candidate, contract = found
        if contract.review.state == "confirmed":
            return ResolvedSource(data_dir=data_dir, fmt=contract.format, adapter_config=str(candidate))
        raise IngestError(
            f"upload {upload_id!r} has a PROPOSED but unconfirmed contract at {candidate} -- run "
            f'`rhino adapt confirm {contract.format} --data uploads/{upload_id} --by "<you>"` first, '
            "then retry. Confirmation is a signed act that stays outside this system's automated routing."
        )
    raise IngestError(
        f"upload {upload_id!r} doesn't match a known built-in format ({sorted(FORMATS)}) and has no "
        "confirmed contract yet -- submit an ingest_propose job for it first, then confirm the result."
    )


def _read_upload_contract_marker(data_dir: Path) -> str | None:
    marker = data_dir / _CONTRACT_NAME_MARKER
    if not marker.is_file():
        return None
    try:
        return marker.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def resolve_source_ref(source_ref: str) -> ResolvedSource:
    """Resolves a Router `source_ref` (or, identically, a human-typed one)
    to a real directory and ingest format. Two shapes, tried in order:

    1. **An upload** (`web/uploads.py`'s `data/uploads/<id>/` shape),
       recognized as either the bare 32-hex-character id or the
       `uploads/<id>` form (`_upload_id_from_source_ref`) -- but only
       actually TREATED as an upload if `data/uploads/<id>/` really
       exists; otherwise this falls through to shape 2 rather than
       refusing outright, since a legitimately-named `--data` directory
       can coincidentally look upload-id-shaped (a hash-named dataset,
       say). If the uploaded filenames exactly match a built-in format
       (`known_format_match` -- the confirmation gate's own fast path),
       that format is used directly, no LLM, no contract. Otherwise, an
       already-CONFIRMED contract for this upload is used if one exists
       -- checked first under whatever name `_run_ingest_propose` last
       recorded for it (`_CONTRACT_NAME_MARKER`, covers an operator-
       chosen `name`), then under the auto-generated default name
       (`_default_propose_name`) for backward compatibility. A
       PROPOSED-but-not-yet-confirmed contract is refused with a message
       naming the exact `rhino adapt confirm` command that would finish
       it: confirmation stays a dedicated, non-conversational, signed
       act (CLAUDE.md's own reasoning for excluding `INGEST_CONFIRM`
       from the Router entirely) -- nothing here, or upstream of here,
       may skip that gate by resolving around it.
    2. **A bare `--data <name>` directory name**, native format --
       mirrors `cli._resolve_data_dir`'s own convention (checked under
       `data/<name>` first, then as a literal path), duplicated rather
       than imported since `cli.py` is not a dependency of this module
       (see `_log_exclusions`'s docstring for that existing boundary).

    Raises `IngestError` (already caught by every `_execute_job` path
    that can raise it) naming exactly which of these was tried and why
    it failed -- never guesses a format for an unrecognized upload."""
    upload_id = _upload_id_from_source_ref(source_ref)
    if upload_id is not None:
        data_dir = uploads_module.DEFAULT_UPLOADS_DIR / upload_id
        if data_dir.is_dir():
            return _resolve_upload_source(upload_id, data_dir)
        # Shaped like an upload reference, but no such upload exists --
        # falls through to the bare-directory branch rather than refusing
        # immediately, since a real --data directory can coincidentally
        # be named with 32 hex characters too.

    named = REPO_ROOT / "data" / source_ref
    if named.is_dir():
        return ResolvedSource(data_dir=named, fmt=DEFAULT_FORMAT, adapter_config=None)
    literal = Path(source_ref)
    if literal.is_dir():
        return ResolvedSource(data_dir=literal, fmt=DEFAULT_FORMAT, adapter_config=None)
    if upload_id is not None:
        raise IngestError(
            f"no such source: {source_ref!r} -- not a known upload (looked for "
            f"{uploads_module.DEFAULT_UPLOADS_DIR / upload_id}) and not a --data directory "
            f"(looked for {named} and {literal})"
        )
    raise IngestError(f"no such data set: {source_ref!r} (looked for {named} and {literal})")


def _resolve_provisional(source_ref: str) -> tuple[ConfiguredAdapter, ResolvedSource] | None:
    """The provisional-run gate shared by `_run_run_deterministic` and
    `_run_run_agents` (CLAUDE.md's provisional-run entry): an upload whose
    contract exists but was never confirmed gets scored PROVISIONALLY
    instead of refused outright -- ordinarily `resolve_source_ref`'s own
    refusal ("confirmation stays outside this system's automated
    routing"). Returns `None` when this gate doesn't apply at all -- not
    an upload (by shape), no upload directory, no contract ever proposed
    for it, or the contract IS already confirmed -- collapsing all four
    into the identical "fall through to the ordinary `resolve_source_ref`
    call" signal every caller already uses the same way.

    Takes the RAW `source_ref`, not a pre-split `upload_id`/`upload_dir`,
    so every caller shares the ENTIRE gate, including the upload-shape
    check -- not just the contract-building tail of it. Returns the
    already-built `ResolvedSource` too (derived from `contract.format`) so
    neither caller has to reconstruct it a second time."""
    upload_id = _upload_id_from_source_ref(source_ref)
    if upload_id is None:
        return None
    upload_dir = uploads_module.DEFAULT_UPLOADS_DIR / upload_id
    if not upload_dir.is_dir():
        return None
    found = _find_upload_contract(upload_id, upload_dir)
    if found is None or found[1].review.state == "confirmed":
        return None
    contract = found[1]
    # `role` gets a `literal` placeholder ONLY via the provisional-
    # assembly auto-fill (assemble_provisional_contract) -- a real,
    # confident model proposal never uses `literal` for a per-asset field
    # like role. Checking the contract itself (rather than trusting stale
    # state from whatever job proposed it) means this is correct even if
    # the contract was hand-edited or resolved through the browser
    # slot-resolution form after the fact.
    force_not_collected = (
        frozenset({"role"}) if contract.asset["role"].kind == "literal" else frozenset()
    )
    # `ConfiguredAdapter.load_assets`/`.load_findings` run the real
    # `validate_contract` on every load (docs/adapter-generation.md's
    # "Order, which is not negotiable"), which includes V18: a
    # scoring-relevant slot the model mapped at below
    # `LOW_CONFIDENCE_THRESHOLD` (a REAL mapping, just an unconfident one
    # -- a different case from an unresolved slot, and not something
    # assemble_provisional_contract touches at all) requires a
    # `low_confidence_mappings` attestation. `_provisional()`'s own stamp
    # clears `review` entirely, so this contract carries none --
    # confirmed live: a real run against a model output with
    # asset.environment/internet_exposed both at 0.55 confidence failed
    # here with exactly this ContractValidationError before this fix.
    # Placeholder attestations -- the identical "propose-time structural
    # check only, not a real one" text and mechanism
    # `_assemble_and_validate`'s own pre-check already uses -- satisfy
    # V18 without claiming a human reviewed anything; they are attached
    # to THIS in-memory copy only, never written, exactly like
    # assemble_contract's placeholder attestations never reach the file
    # it writes either.
    placeholder_attestations = [
        Attestation(item=item, text="provisional run -- not a real attestation", at=_now())
        for item in missing_attestations(contract)
    ]
    contract = contract.model_copy(
        update={"attestations": list(contract.attestations) + placeholder_attestations}
    )
    adapter = ConfiguredAdapter(
        provisional_stamp(contract),
        excluding_targets=SCORING_ENUM_TARGETS,
        force_not_collected=force_not_collected,
    )
    resolved = ResolvedSource(data_dir=upload_dir, fmt=contract.format, adapter_config=None)
    return adapter, resolved


class PlanState:
    """One server process's one CURRENT plan: a long-lived `Coordinator` +
    `Memory` pair, seeded lazily rather than at server startup. `export_
    path` is always the SAME path `web/server.py`'s read routes serve
    (`app.state.export_path`) -- passed in explicitly by `mount_job_
    routes` rather than duplicated on `JobConfig`, so a job can never be
    misconfigured to write somewhere the read routes don't look.

    "Current" is no longer fixed for the process's whole lifetime --
    the conversational front end's `run_deterministic`/`run_agents` job
    kinds can point this at a DIFFERENT source than whatever `JobConfig
    .data_dir` was at startup, replacing `self.coordinator`/`self.
    memory`/`self.findings`/`self.active_source` wholesale each time
    (never accumulating two plans at once -- "one current plan," not
    "one plan per source ever run"). `constraint_submit` (via `seed`)
    always operates against whichever plan is CURRENT, which is why a
    Router-driven `run_agents` job has to actually replace this state,
    not just write an export file and leave `PlanState` pointing at the
    old source underneath it."""

    def __init__(self, config: JobConfig, export_path: Path):
        self.config = config
        self.export_path = export_path
        self.coordinator: Coordinator | None = None
        self.memory: Memory | None = None
        self.findings: list[EnrichedFinding] | None = None
        self.active_source: ResolvedSource | None = None

    def seed(self, on_stage: Callable[[str], None] | None = None) -> None:
        """Ensures SOME plan is current, for `constraint_submit`'s sake --
        a no-op if one already is (regardless of whether it came from
        server startup or a later `run_agents` job). Falls back to the
        server's startup `JobConfig.data_dir`/`fmt`/`adapter_config` only
        when nothing has run yet; raises `PlanNotSeededError` if that
        fallback is also `None` (the empty-workspace case) -- there is
        nothing honest to seed from, and constraint_submit has no
        `source_ref` of its own to resolve one from."""
        if self.coordinator is not None:
            return
        if self.config.data_dir is None:
            raise PlanNotSeededError(
                "no plan exists yet, and this server was started with no default --data source -- "
                "submit a run_deterministic or run_agents job naming a real source first"
            )
        self.run_agents_pipeline(
            ResolvedSource(data_dir=self.config.data_dir, fmt=self.config.fmt, adapter_config=self.config.adapter_config),
            on_stage,
        )

    def _build_and_run_coordinator(
        self,
        resolved: ResolvedSource,
        adapter: Any,
        *,
        memory: Memory | None,
        on_stage: Callable[[str], None] | None = None,
    ) -> tuple[Coordinator, list[EnrichedFinding]]:
        """The build-and-run sequence `run_agents_pipeline` (below) and a
        PROVISIONAL `run_agents` job (`_run_run_agents`'s provisional
        branch) both need: ingest, build a `Coordinator`, dispatch
        `run()`. Deliberately does NOT touch `self.coordinator`/`.memory`/
        `.active_source`/`.findings` -- the caller decides whether and how
        to commit the result. `run_agents_pipeline` commits unconditionally
        (see its own docstring); the provisional branch never does at all
        (CLAUDE.md's provisional-run entry, point 5 -- `constraint_submit`
        stays refusing against a provisional plan precisely BECAUSE this
        method's result is never assigned onto `self` for one).

        `memory=None` is what makes a provisional run's `Coordinator`
        durably constraint-blind, not a convention this method has to
        enforce itself: `Coordinator.submit_constraint`'s own `if self
        .memory is None: raise CoordinatorError` guard fires on anything
        that tries, and `agents/risk.py`'s `score_finding_tool` never
        queries constraints at all when `memory is None` (`if memory is
        not None:`) -- both pre-existing guards, doing double duty."""
        if on_stage is not None:
            on_stage("seeding")
        random.seed(self.config.seed)
        assets, enriched = load_batch(resolved.data_dir, adapter)
        findings = list(enriched)
        _log_exclusions(adapter, adapter.format)

        coordinator = Coordinator(
            resolved.data_dir,
            cache=SnapshotCache(offline=self.config.offline),
            memory=memory,
            assets=assets,
            ingest_format=adapter.run_label,
            contract=getattr(adapter, "contract", None),
        )
        coordinator.run(findings, on_stage=on_stage)
        return coordinator, findings

    def run_agents_pipeline(self, resolved: ResolvedSource, on_stage: Callable[[str], None] | None = None) -> Coordinator:
        """The full agent pipeline against `resolved`, REPLACING whatever
        plan was current before -- the generalized form of what `seed()`
        used to do only against the server's fixed startup source. Left
        with the OLD `self.coordinator` still in place if this raises
        (assignment happens last, same as the original `seed()`), so a
        failed `run_agents` job never leaves `constraint_submit` pointed
        at a half-built plan -- it just keeps working against whatever
        plan was current before the failed attempt.

        Always builds a REAL `Memory` (unlike the provisional branch,
        which passes `memory=None` to `_build_and_run_coordinator`
        directly and never calls this method at all) -- this is the
        CONFIRMED-contract path, where persisting constraints/decisions/
        runs against this plan is exactly what's supposed to happen."""
        adapter = load_config_adapter(resolved.adapter_config) if resolved.adapter_config else get_adapter(resolved.fmt)
        memory = Memory(self.config.db_path)
        coordinator, findings = self._build_and_run_coordinator(
            resolved, adapter, memory=memory, on_stage=on_stage
        )

        self.memory = memory
        self.findings = findings
        self.active_source = resolved
        self.coordinator = coordinator  # set last: see this method's own docstring
        return coordinator


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
    flag = f"--adapter-config {fmt}" if getattr(adapter, "contract", None) is not None else f"--format {fmt}"
    print(
        f"Note: {flag} excluded {len(stats.excluded_assets)} asset(s) and "
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


def known_format_match(filenames: list[str]) -> str | None:
    """The confirmation-gate design's own "does this already look like a
    known format" fast path (CLAUDE.md's conversational-front-end
    section 2) -- purely mechanical and LLM-free. True only when
    `filenames`, as a SET, exactly matches one built-in adapter's own
    `(assets_filename, findings_filename)` pair -- filename-exact, never
    content-sniffed: a wrong content guess would be exactly the
    wrong-but-plausible inference the not-collected/refuse-rather-than-
    guess discipline exists to prevent. Returns the matching format name,
    or None -- a caller (the Router, a later slice) uses a match to skip
    propose/confirm entirely and dispatch a run with `--format <name>`
    directly against the upload directory."""
    uploaded = set(filenames)
    for name, adapter_cls in FORMATS.items():
        if {adapter_cls.assets_filename, adapter_cls.findings_filename} == uploaded:
            return name
    return None


def _default_propose_name(upload_id: str) -> str:
    # config_model._FORMAT_PATTERN allows at most 32 characters total;
    # "upload-" (7) plus a 24-character slice of the 32-character hex id
    # stays inside that with room to spare, and keeps enough of the id
    # to be recognizable next to it under data/adapters/.
    return f"upload-{upload_id[:24]}"


def _run_ingest_propose(job: Job, plan_state: PlanState, on_stage: Callable[[str], None]) -> JobOutcome:
    """Phase 1 of LLM-assisted adapter generation (docs/adapter-
    generation.md), dispatched against an uploaded source instead of a
    `--data` directory a human named on the command line -- the
    conversational front end's confirmation-gate design (CLAUDE.md).
    `plan_state` is accepted only to match every other handler in
    `JOB_HANDLERS`' shared signature and is never touched: schema
    inference reasons about one source's shape, not a fleet's scoring,
    and has nothing to do with `Coordinator`/`Memory`.

    Writes an UNCONFIRMED contract (`review.state == "proposed"`) to
    `data/adapters/<name>.json` when every slot is mapped and grounded --
    exactly what `rhino adapt propose` itself writes, via the identical
    `propose_contract`/`write_contract` calls. This is inert until a
    human runs the separate, dedicated `rhino adapt confirm` signature
    step: `ConfiguredAdapter.__init__` refuses to construct against
    anything not `review.state == "confirmed"` (`config_io.assert_
    confirmed`), so nothing this job writes can affect a real run on its
    own -- the same backstop the front-end design leans on for
    deliberately excluding `INGEST_CONFIRM` from the Router's own
    operation vocabulary.

    `input.edited_saved_proposal`, when present, is a whole saved-proposal
    dict (`{"proposal", "generator", "attempt_usage"}` -- what `GET
    /api/adapters/{name}/proposal` (web/adapters.py) hands the browser and
    what it resubmits after a human fills in an unresolved slot). Routes
    straight to `propose_contract(..., from_proposal=...)`, the identical
    LLM-free grounding+assembly path `rhino adapt propose --from-proposal`
    already uses -- an illegal edit is refused by the same
    `check_grounding`/`assemble_contract` gate a bad model output already
    goes through, never a second, browser-specific validator. This is
    additive: every existing caller (a fresh, LLM-driven propose) has no
    such key and is unaffected. `agents/router.py`'s `IngestProposeParams`
    has no field for this, so chat can dispatch a fresh propose but can
    never smuggle in a slot edit -- only a direct `POST /api/jobs` call
    from the dedicated resolution form can."""
    upload_id = str(job.input.get("upload_id") or "").strip()
    if not upload_id:
        raise SchemaInferenceError("ingest_propose requires a non-empty input.upload_id")

    data_dir = uploads_module.DEFAULT_UPLOADS_DIR / upload_id
    if not data_dir.is_dir():
        raise SchemaInferenceError(f"no such upload set: {upload_id!r} (looked for {data_dir})")

    name = str(job.input.get("name") or "").strip() or _default_propose_name(upload_id)
    output_path = resolve_config_path(name)
    overwrite_confirmed = bool(job.input.get("overwrite_confirmed", False))

    if output_path.exists() and not overwrite_confirmed:
        try:
            existing = read_contract(output_path)
        except Exception:
            existing = None
        if existing is not None and existing.review.state == "confirmed":
            raise SchemaInferenceError(
                f"{output_path} already holds a CONFIRMED contract (signed {existing.review.confirmed_at} "
                f"by {existing.review.confirmed_by}) -- re-proposing would silently overwrite that signature. "
                "Pass input.overwrite_confirmed=true if you really mean to replace it."
            )

    edited_saved_proposal_data = job.input.get("edited_saved_proposal")
    if edited_saved_proposal_data is not None:
        on_stage("re-grounding the edited proposal")
        from_proposal = saved_proposal_from_dict(edited_saved_proposal_data)
        result = propose_contract(data_dir, name, generated_at=_now(), from_proposal=from_proposal)
    else:
        on_stage("proposing")
        result = propose_contract(
            data_dir,
            name,
            generated_at=_now(),
            assets_filename=job.input.get("assets_filename") or None,
            findings_filename=job.input.get("findings_filename") or None,
            max_attempts=int(job.input.get("max_attempts") or PROPOSE_DEFAULT_MAX_ATTEMPTS),
            sample_rows=int(job.input.get("sample_rows") or DEFAULT_SAMPLE_ROWS),
        )

    on_stage("saving proposal")
    saved_path = REPO_ROOT / "out" / f"propose_{name}.json"
    saved_path.parent.mkdir(parents=True, exist_ok=True)
    saved_path.write_text(
        json.dumps(
            dump_saved_proposal(SavedProposal(result.proposal, result.generator, result.attempt_usage)),
            indent=2, sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    result_dict: dict[str, Any] = {
        "upload_id": upload_id,
        "name": name,
        "layout": result.proposal.meta.source_layout,
        "proposal_saved_path": str(saved_path),
        "unresolved_slots": unresolved_slots(result.proposal),
        "grounding": {
            "failures": [{"slot": i.slot, "message": i.message} for i in result.grounding.failures],
            "caveats": [{"slot": i.slot, "message": i.message} for i in result.grounding.caveats],
        },
        "generator": {
            "model": result.generator.model,
            "attempts": result.generator.attempts,
            "prompt_tokens": result.generator.prompt_tokens,
            "completion_tokens": result.generator.completion_tokens,
            "estimated_cost_usd": result.generator.estimated_cost_usd,
            # One entry per attempt actually made (including discarded
            # ones) -- see SavedProposal.attempt_usage's own docstring for
            # why this sits beside, not inside, the summed totals above.
            "per_attempt": list(result.attempt_usage),
        },
        "contract_written": False,
        "contract_path": None,
        "incomplete_reason": result.incomplete_reason,
        "next_step": None,
        "provisional": False,
        "neutralized_axes": [],
        "invalid_mappings_dropped": [],
    }

    if result.contract is None:
        # CLAUDE.md's "drop a CSV, get a plan" spec: assemble_contract
        # refused (a real unresolved slot, or a grounding failure), but that
        # doesn't have to mean nothing gets written -- assemble_provisional_
        # contract (degrade-rather-than-block) gets a second attempt against
        # the identical proposal/profiles/grounding report, auto-filling
        # what it legally can and neutralizing the scoring axes it can't
        # honestly determine. Still refuses (contract stays None) for a real
        # grounding failure or a genuinely load-bearing gap (an identity
        # field, scanner_severity) -- see that function's own docstring.
        on_stage("attempting a provisional assembly")
        provisional_contract, notes = assemble_provisional_contract(
            result.proposal, result.profiles, result.grounding, generator=result.generator, generated_at=_now()
        )
        if provisional_contract is None:
            result_dict["incomplete_reason"] = notes.hard_stop_reason or result.incomplete_reason
            return JobOutcome(result=result_dict)

        on_stage("writing provisional contract")
        written = write_contract(output_path, provisional_contract)
        _record_upload_contract_name(data_dir, name)
        result_dict["contract_written"] = True
        result_dict["contract_path"] = str(output_path)
        result_dict["contract_version"] = written.version
        result_dict["incomplete_reason"] = None
        result_dict["provisional"] = True
        result_dict["neutralized_axes"] = sorted(notes.neutralized_axes)
        result_dict["invalid_mappings_dropped"] = sorted(notes.invalid_mappings_dropped)
        result_dict["next_step"] = f'rhino adapt confirm {name} --data uploads/{upload_id} --by "<you>"'
        return JobOutcome(result=result_dict)

    on_stage("writing contract")
    written = write_contract(output_path, result.contract)
    # So resolve_source_ref can find this contract later regardless of
    # `name` -- an adversarial review found that without this marker,
    # a contract proposed under anything other than the auto-generated
    # default name (a real, intentionally exposed input above) could
    # never be found again by run_deterministic/run_agents at all.
    _record_upload_contract_name(data_dir, name)
    result_dict["contract_written"] = True
    result_dict["contract_path"] = str(output_path)
    result_dict["contract_version"] = written.version
    result_dict["next_step"] = f'rhino adapt confirm {name} --data uploads/{upload_id} --by "<you>"'
    return JobOutcome(result=result_dict)


def _require_source_ref(job: Job, kind: str) -> str:
    source_ref = str(job.input.get("source_ref") or "").strip()
    if not source_ref:
        raise IngestError(f"{kind} requires a non-empty input.source_ref")
    return source_ref


def _run_run_deterministic(job: Job, plan_state: PlanState, on_stage: Callable[[str], None]) -> JobOutcome:
    """The Router's `run_deterministic` operation -- the no-LLM-in-the-
    loop pipeline, dispatched over a resolved `source_ref` instead of a
    `--data`/`--format` pair a human typed. Deliberately does NOT touch
    `plan_state.coordinator`/`.memory`/`.active_source` at all: those
    represent the CURRENT plan `constraint_submit` re-plans against, and
    a deterministic run is a cheap, throwaway view of one source, not a
    plan `Coordinator`-backed re-planning could ever apply to (Section 8
    rule 2 -- scoring stays LLM-free -- has no re-plan concept at all).

    Calls `cli.run_with_report` directly rather than reimplementing its
    scoring loop -- a DIFFERENT call than `_log_exclusions`'s "cli.py is
    not a dependency of this module" note describes: that note is about
    this module not depending on cli.py's PRESENTATION layer (argument
    parsing, printing), and `export.py` itself already imports `cli.
    RunResult` directly as the deterministic export's own required
    shape (see export.py's module docstring) -- reimplementing `run_
    with_report`'s ~30-line loop here to avoid a second, thin dependency
    on the exact type export.py already requires would only create a
    second copy of that loop to keep in sync, not a cleaner boundary."""
    on_stage("resolving source")  # before validation -- a bad input's error must not carry stage=null
    source_ref = _require_source_ref(job, "run_deterministic")

    # CLAUDE.md's "drop a CSV, get a plan" spec: an upload whose contract
    # exists but was never confirmed -- ordinarily resolve_source_ref's own
    # refusal ("confirmation stays outside this system's automated
    # routing") -- gets a PROVISIONAL run instead, here and only here. This
    # check runs BEFORE calling resolve_source_ref, never around a refusal
    # it raised: resolve_source_ref itself, and every other caller of it
    # (constraint_submit), is completely untouched. A confirmed contract, a
    # known built-in format match, or no contract proposed for this upload
    # at all fall straight through to the identical resolve_source_ref call
    # this function has always made. `_resolve_provisional` is the SAME
    # gate `_run_run_agents`'s own provisional branch uses -- see that
    # function and CLAUDE.md's provisional-run entry.
    found_provisional = _resolve_provisional(source_ref)
    if found_provisional is not None:
        provisional_adapter, resolved = found_provisional
    else:
        provisional_adapter = None
        resolved = resolve_source_ref(source_ref)

    on_stage("scoring")
    from rhinosecure.cli import run_with_report

    result = run_with_report(
        resolved.data_dir,
        plan_state.config.seed,
        offline=plan_state.config.offline,
        fmt=resolved.fmt,
        adapter_config=resolved.adapter_config,
        adapter=provisional_adapter,
    )

    on_stage("exporting")
    export_memory = plan_state.memory if plan_state.memory is not None else Memory(plan_state.config.db_path)
    export.write_run_export(
        plan_state.export_path,
        fmt=result.report.format,
        data_dir=resolved.data_dir,
        seed=plan_state.config.seed,
        offline=plan_state.config.offline,
        agents=False,
        result=result,
        memory=export_memory,
    )

    bucket_counts = Counter(sf.bucket.value for sf in result.scored)
    return JobOutcome(
        result={
            "source_ref": source_ref,
            "format": result.report.format,
            "total_findings": len(result.scored),
            "bucket_distribution": dict(bucket_counts),
            "provisional": provisional_adapter is not None,
        },
        export_written=True,
    )


def _run_run_agents(job: Job, plan_state: PlanState, on_stage: Callable[[str], None]) -> JobOutcome:
    """The Router's `run_agents` operation -- the full agent pipeline
    against a resolved `source_ref`, REPLACING whatever plan was current
    on this `PlanState` before (see `PlanState.run_agents_pipeline`'s own
    docstring on why replacing, not accumulating, is correct here) --
    UNLESS `source_ref` names an upload with a proposed-but-unconfirmed
    contract, in which case this runs the identical PROVISIONAL branch
    `_run_run_deterministic` has (CLAUDE.md's provisional-run entry,
    "drop a CSV, get a plan"): the same `_resolve_provisional` gate, the
    same `excluding_targets=SCORING_ENUM_TARGETS`/`force_not_collected`
    adapter, but through the full 4-agent pipeline (Research/Environment/
    Risk/ToT) instead of the deterministic-only one.

    The provisional branch deliberately NEVER commits onto `plan_state`
    (`self.coordinator`/`.memory`/`.active_source`/`.findings` all stay
    whatever they were before this job) -- `PlanState._build_and_run_
    coordinator` is called directly instead of `run_agents_pipeline`,
    with `memory=None`. This is what makes `constraint_submit` against a
    provisional plan a structural non-issue rather than a special case
    this handler has to guard against itself: with nothing committed,
    the next `constraint_submit` job either finds no plan at all
    (`PlanNotSeededError`) or re-plans whatever OLDER, confirmed plan was
    already current -- never this provisional run. See CLAUDE.md's
    provisional-run entry, point 5, for the full reasoning and the
    backstop (`Coordinator.submit_constraint`'s own `if self.memory is
    None: raise CoordinatorError`) that holds even if something ever DID
    hold a direct reference to this provisional Coordinator.

    `run_agents` still never auto-fires from `ingest_propose` or
    `run_deterministic` -- this is dispatched only as its own explicit
    job (or Router `RUN_AGENTS` step, gated by `assert_step_approved`),
    exactly as before this branch existed."""
    on_stage("resolving source")  # before validation -- a bad input's error must not carry stage=null
    source_ref = _require_source_ref(job, "run_agents")

    found_provisional = _resolve_provisional(source_ref)
    if found_provisional is not None:
        provisional_adapter, resolved = found_provisional
        coordinator, _findings = plan_state._build_and_run_coordinator(
            resolved, provisional_adapter, memory=None, on_stage=on_stage
        )
        # Mirrors _run_run_deterministic's own export_memory pattern:
        # read-only, for the constraints section's display ONLY -- this
        # coordinator's own scoring never touched memory at all
        # (memory=None above), so no constraint from this file was ever
        # actually folded into what was just scored.
        export_memory = plan_state.memory if plan_state.memory is not None else Memory(plan_state.config.db_path)
        provisional = True
    else:
        resolved = resolve_source_ref(source_ref)
        coordinator = plan_state.run_agents_pipeline(resolved, on_stage)
        export_memory = plan_state.memory
        provisional = False

    on_stage("exporting")
    export.write_run_export(
        plan_state.export_path,
        fmt=coordinator.contract.format if coordinator.contract else coordinator.ingest_format,
        data_dir=resolved.data_dir,
        seed=plan_state.config.seed,
        offline=plan_state.config.offline,
        agents=True,
        coordinator=coordinator,
        memory=export_memory,
    )

    recommendations = coordinator.ranked()
    bucket_counts = Counter(r.bucket for r in recommendations)
    return JobOutcome(
        result={
            "source_ref": source_ref,
            "format": coordinator.contract.format if coordinator.contract else coordinator.ingest_format,
            "total_findings": len(recommendations),
            "bucket_distribution": dict(bucket_counts),
            "provisional": provisional,
        },
        export_written=True,
    )


def _run_remediation_mark(job: Job, plan_state: PlanState, on_stage: Callable[[str], None]) -> JobOutcome:
    """The Router's `remediation_mark` operation -- mirrors `rhino
    remediation mark` exactly (same status vocabulary, same note-
    required-for-a-`remediated`-back-to-`open` transition, same "warn,
    don't refuse" treatment of a finding_id no scored run has ever seen).
    Deliberately the cheapest handler here: no ingest, no LLM, no export
    write -- `rhino remediation mark` never touches `--export` either,
    since remediation status is tracking, not scoring (CLAUDE.md Section
    7: "never feeds back into scoring.py")."""
    on_stage("marking")  # before validation -- a bad input's error must not carry stage=null
    finding_id = str(job.input.get("finding_id") or "").strip()
    status = str(job.input.get("status") or "").strip()
    note = job.input.get("note")
    note = str(note).strip() or None if note else None

    if not finding_id:
        raise IngestError("remediation_mark requires a non-empty input.finding_id")
    if status not in REMEDIATION_STATUSES:
        raise IngestError(f"remediation_mark: status must be one of {REMEDIATION_STATUSES}, got {status!r}")

    memory = plan_state.memory if plan_state.memory is not None else Memory(plan_state.config.db_path)
    previous = memory.latest_remediation_event_for_finding(finding_id)
    previous_status = previous.status if previous is not None else None

    if note_required_for_transition(previous_status, status) and not note:
        raise IngestError(
            f"remediation_mark: a note is required when marking {finding_id!r} back to 'open' from "
            "'remediated' -- that's the transition where the reason matters most."
        )

    seen_before = bool(memory.decisions_for_finding(finding_id))
    memory.record_remediation_event(finding_id, status, note=note, source="human")
    transition = f"{previous_status} -> {status}" if previous_status else f"(untracked) -> {status}"
    return JobOutcome(
        result={
            "finding_id": finding_id,
            "status": status,
            "previous_status": previous_status,
            "transition": transition,
            "note": note,
            "seen_before_in_a_scored_run": seen_before,
        }
    )


JOB_HANDLERS: dict[str, Callable[[Job, PlanState, Callable[[str], None]], JobOutcome]] = {
    "constraint_submit": _run_constraint_submit,
    "ingest_propose": _run_ingest_propose,
    "run_deterministic": _run_run_deterministic,
    "run_agents": _run_run_agents,
    "remediation_mark": _run_remediation_mark,
    # below this line: same registry, same routes, same locking.
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
    except ProposalGenerationError as exc:
        # `exc.attempt_usage`/`exc.estimated_cost_usd`: every attempt still
        # spent real tokens even though nothing got written -- the same
        # gap CLAUDE.md's own "Cost/usage visibility" item (Section 8)
        # names, closed here the same way cli.py's matching except clause
        # closes it for the CLI path.
        registry.finish(
            job.id,
            status="failed",
            error={
                "stage": "proposing",
                "type": type(exc).__name__,
                "message": str(exc),
                "attempt_usage": list(exc.attempt_usage),
                "estimated_cost_usd": exc.estimated_cost_usd,
            },
        )
        return
    except SchemaInferenceError as exc:
        registry.finish(
            job.id,
            status="failed",
            error={"stage": "proposing", "type": type(exc).__name__, "message": str(exc)},
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


#: kind -> required, non-empty string field(s) in `input` -- checked here so
#: a malformed submission gets a fast 400 before ever claiming the single
#: running-job slot, not just inside the handler after a job record already
#: exists. `remediation_mark` additionally needs its own status-vocabulary
#: check below, since "a required field is present" doesn't cover "and its
#: value is legal."
_REQUIRED_JOB_INPUT_FIELDS: dict[str, tuple[str, ...]] = {
    "constraint_submit": ("text",),
    "ingest_propose": ("upload_id",),
    "run_deterministic": ("source_ref",),
    "run_agents": ("source_ref",),
    "remediation_mark": ("finding_id", "status"),
}


def validate_job_input(kind: str, input: dict[str, Any]) -> None:
    """Public (not `_`-prefixed) because `web/route.py`'s per-step
    approval path needs the identical check `POST /api/jobs` already
    runs -- an adversarial review found that route.py's dispatch used
    to skip this entirely, letting a step whose params pass the
    Router's own pydantic shape (e.g. a `RemediationMarkParams.status`
    that isn't actually in `REMEDIATION_STATUSES`, since that field is a
    bare `str`) claim the single global job slot before failing inside
    the job itself, instead of being refused up front like the
    identical input sent to `POST /api/jobs` already is."""
    for field_name in _REQUIRED_JOB_INPUT_FIELDS.get(kind, ()):
        if not str(input.get(field_name) or "").strip():
            raise HTTPException(400, f"{kind} requires non-empty input.{field_name}")
    if kind == "remediation_mark" and input["status"] not in REMEDIATION_STATUSES:
        raise HTTPException(
            400, f"remediation_mark: status must be one of {REMEDIATION_STATUSES}, got {input['status']!r}"
        )


def dispatch_job(kind: str, input: dict[str, Any], registry: JobRegistry, plan_state: PlanState) -> Job | None:
    """Claims the single running-job slot and starts `kind` on its own
    background thread, or returns `None` if another job is already
    running. The one place a `Job` actually gets created and executed --
    `POST /api/jobs` (below) and `web/route.py`'s per-step approval both
    call this instead of each re-implementing "create, start a thread,"
    so there is exactly one dispatch path to keep correct regardless of
    how many places in this codebase can trigger a job."""
    job = registry.create_and_start(kind, input)
    if job is None:
        return None
    threading.Thread(target=_execute_job, args=(job, registry, plan_state), daemon=True).start()
    return job


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
        validate_job_input(body.kind, body.input)

        job = dispatch_job(body.kind, body.input, registry, plan_state)
        if job is None:
            raise HTTPException(409, "another job is already running -- try again once it finishes")
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
