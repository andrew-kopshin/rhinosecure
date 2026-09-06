"""The dispatcher: wires `agents/router.py`'s Router agent into the web
app -- CLAUDE.md's conversational-front-end design, sections 3-4. A fourth
sibling module `web/server.py` is allowed to reach for beyond serving a
static export file (alongside `web/jobs.py`/`web/uploads.py`/`web/chat.py`),
mounted only when `create_app(jobs_enabled=True, ...)` -- the Router's own
callable surface is `JOB_HANDLERS` plus two non-job actions, so a deployment
with no job substrate has nothing for it to dispatch to at all.

**`depends_on` resolution turned out not to need a generic value-injection
mechanism -- a real design finding, not an assumption carried in from
CLAUDE.md.** The design's own worked example ("the dispatcher... reads its
real, persisted export path, and injects that into operation 1") reads as
if a later step's params need a field filled in from an earlier step's
output. Every operation actually built (`ingest_propose`, `run_
deterministic`, `run_agents`, `constraint_submit`, `remediation_mark`,
`view_scenario`, `qa_question`) either has no params field that COULD
receive such a value, or reads its input from the one shared, fixed
`PlanState.export_path` regardless of which earlier step wrote it -- so
"wait for step N to finish before dispatching step N+1" (sequencing) is
the entire mechanism `depends_on` needs today. Each step's own required
`RoutePlanState.assert_approved` check (below) already enforces this by
construction: approving step `i` requires every step before it to have
`status == "succeeded"`, so `depends_on`'s own extra check (a real,
EARLIER index) can never be violated by anything this module executes --
it exists to catch a Router mistake, not to resolve a value at runtime. If
a future operation's params ever needs an earlier step's actual output
value, that is a real extension point (a `resolve_from_step` field on
`RouteStep`, say) -- deliberately not built speculatively here.

**Per-step human approval, not one blanket approval for a whole decision.**
`assert_step_approved` mirrors `config_io.assert_confirmed`'s "refuses to
construct/proceed" posture: a step must be individually marked approved,
AND every step before it must have already succeeded, before it is ever
dispatched. Editing a step's params (`edit_step`) clears ITS OWN approval
and every later step's -- by construction, every later step is still
`"pending"` at that point (a `"pending"` step cannot have an already-
approved-and-run step after it, since approval requires strict, in-order
completion), so there is no already-applied effect to undo, only future
approvals to re-request. `view_scenario`/`qa_question` still go through
this same one-click-per-step gate even though they're synchronous reads --
CLAUDE.md's own design makes no exception for them ("a mandatory human
click before *every* step, not just the first"). A `"failed"` step can
also be edited and re-approved -- the one recovery path this module
gives a human for a step whose params passed the Router's own grounding
but were rejected downstream (a bad `remediation_mark` status, a job
that failed for a fixable reason), short of abandoning the whole plan.

**The approve-and-claim step is atomic (`claim_step`, under `RoutePlan
.lock`), closing a real race an adversarial review found**: reading
"is this step approved and pending" and writing "now it's running" used
to be two separate, unlocked steps, so two concurrent approve requests
for the same step could both pass the read before either applied the
write. Job-backed steps were usually saved by `JobRegistry`'s own
single-slot claim rejecting the loser, but a synchronous step
(`view_scenario`/`qa_question`, which never touches `JobRegistry`)
would have run twice.

**`view_scenario`/`qa_question` are dispatched inline, never through
`JobRegistry`, on purpose.** `agents/chat.py`'s whole design point is that
concurrent chat needs no lock -- "nothing here can race with itself" --
specifically because it never touches `JobRegistry`'s single-in-flight
slot; forcing `qa_question` through a job would let a long `run_agents`
job block a simple question, contradicting that design outright. Every
job-BACKED operation (`ingest_propose`, `run_deterministic`, `run_agents`,
`constraint_submit`, `remediation_mark`) reuses the EXACT existing
`JobRegistry.create_and_start`/`_execute_job` machinery `web/jobs.py`
already has -- this module adds no second way to run a job, only a second
way to ask for one to start (per-step approval instead of a bare `POST
/api/jobs`).
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, ValidationError

from rhinosecure.agents.router import (
    OperationKind,
    PARAM_MODEL_BY_OP,
    RouterGroundingResult,
    route_message,
)
from rhinosecure.web.jobs import JobRegistry, PlanState, dispatch_job, known_format_match, validate_job_input
from rhinosecure.web.server import load_export

#: Operation kinds this module dispatches inline -- never through
#: JobRegistry. See module docstring.
_SYNCHRONOUS_OPS = frozenset({OperationKind.VIEW_SCENARIO.value, OperationKind.QA_QUESTION.value})

MAX_ROUTE_PLAN_HISTORY = 50


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RouteApprovalError(RuntimeError):
    """Raised by `assert_step_approved` -- a step that isn't the correct
    next step, or isn't itself marked approved, can never be dispatched.
    Mirrors `config_io.ContractError`'s "refuses to construct/proceed"
    role for `ConfiguredAdapter`, one layer up: the SAME backstop that
    protects a confirmed contract from a Router bug protects a plan's
    step sequence from one too."""


@dataclass
class RouteStep:
    op: str
    params: dict[str, Any]
    summary: str
    depends_on: int | None = None
    approved: bool = False
    status: str = "pending"  # pending -> running -> succeeded/failed
    job_id: str | None = None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    #: Copied from the underlying Job when job-backed (never true for a
    #: synchronous op, which never writes the export) -- the frontend's
    #: own signal for "the shared export file just changed, re-fetch it,"
    #: the same fact `handleJobSucceeded`'s `job.export_written` already
    #: drives for the existing constraint-submit UI.
    export_written: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "op": self.op,
            "params": self.params,
            "summary": self.summary,
            "depends_on": self.depends_on,
            "approved": self.approved,
            "status": self.status,
            "job_id": self.job_id,
            "result": self.result,
            "error": self.error,
            "export_written": self.export_written,
        }


@dataclass
class RoutePlan:
    id: str
    message: str
    steps: list[RouteStep]
    clarify: str | None = None
    issues: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=_now)
    #: Guards the claim-a-step-to-run transition (`claim_step`, below)
    #: against two concurrent approve requests for the SAME step index --
    #: excluded from `__eq__`/`repr` since a lock has no meaningful value
    #: identity for either. Not `RoutePlanRegistry._lock`'s job: that lock
    #: protects the registry's own dict of plans, not one plan's steps.
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_id": self.id,
            "message": self.message,
            "steps": [s.to_dict() for s in self.steps],
            "clarify": self.clarify,
            "issues": self.issues,
            "created_at": self.created_at,
        }


def _route_plan_from_grounding(message: str, grounding: RouterGroundingResult) -> RoutePlan:
    steps = [
        RouteStep(op=op.op.value, params=op.params, summary=op.summary, depends_on=op.depends_on)
        for op in grounding.grounded_operations
    ]
    issues = [{"step_index": i.step_index, "message": i.message} for i in grounding.issues]
    return RoutePlan(id=uuid.uuid4().hex, message=message, steps=steps, clarify=grounding.clarify, issues=issues)


class RoutePlanRegistry:
    """In-memory, bounded route-plan history -- mirrors `JobRegistry`'s
    shape (one lock, no per-field atomicity assumptions) for the same
    reason: a `RoutePlan`'s steps are read from an HTTP request thread and
    written from whichever thread executes a step (the calling request
    thread for a synchronous op, a background thread for a job-backed
    one via `_execute_job`). Unlike `JobRegistry`, there is no single-
    plan-at-a-time limit here -- concurrency across DIFFERENT route plans
    is bounded by the SAME underlying `JobRegistry` single-job-at-a-time
    rule every job-backed step still goes through; two plans can coexist
    in this registry, but only one of them can have a job-backed step
    actually running at once."""

    def __init__(self, max_history: int = MAX_ROUTE_PLAN_HISTORY):
        self._lock = threading.Lock()
        self._plans: OrderedDict[str, RoutePlan] = OrderedDict()
        self._max_history = max_history

    def add(self, plan: RoutePlan) -> RoutePlan:
        with self._lock:
            self._plans[plan.id] = plan
            while len(self._plans) > self._max_history:
                self._plans.popitem(last=False)
            return plan

    def get(self, route_id: str) -> RoutePlan | None:
        with self._lock:
            return self._plans.get(route_id)

    def list_recent(self, limit: int = MAX_ROUTE_PLAN_HISTORY) -> list[RoutePlan]:
        with self._lock:
            return list(self._plans.values())[-limit:]


def assert_step_approved(plan: RoutePlan, index: int) -> RouteStep:
    """Refuses (`RouteApprovalError`) unless `index` names a real step,
    every step before it has already succeeded, and the step at `index`
    is itself marked `approved` and still `"pending"`. Returns the step
    on success -- the caller dispatches it, this function only ever
    decides whether that's allowed."""
    if not (0 <= index < len(plan.steps)):
        raise RouteApprovalError(f"step index {index} does not exist in route plan {plan.id!r}")
    for earlier in plan.steps[:index]:
        if earlier.status != "succeeded":
            raise RouteApprovalError(
                f"step {index} cannot run yet -- an earlier step has not succeeded (status={earlier.status!r})"
            )
    step = plan.steps[index]
    if step.status != "pending":
        raise RouteApprovalError(f"step {index} is already {step.status!r}, not pending approval")
    if not step.approved:
        raise RouteApprovalError(f"step {index} has not been approved yet")
    return step


def edit_step(plan: RoutePlan, index: int, new_params: dict[str, Any]) -> RouteStep:
    """Replaces step `index`'s params (revalidated against its own op's
    fixed shape), resets it to a clean `"pending"` slate, and clears
    approval for it and every step after it.

    Accepts a step in either `"pending"` OR `"failed"` status -- an
    adversarial review flagged that refusing to edit a `"failed"` step
    left no recovery path at all for the case a human most needs to
    correct: a param that passed the Router's own grounding but was
    rejected by `validate_job_input` (a bad `remediation_mark` status,
    say), or a job that failed for a fixable reason. The only alternative
    would be abandoning the whole plan and re-proposing from scratch,
    discarding every already-succeeded earlier step for one bad
    parameter. Every OTHER status (`"running"`, `"succeeded"`) still
    refuses -- a step that already ran, or is running, cannot be edited;
    by construction every LATER step is still `"pending"` whenever this
    succeeds (approval requires strict in-order completion), so there is
    never an already-applied effect this needs to undo, only future
    approvals to re-request."""
    if not (0 <= index < len(plan.steps)):
        raise RouteApprovalError(f"step index {index} does not exist in route plan {plan.id!r}")
    step = plan.steps[index]
    if step.status not in ("pending", "failed"):
        raise RouteApprovalError(f"step {index} is already {step.status!r} and can no longer be edited")

    param_model = PARAM_MODEL_BY_OP[OperationKind(step.op)]
    try:
        validated = param_model.model_validate(new_params)
    except ValidationError as exc:
        raise RouteApprovalError(f"params do not match the fixed shape required for {step.op!r}: {exc}") from exc

    step.params = validated.model_dump()
    step.status = "pending"
    step.result = None
    step.error = None
    step.job_id = None
    step.export_written = False
    step.approved = False
    for later in plan.steps[index + 1 :]:
        later.approved = False
    return step


def claim_step(plan: RoutePlan, index: int) -> RouteStep:
    """Atomically (under `plan.lock`) runs `assert_step_approved`'s exact
    checks and, only if they pass, immediately marks the step
    `"running"` before releasing the lock -- the same check-and-set
    shape `JobRegistry.create_and_start` already uses so a claim and the
    read it's based on can never be split by another thread's claim in
    between.

    An adversarial review found the original code called `assert_step_
    approved` with no lock at all: two concurrent `POST .../approve`
    calls for the SAME step could both pass its read-only checks (both
    see `status == "pending"`, `approved == True`) before either had
    written `status = "running"`, and both would go on to dispatch. For
    a job-backed step this was usually masked by `JobRegistry`'s own
    single-slot claim rejecting the loser -- but for a SYNCHRONOUS step
    (`view_scenario`/`qa_question`, which never touches `JobRegistry` at
    all) nothing would have stopped both callers from running the same
    step to completion twice."""
    with plan.lock:
        step = assert_step_approved(plan, index)
        step.status = "running"
        return step


def _sync_step_from_job(step: RouteStep, registry: JobRegistry) -> None:
    """If `step` is job-backed and still marked running, refreshes its
    status/result/error from the real `Job` record -- the same "one
    source of truth, copied, never duplicated" shape `JobRegistry.get`
    already gives `GET /api/jobs/{id}`, read here instead of making a
    caller poll two endpoints to watch one route plan's progress.

    A step whose job has since aged out of `JobRegistry`'s bounded
    history (`MAX_JOB_HISTORY`, oldest evicted once history exceeds it)
    is a real terminal state this must resolve, not silently ignore --
    an adversarial review found the original version left such a step
    reporting `"running"` forever with no way for a client to ever learn
    what actually happened. History only ever holds jobs that already
    reached a terminal status (a running job is tracked separately, via
    `_running_job_id`, until it finishes), so "the job vanished while
    this step still reads running" can only mean it finished and then
    aged out before this ever polled it -- recorded here as failed,
    honestly labeled as a bookkeeping gap rather than anything that went
    wrong with the underlying job itself."""
    if step.job_id is None or step.status != "running":
        return
    job = registry.get(step.job_id)
    if job is None:
        step.status = "failed"
        step.error = {
            "stage": "polling",
            "type": "JobHistoryEvictedError",
            "message": (
                f"job {step.job_id!r} is no longer in job history (evicted once more than "
                "MAX_JOB_HISTORY newer jobs ran) -- it finished, but its actual outcome is no "
                "longer available"
            ),
        }
        return
    if job.status in ("succeeded", "failed"):
        step.status = job.status
        step.result = job.result
        step.export_written = job.export_written
        step.error = job.error


def _execute_synchronous_step(step: RouteStep, plan_state: PlanState, history: list[dict[str, str]]) -> None:
    """Runs a `view_scenario`/`qa_question` step inline and sets its
    terminal status directly -- no job, no thread, matching `agents/
    chat.py`'s own "not the job substrate" design (module docstring)."""
    try:
        export_data = load_export(plan_state.export_path)
    except HTTPException as exc:
        step.status = "failed"
        step.error = {"stage": "reading export", "type": "HTTPException", "message": str(exc.detail)}
        return

    try:
        if step.op == OperationKind.VIEW_SCENARIO.value:
            step.result = _view_scenario(export_data, step.params)
        else:
            from rhinosecure.agents.chat import answer_question

            step.result = answer_question(export_data, step.params["question"], history)
        step.status = "succeeded"
    except Exception as exc:  # a synchronous step must never leave the plan stuck "running" forever
        step.status = "failed"
        step.error = {"stage": step.op, "type": type(exc).__name__, "message": str(exc)}


def _view_scenario(export_data: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    """`"recommended"` is the one filter this module ever computes itself
    (`bucket in {patch_now, contested}`, the same definition the existing
    Scenarios tab's Recommended mode already uses) -- never a Router-
    authored predicate (CLAUDE.md's own reasoning: the Router "never...
    writes a filter predicate from scratch"). `"selection"` is
    deliberately NOT a richer server-side filter language here: it
    returns every finding unfiltered, leaving the existing Scenarios
    tab's own client-side filter controls (bucket/KEV/exposure/role) as
    the actual selection mechanism -- a known, named scope limit, not a
    silent gap."""
    findings = export_data.get("findings", [])
    mode = params.get("mode") or "recommended"
    if mode == "recommended":
        matched = [f for f in findings if f.get("bucket") in ("patch_now", "contested")]
    else:
        matched = findings
    return {"mode": mode, "total": len(findings), "matched": len(matched), "findings": matched}


def _dispatch_job_backed_step(step: RouteStep, registry: JobRegistry, plan_state: PlanState) -> None:
    """`step.status` is already `"running"` -- `claim_step` sets that
    before this is ever called. This function's only job is turning that
    claim into either a real dispatched `Job` or an honest terminal
    outcome; it never itself performs the pending->running transition.

    Runs the SAME `validate_job_input` check `POST /api/jobs` already
    runs on identical input -- an adversarial review found this path
    skipped it entirely, letting params that pass the Router's own fixed
    pydantic shape (e.g. a `RemediationMarkParams.status` that's a bare
    `str`, not constrained to `REMEDIATION_STATUSES`) claim, and
    immediately waste, the single global job slot before failing deep
    inside the job itself. A validation failure here is recorded as a
    normal terminal step failure -- matching what would happen had the
    job actually been allowed to start and fail internally -- rather
    than raised back to the HTTP layer: by this point the step has
    already been approved and claimed, so the honest outcome is "this
    step failed," not "the approve request itself was malformed.\""""
    try:
        validate_job_input(step.op, step.params)
    except HTTPException as exc:
        step.status = "failed"
        step.error = {"stage": "validating input", "type": "HTTPException", "message": str(exc.detail)}
        return

    job = dispatch_job(step.op, step.params, registry, plan_state)
    if job is None:
        # A DIFFERENT plan's step (or a bare POST /api/jobs) already
        # holds JobRegistry's single running slot -- transient, not a
        # property of this step's params, so it goes back to "pending"
        # rather than "failed": the same approval can simply be retried
        # once that other job finishes, with nothing here to edit.
        step.status = "pending"
        raise RouteApprovalError("another job is already running -- try again once it finishes")
    step.job_id = job.id


def execute_step(
    plan: RoutePlan,
    index: int,
    *,
    registry: JobRegistry,
    plan_state: PlanState,
    history: list[dict[str, str]] | None = None,
) -> RouteStep:
    """The one entry point that actually runs a step: `claim_step` first
    (raises `RouteApprovalError` -- callers map that to a 409), then
    dispatches per `_SYNCHRONOUS_OPS`/job-backed above."""
    step = claim_step(plan, index)
    if step.op in _SYNCHRONOUS_OPS:
        _execute_synchronous_step(step, plan_state, history or [])
    else:
        _dispatch_job_backed_step(step, registry, plan_state)
    return step


class ProposeRouteRequest(BaseModel):
    message: str
    history: list[dict[str, str]] = []


class EditStepRequest(BaseModel):
    params: dict[str, Any] = {}


def _registered_ops(chat_enabled: bool) -> frozenset[str]:
    from rhinosecure.web.jobs import JOB_HANDLERS

    ops = set(JOB_HANDLERS) | {OperationKind.VIEW_SCENARIO.value}
    if chat_enabled:
        ops.add(OperationKind.QA_QUESTION.value)
    return frozenset(ops)


def _context_note(upload_registry: Any, plan_state: PlanState) -> str:
    """A short, factual summary of what the Router can currently see --
    ready uploads by id, and whether a plan already exists -- so a human
    message like "analyze the file I just uploaded" can resolve to a real
    `upload_id`/`source_ref` without the human ever typing one
    themselves. Built fresh on every `/api/route` call, never cached:
    upload state changes between messages."""
    lines: list[str] = []
    uploads = upload_registry.list_recent()
    ready = [u for u in uploads if u["ready"]]
    if ready:
        lines.append("Ready uploads (usable as source_ref for ingest_propose/run_deterministic/run_agents):")
        for u in ready:
            names = ", ".join(f["filename"] for f in u["files"])
            matched = known_format_match([f["filename"] for f in u["files"]])
            format_note = (
                f" -- already matches the built-in {matched!r} format, so run_deterministic/run_agents "
                "can be dispatched on it directly; ingest_propose is unnecessary for this one"
                if matched is not None
                else " -- not a recognized built-in format; propose a schema for it first (ingest_propose) "
                "unless the human says it already has a confirmed contract"
            )
            lines.append(f"  - upload_id={u['upload_id']!r}, layout={u['layout']}, files: {names}{format_note}")
    not_ready = [u for u in uploads if not u["ready"]]
    if not_ready:
        lines.append(
            f"{len(not_ready)} upload(s) still need labeling before they can be used -- do not propose "
            "an operation naming one of these; ask the human to finish labeling it instead."
        )
    if plan_state.coordinator is not None and plan_state.active_source is not None:
        lines.append(f"A plan already exists, most recently run against: {plan_state.active_source.data_dir}")
    elif plan_state.config.data_dir is not None:
        # No run has happened yet, but this server was started with a
        # default --data source (the pre-front-end deployment shape) --
        # worth naming so "analyze the plan"/"show me what needs
        # patching" has something to resolve source_ref to without the
        # human needing to name it, or an upload existing at all.
        lines.append(
            f"No plan has been run yet this session, but this server's configured default source is "
            f"{str(plan_state.config.data_dir)!r} -- usable as source_ref if nothing else was named."
        )
    else:
        lines.append("No plan exists yet -- this is an empty workspace, with no default source configured.")
    return "\n".join(lines)


def _known_finding_ids(plan_state: PlanState) -> frozenset[str]:
    if plan_state.findings is None:
        return frozenset()
    return frozenset(e.finding.finding_id for e in plan_state.findings)


class ApproveStepRequest(BaseModel):
    #: Only meaningful for a qa_question step -- the prior conversation
    #: turns `agents.chat.answer_question` threads into its prompt. Empty
    #: for every other op, which ignores it entirely.
    history: list[dict[str, str]] = []


def mount_route_routes(app: FastAPI, *, chat_enabled: bool) -> None:
    """Called by `create_app()` only when `jobs_enabled=True` -- see
    module docstring. Reads `app.state.job_registry`/`app.state.
    plan_state`/`app.state.upload_registry` back off what `mount_job_
    routes`/`mount_upload_routes` already created -- `create_app` calls
    both of those before this, in the same `jobs_enabled` branch, so all
    three are guaranteed to already exist on `app.state` by the time any
    route registered here can possibly run."""
    plan_registry = RoutePlanRegistry()
    app.state.route_plan_registry = plan_registry

    @app.post("/api/route", status_code=201)
    def propose_route(body: ProposeRouteRequest) -> dict[str, Any]:
        plan_state: PlanState = app.state.plan_state
        grounding = route_message(
            body.message,
            body.history,
            registered_ops=_registered_ops(chat_enabled),
            known_upload_ids=frozenset(u["upload_id"] for u in app.state.upload_registry.list_recent()),
            known_finding_ids=_known_finding_ids(plan_state),
            context_note=_context_note(app.state.upload_registry, plan_state),
        )
        plan = _route_plan_from_grounding(body.message, grounding)
        plan_registry.add(plan)
        return plan.to_dict()

    @app.get("/api/route/{route_id}")
    def get_route(route_id: str) -> dict[str, Any]:
        plan = plan_registry.get(route_id)
        if plan is None:
            raise HTTPException(404, f"no such route plan: {route_id!r}")
        for step in plan.steps:
            _sync_step_from_job(step, app.state.job_registry)
        return plan.to_dict()

    @app.get("/api/route")
    def list_routes() -> list[dict[str, Any]]:
        return [p.to_dict() for p in plan_registry.list_recent()]

    @app.post("/api/route/{route_id}/steps/{index}/approve")
    def approve_step(
        route_id: str, index: int, response: Response, body: ApproveStepRequest = ApproveStepRequest()
    ) -> dict[str, Any]:
        plan = plan_registry.get(route_id)
        if plan is None:
            raise HTTPException(404, f"no such route plan: {route_id!r}")
        if not (0 <= index < len(plan.steps)):
            raise HTTPException(404, f"no such step index: {index}")

        plan.steps[index].approved = True
        try:
            step = execute_step(
                plan, index, registry=app.state.job_registry, plan_state=app.state.plan_state,
                history=body.history,
            )
        except RouteApprovalError as exc:
            # Only roll the approval flag back if the claim genuinely
            # never went through (status is still "pending"). An
            # adversarial review found the original code reset `approved`
            # unconditionally -- but by the time this except fires, a
            # concurrent request may have already WON the claim race and
            # left the step legitimately "running"/"succeeded"/"failed";
            # stomping `approved` back to False for that step would
            # misreport a step actually in flight (or already done) as
            # never having been approved at all.
            if plan.steps[index].status == "pending":
                plan.steps[index].approved = False
            raise HTTPException(409, str(exc))
        # A job-backed step is still "running" at this point (its Job
        # runs on its own background thread) -- 202 says so honestly,
        # rather than 200 implying the step already finished within this
        # request. A synchronous step (view_scenario/qa_question) is
        # already terminal by the time execute_step returns, so it still
        # gets a plain 200.
        if step.status == "running":
            response.status_code = 202
        return plan.to_dict()

    @app.post("/api/route/{route_id}/steps/{index}")
    def edit_route_step(route_id: str, index: int, body: EditStepRequest) -> dict[str, Any]:
        plan = plan_registry.get(route_id)
        if plan is None:
            raise HTTPException(404, f"no such route plan: {route_id!r}")
        if not (0 <= index < len(plan.steps)):
            raise HTTPException(404, f"no such step index: {index}")
        try:
            edit_step(plan, index, body.params)
        except RouteApprovalError as exc:
            raise HTTPException(409, str(exc))
        return plan.to_dict()
