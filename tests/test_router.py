"""Coverage for agents/router.py -- the Router agent, its closed
per-operation params shapes, and its two LLM-free backstops
(`ground_router_decision`, `verify_step_summary`). Only the LLM dispatch
is faked (`_QueuedFakeCrew`, the same pattern every other agent test file
in this suite uses for the same reason) -- these tests exercise the real
parsing, grounding, and retry code.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from rhinosecure.agents import router as router_module
from rhinosecure.agents.parsing import AgentOutputParseError
from rhinosecure.agents.router import (
    ConstraintSubmitParams,
    IngestProposeParams,
    OperationKind,
    QaQuestionParams,
    RemediationMarkParams,
    RouterDecision,
    RouterDecisionError,
    RouterOperation,
    RunDeterministicParams,
    ViewScenarioParams,
    find_wrong_upload_id_mentions,
    ground_router_decision,
    route_message,
    verify_step_summary,
)

UPLOAD_A = "a" * 32
UPLOAD_B = "b" * 32


def _op(op: OperationKind, params: dict, *, summary: str = "do the thing", depends_on: int | None = None) -> RouterOperation:
    return RouterOperation(op=op, params=params, summary=summary, depends_on=depends_on)


# ---------------- per-op params: closed, extra="forbid" ----------------


def test_ingest_propose_params_rejects_an_unexpected_field():
    with pytest.raises(ValidationError):
        IngestProposeParams(upload_id=UPLOAD_A, bogus_field="x")


def test_ingest_propose_params_allows_the_optional_fields_to_be_omitted():
    params = IngestProposeParams(upload_id=UPLOAD_A)
    assert params.name is None
    assert params.assets_filename is None


def test_constraint_submit_params_has_only_raw_text():
    params = ConstraintSubmitParams(raw_text="the payroll server only reboots on Sundays")
    assert params.raw_text
    with pytest.raises(ValidationError):
        ConstraintSubmitParams(raw_text="x", asset_id="A01")  # no such field, even though tempting


def test_remediation_mark_params_requires_finding_id_and_status():
    with pytest.raises(ValidationError):
        RemediationMarkParams(status="open")  # missing finding_id


def test_view_scenario_params_defaults_to_recommended():
    assert ViewScenarioParams().mode == "recommended"


def test_router_operation_rejects_an_unrecognized_op_value():
    with pytest.raises(ValidationError):
        RouterOperation(op="delete_everything", params={}, summary="x")


# ---------------- ground_router_decision ----------------


def test_a_clean_decision_grounds_every_step_unchanged():
    decision = RouterDecision(
        operations=[
            _op(OperationKind.INGEST_PROPOSE, {"upload_id": UPLOAD_A}, summary=f"Propose a schema for {UPLOAD_A}"),
            _op(OperationKind.VIEW_SCENARIO, {"mode": "recommended"}, summary="Show the recommended view", depends_on=0),
        ]
    )
    result = ground_router_decision(
        decision, registered_ops=frozenset({"ingest_propose", "view_scenario"}), known_upload_ids=frozenset({UPLOAD_A})
    )
    assert result.clean
    assert len(result.grounded_operations) == 2
    assert result.grounded_operations[1].depends_on == 0


def test_an_op_with_no_registered_handler_is_dropped():
    decision = RouterDecision(operations=[_op(OperationKind.RUN_AGENTS, {"source_ref": "demo"})])
    result = ground_router_decision(decision, registered_ops=frozenset({"run_deterministic"}))
    assert result.grounded_operations == []
    assert len(result.issues) == 1
    assert "run_agents" in result.issues[0].message
    assert "no registered handler" in result.issues[0].message


def test_params_with_an_extra_field_are_dropped_not_silently_stripped():
    decision = RouterDecision(operations=[RouterOperation(op=OperationKind.CONSTRAINT_SUBMIT, params={"raw_text": "x", "asset_id": "A01"}, summary="submit")])
    result = ground_router_decision(decision, registered_ops=frozenset({"constraint_submit"}))
    assert result.grounded_operations == []
    assert "do not match the fixed shape" in result.issues[0].message


def test_an_unknown_upload_id_is_dropped_when_known_upload_ids_is_supplied():
    decision = RouterDecision(operations=[_op(OperationKind.INGEST_PROPOSE, {"upload_id": UPLOAD_A}, summary=f"propose {UPLOAD_A}")])
    result = ground_router_decision(
        decision, registered_ops=frozenset({"ingest_propose"}), known_upload_ids=frozenset({UPLOAD_B})
    )
    assert result.grounded_operations == []
    assert "not a real, current upload" in result.issues[0].message


def test_an_upload_id_is_not_checked_when_known_upload_ids_is_empty():
    """Empty means the caller chose not to enforce this -- not a false
    claim that nothing is real (mirrors verify_research_matches_tool's
    inert-when-no-call-log shape)."""
    decision = RouterDecision(operations=[_op(OperationKind.INGEST_PROPOSE, {"upload_id": UPLOAD_A}, summary=f"propose {UPLOAD_A}")])
    result = ground_router_decision(decision, registered_ops=frozenset({"ingest_propose"}))
    assert result.clean


def test_an_unknown_finding_id_is_dropped_when_known_finding_ids_is_supplied():
    decision = RouterDecision(
        operations=[_op(OperationKind.REMEDIATION_MARK, {"finding_id": "F99", "status": "remediated"}, summary="mark F99 remediated")]
    )
    result = ground_router_decision(
        decision, registered_ops=frozenset({"remediation_mark"}), known_finding_ids=frozenset({"F01"})
    )
    assert result.grounded_operations == []
    assert "F99" in result.issues[0].message


def test_depends_on_a_later_step_is_rejected():
    decision = RouterDecision(
        operations=[
            _op(OperationKind.VIEW_SCENARIO, {}, summary="view", depends_on=1),
            _op(OperationKind.INGEST_PROPOSE, {"upload_id": UPLOAD_A}, summary=f"propose {UPLOAD_A}"),
        ]
    )
    result = ground_router_decision(decision, registered_ops=frozenset({"view_scenario", "ingest_propose"}))
    # Step 0's forward-reference depends_on is rejected; step 1 (no
    # depends_on of its own) is independently valid and survives.
    assert len(result.grounded_operations) == 1
    assert result.grounded_operations[0].op == OperationKind.INGEST_PROPOSE
    assert any("does not name an earlier step" in i.message for i in result.issues)


def test_depends_on_itself_is_rejected():
    decision = RouterDecision(operations=[_op(OperationKind.VIEW_SCENARIO, {}, summary="view", depends_on=0)])
    result = ground_router_decision(decision, registered_ops=frozenset({"view_scenario"}))
    assert result.grounded_operations == []


def test_a_negative_depends_on_is_rejected():
    decision = RouterDecision(operations=[_op(OperationKind.VIEW_SCENARIO, {}, summary="view", depends_on=-1)])
    result = ground_router_decision(decision, registered_ops=frozenset({"view_scenario"}))
    assert result.grounded_operations == []


def test_a_step_failing_grounding_does_not_affect_other_valid_steps():
    decision = RouterDecision(
        operations=[
            _op(OperationKind.RUN_AGENTS, {"source_ref": "demo"}),  # not registered
            _op(OperationKind.VIEW_SCENARIO, {"mode": "recommended"}, summary="show recommended"),
        ]
    )
    result = ground_router_decision(decision, registered_ops=frozenset({"view_scenario"}))
    assert len(result.grounded_operations) == 1
    assert result.grounded_operations[0].op == OperationKind.VIEW_SCENARIO
    assert len(result.issues) == 1
    assert result.issues[0].step_index == 0


# ---------------- verify_step_summary / find_wrong_upload_id_mentions ----------------


def test_find_wrong_upload_id_mentions_is_empty_when_only_the_real_id_is_named():
    assert find_wrong_upload_id_mentions(f"propose a schema for {UPLOAD_A}", {UPLOAD_A}) == []


def test_find_wrong_upload_id_mentions_is_case_insensitive():
    assert find_wrong_upload_id_mentions(f"propose {UPLOAD_A.upper()}", {UPLOAD_A}) == []


def test_find_wrong_upload_id_mentions_flags_a_different_id():
    assert find_wrong_upload_id_mentions(f"propose {UPLOAD_B}", {UPLOAD_A}) == [UPLOAD_B]


def test_verify_step_summary_passes_for_ingest_propose_naming_its_own_upload_id():
    step = _op(OperationKind.INGEST_PROPOSE, {"upload_id": UPLOAD_A}, summary=f"Propose a schema for upload {UPLOAD_A}.")
    assert verify_step_summary(step) == []


def test_verify_step_summary_flags_a_different_upload_id_in_the_summary():
    step = _op(OperationKind.INGEST_PROPOSE, {"upload_id": UPLOAD_A}, summary=f"Propose a schema for upload {UPLOAD_B}.")
    problems = verify_step_summary(step)
    assert problems
    assert UPLOAD_B in problems[0]


def test_verify_step_summary_recognizes_an_upload_shaped_source_ref_too():
    """run_deterministic has no `upload_id` field, but its `source_ref`
    can itself be one -- checked by SHAPE, not field name."""
    step = _op(OperationKind.RUN_DETERMINISTIC, {"source_ref": UPLOAD_A}, summary=f"Run the plan for {UPLOAD_A}.")
    assert verify_step_summary(step) == []


def test_verify_step_summary_is_wired_into_ground_router_decision():
    decision = RouterDecision(
        operations=[_op(OperationKind.INGEST_PROPOSE, {"upload_id": UPLOAD_A}, summary=f"Propose a schema for {UPLOAD_B}.")]
    )
    result = ground_router_decision(decision, registered_ops=frozenset({"ingest_propose"}))
    assert result.grounded_operations == []
    assert "summary mentions upload id" in result.issues[0].message


# ---------------- route_message: the LLM dispatch + retry loop ----------------


class _QueuedFakeCrew:
    queue: list = []
    instantiations: int = 0

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.tasks = tasks
        type(self).instantiations += 1

    def kickoff(self):
        for task in self.tasks:
            task.output = SimpleNamespace(raw=_QueuedFakeCrew.queue.pop(0))
        return None


@pytest.fixture(autouse=True)
def fake_crew(monkeypatch):
    _QueuedFakeCrew.queue = []
    _QueuedFakeCrew.instantiations = 0
    monkeypatch.setattr(router_module, "Crew", _QueuedFakeCrew)
    return _QueuedFakeCrew


def _decision_json(**overrides) -> str:
    base = {
        "operations": [
            {"op": "view_scenario", "params": {"mode": "recommended"}, "summary": "Show the recommended view", "depends_on": None}
        ],
        "clarify": None,
    }
    base.update(overrides)
    return json.dumps(base)


def test_route_message_happy_path_returns_a_grounded_result():
    _QueuedFakeCrew.queue = [_decision_json()]
    result = route_message("show me what needs patching now", registered_ops=frozenset({"view_scenario"}))
    assert result.clean
    assert result.grounded_operations[0].op == OperationKind.VIEW_SCENARIO
    assert _QueuedFakeCrew.instantiations == 1


def test_route_message_retries_on_unparseable_output_then_succeeds():
    _QueuedFakeCrew.queue = ["not json at all", _decision_json()]
    result = route_message("show me what needs patching now", registered_ops=frozenset({"view_scenario"}))
    assert result.clean
    assert _QueuedFakeCrew.instantiations == 2


def test_route_message_raises_after_max_attempts_of_unparseable_output():
    _QueuedFakeCrew.queue = ["not json", "still not json"]
    with pytest.raises(RouterDecisionError) as excinfo:
        route_message("anything", registered_ops=frozenset({"view_scenario"}), max_attempts=2)
    assert isinstance(excinfo.value.__cause__, AgentOutputParseError)
    assert _QueuedFakeCrew.instantiations == 2


def test_route_message_does_not_retry_on_a_grounding_failure():
    """An ungrounded step is a reportable outcome, not a retry trigger --
    one dispatch, one result, even though the step itself gets dropped."""
    _QueuedFakeCrew.queue = [
        json.dumps({"operations": [{"op": "run_agents", "params": {"source_ref": "demo"}, "summary": "run agents", "depends_on": None}], "clarify": None})
    ]
    result = route_message("explain why this is contested", registered_ops=frozenset({"view_scenario"}))
    assert result.grounded_operations == []
    assert len(result.issues) == 1
    assert _QueuedFakeCrew.instantiations == 1


def test_route_message_surfaces_a_clarify_only_decision():
    _QueuedFakeCrew.queue = [json.dumps({"operations": [], "clarify": "Which uploaded file is the asset inventory?"})]
    result = route_message("go", registered_ops=frozenset({"view_scenario"}))
    assert result.clean
    assert result.grounded_operations == []
    assert result.clarify == "Which uploaded file is the asset inventory?"


def test_ground_router_decision_carries_clarify_through_even_when_steps_exist():
    decision = RouterDecision(
        operations=[_op(OperationKind.VIEW_SCENARIO, {"mode": "recommended"}, summary="show it")],
        clarify="Also, did you want the selection view instead?",
    )
    result = ground_router_decision(decision, registered_ops=frozenset({"view_scenario"}))
    assert result.clarify == "Also, did you want the selection view instead?"
    assert len(result.grounded_operations) == 1


def test_build_router_agent_has_a_max_execution_time():
    from rhinosecure.agents.limits import MAX_AGENT_EXECUTION_SECONDS
    from rhinosecure.agents.router import build_router_agent

    agent = build_router_agent()
    assert agent.max_execution_time == MAX_AGENT_EXECUTION_SECONDS
    assert agent.tools == []


def test_build_router_task_embeds_the_message_and_available_ops():
    from rhinosecure.agents.router import build_router_agent, build_router_task

    agent = build_router_agent()
    task = build_router_task("only three patches fit this window", [], ["constraint_submit", "view_scenario"], agent)
    assert "only three patches fit this window" in task.description
    assert "constraint_submit" in task.description
    assert "ingest_confirm" not in task.description.lower().replace("_", "")
