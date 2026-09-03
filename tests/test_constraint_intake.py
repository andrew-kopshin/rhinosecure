import json

import pytest
from crewai import Task

from rhinosecure.agents.constraint_intake import (
    ConstraintInterpretation,
    ConstraintKind,
    apply_constraints,
    build_constraint_agent,
    build_constraint_task,
    build_constraint_tools,
)
from rhinosecure.llm import LLMConfig, get_llm
from rhinosecure.memory import Constraint
from rhinosecure.schema import Asset, EnrichedFinding, Finding
from rhinosecure.scoring import ScoredFinding, score_finding

ASSET = Asset(
    asset_id="A12",
    hostname="PAY01",
    os="Windows Server 2019",
    os_build="17763",
    role="file",
    business_function="Payroll processing",
    criticality=4,
    internet_exposed=False,
    environment="prod",
    data_sensitivity="regulated",
    patch_window="",
    patch_restrictions="",
    compensating_controls="",
    owner="finance-it",
)


def _constraint(effect_kind: str | None, effect_value: str | None, *, id_: int = 1) -> Constraint:
    return Constraint(
        id=id_,
        asset_id="A12",
        constraint_text="fake constraint text",
        created_at="2026-09-04T00:00:00+00:00",
        active=True,
        effect_kind=effect_kind,
        effect_value=effect_value,
    )


# --- apply_constraints (pure, no LLM) ----------------------------------------


def test_no_constraints_leaves_the_asset_unchanged():
    result = apply_constraints(ASSET, [])
    assert result == ASSET


def test_never_mutates_the_input_asset():
    apply_constraints(ASSET, [_constraint("patch_window", "Sun 00:00-06:00")])
    assert ASSET.patch_window == ""  # untouched


def test_patch_window_constraint_overrides_patch_window_only():
    result = apply_constraints(ASSET, [_constraint("patch_window", "Sun 00:00-06:00")])
    assert result.patch_window == "Sun 00:00-06:00"
    assert result.patch_restrictions == ASSET.patch_restrictions
    assert result.compensating_controls == ASSET.compensating_controls


def test_patch_restriction_constraint_overrides_patch_restrictions_only():
    result = apply_constraints(ASSET, [_constraint("patch_restriction", "no reboots during business hours")])
    assert result.patch_restrictions == "no reboots during business hours"
    assert result.patch_window == ASSET.patch_window


def test_compensating_control_constraint_is_additive_on_an_empty_asset():
    result = apply_constraints(ASSET, [_constraint("compensating_control", "WAF rule enabled")])
    assert result.compensating_control_list == ("WAF rule enabled",)


def test_compensating_control_constraint_is_additive_alongside_existing_controls():
    asset = ASSET.model_copy(update={"compensating_controls": "network isolated"})
    result = apply_constraints(asset, [_constraint("compensating_control", "WAF rule enabled")])
    assert result.compensating_control_list == ("network isolated", "WAF rule enabled")


def test_multiple_different_effect_kinds_all_apply_together():
    result = apply_constraints(
        ASSET,
        [
            _constraint("patch_window", "Sun 00:00-06:00", id_=1),
            _constraint("compensating_control", "WAF rule enabled", id_=2),
        ],
    )
    assert result.patch_window == "Sun 00:00-06:00"
    assert result.compensating_control_list == ("WAF rule enabled",)


def test_later_same_kind_constraint_wins_over_an_earlier_one():
    """constraints_for_asset returns oldest-first; a later statement about
    the same fact supersedes an earlier one, the same as a human
    correcting themselves."""
    result = apply_constraints(
        ASSET,
        [
            _constraint("patch_window", "Sun 00:00-06:00", id_=1),
            _constraint("patch_window", "Sat 22:00-Sun 06:00", id_=2),
        ],
    )
    assert result.patch_window == "Sat 22:00-Sun 06:00"


def test_a_constraint_with_no_effect_value_is_skipped():
    """An un-interpreted constraint (effect_kind/effect_value both None,
    memory.py's own default) must not blow up or apply a null override."""
    result = apply_constraints(ASSET, [_constraint(None, None)])
    assert result == ASSET


# --- build_constraint_tools ---------------------------------------------


ASSET_2 = Asset(
    asset_id="A09",
    hostname="WKS-FIN12",
    os="Windows 10",
    os_build="19045",
    role="workstation",
    business_function="Finance analyst workstation",
    criticality=2,
    internet_exposed=False,
    environment="prod",
    data_sensitivity="confidential",
    patch_window="",
    patch_restrictions="",
    compensating_controls="",
    owner="finance-it",
)

ASSET_INDEX = {"A12": ASSET, "A09": ASSET_2}


def _scored(finding_id: str, asset: Asset, *, scanner_severity: str = "high") -> ScoredFinding:
    finding = Finding(
        finding_id=finding_id, asset_id=asset.asset_id, cve_id="CVE-2021-26855",
        scanner_severity=scanner_severity, product="X", version="1.0", evidence="e",
    )
    return score_finding(EnrichedFinding(finding=finding, asset=asset))


def _tools():
    call_log: list[dict] = []
    findings_by_asset = {"A12": [_scored("F15", ASSET)], "A09": [_scored("F07", ASSET_2), _scored("F14", ASSET_2)]}
    tools = build_constraint_tools(ASSET_INDEX, findings_by_asset, call_log)
    return {t.name: t for t in tools}, call_log


def test_returns_exactly_search_assets_and_list_findings_for_asset():
    tools, _ = _tools()
    assert set(tools) == {"search_assets", "list_findings_for_asset"}


def test_search_assets_matches_business_function_case_insensitively():
    tools, call_log = _tools()
    result = json.loads(tools["search_assets"].run(query="PAYROLL"))
    assert [m["asset_id"] for m in result["matches"]] == ["A12"]
    assert call_log[0] == {"tool": "search_assets", "args": {"query": "PAYROLL"}, "result": result}


def test_search_assets_matches_hostname_and_role_and_owner():
    tools, _ = _tools()
    assert [m["asset_id"] for m in json.loads(tools["search_assets"].run(query="wks-fin12"))["matches"]] == ["A09"]
    assert [m["asset_id"] for m in json.loads(tools["search_assets"].run(query="workstation"))["matches"]] == ["A09"]
    assert [m["asset_id"] for m in json.loads(tools["search_assets"].run(query="finance-it"))["matches"]] == [
        "A12", "A09",
    ]


def test_search_assets_returns_no_matches_for_an_unrelated_query():
    tools, _ = _tools()
    assert json.loads(tools["search_assets"].run(query="exchange"))["matches"] == []


def test_list_findings_for_asset_returns_bucket_and_risk_score_context():
    tools, call_log = _tools()
    result = json.loads(tools["list_findings_for_asset"].run(asset_id="A09"))
    assert result["asset_id"] == "A09"
    assert {f["finding_id"] for f in result["findings"]} == {"F07", "F14"}
    assert all("bucket" in f and "risk_score" in f for f in result["findings"])
    assert call_log[-1]["tool"] == "list_findings_for_asset"


def test_list_findings_for_asset_returns_empty_list_for_an_asset_with_none():
    tools, _ = _tools()
    result = json.loads(tools["list_findings_for_asset"].run(asset_id="A99"))
    assert result["findings"] == []


# --- agent / task construction (no network, no LLM call) --------------------


def _fake_llm():
    return get_llm(LLMConfig(model="claude-sonnet-5", api_key="sk-test-key"))


def test_build_constraint_agent_has_role_and_both_tools():
    tools, _ = _tools()
    agent = build_constraint_agent(list(tools.values()), llm=_fake_llm())
    assert agent.role == "Constraint Interpreter"
    assert {t.name for t in agent.tools} == {"search_assets", "list_findings_for_asset"}


def test_build_constraint_task_embeds_the_constraint_text_and_effect_menu():
    tools, _ = _tools()
    agent = build_constraint_agent(list(tools.values()), llm=_fake_llm())
    task = build_constraint_task("the payroll server only reboots on Sundays", agent)

    assert isinstance(task, Task)
    assert task.output_pydantic is None  # own parsing, not CrewAI's converter
    assert "the payroll server only reboots on Sundays" in task.description
    assert "patch_window" in task.description
    assert "compensating_control" in task.description
    assert "patch_restriction" in task.description
    assert "do not guess" in task.description.lower()
    assert "not wrapped in any container key" in task.expected_output
    assert "affected_finding_ids" in task.expected_output


def test_build_constraint_task_describes_the_capacity_shape_with_an_example():
    tools, _ = _tools()
    agent = build_constraint_agent(list(tools.values()), llm=_fake_llm())
    task = build_constraint_task("only five patches fit this window", agent)

    assert "capacity" in task.description.lower()
    assert "only five patches fit this window" in task.description
    assert "patch_limit" in task.description


def test_build_constraint_task_expected_output_lists_the_new_capacity_fields():
    tools, _ = _tools()
    agent = build_constraint_agent(list(tools.values()), llm=_fake_llm())
    task = build_constraint_task("only five patches fit this window", agent)

    assert "constraint_kind" in task.expected_output
    assert "patch_limit" in task.expected_output


# --- ConstraintInterpretation schema (three-way shape) -----------------------


def test_capacity_interpretation_validates_with_only_patch_limit_populated():
    interpretation = ConstraintInterpretation(
        constraint_kind=ConstraintKind.CAPACITY.value,
        asset_id=None,
        effect_kind=None,
        effect_value=None,
        patch_limit=5,
        affected_finding_ids=[],
        rationale="fleet-wide capacity statement: five patches fit this window",
        sources=[],
    )
    assert interpretation.constraint_kind == "capacity"
    assert interpretation.patch_limit == 5
    assert interpretation.asset_id is None
    assert interpretation.affected_finding_ids == []


def test_asset_interpretation_still_validates_with_the_existing_fields_populated():
    interpretation = ConstraintInterpretation(
        constraint_kind=ConstraintKind.ASSET.value,
        asset_id="A12",
        effect_kind="patch_window",
        effect_value="Sun 00:00-06:00",
        patch_limit=None,
        affected_finding_ids=["F15"],
        rationale="matched A12 via business_function",
        sources=["search_assets", "list_findings_for_asset"],
    )
    assert interpretation.constraint_kind == "asset"
    assert interpretation.asset_id == "A12"
    assert interpretation.effect_kind == "patch_window"
    assert interpretation.patch_limit is None


def test_refusal_interpretation_still_validates_with_everything_null_or_empty():
    interpretation = ConstraintInterpretation(
        constraint_kind=None,
        asset_id=None,
        effect_kind=None,
        effect_value=None,
        patch_limit=None,
        affected_finding_ids=[],
        rationale="statement is neither asset-scoped nor a recognizable capacity limit",
        sources=[],
    )
    assert interpretation.constraint_kind is None
    assert interpretation.asset_id is None
    assert interpretation.patch_limit is None
    assert interpretation.affected_finding_ids == []


# --- not_collected: a source that never supplied these fields ----------------
#
# A Microsoft Defender export supplies no role, business_function, owner,
# patch_window, patch_restrictions, or compensating_controls (adapters/
# defender.py). Those fields hold documented defaults and are named in
# Asset.not_collected. Two consequences this section pins down: the
# Interpreter must not resolve an asset off a placeholder, and a
# constraint that supplies a field must clear its marker.

DEFENDER_ASSET = Asset(
    asset_id="1a" * 20,
    hostname="dc01.corp.example.com",
    os="Windows Server 2019",
    os_build="17763",
    role="file",  # defaulted by OS class -- Defender exports no role
    business_function="",
    criticality=3,
    internet_exposed=False,
    environment="prod",
    data_sensitivity="internal",
    not_collected=frozenset(
        {
            "role", "business_function", "environment", "data_sensitivity",
            "patch_window", "patch_restrictions", "compensating_controls", "owner",
        }
    ),
)


def _defender_tools():
    call_log: list[dict] = []
    index = {DEFENDER_ASSET.asset_id: DEFENDER_ASSET, "A09": ASSET_2}
    tools = build_constraint_tools(index, {}, call_log)
    return {t.name: t for t in tools}, call_log


def test_search_assets_never_matches_a_not_collected_field():
    """DEFENDER_ASSET's role is the defaulted "file", not a fact. A human
    asking about "the file server" must not resolve to it -- that would
    land their constraint on a domain controller."""
    tools, _ = _defender_tools()
    matches = json.loads(tools["search_assets"].run(query="file"))["matches"]
    assert [m["asset_id"] for m in matches] == []
    # ASSET_2's role IS collected, so role matching still works normally.
    assert [m["asset_id"] for m in json.loads(tools["search_assets"].run(query="workstation"))["matches"]] == ["A09"]


def test_search_assets_still_matches_hostname_and_asset_id_on_a_defender_asset():
    """Identity fields are always collected, so a Defender asset stays
    resolvable -- refusing to match placeholders must not make the whole
    fleet unreachable."""
    tools, _ = _defender_tools()
    by_host = json.loads(tools["search_assets"].run(query="dc01"))["matches"]
    assert [m["asset_id"] for m in by_host] == [DEFENDER_ASSET.asset_id]
    by_id = json.loads(tools["search_assets"].run(query="1a1a1a"))["matches"]
    assert [m["asset_id"] for m in by_id] == [DEFENDER_ASSET.asset_id]


def test_search_assets_reports_not_collected_so_the_model_can_see_the_gap():
    tools, _ = _defender_tools()
    (match,) = json.loads(tools["search_assets"].run(query="dc01"))["matches"]
    assert "role" in match["not_collected"] and "patch_window" in match["not_collected"]
    assert match["role"] == "file"  # the placeholder is still shown, just labelled
    native = json.loads(tools["search_assets"].run(query="wks-fin12"))["matches"][0]
    assert native["not_collected"] == []


def test_a_supplied_field_stops_being_not_collected():
    """Once a human states the window, it is known -- continuing to flag
    it as a data gap would be false, and the scoring rationale and CLI
    gap note both read this set."""
    result = apply_constraints(DEFENDER_ASSET, [_defender_constraint("patch_window", "Sun 02:00-06:00")])
    assert result.patch_window == "Sun 02:00-06:00"
    assert result.has_patch_window
    assert "patch_window" not in result.not_collected


def test_untouched_fields_keep_their_marker():
    """One constraint must not launder an asset's other gaps."""
    result = apply_constraints(DEFENDER_ASSET, [_defender_constraint("patch_window", "Sun 02:00-06:00")])
    assert result.not_collected == DEFENDER_ASSET.not_collected - {"patch_window"}
    assert {"role", "compensating_controls", "environment"} <= result.not_collected


def test_each_effect_kind_clears_its_own_field():
    for effect_kind, field_name in (
        ("patch_window", "patch_window"),
        ("patch_restriction", "patch_restrictions"),
        ("compensating_control", "compensating_controls"),
    ):
        result = apply_constraints(DEFENDER_ASSET, [_defender_constraint(effect_kind, "a real value")])
        assert field_name not in result.not_collected, effect_kind
        assert result.not_collected == DEFENDER_ASSET.not_collected - {field_name}


def test_a_constraint_with_no_effect_value_clears_nothing():
    result = apply_constraints(DEFENDER_ASSET, [_defender_constraint("patch_window", None)])
    assert result.not_collected == DEFENDER_ASSET.not_collected


def test_a_native_asset_is_unaffected_by_the_clearing_logic():
    result = apply_constraints(ASSET, [_constraint("patch_window", "Sun 02:00-06:00")])
    assert result.not_collected == frozenset()
    assert result.patch_window == "Sun 02:00-06:00"


def _defender_constraint(effect_kind, effect_value, *, id_=1) -> Constraint:
    return Constraint(
        id=id_,
        asset_id=DEFENDER_ASSET.asset_id,
        constraint_text="fake constraint text",
        created_at="2026-09-04T00:00:00+00:00",
        active=True,
        effect_kind=effect_kind,
        effect_value=effect_value,
    )


def test_task_prompt_tells_the_interpreter_not_to_resolve_on_a_placeholder():
    agent = build_constraint_agent([], llm=get_llm(LLMConfig(api_key="test-key-not-used")))
    description = build_constraint_task("the file server reboots on Sundays", agent).description
    assert "not_collected" in description
    assert "placeholder" in description
