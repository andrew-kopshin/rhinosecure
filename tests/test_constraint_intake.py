import json

import pytest
from crewai import Task

from rhinosecure.agents.constraint_intake import (
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
