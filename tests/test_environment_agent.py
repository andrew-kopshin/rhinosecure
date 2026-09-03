import json

import pytest
from crewai import Task
from pydantic import ValidationError

from rhinosecure.agents.environment import (
    EnvironmentAssessment,
    build_environment_agent,
    build_environment_task,
    build_environment_tools,
)
from rhinosecure.agents.research import ResearchFinding
from rhinosecure.llm import LLMConfig, get_llm
from rhinosecure.memory import Memory
from rhinosecure.schema import Asset, EnrichedFinding, Finding

_ASSESSMENT_KWARGS = dict(
    finding_id="F01",
    cve_id="CVE-2021-26855",
    asset_id="A02",
    hostname="EXCH02",
    os="Windows Server 2016",
    os_build="14393",
    os_build_consistent=True,
    role="exchange",
    environment="prod",
    internet_exposed=True,
    compensating_controls=[],
    has_patch_window=True,
    patch_window="Sun 02:00-06:00",
    patch_restrictions="",
    applicability_summary="...",
    sources=["lookup_asset_context(asset_id=A02)"],
)

ASSET_A02 = Asset(
    asset_id="A02",
    hostname="EXCH02",
    os="Windows Server 2016",
    os_build="14393",
    role="exchange",
    business_function="Email",
    criticality=5,
    internet_exposed=True,
    environment="prod",
    data_sensitivity="confidential",
    patch_window="Sun 02:00-06:00",
    patch_restrictions="",
    compensating_controls="WAF, network isolated",
    owner="msg-team",
)


def _asset_index():
    return {"A02": ASSET_A02}


def _tools():
    call_log: list[dict] = []
    tools = build_environment_tools(_asset_index(), call_log)
    return {t.name: t for t in tools}, call_log


def test_returns_the_lookup_asset_context_tool():
    tools, _ = _tools()
    assert set(tools) == {"lookup_asset_context"}


def test_lookup_asset_context_returns_full_record_and_logs_the_call():
    tools, call_log = _tools()

    result = json.loads(tools["lookup_asset_context"].run(asset_id="A02"))

    assert result["found"] is True
    assert result["hostname"] == "EXCH02"
    assert result["os"] == "Windows Server 2016"
    assert result["os_build"] == "14393"
    assert result["role"] == "exchange"
    assert result["internet_exposed"] is True
    assert result["environment"] == "prod"
    assert result["patch_window"] == "Sun 02:00-06:00"
    assert result["compensating_controls"] == ["WAF", "network isolated"]

    assert len(call_log) == 1
    assert call_log[0]["tool"] == "lookup_asset_context"
    assert call_log[0]["args"] == {"asset_id": "A02"}
    assert call_log[0]["result"] == result


def test_lookup_asset_context_unknown_asset_id_reports_not_found():
    tools, call_log = _tools()

    result = json.loads(tools["lookup_asset_context"].run(asset_id="A99"))

    assert result == {"asset_id": "A99", "found": False}
    assert call_log[0]["result"] == {"asset_id": "A99", "found": False}


# --- human_constraints: the overlay is visible, never merged ----------------


def test_lookup_asset_context_without_memory_reports_no_human_constraints():
    """Every call site before constraints existed omits memory -- must
    reproduce the exact prior behavior, just with the new field present
    and empty."""
    tools, _ = _tools()
    result = json.loads(tools["lookup_asset_context"].run(asset_id="A02"))
    assert result["human_constraints"] == []


def test_lookup_asset_context_with_memory_but_no_constraints_on_file(tmp_path):
    memory = Memory(tmp_path / "mem.db")
    call_log: list[dict] = []
    tools = {t.name: t for t in build_environment_tools(_asset_index(), call_log, memory)}

    result = json.loads(tools["lookup_asset_context"].run(asset_id="A02"))
    assert result["human_constraints"] == []


def test_lookup_asset_context_surfaces_active_constraints_separately_from_asset_fields(tmp_path):
    memory = Memory(tmp_path / "mem.db")
    memory.add_constraint(
        "A02", "the mail server only reboots on Sundays",
        effect_kind="patch_window", effect_value="Sun 00:00-06:00",
    )
    call_log: list[dict] = []
    tools = {t.name: t for t in build_environment_tools(_asset_index(), call_log, memory)}

    result = json.loads(tools["lookup_asset_context"].run(asset_id="A02"))

    assert result["human_constraints"] == ["the mail server only reboots on Sundays"]
    # The asset's own declared fields are untouched by the constraint --
    # ASSET_A02's real patch_window, not the constraint's effect_value.
    assert result["patch_window"] == "Sun 02:00-06:00"


def test_lookup_asset_context_excludes_deactivated_constraints(tmp_path):
    memory = Memory(tmp_path / "mem.db")
    constraint_id = memory.add_constraint("A02", "retracted statement")
    memory.deactivate_constraint(constraint_id)
    call_log: list[dict] = []
    tools = {t.name: t for t in build_environment_tools(_asset_index(), call_log, memory)}

    result = json.loads(tools["lookup_asset_context"].run(asset_id="A02"))
    assert result["human_constraints"] == []


# --- os_build_consistent provenance marker -----------------------------------


def test_os_build_consistent_defaults_to_model_judgment_provenance():
    assessment = EnvironmentAssessment(**_ASSESSMENT_KWARGS)
    assert assessment.os_build_consistent_provenance == "model_judgment"


def test_os_build_consistent_provenance_rejects_any_other_value():
    with pytest.raises(ValidationError):
        EnvironmentAssessment(**{**_ASSESSMENT_KWARGS, "os_build_consistent_provenance": "sourced"})


# --- agent/task construction (no network, no LLM call) ----------------------


def _fake_llm():
    return get_llm(LLMConfig(model="claude-sonnet-5", api_key="sk-test-key"))


def test_build_environment_agent_has_role_and_the_tool():
    tools = build_environment_tools(_asset_index(), [])
    agent = build_environment_agent(tools, llm=_fake_llm())

    assert agent.role == "Environment Analysis"
    assert {t.name for t in agent.tools} == {"lookup_asset_context"}


def test_build_environment_task_embeds_finding_and_upstream_research_context():
    tools = build_environment_tools(_asset_index(), [])
    agent = build_environment_agent(tools, llm=_fake_llm())

    finding = Finding(
        finding_id="F01",
        asset_id="A02",
        cve_id="CVE-2021-26855",
        scanner_severity="critical",
        product="Microsoft Exchange Server",
        version="2016 CU19",
        evidence="OWA endpoint vulnerable to pre-auth SSRF chain (ProxyLogon)",
    )
    enriched = EnrichedFinding(finding=finding, asset=ASSET_A02)
    research = ResearchFinding(
        finding_id="F01",
        cve_id="CVE-2021-26855",
        scanner_severity="critical",
        nvd_base_score=9.8,
        nvd_severity="critical",
        severity_disagreement=False,
        is_kev=True,
        kev_date_added="2021-11-03",
        epss_score=0.99996,
        epss_percentile=0.99988,
        attack_techniques=[],
        exploitation_summary="Confirmed actively exploited, KEV-listed.",
        sources=["nvd", "kev", "epss", "attack"],
    )

    task = build_environment_task(enriched, research, agent)

    assert isinstance(task, Task)
    # No output_pydantic: CrewAI's own conversion caused an unbounded retry
    # loop on a malformed response (PROGRESS.md) -- parsing is now this
    # project's own code (agents/parsing.py), not CrewAI's.
    assert task.output_pydantic is None
    assert task.agent is agent
    assert "F01" in task.description
    assert "CVE-2021-26855" in task.description
    assert "A02" in task.description
    assert "KEV-listed: True" in task.description
    assert "Confirmed actively exploited, KEV-listed." in task.description
    assert "os_build_consistent_provenance" in task.description
    assert "os_build_consistent_provenance" in task.expected_output
    assert "not wrapped in any container key" in task.expected_output
    assert "human_constraints" in task.description
    assert "human_constraints" in task.expected_output
    assert "never blend a human constraint" in task.description


# --- not_collected: fields the asset's source never supplied ----------------


def test_lookup_asset_context_reports_not_collected_fields():
    """A blank patch_window on a Defender-sourced asset means "nobody
    recorded one", not "patching is unrestricted" (adapters/base.py).
    Environment Analysis has to be able to tell the two apart, so the
    tool result carries the marker alongside the values."""
    from rhinosecure.schema import Asset

    defender_asset = Asset(
        asset_id="1a" * 20,
        hostname="dc01.corp.example.com",
        os="Windows Server 2019",
        os_build="17763",
        role="file",
        criticality=3,
        internet_exposed=False,
        environment="prod",
        data_sensitivity="internal",
        not_collected=frozenset({"role", "patch_window", "compensating_controls", "owner"}),
    )
    call_log: list[dict] = []
    tools = {t.name: t for t in build_environment_tools({defender_asset.asset_id: defender_asset}, call_log)}

    result = json.loads(tools["lookup_asset_context"].run(asset_id=defender_asset.asset_id))

    assert result["patch_window"] == ""  # value unchanged -- only the claim differs
    assert result["not_collected"] == ["compensating_controls", "owner", "patch_window", "role"]
    assert call_log[0]["result"]["not_collected"] == result["not_collected"]


def test_lookup_asset_context_on_a_native_asset_reports_no_gaps():
    """A native assets.csv row declares every field, so the marker is
    always empty and the tool's output is unchanged from before it existed."""
    tools, _ = _tools()
    assert json.loads(tools["lookup_asset_context"].run(asset_id="A02"))["not_collected"] == []
