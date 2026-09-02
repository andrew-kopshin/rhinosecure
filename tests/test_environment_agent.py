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
    assert task.output_pydantic is EnvironmentAssessment
    assert task.agent is agent
    assert "F01" in task.description
    assert "CVE-2021-26855" in task.description
    assert "A02" in task.description
    assert "KEV-listed: True" in task.description
    assert "Confirmed actively exploited, KEV-listed." in task.description
    assert "os_build_consistent_provenance" in task.description
    assert "os_build_consistent_provenance" in task.expected_output
