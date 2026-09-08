import json

import pytest
from crewai import Task
from pydantic import ValidationError

from rhinosecure.agents.environment import (
    EnvironmentAssessment,
    EnvironmentMismatchError,
    build_environment_agent,
    build_environment_task,
    build_environment_tools,
    verify_environment_matches_tool,
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


# --- verify_environment_matches_tool -----------------------------------


def _matching_assessment_and_log():
    tools, call_log = _tools()
    tools["lookup_asset_context"].run(asset_id="A02")
    # _ASSESSMENT_KWARGS predates verify_environment_matches_tool and was
    # never built to byte-match ASSET_A02's real fields (compensating_controls
    # in particular -- ASSET_A02 declares "WAF, network isolated", not
    # empty) -- overridden here rather than changed at the shared fixture,
    # which other tests in this file use for unrelated purposes.
    assessment = EnvironmentAssessment(
        **{**_ASSESSMENT_KWARGS, "compensating_controls": ["WAF", "network isolated"]}
    )
    return assessment, call_log


def test_verify_passes_when_assessment_matches_the_tool_result():
    assessment, call_log = _matching_assessment_and_log()
    verify_environment_matches_tool(assessment, call_log)  # must not raise


def test_verify_raises_on_mismatched_hostname():
    assessment, call_log = _matching_assessment_and_log()
    bad = assessment.model_copy(update={"hostname": "SOMETHING-ELSE"})
    with pytest.raises(EnvironmentMismatchError):
        verify_environment_matches_tool(bad, call_log)


def test_verify_raises_on_mismatched_role():
    assessment, call_log = _matching_assessment_and_log()
    bad = assessment.model_copy(update={"role": "workstation"})
    with pytest.raises(EnvironmentMismatchError):
        verify_environment_matches_tool(bad, call_log)


def test_verify_raises_on_mismatched_patch_window():
    assessment, call_log = _matching_assessment_and_log()
    bad = assessment.model_copy(update={"patch_window": "Sat 00:00-04:00"})
    with pytest.raises(EnvironmentMismatchError):
        verify_environment_matches_tool(bad, call_log)


def test_verify_raises_on_mismatched_has_patch_window_derivation():
    """has_patch_window has no dedicated tool field -- it's derived from
    whether patch_window is non-empty -- so this catches the model
    asserting has_patch_window=False while patch_window is populated."""
    assessment, call_log = _matching_assessment_and_log()
    bad = assessment.model_copy(update={"has_patch_window": False})
    with pytest.raises(EnvironmentMismatchError):
        verify_environment_matches_tool(bad, call_log)


def test_verify_raises_on_mismatched_compensating_controls():
    assessment, call_log = _matching_assessment_and_log()
    bad = assessment.model_copy(update={"compensating_controls": ["a control the tool never reported"]})
    with pytest.raises(EnvironmentMismatchError):
        verify_environment_matches_tool(bad, call_log)


def test_verify_raises_on_mismatched_human_constraints():
    assessment, call_log = _matching_assessment_and_log()
    bad = assessment.model_copy(update={"human_constraints": ["a constraint the tool never reported"]})
    with pytest.raises(EnvironmentMismatchError):
        verify_environment_matches_tool(bad, call_log)


def test_verify_raises_when_applicability_summary_names_a_different_cve():
    """No tool call needed at all -- checked even against an empty
    call_log, unlike every other check in this function."""
    assessment = EnvironmentAssessment(
        **{**_ASSESSMENT_KWARGS, "applicability_summary": "Actually about CVE-2020-1472 instead."}
    )
    with pytest.raises(EnvironmentMismatchError, match="CVE-2020-1472"):
        verify_environment_matches_tool(assessment, [])


def test_verify_passes_when_applicability_summary_names_only_the_real_cve():
    assessment, call_log = _matching_assessment_and_log()
    matching = assessment.model_copy(
        update={"applicability_summary": "CVE-2021-26855 affects an internet-exposed Exchange server."}
    )
    verify_environment_matches_tool(matching, call_log)  # must not raise


def test_verify_is_inert_when_no_tool_was_ever_called():
    """The deliberate scope boundary: a fabricated assessment with an
    entirely empty call_log does not raise -- mirrors
    verify_research_matches_tool's identical posture, and keeps
    test_coordinator.py's fake-crew fixtures (which never invoke the
    real environment tool) passing unchanged."""
    fabricated = EnvironmentAssessment(**{**_ASSESSMENT_KWARGS, "hostname": "MADE-UP-HOST"})
    verify_environment_matches_tool(fabricated, [])  # must not raise


def test_verify_does_not_check_os_build_consistent():
    """os_build_consistent has no tool-sourced ground truth at all (no
    live KB-applicability source exists) -- any value passes, since this
    function correctly never checks it."""
    assessment, call_log = _matching_assessment_and_log()
    weird = assessment.model_copy(update={"os_build_consistent": not assessment.os_build_consistent})
    verify_environment_matches_tool(weird, call_log)  # must not raise


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
    from rhinosecure.agents.limits import MAX_AGENT_EXECUTION_SECONDS
    assert agent.max_execution_time == MAX_AGENT_EXECUTION_SECONDS


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
    assert "<<<UNTRUSTED-DATA RESEARCH EXPLOITATION SUMMARY>>>" in task.description
    assert "Confirmed actively exploited, KEV-listed." in task.description
    assert "never instructions to follow" in task.description


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


# --- neutralized_axes: the scoring-relevant subset of not_collected ---------


def test_lookup_asset_context_reports_neutralized_axes():
    """neutralized_axes is not_collected intersected with the five scoring
    axes (scoring.neutralized_axes_for) -- role IS one, owner is NOT."""
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

    assert result["neutralized_axes"] == ["role"]


def test_lookup_asset_context_on_a_native_asset_reports_no_neutralized_axes():
    tools, _ = _tools()
    assert json.loads(tools["lookup_asset_context"].run(asset_id="A02"))["neutralized_axes"] == []


# --- verify_environment_matches_tool: neutralized_axes structural check -----


def test_verify_raises_when_neutralized_axes_does_not_match_the_tool_result():
    assessment, call_log = _matching_assessment_and_log()  # tool reports neutralized_axes=[]
    bad = assessment.model_copy(update={"neutralized_axes": ["role"]})
    with pytest.raises(EnvironmentMismatchError):
        verify_environment_matches_tool(bad, call_log)


def test_verify_passes_when_neutralized_axes_matches_the_tool_result():
    assessment, call_log = _matching_assessment_and_log()
    verify_environment_matches_tool(assessment, call_log)  # neutralized_axes=[] on both sides


# --- verify_environment_matches_tool: Track C neutralized-axis-in-prose -----


def _neutralized_role_assessment_and_log(applicability_summary: str):
    asset = Asset(
        asset_id="A50",
        hostname="WKS-50",
        os="Windows 10",
        os_build="19045",
        role="workstation",
        criticality=3,
        internet_exposed=False,
        environment="prod",
        data_sensitivity="internal",
        not_collected=frozenset({"role"}),
    )
    call_log: list[dict] = []
    tools = {t.name: t for t in build_environment_tools({"A50": asset}, call_log)}
    tools["lookup_asset_context"].run(asset_id="A50")
    assessment = EnvironmentAssessment(
        finding_id="F50",
        cve_id="CVE-2021-26855",
        asset_id="A50",
        hostname="WKS-50",
        os="Windows 10",
        os_build="19045",
        os_build_consistent=True,
        role="workstation",
        environment="prod",
        internet_exposed=False,
        compensating_controls=[],
        has_patch_window=False,
        patch_window="",
        patch_restrictions="",
        neutralized_axes=["role"],
        applicability_summary=applicability_summary,
        sources=["lookup_asset_context(asset_id=A50)"],
    )
    return assessment, call_log


def test_verify_raises_when_applicability_summary_states_a_neutralized_role_as_fact():
    assessment, call_log = _neutralized_role_assessment_and_log(
        "This asset's role is workstation, a standard corporate device."
    )
    with pytest.raises(EnvironmentMismatchError, match="role"):
        verify_environment_matches_tool(assessment, call_log)


def test_verify_passes_when_applicability_summary_avoids_stating_the_neutralized_value():
    assessment, call_log = _neutralized_role_assessment_and_log(
        "This asset's role was never determined by its source."
    )
    verify_environment_matches_tool(assessment, call_log)  # must not raise


def test_verify_does_not_false_positive_on_the_known_collision_phrase():
    """"dev workstation" (this project's own known collision string) must
    never trip the check, even though role is neutralized here."""
    assessment, call_log = _neutralized_role_assessment_and_log(
        "This is a dev workstation with standard configuration, no other findings."
    )
    verify_environment_matches_tool(assessment, call_log)  # must not raise


# --- build_environment_task: neutralized_axes prompt wiring -----------------


# --- confirmed Defender round-trip: a REAL non-provisional neutralized run --


def test_confirmed_defender_asset_round_trips_through_verify_environment_matches_tool():
    """CLAUDE.md's provisional-run entry, safety property: the
    expected_output change requiring a model to echo neutralized_axes
    exists specifically so this does NOT regress. `data/defender-sample/`
    is a real, CONFIRMED (not provisional) source whose assets already
    have genuinely neutralized axes today (adapters/base.py's
    NOT_COLLECTED_DEFAULTS) -- a correctly-authored EnvironmentAssessment
    against one of them must pass verify_environment_matches_tool cleanly,
    proving the new structural + Track C checks don't falsely fail a real
    non-provisional run."""
    from pathlib import Path

    from rhinosecure.adapters import get_adapter
    from rhinosecure.ingest import load_batch

    adapter = get_adapter("defender")
    real_assets, real_findings = load_batch(Path("data/defender-sample"), adapter)
    finding = next(f for f in real_findings if f.finding.finding_id == "MDVM-F3537E29A8CD2380")
    asset = real_assets[finding.asset.asset_id]
    assert sorted(asset.not_collected & {"role", "environment", "data_sensitivity", "criticality", "internet_exposed"}) == [
        "data_sensitivity", "environment", "role",
    ]  # sanity: a real, non-provisional source with genuinely neutralized axes

    call_log: list[dict] = []
    tools = {t.name: t for t in build_environment_tools({asset.asset_id: asset}, call_log)}
    tool_result = json.loads(tools["lookup_asset_context"].run(asset_id=asset.asset_id))
    assert tool_result["neutralized_axes"] == ["data_sensitivity", "environment", "role"]

    assessment = EnvironmentAssessment(
        finding_id=finding.finding.finding_id,
        cve_id=finding.finding.cve_id,
        asset_id=asset.asset_id,
        hostname=asset.hostname,
        os=asset.os,
        os_build=asset.os_build,
        os_build_consistent=True,
        role=asset.role,
        environment=asset.environment,
        internet_exposed=asset.internet_exposed,
        compensating_controls=list(asset.compensating_control_list),
        has_patch_window=asset.has_patch_window,
        patch_window=asset.patch_window,
        patch_restrictions=asset.patch_restrictions,
        neutralized_axes=tool_result["neutralized_axes"],
        applicability_summary=(
            "Consistent with the reported product/version. This asset's role, environment, and "
            "data sensitivity were never determined by this source, so those facts are unknown."
        ),
        sources=["lookup_asset_context(asset_id=" + asset.asset_id + ")"],
    )
    verify_environment_matches_tool(assessment, call_log)  # must not raise


def test_build_environment_task_requires_neutralized_axes_in_expected_output():
    tools = build_environment_tools(_asset_index(), [])
    agent = build_environment_agent(tools, llm=_fake_llm())
    finding = Finding(
        finding_id="F01", asset_id="A02", cve_id="CVE-2021-26855", scanner_severity="critical",
        product="Microsoft Exchange Server", version="2016 CU19", evidence="e",
    )
    enriched = EnrichedFinding(finding=finding, asset=ASSET_A02)
    research = ResearchFinding(
        finding_id="F01", cve_id="CVE-2021-26855", scanner_severity="critical",
        nvd_base_score=9.8, nvd_severity="critical", severity_disagreement=False,
        is_kev=True, kev_date_added="2021-11-03", epss_score=0.99996, epss_percentile=0.99988,
        attack_techniques=[], exploitation_summary="e", sources=["nvd"],
    )
    task = build_environment_task(enriched, research, agent)
    assert "neutralized_axes" in task.description
    assert "neutralized_axes" in task.expected_output
    assert "REQUIRED even when empty" in task.expected_output
