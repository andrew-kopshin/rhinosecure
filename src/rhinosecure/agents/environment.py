"""Environment Analysis agent (CLAUDE.md Section 5): maps an enriched CVE
onto the Windows fleet -- OS-build applicability, internet exposure,
compensating controls, and patch constraints for the specific asset a
finding was detected on.

Consumes the Vulnerability Research agent's `ResearchFinding` as grounding
context (what the CVE is, how it's rated, whether it's KEV-listed) but its
own output is asset-side facts only -- Section 5's "applicability verdict"
half of the inter-agent payload, not a restatement of Research's threat
data. Like Research, this agent never estimates a risk score, bucket, or
remediation priority -- `scoring.py`'s `bucket_for` already owns the
compensating-control / patch-window logic deterministically (Section 3),
and this agent must not pre-empt or duplicate that decision in prose.

Unlike Research's tools, `lookup_asset_context` is a local lookup against
the already-ingested fleet inventory (`ingest.py`), not a live external
fetch -- there is no live "which KB applies to which OS build" source
named in CLAUDE.md Section 11 to call out to, so OS-build applicability is
this agent's own grounded judgment from the finding's product/version text
against the asset's os/os_build, not a database answer. One tool, not
four: OS build, exposure, controls, and patch constraints are all facets
of the same single Asset record, so splitting them into separate tool
calls the way Research's four independent external sources are split
would be artificial.

Because `os_build_consistent` is a judgment call rather than a fact any
tool returned, `EnvironmentAssessment` carries that distinction as a typed
field (`os_build_consistent_provenance`) rather than leaving it implicit
in prose -- CLAUDE.md's "Safety and guardrails" -> "Grounding
validation" item names exactly this failure mode ("restated model
knowledge dressed up as a citation"). `os_build_consistent_provenance`
only labels that one field as unsourced; it was never a check on any of
this agent's OTHER fields, and until `verify_environment_matches_tool`
below, nothing was: every other field here -- hostname, os, os_build,
role, environment, internet_exposed, compensating_controls,
has_patch_window, patch_window, patch_restrictions, human_constraints --
is exactly as verbatim-copyable from `lookup_asset_context`'s own logged
result as `agents/research.py`'s already-checked enrichment fields, and
was simply never checked. `verify_environment_matches_tool` closes that,
the identical shape `agents/risk.py`'s `verify_scoring_matches_tool` and
`agents/research.py`'s `verify_research_matches_tool` already close for
their agents -- wired into `Coordinator._dispatch_environment`, which
previously passed no `extra_validate` to `_resolve_output` at all.
`applicability_summary`/`sources` remain unchecked here: free prose with
no single tool field to diff against byte-for-byte, the same class
`exploitation_summary` is in research.py -- CLAUDE.md's own note on why a
narrower, different mechanism (entity-consistency checking, not
verbatim equality) is what applies to prose, not this function.

All LLM calls route through `rhinosecure.llm.get_llm` -- this module never
constructs a provider client itself (Trust boundary section).

`build_environment_task` does not set `output_pydantic` -- CrewAI's own
structured-output conversion caused an unbounded retry loop on a 24-finding
run (`agents/parsing.py`'s module docstring has the full trace). The task's
final raw text is parsed into `EnvironmentAssessment` by
`agents.parsing.parse_structured_output`, dispatched with a retry cap by
`agents/coordinator.py`.

**`human_constraints` is informational here, never merged into
`patch_window`/`compensating_controls`/`patch_restrictions`.** When
`build_environment_tools` is given a `memory.Memory`, `lookup_asset_context`
also returns whatever active constraints exist for this asset
(`agents/constraint_intake.py`'s overlay mechanism) as a *separate* field.
This agent's job is to surface them distinctly in
`applicability_summary` -- "declared patch_window: none; human
constraint: Sundays only" -- not to fold a human statement into the same
field a scanner-derived fact occupies, which is exactly what would make
the two indistinguishable for provenance. The three asset fields
(`patch_window`/`compensating_controls`/`patch_restrictions`) always
report what the asset record itself says, regardless of any constraint
on file; `agents/risk.py`'s `score_finding` tool is where a constraint's
effect actually reaches scoring, applied separately and reported
separately (`RiskRecommendation.constraints_applied`).
"""

from __future__ import annotations

import json
from typing import Any, Literal

from crewai import Agent, Task
from crewai.llms.base_llm import BaseLLM
from crewai.tools import BaseTool, tool
from pydantic import BaseModel

from rhinosecure.agents.entity_consistency import (
    find_neutralized_axis_assertions,
    find_wrong_cve_mentions,
)
from rhinosecure.agents.limits import MAX_AGENT_EXECUTION_SECONDS
from rhinosecure.agents.prompt_safety import UNTRUSTED_TEXT_NOTICE, fence
from rhinosecure.agents.research import ResearchFinding
from rhinosecure.llm import get_llm
from rhinosecure.memory import Memory
from rhinosecure.schema import Asset, EnrichedFinding
from rhinosecure.scoring import neutralized_axes_for

ROLE = "Environment Analysis"

# `os_build_consistent` is the only field here without a tool-sourced
# answer -- there is no live source to check it against, only the model's
# own reasoning from the finding's product/version text against the
# asset's os/os_build. This is a fixed single-value Literal, not a
# two-value enum, so the schema itself guarantees the marker can't be
# wrong: every EnvironmentAssessment that exists today has exactly one
# unsourced field, and this is it.
ModelJudgmentProvenance = Literal["model_judgment"]


class EnvironmentAssessment(BaseModel):
    """This agent's structured output for one finding -- Section 5's
    "applicability verdict" half of the inter-agent payload: OS/build
    compatibility, exposure, compensating controls, and patch constraints
    as declared on the asset record. No score, no bucket, no remediation
    timing; that belongs to Risk & Recommendation.

    Every field here is sourced from `lookup_asset_context` or the
    finding's own product/version text, except `os_build_consistent` --
    `os_build_consistent_provenance` marks that explicitly so a downstream
    consumer can tell sourced facts from model judgment without having to
    infer it from `applicability_summary`'s prose."""

    finding_id: str
    cve_id: str
    asset_id: str
    hostname: str
    os: str
    os_build: str
    os_build_consistent: bool
    os_build_consistent_provenance: ModelJudgmentProvenance = "model_judgment"
    role: str
    environment: str
    internet_exposed: bool
    compensating_controls: list[str]
    has_patch_window: bool
    patch_window: str
    patch_restrictions: str
    # Active memory.Constraint text for this asset, if any -- informational
    # only, never merged into the three fields above. See module docstring.
    human_constraints: list[str] = []
    # Which of criticality/environment/data_sensitivity/role/internet_exposed
    # this asset's SOURCE never determined at all (scoring.neutralized_axes_for)
    # -- copied verbatim from lookup_asset_context's own result, the same
    # copy-fidelity discipline every other tool-sourced field here already
    # gets. Defaults to [] so every existing fixture/test (never populating
    # this) is unaffected; expected_output below requires a model to echo it
    # explicitly rather than let the empty default silently satisfy the
    # schema -- omitting that requirement would make verify_environment_
    # matches_tool's new structural check below falsely fail a genuinely
    # neutralized-axis run whose model simply left the field at [].
    neutralized_axes: list[str] = []
    applicability_summary: str
    sources: list[str]


def build_environment_tools(
    asset_index: dict[str, Asset],
    call_log: list[dict[str, Any]],
    memory: Memory | None = None,
) -> list[BaseTool]:
    """Wrap a lookup against the already-ingested asset inventory as a
    CrewAI tool, logging every call the same way research.py's tools do.
    `memory` is optional and defaults to None -- omitting it (as every
    call site did before constraints existed) reproduces the exact prior
    behavior, `human_constraints` always empty."""

    @tool("lookup_asset_context")
    def lookup_asset_context(asset_id: str) -> str:
        """The asset record a finding was detected on: hostname, OS and
        build, role, criticality, environment, exposure, compensating
        controls, and patch window/restrictions, as declared in the fleet
        inventory -- plus, separately, any active human-supplied
        constraint on file for this asset (see human_constraints in the
        result), which is never merged into the asset's own fields. Any
        field named in the result's not_collected list holds a default
        rather than a value this asset's source supplied: a blank
        patch_window listed there means nobody recorded one, not that
        patching is unrestricted."""
        asset = asset_index.get(asset_id)
        if asset is None:
            result: dict[str, Any] = {"asset_id": asset_id, "found": False}
        else:
            human_constraints = memory.constraints_for_asset(asset_id) if memory is not None else []
            # NOT fenced here, deliberately: patch_window/patch_restrictions/
            # compensating_controls/human_constraints are the fields the task
            # below instructs the model to copy VERBATIM into its own
            # EnvironmentAssessment output (which flows on to Risk, export.py,
            # and the web UI) -- wrapping them in fence markers at the source
            # would leak "<<<UNTRUSTED-DATA...>>>" into human-facing plan
            # text. business_function/owner never reach EnvironmentAssessment
            # at all (no such field exists on it), so there is nothing to
            # leak, but leaving all six fields consistently unfenced here
            # avoids having to track which ones are "safe" as the schema
            # changes. UNTRUSTED_TEXT_NOTICE below covers this tool's return
            # value too ("or returned by any tool you call") -- the model is
            # told once, generally, not to treat any of it as a command.
            result = {
                "asset_id": asset.asset_id,
                "found": True,
                "hostname": asset.hostname,
                "os": asset.os,
                "os_build": asset.os_build,
                "role": asset.role,
                "business_function": asset.business_function,
                "criticality": asset.criticality,
                "internet_exposed": asset.internet_exposed,
                "environment": asset.environment,
                "data_sensitivity": asset.data_sensitivity,
                "patch_window": asset.patch_window,
                "patch_restrictions": asset.patch_restrictions,
                "compensating_controls": list(asset.compensating_control_list),
                "owner": asset.owner,
                "human_constraints": [c.constraint_text for c in human_constraints],
                # Field names above whose value is a documented default,
                # because this asset's source never collected them
                # (adapters/base.py). A blank patch_window listed here
                # means "unknown", not "none declared" -- the distinction
                # a Defender-sourced asset needs and a native one never
                # has (its set is always empty).
                "not_collected": sorted(asset.not_collected),
                # The scoring-relevant subset of not_collected --
                # scoring.neutralized_axes_for, the same set score_finding
                # itself drops/renormalizes around. Structurally identical
                # information to not_collected filtered to the five scoring
                # axes, surfaced separately so this agent (and the
                # verify_environment_matches_tool check below) doesn't have
                # to re-derive that intersection itself.
                "neutralized_axes": sorted(neutralized_axes_for(asset)),
            }
        call_log.append(
            {"tool": "lookup_asset_context", "args": {"asset_id": asset_id}, "result": result}
        )
        return json.dumps(result)

    return [lookup_asset_context]


def build_environment_agent(tools: list[BaseTool], llm: BaseLLM | None = None) -> Agent:
    """`llm` defaults to the trust-boundary seam's `get_llm()` -- pass one
    explicitly (as tests do, with a throwaway key) to avoid depending on
    real `.env` state at construction time."""
    return Agent(
        role=ROLE,
        goal=(
            "Map one finding's CVE onto the specific asset it was detected "
            "on, using only the lookup_asset_context tool: is the affected "
            "product/version consistent with this asset's OS and build, "
            "what is its internet exposure, what compensating controls and "
            "patch constraints are on file. Never estimate a risk score, "
            "bucket, or remediation priority -- that is a different agent's job."
        ),
        backstory=(
            "A systems inventory analyst who reports only what the asset "
            "record and the finding's own product/version text support, "
            "and never guesses at operational facts the inventory doesn't "
            "state."
        ),
        tools=tools,
        llm=llm or get_llm(),
        verbose=True,
        max_execution_time=MAX_AGENT_EXECUTION_SECONDS,
    )


def build_environment_task(
    enriched: EnrichedFinding, research: ResearchFinding, agent: Agent
) -> Task:
    finding = enriched.finding
    return Task(
        description=(
            f"{UNTRUSTED_TEXT_NOTICE}\n\n"
            f"Assess environment context for finding {finding.finding_id}: "
            f"CVE {finding.cve_id}, detected on asset {finding.asset_id}.\n"
            f"{fence('SCANNER-REPORTED PRODUCT/VERSION', f'{finding.product} {finding.version}')}\n\n"
            "Upstream research on this CVE, from the Vulnerability Research "
            f"agent: NVD severity {research.nvd_severity or 'unknown'} "
            f"(base score {research.nvd_base_score}), KEV-listed: "
            f"{research.is_kev}, EPSS score: {research.epss_score}.\n"
            f"{fence('RESEARCH EXPLOITATION SUMMARY', research.exploitation_summary)}\n\n"
            "Call lookup_asset_context for this finding's asset_id and use "
            "only what it returns, plus the finding's own product/version "
            "text above, to assess OS-build consistency, exposure, "
            "compensating controls, and patch constraints. Do not estimate "
            "a risk score or remediation bucket -- report the asset facts "
            "as declared. os_build_consistent has no tool to check it "
            "against -- it is your own judgment from the product/version "
            "text against the asset's os/os_build, so leave "
            "os_build_consistent_provenance at its default value "
            "\"model_judgment\"; every other field must come from "
            "lookup_asset_context or the finding text above. If the tool's "
            "human_constraints is non-empty, copy it verbatim into your own "
            "human_constraints field and mention it explicitly in "
            "applicability_summary as a fact distinct from the asset's own "
            "declared patch_window/compensating_controls/patch_restrictions "
            "-- never blend a human constraint into those three fields, "
            "which must always report only what the asset record itself "
            "declares. Copy the tool's neutralized_axes list verbatim into "
            "your own neutralized_axes field. For every axis named there "
            "(role, environment, data_sensitivity, criticality, "
            "internet_exposed), the value the tool returned for it is a "
            "PLACEHOLDER, not a fact this asset's source ever actually "
            "determined -- do not state that axis's specific value in "
            "applicability_summary at all, not even hedged (\"likely a "
            "workstation\" is still an assertion). Say instead that this "
            "asset's source never determined it, without repeating the "
            "placeholder value."
        ),
        expected_output=(
            "Return ONLY a single JSON object, with these keys directly at "
            'the top level -- not wrapped in any container key such as '
            '{"assessment": {...}} or {"result": {...}}, and no markdown '
            "code fences or prose before or after it: finding_id, cve_id, "
            "asset_id, hostname, os, os_build, os_build_consistent (bool), "
            'os_build_consistent_provenance (always the literal string '
            '"model_judgment"), role, environment, internet_exposed (bool), '
            "compensating_controls (a list of strings), has_patch_window "
            "(bool), patch_window, patch_restrictions, human_constraints "
            "(a list of strings, copied verbatim from the tool result -- "
            "empty list if the tool returned none), neutralized_axes (a "
            "list of strings, copied verbatim from the tool result's own "
            "neutralized_axes -- empty list if the tool returned none; "
            "REQUIRED even when empty, never omitted), applicability_summary "
            "(a short prose summary that never states the specific value of "
            "any axis named in neutralized_axes), and sources (a list of "
            "strings citing each source used)."
        ),
        agent=agent,
    )


class EnvironmentMismatchError(RuntimeError):
    """Raised when an EnvironmentAssessment's asset-sourced fields don't
    match what `lookup_asset_context` actually returned for that
    asset_id -- the identical gap CLAUDE.md's Safety and guardrails
    "Grounding validation" open item names, now closed for this agent
    the same way `agents/risk.py`'s `verify_scoring_matches_tool` and
    `agents/research.py`'s `verify_research_matches_tool` already close
    it for theirs."""


def verify_environment_matches_tool(
    assessment: EnvironmentAssessment, call_log: list[dict[str, Any]]
) -> None:
    """Raise EnvironmentMismatchError if `assessment` contradicts the
    actual result of the last `lookup_asset_context` call for its
    asset_id. Mirrors `agents/research.py`'s `verify_research_matches_
    tool` exactly: inert (does nothing) when no matching call exists in
    `call_log`, since this checks copy-fidelity ("the agent called the
    tool, then contradicted it"), not tool-skipping.

    `os_build_consistent`/`os_build_consistent_provenance` are
    deliberately excluded -- there is no live source to check
    `os_build_consistent` against at all (see module docstring).
    `applicability_summary`'s CVE-mention check (below) needs no tool
    call at all -- it only needs the CVE ID `assessment` itself already
    carries -- so it always runs, even against an empty `call_log`,
    unlike every other check here.

    Also runs `entity_consistency.find_neutralized_axis_assertions`
    against `applicability_summary` (Track C, CLAUDE.md's provisional-run
    entry) whenever `neutralized_axes` is non-empty -- catching a model
    that stated a neutralized axis's placeholder value as though it were
    an observed fact. This one DOES need the tool result (for the actual
    axis values in effect), so unlike the CVE check it runs after the
    `if not calls: return` early exit, alongside the other tool-sourced
    checks below."""
    # Checked first, and unconditionally: unlike the tool-result checks
    # below, this needs no matching lookup_asset_context call at all.
    wrong_cves = find_wrong_cve_mentions(assessment.applicability_summary, assessment.cve_id)
    if wrong_cves:
        raise EnvironmentMismatchError(
            f"{assessment.asset_id}: applicability_summary mentions {sorted(wrong_cves)}, a "
            "different CVE than this finding is about"
        )

    calls = [
        c["result"]
        for c in call_log
        if c["tool"] == "lookup_asset_context" and c["args"].get("asset_id") == assessment.asset_id
    ]
    if not calls:
        return
    tool_result = calls[-1]

    scalar_checks = (
        ("hostname", assessment.hostname, tool_result.get("hostname")),
        ("os", assessment.os, tool_result.get("os")),
        ("os_build", assessment.os_build, tool_result.get("os_build")),
        ("role", assessment.role, tool_result.get("role")),
        ("environment", assessment.environment, tool_result.get("environment")),
        ("internet_exposed", assessment.internet_exposed, tool_result.get("internet_exposed")),
        ("patch_window", assessment.patch_window, tool_result.get("patch_window")),
        ("patch_restrictions", assessment.patch_restrictions, tool_result.get("patch_restrictions")),
        # has_patch_window has no dedicated tool field -- it's the model's
        # own derivation from patch_window, so the expected value is
        # computed here rather than read from the result directly.
        ("has_patch_window", assessment.has_patch_window, bool(tool_result.get("patch_window"))),
        ("neutralized_axes", sorted(assessment.neutralized_axes), sorted(tool_result.get("neutralized_axes", []))),
    )
    for field_name, reported, actual in scalar_checks:
        if reported != actual:
            raise EnvironmentMismatchError(
                f"{assessment.asset_id}: {field_name}={reported!r} != tool result {actual!r}"
            )

    if list(assessment.compensating_controls) != list(tool_result.get("compensating_controls", [])):
        raise EnvironmentMismatchError(
            f"{assessment.asset_id}: compensating_controls does not match the tool's result verbatim"
        )
    if list(assessment.human_constraints) != list(tool_result.get("human_constraints", [])):
        raise EnvironmentMismatchError(
            f"{assessment.asset_id}: human_constraints does not match the tool's result verbatim"
        )

    neutralized = tool_result.get("neutralized_axes") or []
    if neutralized:
        axis_values = {
            "role": tool_result.get("role"),
            "environment": tool_result.get("environment"),
            "data_sensitivity": tool_result.get("data_sensitivity"),
            "criticality": tool_result.get("criticality"),
            "internet_exposed": tool_result.get("internet_exposed"),
        }
        violated = find_neutralized_axis_assertions(
            assessment.applicability_summary, neutralized, axis_values
        )
        if violated:
            raise EnvironmentMismatchError(
                f"{assessment.asset_id}: applicability_summary states a value for neutralized "
                f"axis/axes {sorted(violated)} as though it were an observed fact -- this "
                "source never determined it (see neutralized_axes)"
            )
