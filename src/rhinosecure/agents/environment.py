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
in prose -- CLAUDE.md's "Safety and guardrails" -> Open -> "Grounding
validation" item names exactly this failure mode ("restated model
knowledge dressed up as a citation"). This doesn't build the validator
that item still asks for -- nothing yet checks a rationale's citations
against the evidence actually passed in -- it only makes the one field
that needs that check machine-identifiable instead of requiring a human
to reread the prose to notice it isn't sourced.

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

from rhinosecure.agents.research import ResearchFinding
from rhinosecure.llm import get_llm
from rhinosecure.memory import Memory
from rhinosecure.schema import Asset, EnrichedFinding

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
        result), which is never merged into the asset's own fields."""
        asset = asset_index.get(asset_id)
        if asset is None:
            result: dict[str, Any] = {"asset_id": asset_id, "found": False}
        else:
            human_constraints = memory.constraints_for_asset(asset_id) if memory is not None else []
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
    )


def build_environment_task(
    enriched: EnrichedFinding, research: ResearchFinding, agent: Agent
) -> Task:
    finding = enriched.finding
    return Task(
        description=(
            f"Assess environment context for finding {finding.finding_id}: "
            f"CVE {finding.cve_id} in {finding.product} {finding.version}, "
            f"detected on asset {finding.asset_id}.\n\n"
            "Upstream research on this CVE, from the Vulnerability Research "
            f"agent: NVD severity {research.nvd_severity or 'unknown'} "
            f"(base score {research.nvd_base_score}), KEV-listed: "
            f"{research.is_kev}, EPSS score: {research.epss_score}. "
            f"Exploitation summary: {research.exploitation_summary}\n\n"
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
            "declares."
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
            "empty list if the tool returned none), applicability_summary "
            "(a short prose summary), and sources (a list of strings "
            "citing each source used)."
        ),
        agent=agent,
    )
