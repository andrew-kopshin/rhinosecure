"""Risk & Recommendation agent (CLAUDE.md Section 5): scores, ranks, and
writes cited rationale for one finding, using `ResearchFinding` and
`EnvironmentAssessment` as its evidence.

The one hard rule for this agent: it never computes a risk score or bucket
itself. `scoring.py` is the sole, deterministic, LLM-free owner of that
arithmetic (Section 8 rule 2) -- this agent's only access to a number is
through the `score_finding` tool, which calls `scoring.score_finding`
directly and hands back its `risk_score`/`bucket`/`rationale` verbatim.
The agent's own job is narrative: weave Research's threat evidence and
Environment's asset-context evidence around that deterministic result and
cite where each fact came from. `verify_scoring_matches_tool` below is the
part that makes "must not compute either itself" a checked property
instead of a prompt instruction hoping the model behaves -- see CLAUDE.md
"Safety and guardrails" -> Open -> "Grounding validation", which this
extends past Environment Analysis's `os_build_consistent_provenance`
marker into an actual pass/fail check.

**Why the score_finding tool reconstructs EnrichedFinding from the
original ground-truth Finding/Asset, not from EnvironmentAssessment's
JSON.** EnvironmentAssessment already carries every asset fact
scoring.py's ImpactInputs would need (role, environment, exposure,
compensating controls, patch window), but it arrived by round-tripping
those facts through an LLM once already, and one of its fields
(`os_build_consistent`) is explicitly *not* sourced -- see
`environment.py`'s `os_build_consistent_provenance`. Feeding a
deterministic scoring path data that passed through an LLM hop, when the
real ingested `Finding`/`Asset` objects are already sitting in the same
Python process untouched by any model, is a needless source of fragility
(schema drift, transcription slips) for zero benefit. So `score_finding`
merges the *ground-truth* `EnrichedFinding` with only the enrichment
signals `ResearchFinding` actually adds (is_kev/epss/nvd/attack) --
exactly mirroring `cli.py`'s `_attach_threat_signals`, just sourcing
those signals from Research's already-computed output instead of a fresh
live fetch. `EnvironmentAssessment` is still real evidence this agent
consumes -- its facts are embedded in the task prompt so the narrative
can cite exposure, controls, and patch constraints -- it just isn't the
channel scoring inputs travel through.

All LLM calls route through `rhinosecure.llm.get_llm` -- this module never
constructs a provider client itself (Trust boundary section).
"""

from __future__ import annotations

import json
import math
from typing import Any

from crewai import Agent, Task
from crewai.llms.base_llm import BaseLLM
from crewai.tools import BaseTool, tool
from pydantic import BaseModel

from rhinosecure.agents.environment import EnvironmentAssessment
from rhinosecure.agents.research import ResearchFinding
from rhinosecure.llm import get_llm
from rhinosecure.schema import AttackTechniqueRef, EnrichedFinding
from rhinosecure.scoring import score_finding

ROLE = "Risk & Recommendation"


class RiskRecommendation(BaseModel):
    """This agent's structured output for one finding. `risk_score`,
    `bucket`, and `scoring_rationale` must be copied verbatim from the
    score_finding tool's result -- `verify_scoring_matches_tool` checks
    that after the fact. `narrative` is the only field this agent
    actually authors: a synthesis of Research's threat evidence,
    Environment's asset-context evidence, and the deterministic
    rationale, in plain language, citing sources."""

    finding_id: str
    cve_id: str
    asset_id: str
    hostname: str
    risk_score: float
    bucket: str
    scoring_rationale: list[str]
    narrative: str
    sources: list[str]


class ScoringMismatchError(RuntimeError):
    """Raised when a RiskRecommendation's risk_score/bucket doesn't match
    what the score_finding tool actually computed for that finding --
    exactly the failure mode CLAUDE.md's grounding-validation open item
    describes: model output presented as sourced when it wasn't."""


def _merge_research_into_enriched(
    enriched: EnrichedFinding, research: ResearchFinding
) -> EnrichedFinding:
    """The scoring input: ground-truth Finding/Asset, with Research's
    enrichment signals layered on -- the same shape cli.py's
    `_attach_threat_signals` produces, sourced from `research` instead of
    a live fetch. See the module docstring for why ground truth, not
    EnvironmentAssessment, is what gets merged here."""
    confirmed_prevalence = [
        t.prevalence for t in research.attack_techniques if t.confidence == "confirmed"
    ]
    return enriched.model_copy(
        update={
            "is_kev": research.is_kev,
            "epss": research.epss_score,
            "nvd_base_score": research.nvd_base_score,
            "nvd_severity": research.nvd_severity,
            "attack_techniques": tuple(
                AttackTechniqueRef(technique_id=t.technique_id, name=t.name, confidence=t.confidence)
                for t in research.attack_techniques
            ),
            "attack_prevalence": max(confirmed_prevalence, default=None),
        }
    )


def build_risk_tools(
    enriched_by_id: dict[str, EnrichedFinding],
    research_by_id: dict[str, ResearchFinding],
    call_log: list[dict[str, Any]],
) -> list[BaseTool]:
    """One tool: `score_finding`, wrapping `scoring.score_finding` -- the
    only source of a risk score or bucket this agent may use."""

    @tool("score_finding")
    def score_finding_tool(finding_id: str) -> str:
        """Compute this finding's deterministic risk score and remediation
        bucket. This is the ONLY way to get either -- never estimate them
        yourself. Returns risk_score, bucket, and a fully cited rationale
        (severity source, exposure, EPSS/KEV, ATT&CK, impact factors,
        compensating controls, patch window) to use verbatim."""
        enriched = _merge_research_into_enriched(
            enriched_by_id[finding_id], research_by_id[finding_id]
        )
        scored = score_finding(enriched)
        result = {
            "finding_id": scored.finding_id,
            "cve_id": scored.cve_id,
            "asset_id": scored.asset_id,
            "hostname": scored.hostname,
            "risk_score": scored.risk_score,
            "bucket": scored.bucket.value,
            "rationale": list(scored.rationale),
        }
        call_log.append(
            {"tool": "score_finding", "args": {"finding_id": finding_id}, "result": result}
        )
        return json.dumps(result)

    return [score_finding_tool]


def build_risk_agent(tools: list[BaseTool], llm: BaseLLM | None = None) -> Agent:
    """`llm` defaults to the trust-boundary seam's `get_llm()` -- pass one
    explicitly (as tests do, with a throwaway key) to avoid depending on
    real `.env` state at construction time."""
    return Agent(
        role=ROLE,
        goal=(
            "Explain one finding's remediation priority by calling "
            "score_finding and citing its result exactly, alongside "
            "Research's threat evidence and Environment's asset-context "
            "evidence. Never estimate a risk score or bucket yourself -- "
            "score_finding is the only source of either."
        ),
        backstory=(
            "A risk analyst who writes the plain-language case for a "
            "verdict a deterministic model already reached, never a "
            "verdict of their own -- and always shows which fact came "
            "from which source."
        ),
        tools=tools,
        llm=llm or get_llm(),
        verbose=True,
    )


def build_risk_task(
    enriched: EnrichedFinding,
    research: ResearchFinding,
    environment: EnvironmentAssessment,
    agent: Agent,
) -> Task:
    finding = enriched.finding
    return Task(
        description=(
            f"Write the risk recommendation for finding {finding.finding_id}: "
            f"CVE {finding.cve_id} on {environment.hostname} ({environment.asset_id}).\n\n"
            "From Vulnerability Research: NVD severity "
            f"{research.nvd_severity or 'unknown'} (base score {research.nvd_base_score}), "
            f"KEV-listed: {research.is_kev}, EPSS: {research.epss_score}. "
            f"{research.exploitation_summary}\n\n"
            "From Environment Analysis: OS "
            f"{environment.os} (build {environment.os_build}), role {environment.role}, "
            f"environment {environment.environment}, internet_exposed: "
            f"{environment.internet_exposed}, compensating_controls: "
            f"{environment.compensating_controls}, has_patch_window: "
            f"{environment.has_patch_window} ({environment.patch_window!r}). "
            f"{environment.applicability_summary}\n\n"
            f"Call score_finding with finding_id={finding.finding_id!r} exactly once "
            "and copy its risk_score, bucket, and rationale into your output "
            "verbatim -- do not adjust, round, or reinterpret them. Then write a "
            "short narrative in plain language explaining the verdict, drawing on "
            "the Research and Environment evidence above plus the tool's "
            "rationale. Do not introduce any fact not present in the evidence "
            "given or returned by the tool."
        ),
        expected_output=(
            "A RiskRecommendation: risk_score and bucket copied exactly from "
            "score_finding, its rationale list copied verbatim, and a narrative "
            "citing Research, Environment, and the scoring rationale."
        ),
        agent=agent,
        output_pydantic=RiskRecommendation,
    )


def verify_scoring_matches_tool(
    recommendation: RiskRecommendation, call_log: list[dict[str, Any]]
) -> None:
    """Raise ScoringMismatchError if `recommendation` didn't just copy the
    score_finding tool's actual result for its finding_id. This is a real
    check, not a hope: an agent could in principle round a number, swap a
    bucket, or paraphrase the rationale in its final structured-output
    pass, and nothing about output_pydantic prevents that on its own.
    """
    calls = [
        c
        for c in call_log
        if c["tool"] == "score_finding" and c["args"]["finding_id"] == recommendation.finding_id
    ]
    if not calls:
        raise ScoringMismatchError(
            f"{recommendation.finding_id}: no score_finding call recorded -- "
            "risk_score/bucket cannot be verified against anything"
        )
    tool_result = calls[-1]["result"]
    if not math.isclose(recommendation.risk_score, tool_result["risk_score"], rel_tol=1e-9):
        raise ScoringMismatchError(
            f"{recommendation.finding_id}: recommendation.risk_score="
            f"{recommendation.risk_score} != tool result {tool_result['risk_score']}"
        )
    if recommendation.bucket != tool_result["bucket"]:
        raise ScoringMismatchError(
            f"{recommendation.finding_id}: recommendation.bucket={recommendation.bucket!r} "
            f"!= tool result {tool_result['bucket']!r}"
        )
    if list(recommendation.scoring_rationale) != list(tool_result["rationale"]):
        raise ScoringMismatchError(
            f"{recommendation.finding_id}: scoring_rationale does not match the "
            "tool's rationale verbatim"
        )
