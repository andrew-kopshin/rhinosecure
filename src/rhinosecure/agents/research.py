"""Vulnerability Research agent (CLAUDE.md Section 5): NVD, KEV, EPSS, and
ATT&CK lookup and enrichment for one finding at a time.

Enrichment only. This agent never estimates a risk score, bucket, or
remediation priority -- `scoring.py` stays the sole, deterministic,
LLM-free owner of that (Section 8 rule 2; "Trust boundary" section). Its
tools are thin wrappers around the same `enrich/*.py` fetchers and
`SnapshotCache` that `cli.py`'s deterministic `run()` uses, so the agent's
evidence comes from the same trusted, cached sources ("Safety and
guardrails" -> Implemented -> Trusted-source-only enrichment) rather than
anything the model already "knows" or fetches on its own initiative.

All LLM calls route through `rhinosecure.llm.get_llm` -- this module never
constructs a provider client itself (Trust boundary section).
"""

from __future__ import annotations

import json
from typing import Any

from crewai import Agent, Task
from crewai.llms.base_llm import BaseLLM
from crewai.tools import BaseTool, tool
from pydantic import BaseModel

from rhinosecure.enrich.attack import load_index as load_attack_index
from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.enrich.epss import lookup as epss_lookup
from rhinosecure.enrich.kev import load_catalog as load_kev_catalog
from rhinosecure.enrich.nvd import lookup as nvd_lookup
from rhinosecure.llm import get_llm
from rhinosecure.schema import EnrichedFinding

ROLE = "Vulnerability Research"


class AttackTechniqueSummary(BaseModel):
    technique_id: str
    name: str
    confidence: str  # "confirmed" or "candidate" -- enrich/attack.py's two tiers


class ResearchFinding(BaseModel):
    """This agent's structured output for one finding -- Section 5's
    "structured payloads, not free conversation": CVE ID, severity,
    exploitation status, ATT&CK techniques. No score, no bucket, no
    remediation verdict; that belongs to Risk & Recommendation."""

    finding_id: str
    cve_id: str
    scanner_severity: str
    nvd_base_score: float | None = None
    nvd_severity: str | None = None
    severity_disagreement: bool = False
    is_kev: bool = False
    kev_date_added: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    attack_techniques: list[AttackTechniqueSummary] = []
    exploitation_summary: str
    sources: list[str]


def build_research_tools(
    cache: SnapshotCache, call_log: list[dict[str, Any]]
) -> list[BaseTool]:
    """Wrap the enrich/*.py fetchers as CrewAI tools bound to one shared
    `cache`. KEV and ATT&CK are bulk, single-fetch resources -- loaded once
    here, not once per tool call, same as `cli.py`'s `run()`. Every
    invocation is appended to `call_log` (tool name, args, result) so a
    caller can audit exactly what the agent looked up, independent of
    whatever CrewAI's own execution logging shows.
    """

    kev_catalog = load_kev_catalog(cache)
    attack_index = load_attack_index(cache)

    @tool("lookup_nvd")
    def lookup_nvd(cve_id: str) -> str:
        """Authoritative CVSS base score and severity for a CVE, from NVD.
        Fields are null if NVD has no CVSS record for this CVE yet."""
        cvss = nvd_lookup(cve_id, cache)
        entry = cache.read("nvd", cve_id)
        result = {
            "cve_id": cve_id,
            "base_score": cvss.base_score if cvss else None,
            "base_severity": cvss.base_severity if cvss else None,
            "vector_string": cvss.vector_string if cvss else None,
            "source": "nvd",
            "retrieved_at": entry.retrieved_at if entry else None,
        }
        call_log.append({"tool": "lookup_nvd", "args": {"cve_id": cve_id}, "result": result})
        return json.dumps(result)

    @tool("lookup_kev")
    def lookup_kev(cve_id: str) -> str:
        """Whether a CVE is on the CISA Known Exploited Vulnerabilities
        catalog -- confirmed real-world exploitation, not a prediction."""
        status = kev_catalog.status(cve_id)
        entry = cache.read("kev", None)
        result = {
            "cve_id": cve_id,
            "is_listed": status.is_listed,
            "date_added": status.date_added,
            "due_date": status.due_date,
            "source": "kev",
            "retrieved_at": entry.retrieved_at if entry else None,
        }
        call_log.append({"tool": "lookup_kev", "args": {"cve_id": cve_id}, "result": result})
        return json.dumps(result)

    @tool("lookup_epss")
    def lookup_epss(cve_id: str) -> str:
        """FIRST EPSS exploitation-probability score and percentile for a
        CVE -- a model's predicted likelihood, distinct from KEV's confirmed
        record. Fields are null if FIRST has no EPSS entry for this CVE."""
        score = epss_lookup(cve_id, cache)
        entry = cache.read("epss", cve_id)
        result = {
            "cve_id": cve_id,
            "score": score.score,
            "percentile": score.percentile,
            "score_date": score.score_date,
            "source": "epss",
            "retrieved_at": entry.retrieved_at if entry else None,
        }
        call_log.append({"tool": "lookup_epss", "args": {"cve_id": cve_id}, "result": result})
        return json.dumps(result)

    @tool("lookup_attack_techniques")
    def lookup_attack_techniques(cve_id: str, product: str = "", evidence: str = "") -> str:
        """MITRE ATT&CK techniques implicated by a CVE. Returns "confirmed"
        matches when the CVE is explicitly named in ATT&CK's own procedure-
        example documentation; otherwise semantically similar "candidate"
        techniques matched against `product`/`evidence` text. Never both
        tiers in one result -- pass the finding's product and evidence text
        so the candidate tier has something to match against."""
        matches = attack_index.lookup(cve_id, product, evidence)
        entry = cache.read("attack", "enterprise-windows")
        result = {
            "cve_id": cve_id,
            "techniques": [
                {
                    "technique_id": m.technique.technique_id,
                    "name": m.technique.name,
                    "confidence": m.confidence,
                    "reason": m.reason,
                }
                for m in matches
            ],
            "source": "attack",
            "retrieved_at": entry.retrieved_at if entry else None,
        }
        call_log.append(
            {
                "tool": "lookup_attack_techniques",
                "args": {"cve_id": cve_id, "product": product, "evidence": evidence},
                "result": result,
            }
        )
        return json.dumps(result)

    return [lookup_nvd, lookup_kev, lookup_epss, lookup_attack_techniques]


def build_research_agent(tools: list[BaseTool], llm: BaseLLM | None = None) -> Agent:
    """`llm` defaults to the trust-boundary seam's `get_llm()` -- pass one
    explicitly (as tests do, with a throwaway key) to avoid depending on
    real `.env` state at construction time."""
    return Agent(
        role=ROLE,
        goal=(
            "Enrich one finding's CVE with authoritative severity, confirmed "
            "and predicted exploitation status, and ATT&CK technique mapping, "
            "using only the lookup_nvd, lookup_kev, lookup_epss, and "
            "lookup_attack_techniques tools. Never estimate a risk score, "
            "bucket, or remediation priority -- that is a different agent's job."
        ),
        backstory=(
            "A threat intelligence analyst who reports only what the trusted "
            "sources say, with each fact's source and retrieval time attached, "
            "and never substitutes personal judgment of a CVE for the record."
        ),
        tools=tools,
        llm=llm or get_llm(),
        verbose=True,
    )


def build_research_task(enriched: EnrichedFinding, agent: Agent) -> Task:
    finding = enriched.finding
    return Task(
        description=(
            f"Research finding {finding.finding_id}: CVE {finding.cve_id} in "
            f"{finding.product} {finding.version} (scanner-reported severity: "
            f"{finding.scanner_severity}). Scanner evidence: {finding.evidence!r}.\n\n"
            "Call lookup_nvd, lookup_kev, lookup_epss, and "
            "lookup_attack_techniques for this CVE -- all four, every time, "
            "even if you expect an empty result -- and base your answer only "
            "on what they return, not on prior knowledge of this CVE. Do not "
            "estimate a risk score or remediation bucket."
        ),
        expected_output=(
            "A ResearchFinding: CVE ID, NVD's authoritative severity versus "
            "the scanner's (and whether they disagree), KEV status, EPSS "
            "score, matched ATT&CK techniques, a short exploitation-status "
            "summary, and the source+timestamp of every fact used."
        ),
        agent=agent,
        output_pydantic=ResearchFinding,
    )
