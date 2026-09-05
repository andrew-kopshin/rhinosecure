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

`build_research_task` does not set `output_pydantic` -- CrewAI's own
structured-output conversion caused an unbounded retry loop on a 24-finding
run (`agents/parsing.py`'s module docstring has the full trace). The task's
final raw text is parsed into `ResearchFinding` by
`agents.parsing.parse_structured_output`, dispatched with a retry cap by
`agents/coordinator.py`.

**`finding.evidence`/`product`/`version` are untrusted, scanner-controlled
free text** -- CLAUDE.md Safety and guardrails' prompt-injection open
item, and this agent is where that text first reaches a prompt.
`build_research_task` fences them (`agents/prompt_safety.py`) rather than
interpolating them raw.

**`verify_research_matches_tool` closes a real gap next to that one: this
agent's OWN enrichment fields were never checked against what its tools
actually returned**, unlike Risk's `verify_scoring_matches_tool`.
`is_kev`/`kev_due_date`/`epss_score`/`nvd_base_score`/`nvd_severity`/
`attack_techniques` are exactly the fields `agents/risk.py`'s
`merge_research_into_enriched` copies UNVERIFIED into the `EnrichedFinding`
that `scoring.score_finding()` treats as ground truth -- `is_kev` alone
forces at least the actionable bucket tier (Section 3), so a fabricated
value here, whether an ordinary hallucination or one induced by an
injected instruction in `finding.evidence`, would silently corrupt a real
risk_score/bucket with nothing catching it. `exploitation_summary` and
`sources` are free prose with no ground truth to check byte-for-byte --
those are handled by fencing, not verification, for that reason.

**This check is inert when a tool was never called for a CVE at all --
by design, not by oversight.** It verifies copy-fidelity ("the agent
called the tool, then contradicted it"), the same shape
`verify_scoring_matches_tool` already checks for Risk. It does not, and
structurally cannot, catch "the agent skipped tool use entirely and
invented a value" -- that is a different failure mode the task's own
explicit instruction ("all four, every time") already targets, and
CrewAI's native function-calling loop makes skipping a tool call far less
likely than free-form instruction-following would. This scoping is also
what keeps this check compatible with `test_coordinator.py`'s existing
fake-crew fixtures, which never invoke the real tools at all (there is
nothing to verify against there, and this function correctly does
nothing rather than failing every one of those tests).
"""

from __future__ import annotations

import json
import math
from typing import Any

from crewai import Agent, Task
from crewai.llms.base_llm import BaseLLM
from crewai.tools import BaseTool, tool
from pydantic import BaseModel

from rhinosecure.agents.prompt_safety import UNTRUSTED_TEXT_NOTICE, fence
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
    # Percentile-rank prevalence (Technique.prevalence in enrich/attack.py).
    # Needed downstream: scoring.py's attack_prevalence threat term is the
    # max prevalence among a finding's *confirmed* techniques (see
    # cli.py's _attach_threat_signals), and Risk & Recommendation
    # reconstructs that same input from this field rather than re-fetching
    # ATT&CK data itself -- see agents/risk.py.
    prevalence: float


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
    kev_due_date: str | None = None
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
                    "prevalence": m.technique.prevalence,
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
            f"{UNTRUSTED_TEXT_NOTICE}\n\n"
            f"Research finding {finding.finding_id}: CVE {finding.cve_id} "
            f"(scanner-reported severity: {finding.scanner_severity}).\n"
            f"{fence('SCANNER-REPORTED PRODUCT/VERSION', f'{finding.product} {finding.version}')}\n"
            f"{fence('SCANNER EVIDENCE', finding.evidence)}\n\n"
            "Call lookup_nvd, lookup_kev, lookup_epss, and "
            "lookup_attack_techniques for this CVE -- all four, every time, "
            "even if you expect an empty result -- and base your answer only "
            "on what they return, not on prior knowledge of this CVE. Do not "
            "estimate a risk score or remediation bucket."
        ),
        expected_output=(
            "Return ONLY a single JSON object, with these keys directly at the "
            "top level -- not wrapped in any container key such as "
            '{"finding": {...}} or {"result": {...}}, and no markdown code '
            "fences or prose before or after it: finding_id, cve_id, "
            "scanner_severity, nvd_base_score, nvd_severity, "
            "severity_disagreement (bool), is_kev (bool), kev_date_added, "
            "kev_due_date (CISA's remediation deadline for this CVE, from "
            "lookup_kev's own due_date field -- null if not KEV-listed or "
            "the catalog doesn't record one), epss_score, epss_percentile, "
            "attack_techniques (a list of "
            "objects, each with technique_id, name, confidence, prevalence), "
            "exploitation_summary (a short prose summary), and sources (a "
            "list of strings citing each source and its retrieval time)."
        ),
        agent=agent,
    )


class ResearchMismatchError(RuntimeError):
    """Raised when a ResearchFinding's is_kev/kev_due_date/epss_score/
    nvd_base_score/nvd_severity/attack_techniques don't match what this
    CVE's actual lookup_kev/lookup_epss/lookup_nvd/lookup_attack_techniques
    tool calls returned -- exactly the failure mode CLAUDE.md's grounding-
    validation open item describes, extended one hop upstream of
    `agents/risk.py`'s `ScoringMismatchError` to the fields that reach
    scoring.py's deterministic input in the first place
    (`merge_research_into_enriched`). See module docstring for what this
    checks and, deliberately, does not."""


def verify_research_matches_tool(research: ResearchFinding, call_log: list[dict[str, Any]]) -> None:
    """Raise ResearchMismatchError if `research` contradicts the actual
    result of the last matching lookup_kev/lookup_epss/lookup_nvd/
    lookup_attack_techniques call for its cve_id. Only checks the fields
    `agents/risk.py`'s `merge_research_into_enriched` reads into the
    scoring path -- `kev_date_added`, `epss_percentile`, and
    `severity_disagreement` are reported but never merged into scoring, so
    there is nothing at stake in verifying them here.

    A tool this CVE was never called for is skipped, not treated as a
    failure -- see module docstring's "inert when a tool was never called"
    note for why that's a deliberate scope boundary, not a gap in this
    function."""
    calls_for = {c["tool"]: c["result"] for c in call_log if c["args"].get("cve_id") == research.cve_id}

    kev = calls_for.get("lookup_kev")
    if kev is not None:
        if research.is_kev != kev["is_listed"]:
            raise ResearchMismatchError(
                f"{research.cve_id}: is_kev={research.is_kev} != tool result {kev['is_listed']!r}"
            )
        if research.kev_due_date != kev["due_date"]:
            raise ResearchMismatchError(
                f"{research.cve_id}: kev_due_date={research.kev_due_date!r} != "
                f"tool result {kev['due_date']!r}"
            )

    epss = calls_for.get("lookup_epss")
    if epss is not None and not _floats_match(research.epss_score, epss["score"]):
        raise ResearchMismatchError(
            f"{research.cve_id}: epss_score={research.epss_score} != tool result {epss['score']!r}"
        )

    nvd = calls_for.get("lookup_nvd")
    if nvd is not None:
        if not _floats_match(research.nvd_base_score, nvd["base_score"]):
            raise ResearchMismatchError(
                f"{research.cve_id}: nvd_base_score={research.nvd_base_score} != "
                f"tool result {nvd['base_score']!r}"
            )
        if research.nvd_severity != nvd["base_severity"]:
            raise ResearchMismatchError(
                f"{research.cve_id}: nvd_severity={research.nvd_severity!r} != "
                f"tool result {nvd['base_severity']!r}"
            )

    attack = calls_for.get("lookup_attack_techniques")
    if attack is not None:
        reported = research.attack_techniques
        actual = attack["techniques"]
        mismatch = len(reported) != len(actual) or any(
            r.technique_id != a["technique_id"]
            or r.name != a["name"]
            or r.confidence != a["confidence"]
            or not _floats_match(r.prevalence, a["prevalence"])
            for r, a in zip(reported, actual)
        )
        if mismatch:
            raise ResearchMismatchError(
                f"{research.cve_id}: attack_techniques does not match the tool's techniques verbatim"
            )


def _floats_match(a: float | None, b: float | None) -> bool:
    if a is None or b is None:
        return a is b
    return math.isclose(a, b, rel_tol=1e-9)
