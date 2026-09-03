"""Constraint Interpreter agent (CLAUDE.md Section 5's "Human submits a
constraint" edge, Section 7's memory layer): turns free-form human
constraint text into a structured, asset-scoped effect plus the
finding_ids it affects. This is "constraint intake" -- the one piece of
Slice 4's Coordinator-side wiring every prior commit in this repo named
as unbuilt (`agents/coordinator.py`'s and `tot.py`'s module docstrings,
CLAUDE.md Section 7's own "Deliberately not built" note).

**Scope: asset-scoped operational constraints only, matching CLAUDE.md
Section 7's worked example exactly** ("the payroll server only reboots
on Sundays") -- not Section 10's "only five patches fit this window",
which is a fleet-wide capacity constraint with no single asset to
resolve to and no representation in `memory.py`'s `constraints` table
(`asset_id NOT NULL`). The Interpreter is explicitly instructed to
refuse (`asset_id=None`) rather than guess when a constraint isn't
asset-scoped or doesn't describe one of the three effect kinds below --
see `build_constraint_task`. A fleet-wide capacity constraint would need
its own table and its own re-ranking mechanism; nothing here attempts
that.

**Three effect kinds, matching the three asset-level facts Environment
Analysis and scoring.py already read** (`Asset.patch_window`/
`.patch_restrictions`/`.compensating_control_list`) -- the same
bounded-menu-over-open-generation choice `tot.Strategy` already makes,
for the same reason: a fixed vocabulary is what makes the effect
mechanically applicable (`apply_constraints` below) rather than another
piece of prose an agent has to re-interpret every time it's read back.

- `patch_window` -- establishes or replaces the asset's effective patch
  window
- `compensating_control` -- adds a control (additive: existing controls
  are kept, not replaced)
- `patch_restriction` -- establishes or replaces the asset's effective
  patch restrictions

**Overlay, not mutation -- the actual mechanism.** `apply_constraints`
takes an `Asset` and a list of `memory.Constraint` rows and returns a
NEW `Asset` (`model_copy`) with active constraints' effects folded in;
it never mutates its input, and nothing it touches is written back to
`assets.csv` or to the `Asset` objects `ingest.join_findings` produced
and every other part of the pipeline still holds. The overlay is
recomputed fresh, at read time, every time `apply_constraints` is
called -- from the base asset plus whatever `memory.constraints_for_asset`
currently returns -- so a deactivated constraint (`Memory
.deactivate_constraint`) simply stops applying on the next call, with
nothing to undo.

**Provenance stays distinguishable because the overlay is surfaced
separately, not merged into scoring.py's own vocabulary.**
`scoring.py`'s rationale has no notion of "who declared this
patch_window" -- Section 8 rule 2 keeps it that way; a deterministic,
LLM-free module doesn't need one more concept added to it for this.
Instead, `agents/risk.py`'s `score_finding` tool reports which
constraints (if any) it applied as a *separate* `constraints_applied`
field alongside `risk_score`/`bucket`/`rationale`, and
`RiskRecommendation.constraints_applied` carries that into the agent's
own narrative, verbatim-checked the same way `risk_score`/`bucket`
already are (`verify_scoring_matches_tool`). `agents/environment.py`'s
`lookup_asset_context` tool does the same for `EnvironmentAssessment
.human_constraints` -- informational there (Environment never computes a
score), but explicit rather than silently folded into
`patch_window`/`compensating_controls`, which stay exactly what the
asset record says regardless of any constraint on file.

All LLM calls route through `rhinosecure.llm.get_llm`. `build_constraint_task`
does not set `output_pydantic`, for the same reason research.py/
environment.py/risk.py/tot.py don't (agents/parsing.py's module
docstring). `Coordinator.interpret_constraint` retries a failed parse up
to `max_parse_attempts` times and then raises `ConstraintInterpretationError`
-- unlike a per-finding Research/Environment/Risk failure (recorded and
skipped, the rest of the run continues), a constraint that can't be
interpreted at all has nothing sensible to fall back to, so the whole
`submit_constraint` call aborts rather than persisting or re-planning
anything.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

from crewai import Agent, Task
from crewai.llms.base_llm import BaseLLM
from crewai.tools import BaseTool, tool
from pydantic import BaseModel

from rhinosecure.llm import get_llm
from rhinosecure.memory import Constraint
from rhinosecure.schema import Asset
from rhinosecure.scoring import ScoredFinding

ROLE = "Constraint Interpreter"


class ConstraintEffectKind(str, Enum):
    PATCH_WINDOW = "patch_window"
    COMPENSATING_CONTROL = "compensating_control"
    PATCH_RESTRICTION = "patch_restriction"


class ConstraintInterpretation(BaseModel):
    """This agent's structured output. `asset_id`/`effect_kind`/
    `effect_value` are all None together when the constraint can't be
    honestly resolved to one asset and one of the three effect kinds --
    never a partial guess. `affected_finding_ids` is empty in that case
    too."""

    asset_id: str | None
    effect_kind: str | None
    effect_value: str | None
    affected_finding_ids: list[str]
    rationale: str
    sources: list[str]


def apply_constraints(asset: Asset, constraints: list[Constraint]) -> Asset:
    """Overlay `constraints`' effects onto a COPY of `asset` -- `asset`
    itself is never modified, and nothing this returns is written back
    anywhere (see module docstring). `constraints` should already be
    filtered to active ones for this asset (`Memory.constraints_for_asset`'s
    default). Later constraints in the list win over earlier ones of the
    same effect_kind -- `constraints_for_asset` returns oldest-first, so
    the most recently stated version of a fact supersedes an older one,
    same as a human correcting an earlier statement. compensating_control
    is the one additive kind: multiple controls accumulate rather than
    replacing each other, matching how `Asset.compensating_control_list`
    already treats its own comma/semicolon-separated field as a set, not
    a single value.
    """
    patch_window = asset.patch_window
    patch_restrictions = asset.patch_restrictions
    added_controls: list[str] = []
    for c in constraints:
        if not c.effect_value:
            continue
        if c.effect_kind == ConstraintEffectKind.PATCH_WINDOW.value:
            patch_window = c.effect_value
        elif c.effect_kind == ConstraintEffectKind.PATCH_RESTRICTION.value:
            patch_restrictions = c.effect_value
        elif c.effect_kind == ConstraintEffectKind.COMPENSATING_CONTROL.value:
            added_controls.append(c.effect_value)

    if added_controls:
        compensating_controls = (
            f"{asset.compensating_controls}, {', '.join(added_controls)}"
            if asset.compensating_controls
            else ", ".join(added_controls)
        )
    else:
        compensating_controls = asset.compensating_controls

    return asset.model_copy(
        update={
            "patch_window": patch_window,
            "patch_restrictions": patch_restrictions,
            "compensating_controls": compensating_controls,
        }
    )


class ConstraintInterpretationError(RuntimeError):
    """Raised when the Interpreter's response never parses within
    max_parse_attempts -- see module docstring for why this aborts the
    whole submit_constraint call rather than being recorded and skipped."""


def build_constraint_tools(
    asset_index: dict[str, Asset],
    findings_by_asset: dict[str, list[ScoredFinding]],
    call_log: list[dict[str, Any]],
) -> list[BaseTool]:
    """Two tools, mirroring why Research gets four separate ones and
    Environment gets one: `search_assets` and `list_findings_for_asset`
    are genuinely different lookups (free-text match against asset
    identity fields vs. a keyed listing), not facets of the same record.
    `findings_by_asset`'s ScoredFinding objects come from scoring.py run
    directly on ground-truth (unenriched) findings -- see
    Coordinator.submit_constraint -- context for the model's own
    reasoning about relevance, not an authoritative verdict; the real,
    fully-enriched score for whichever findings end up affected still
    only ever comes from score_finding, dispatched later in the normal
    Risk stage.
    """

    @tool("search_assets")
    def search_assets(query: str) -> str:
        """Find candidate assets by free-text match against hostname,
        business_function, role, owner, or asset_id (case-insensitive
        substring). Use this to resolve a phrase like "the payroll
        server" to a real asset_id before doing anything else."""
        q = query.strip().lower()
        matches = [
            a
            for a in asset_index.values()
            if q
            and (
                q in a.asset_id.lower()
                or q in a.hostname.lower()
                or q in a.business_function.lower()
                or q in a.role.lower()
                or q in a.owner.lower()
            )
        ]
        result = {
            "query": query,
            "matches": [
                {
                    "asset_id": a.asset_id,
                    "hostname": a.hostname,
                    "role": a.role,
                    "business_function": a.business_function,
                    "owner": a.owner,
                    "patch_window": a.patch_window,
                    "patch_restrictions": a.patch_restrictions,
                    "compensating_controls": list(a.compensating_control_list),
                }
                for a in matches
            ],
        }
        call_log.append({"tool": "search_assets", "args": {"query": query}, "result": result})
        return json.dumps(result)

    @tool("list_findings_for_asset")
    def list_findings_for_asset(asset_id: str) -> str:
        """Every finding currently on file for `asset_id`, with its
        (unenriched, context-only) bucket and risk_score. Use this after
        search_assets to see what a constraint on this asset would
        actually affect."""
        findings = findings_by_asset.get(asset_id, [])
        result = {
            "asset_id": asset_id,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "cve_id": f.cve_id,
                    "bucket": f.bucket.value,
                    "risk_score": f.risk_score,
                }
                for f in findings
            ],
        }
        call_log.append(
            {"tool": "list_findings_for_asset", "args": {"asset_id": asset_id}, "result": result}
        )
        return json.dumps(result)

    return [search_assets, list_findings_for_asset]


def build_constraint_agent(tools: list[BaseTool], llm: BaseLLM | None = None) -> Agent:
    """`llm` defaults to the trust-boundary seam's `get_llm()` -- pass one
    explicitly (as tests do, with a throwaway key) to avoid depending on
    real `.env` state at construction time."""
    return Agent(
        role=ROLE,
        goal=(
            "Resolve a free-form operational constraint to exactly one "
            "asset and exactly one of three effect kinds -- patch_window, "
            "compensating_control, or patch_restriction -- using only "
            "search_assets and list_findings_for_asset. Refuse (leave "
            "asset_id, effect_kind, and effect_value null) rather than "
            "guess when the constraint doesn't clearly name one asset or "
            "doesn't describe one of those three effects."
        ),
        backstory=(
            "An operations analyst who translates what a human just said "
            "about one asset into the same structured facts the asset "
            "inventory already records, and who says plainly when a "
            "statement doesn't resolve cleanly rather than forcing a "
            "guess onto the wrong asset."
        ),
        tools=tools,
        llm=llm or get_llm(),
        verbose=True,
    )


def build_constraint_task(constraint_text: str, agent: Agent) -> Task:
    return Task(
        description=(
            f"A human has stated this operational constraint: {constraint_text!r}\n\n"
            "Call search_assets with terms drawn from the constraint text to find "
            "candidate assets. If exactly one asset clearly matches, call "
            "list_findings_for_asset for it to see what it would affect. If zero "
            "assets match, or more than one plausible candidate exists with no way "
            "to tell which one the human meant, do not guess -- leave asset_id null.\n\n"
            "Once (and only if) you have resolved exactly one asset, classify the "
            "constraint into exactly one effect kind:\n"
            "- patch_window: establishes or replaces when this asset may be patched "
            "(e.g. \"only reboots on Sundays\")\n"
            "- compensating_control: adds a mitigating control on this asset (e.g. "
            "\"now sits behind the new WAF rule\")\n"
            "- patch_restriction: establishes or replaces an operational restriction "
            "on patching this asset (e.g. \"no reboots during business hours\")\n\n"
            "If the constraint does not clearly describe one of these three -- for "
            "example, a fleet-wide capacity statement like \"only five patches fit "
            "this window\", which names no single asset -- leave effect_kind and "
            "effect_value null too, and say why in rationale. effect_value must be "
            "grounded in the human's own words -- do not invent scheduling details, "
            "control names, or restrictions the constraint text doesn't state.\n\n"
            "affected_finding_ids defaults to every finding list_findings_for_asset "
            "returned for the resolved asset -- narrow it only if the constraint's "
            "own words scope it further (e.g. to one specific CVE or product)."
        ),
        expected_output=(
            "Return ONLY a single JSON object, with these keys directly at the top "
            "level -- not wrapped in any container key, and no markdown code fences "
            "or prose before or after it: asset_id (string or null), effect_kind "
            '(one of "patch_window", "compensating_control", "patch_restriction", or '
            "null), effect_value (string or null), affected_finding_ids (a list of "
            "strings, empty if asset_id is null), rationale (a short paragraph "
            "explaining the resolution, or why it could not be resolved), and "
            "sources (a list of strings citing which tool calls the resolution came "
            "from)."
        ),
        agent=agent,
    )
