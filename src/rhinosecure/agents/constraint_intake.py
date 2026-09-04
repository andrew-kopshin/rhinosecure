"""Constraint Interpreter agent (CLAUDE.md Section 5's "Human submits a
constraint" edge, Section 7's memory layer): turns free-form human
constraint text into a structured, asset-scoped effect plus the
finding_ids it affects. This is "constraint intake" -- the one piece of
Slice 4's Coordinator-side wiring every prior commit in this repo named
as unbuilt (`agents/coordinator.py`'s and `tot.py`'s module docstrings,
CLAUDE.md Section 7's own "Deliberately not built" note).

**Scope: a three-way classification.** `ConstraintInterpretation
.constraint_kind` (`ConstraintKind`) says which of two honest shapes a
constraint resolved to, or neither:

- `"asset"` -- an asset-scoped operational constraint, matching CLAUDE.md
  Section 7's worked example exactly ("the payroll server only reboots on
  Sundays"). Resolved to one asset and one of the three effect kinds
  below, same as before this classification existed.
- `"capacity"` -- CLAUDE.md Section 10's "only five patches fit this
  window": a fleet-wide capacity constraint with no single asset to
  resolve to. The Interpreter's only job here is to recognize the shape
  and extract the integer `patch_limit` -- it does NOT decide which
  finding_ids a capacity limit affects. That pool (every finding
  currently in the `next_window` bucket) is computed deterministically
  elsewhere in this codebase -- a separate, already-planned piece, not
  built here -- and a capacity constraint also has no representation yet
  in `memory.py`'s `constraints` table (`asset_id NOT NULL`) or its own
  re-ranking mechanism; nothing here attempts that persistence.
- `None` -- a refusal, same meaning as before: the statement doesn't
  honestly resolve to either shape above. The Interpreter is explicitly
  instructed to refuse rather than guess -- see `build_constraint_task`.

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


class ConstraintKind(str, Enum):
    """The two shapes a constraint can honestly resolve to -- mirrors
    ConstraintEffectKind's own reasoning: a fixed, bounded menu is what
    makes the result mechanically usable downstream (which table it
    belongs in, which re-ranking mechanism reads it) rather than more
    prose a later stage has to re-interpret. `constraint_kind` is None
    (not a third member here) when neither shape fits -- see
    ConstraintInterpretation."""

    ASSET = "asset"
    CAPACITY = "capacity"


class ConstraintInterpretation(BaseModel):
    """This agent's structured output, one of three shapes selected by
    `constraint_kind`:

    - `constraint_kind="asset"` -- an asset-scoped operational constraint,
      matching CLAUDE.md Section 7's worked example ("the payroll server
      only reboots on Sundays"). `asset_id`, `effect_kind`, `effect_value`,
      and `affected_finding_ids` are populated as before; `patch_limit` is
      None.
    - `constraint_kind="capacity"` -- a fleet-wide capacity statement
      naming no single asset (CLAUDE.md Section 10's "only five patches
      fit this window"). ONLY `patch_limit` is populated (the integer
      limit extracted from the statement); `asset_id`, `effect_kind`,
      `effect_value` are None and `affected_finding_ids` is empty. Which
      finding_ids a capacity limit actually constrains is computed
      deterministically elsewhere in this codebase, from every finding
      currently in the `next_window` bucket -- a separate, already-planned
      piece this agent does not build and must not attempt: it never
      populates `affected_finding_ids` for a capacity constraint, even if
      list_findings_for_asset was called for some other reason first.
    - `constraint_kind=None` -- a refusal: the statement could not be
      honestly resolved to EITHER an asset-scoped effect or a capacity
      limit (e.g. it gestures at fleet-wide capacity but gives no
      extractable number, or it names no asset and isn't a capacity
      statement either, or it names an asset but no clear effect).
      `asset_id`, `effect_kind`, `effect_value`, and `patch_limit` are all
      None and `affected_finding_ids` is empty; only `rationale` explains
      why.

    In every case exactly one shape applies -- never a partial mix across
    shapes."""

    constraint_kind: str | None
    asset_id: str | None
    effect_kind: str | None
    effect_value: str | None
    patch_limit: int | None
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

    **A supplied field stops being not-collected.** Any field a
    constraint actually writes is removed from `Asset.not_collected`
    (adapters/base.py) on the returned copy. This is the whole point of
    the constraint path for a record ingested from a source that exports
    no operational context: before, a Defender asset's blank
    `patch_window` meant "unknown" and everything downstream said so;
    after a human states the window, it is known, and continuing to flag
    it as a data gap would be false. Fields no constraint touched keep
    their marker, so one constraint never launders an asset's other gaps.
    """
    patch_window = asset.patch_window
    patch_restrictions = asset.patch_restrictions
    added_controls: list[str] = []
    supplied: set[str] = set()
    for c in constraints:
        if not c.effect_value:
            continue
        if c.effect_kind == ConstraintEffectKind.PATCH_WINDOW.value:
            patch_window = c.effect_value
            supplied.add("patch_window")
        elif c.effect_kind == ConstraintEffectKind.PATCH_RESTRICTION.value:
            patch_restrictions = c.effect_value
            supplied.add("patch_restrictions")
        elif c.effect_kind == ConstraintEffectKind.COMPENSATING_CONTROL.value:
            added_controls.append(c.effect_value)
            supplied.add("compensating_controls")

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
            "not_collected": asset.not_collected - supplied,
        }
    )


class ConstraintInterpretationError(RuntimeError):
    """Raised when the Interpreter's response never parses within
    max_parse_attempts -- see module docstring for why this aborts the
    whole submit_constraint call rather than being recorded and skipped.

    Chained (`raise ... from last_error`) onto the `AgentOutputParseError`
    of the final failed attempt, so `self.__cause__.raw` carries that
    attempt's raw, unparsed model output -- kept out of `str(self)` on
    purpose (see AgentOutputParseError's docstring); a caller shows it
    only under --verbose."""


SEARCHABLE_ASSET_FIELDS = ("asset_id", "hostname", "business_function", "role", "owner")


def _matches(asset: Asset, query: str) -> bool:
    """Substring match over the asset's identity fields, skipping any
    field in `Asset.not_collected`.

    Matching a query against a not-collected field would match its
    *default*, not the asset (adapters/base.py). A Microsoft Defender
    export supplies no role, business_function, or owner, so every
    Defender server carries the same defaulted role: without this skip,
    "the file server" would match every server in the fleet and "the
    payroll box" would match none of them for the right reason but some
    of them for the wrong one. Resolving an asset off a placeholder is
    exactly the guess the whole ingest layer refuses to make, and here it
    would land a human's constraint on the wrong machine.
    """
    for name in SEARCHABLE_ASSET_FIELDS:
        if name in asset.not_collected:
            continue
        if query in str(getattr(asset, name)).lower():
            return True
    return False


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
        server" to a real asset_id before doing anything else. Fields
        this asset's source never collected are listed in not_collected
        and are NOT matched against -- their values are placeholders,
        not facts about the asset."""
        q = query.strip().lower()
        matches = [a for a in asset_index.values() if q and _matches(a, q)]
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
                    # Field names above whose value is a placeholder this
                    # asset's source never supplied -- see _matches.
                    "not_collected": sorted(a.not_collected),
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
            "FIRST, decide which of two shapes this statement has -- before doing "
            "anything else. This is the constraint_kind decision, and it comes before "
            "any asset lookup.\n\n"
            "A CAPACITY statement is about how much CAN be done this cycle -- how many "
            "patches, changes, or slots fit -- not about any single machine's "
            "operational facts. Its identifying feature is that it constrains a COUNT "
            "across the whole plan, not a fact about one named system. Examples of "
            "what a capacity statement sounds like:\n"
            "- \"only five patches fit this window\"\n"
            "- \"we can only do three changes this cycle\"\n"
            "- \"the team has capacity for two patches before the freeze\"\n"
            "If (and only if) the statement is capacity-shaped, set constraint_kind to "
            "\"capacity\" and extract the integer limit into patch_limit. Do NOT call "
            "search_assets or list_findings_for_asset for a capacity statement -- it "
            "names no asset to look up. Do NOT populate affected_finding_ids for a "
            "capacity constraint, even though you have list_findings_for_asset "
            "available: which finding_ids a capacity limit actually constrains (every "
            "finding currently in the next_window bucket) is computed deterministically "
            "elsewhere in this codebase, not by you. Leave asset_id, effect_kind, and "
            "effect_value null; leave affected_finding_ids empty. If the statement "
            "gestures at capacity but gives no extractable number, it does not resolve "
            "cleanly -- fall through to the refusal case below rather than guessing a "
            "number.\n\n"
            "An ASSET statement's identifying pattern is the opposite: it names or "
            "clearly implies one specific machine, server, or workstation, and states an "
            "operational fact about that one system (e.g. \"the payroll server only "
            "reboots on Sundays\", \"WKS-FIN12 now sits behind the new WAF rule\"). If "
            "the statement is asset-shaped, set constraint_kind to \"asset\" and resolve "
            "it as follows:\n\n"
            "Call search_assets with terms drawn from the constraint text to find "
            "candidate assets. If exactly one asset clearly matches, call "
            "list_findings_for_asset for it to see what it would affect. If zero "
            "assets match, or more than one plausible candidate exists with no way "
            "to tell which one the human meant, do not guess -- leave asset_id null "
            "and treat this as a refusal instead (constraint_kind null).\n\n"
            "Some fleets are ingested from a scanner export that never collected "
            "every field -- a Microsoft Defender export, for example, supplies no "
            "role, business function, owner, patch window, or compensating controls. "
            "Each search_assets match lists those field names in not_collected, and "
            "the search does not match your query against them. Treat a value whose "
            "field name appears in not_collected as a placeholder, never as a fact "
            "about that asset: do not resolve an asset because its role or "
            "business_function appears to match when that field is not collected, and "
            "do not repeat such a value in your rationale as though the inventory "
            "stated it. Matching on hostname or asset_id is always safe. If the human's "
            "phrase describes a machine only by a role or function this fleet did not "
            "collect, that is a refusal, not a guess -- say so in rationale and name "
            "the field that is missing, so the human can restate it by hostname.\n\n"
            "Once (and only if) you have resolved exactly one asset, classify the "
            "constraint into exactly one effect kind:\n"
            "- patch_window: establishes or replaces when this asset may be patched "
            "(e.g. \"only reboots on Sundays\")\n"
            "- compensating_control: adds a mitigating control on this asset (e.g. "
            "\"now sits behind the new WAF rule\")\n"
            "- patch_restriction: establishes or replaces an operational restriction "
            "on patching this asset (e.g. \"no reboots during business hours\")\n\n"
            "If an asset resolves but the constraint does not clearly describe one of "
            "these three effects, leave effect_kind and effect_value null too, and "
            "treat the whole thing as a refusal (constraint_kind null) -- say why in "
            "rationale. effect_value must be grounded in the human's own words -- do "
            "not invent scheduling details, control names, or restrictions the "
            "constraint text doesn't state. patch_limit stays null for an asset "
            "constraint.\n\n"
            "affected_finding_ids (asset constraints only) defaults to every finding "
            "list_findings_for_asset returned for the resolved asset -- narrow it only "
            "if the constraint's own words scope it further (e.g. to one specific CVE "
            "or product).\n\n"
            "THIRD, if the statement is neither clearly capacity-shaped nor "
            "clearly asset-shaped -- or is asset-shaped but fails to resolve to one "
            "asset and one effect kind, or is capacity-shaped but gives no extractable "
            "number -- this is a refusal. Set constraint_kind to null, and leave "
            "asset_id, effect_kind, effect_value, and patch_limit all null and "
            "affected_finding_ids empty. Never guess a partial answer across shapes: "
            "constraint_kind, and only the fields that shape uses, are populated "
            "together, or nothing is."
        ),
        expected_output=(
            "Return ONLY a single JSON object, with these keys directly at the top "
            "level -- not wrapped in any container key, and no markdown code fences "
            "or prose before or after it: constraint_kind (one of \"asset\", "
            "\"capacity\", or null), asset_id (string or null; populated only when "
            "constraint_kind is \"asset\"), effect_kind (one of \"patch_window\", "
            "\"compensating_control\", \"patch_restriction\", or null; populated only "
            "when constraint_kind is \"asset\"), effect_value (string or null; "
            "populated only when constraint_kind is \"asset\"), patch_limit (integer "
            "or null; populated only when constraint_kind is \"capacity\", and null in "
            "every other case), affected_finding_ids (a list of strings; populated "
            "only when constraint_kind is \"asset\", always empty when constraint_kind "
            "is \"capacity\" or null -- never infer or list finding_ids for a capacity "
            "constraint yourself), rationale (a short paragraph explaining the "
            "resolution, or why it could not be resolved), and sources (a list of "
            "strings citing which tool calls the resolution came from, empty for a "
            "capacity constraint since none are called)."
        ),
        agent=agent,
    )
