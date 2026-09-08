"""Phase 1 of LLM-assisted adapter generation (docs/adapter-generation.md,
CLAUDE.md's "Adapter generation" section): `rhino adapt propose` -- point
RhinoSecure at an arbitrary CSV source and get a candidate ingest contract
back, without hand-writing Python. Phase 2 (`adapters/configured.py`) is
unchanged by this module and never knows a contract passed through here.

**Why this is not `Contract` itself.** `config_model.Contract` requires
every `asset`/`finding` slot mapped to something (`_asset_and_finding_slots_exact`)
-- if the model's own structured output WERE a `Contract`, it would have to
fabricate a mapping for any slot it isn't confident about, exactly the
guessing the whole not-collected/refuse-rather-than-guess discipline
(adapters/base.py, config_model.py's module docstring) exists to prevent.
So the model's output is `AdapterProposal`, a looser type: every slot is
`SlotMapped` (a real, code-owned `Mapping` -- see below) or `SlotUnresolved`
(an honest "I don't know", never auto-filled). A deterministic, LLM-free
`assemble_contract` turns a fully-resolved, fully-grounded proposal into a
real `Contract`; an incomplete one never reaches it.

**Pattern selection is closed by TYPE, not by prompt wording.**
`SlotMapped.mapping` is `config_model.Mapping` itself -- the identical
9-kind discriminated union, `ParsedMapping.parser` Literal, and
`EnrichmentAttackTechnique.pattern` Literal that `configured.py` executes
-- reused, not restated, so this schema cannot silently drift from what the
engine actually runs (the same anti-drift move `GAP_LEGAL_TARGETS =
frozenset(NOT_COLLECTED_DEFAULTS)` already makes one module over).

**No `output_pydantic`, matching every other agent in this codebase.**
`agents/parsing.py`'s module docstring records the incident that moved this
whole project off CrewAI's own structured-output conversion: a Task asks
for raw JSON in its `expected_output`, and `parsing.parse_structured_output`
-- code this project owns, tests, and can retry deliberately -- parses
`task.output.raw`. The same convention `agents/constraint_intake.py` uses.

**Confidence is shown, never checked.** `SlotMapped.confidence` is a model
self-report -- the same category of number `Contract.generator`'s
token/cost fields are (never trusted, never gating), per this project's own
"Grounding validation" open item (CLAUDE.md Section 8). The only gate on
assembly is `check_grounding`: a slot's cited column(s) must be real (not
hallucinated), a `vocabulary`/`derived` table's keys must appear among the
column's actually measured values (`probe.ColumnProfile.distinct_values`),
and a `literal` mapping must cite a column the profiler tagged `constant`.
A slot that fails any of these is treated exactly like `unresolved` --
confidence never overrides a failed grounding check, and a passing
grounding check never overrides an honest `unresolved`.

**The one case grounding is knowingly incomplete: `distinct_overflow`.**
Past `probe.MAX_DISTINCT_TRACKED`, a column's `distinct_values` is a lower
bound (the first values seen), not the full set -- a cited token missing
from it could be a real, later value or a genuine hallucination, and
grounding cannot tell which. This is recorded as a `"caveat"`
`GroundingIssue`, never a `"fail"`: `check_grounding` does not block
assembly on it, but `cli.py`'s report prints every caveat in its own
prominent section, separate from and before the pass/fail list -- this is
the one place a human is being asked to cover for what code could not
verify, and it must never read as a trailing footnote.
"""

from __future__ import annotations

import ast
import csv
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal, Union

from crewai import Agent, Crew, Process, Task
from crewai.llms.base_llm import BaseLLM
from crewai.types.usage_metrics import UsageMetrics
from pydantic import BaseModel, ConfigDict, Field as PydanticField, ValidationError, model_validator

from rhinosecure.adapters import FORMATS as BUILTIN_ADAPTER_FORMATS
from rhinosecure.adapters.base import NOT_COLLECTED_DEFAULTS, ROLE_DEFAULT_BY_OS_CLASS
from rhinosecure.adapters.config_model import (
    ASSET_SLOTS,
    FINDING_SLOTS,
    GAP_LEGAL_TARGETS,
    ABSENT_FACT_LEGAL_TARGETS,
    DATE_FORMATS,
    DEFAULT_BY_LEGAL_TARGET,
    EXCLUDING_TARGETS,
    PARSER_NAMES,
    REGISTERED_DEFAULT_TABLES,
    RESERVED_PROVENANCE_LABELS,
    UNIONABLE_TARGETS,
    AssetGrouping,
    Attestation,
    ColumnMapping,
    Contract,
    Derivation,
    Enrichment,
    FindingDedup,
    Generator,
    Header,
    HeaderSpec,
    LiteralMapping,
    Mapping,
    NotCollectedDerived,
    NotCollectedMapping,
    Review,
    Source,
    UnmappedColumnEntry,
    VocabularyMapping,
    DerivedMapping,
    _compute_not_collected,  # the exact V09 recomputation validate_contract itself uses
    _composed_columns,  # the exact placeholder-extraction validate_contract itself uses
    _FORMAT_PATTERN,  # the exact pattern Contract.format itself is checked against
    check_slot_mapping_legality,  # the exact per-mapping legality checks validate_contract itself runs
    ContractValidationError,
    missing_attestations,
    validate_contract,
)
from rhinosecure.adapters.configured import _apply_case  # the exact case transform applied before any table lookup
from rhinosecure.adapters.schema_registry import (
    TARGET_REGISTRY,
    alias_table_for_column,
    full_alias_coverage,
    resolve_criticality_anchor,
    resolve_enum_alias,
)
from rhinosecure.agents.limits import MAX_AGENT_EXECUTION_SECONDS
from rhinosecure.agents.parsing import AgentOutputParseError, parse_structured_output
from rhinosecure.adapters.probe import ColumnProfile, FileProfile, profile_source
from rhinosecure.llm import DEFAULT_MODEL, get_llm
from rhinosecure.scoring import IMPACT_AXIS_TARGETS, THREAT_AXIS_TARGETS

ROLE = "Schema Inference"

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_SAMPLE_ROWS = 20

#: Measured against the real accepted proposal for a 20-column source
#: (~8,200 tokens -- PROGRESS.md 2026-09-06): generous headroom for a larger
#: real source with more columns/candidates, while still capping a wayward
#: attempt at roughly a fifth of claude-sonnet-5's 128,000-token default --
#: turning "burn tens of thousands of unneeded completion tokens before
#: failing to parse" into "hit the cap and fail fast." Passed to
#: `get_llm(max_tokens=...)` -- see that function's own docstring for why no
#: other agent in this codebase sets this.
PROPOSE_MAX_OUTPUT_TOKENS = 24_000

#: A previous attempt's failure, embedded verbatim in the next attempt's
#: retry prompt (see `build_propose_task`'s `previous_error`). Both
#: `AgentOutputParseError.__str__` and `_check_meta_matches`' `ValueError`
#: are already short, bounded summaries -- this is a second, defensive cap
#: against a hypothetical future failure mode with an unbounded message,
#: not evidence either currently produces one.
_MAX_RETRY_ERROR_CHARS = 2000

#: Claude Sonnet 5's first-party API rate (CLAUDE.md Section 11 pins this
#: model for every agent call). Sourced from Anthropic's published pricing,
#: not recalled -- re-check before changing either number. Cost estimation
#: is CLAUDE.md Section 8's open item 4 ("no run prints its actual dollar
#: cost"); this is the first place in the codebase that computes one.
_INPUT_USD_PER_MILLION_TOKENS = 2.00
_OUTPUT_USD_PER_MILLION_TOKENS = 10.00

#: What `rhino adapt propose` writes -- see the two committed hand-authored
#: contracts (data/adapters/*-gen.json), both declaring this same string.
#: No code-owned constant defines "the current schema version" yet; this
#: mirrors what already exists rather than inventing a second source.
CONFIG_SCHEMA_VERSION = "1.0.0"

_DISPOSITION_LITERAL = UnmappedColumnEntry.model_fields["disposition"].annotation

#: `Source.encoding`'s own closed vocabulary, mirrored (not imported by
#: reflection) so a value `detect_encoding` can return but this Literal
#: cannot represent (e.g. "utf-32") is caught explicitly rather than
#: raising a confusing pydantic error deep inside Contract construction.
_VALID_SOURCE_ENCODINGS = frozenset({"auto", "utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be"})


class SchemaInferenceError(RuntimeError):
    """A propose run could not proceed at all -- an unreadable source, an
    ambiguous two-file layout with no explicit filenames, or a proposal
    whose own `meta` disagrees with the facts it was actually given."""


class ProposalGenerationError(RuntimeError):
    """The model's raw output never parsed into `AdapterProposal` (or kept
    disagreeing with the source facts it was handed) within `max_attempts`
    -- mirrors `ConstraintInterpretationError` (agents/constraint_intake.py):
    there is nothing sensible to fall back to, so the whole propose call
    aborts rather than writing anything.

    `attempt_usage` carries every attempt's real token spend regardless --
    a real gap found running this exact path live (PROGRESS.md 2026-09-06):
    every other outcome (`ProposeResult`) reports per-attempt usage, but a
    TOTAL failure -- arguably the case a human is most confused about cost
    for, since nothing got written for it -- used to raise before that data
    was ever attached to anything, discarding it along with the exception's
    local variables. `estimated_cost_usd` is precomputed rather than left
    for a caller to derive from `attempt_usage`, since a caller reporting a
    failure has no reason to also re-implement `_estimate_cost_usd`."""

    def __init__(self, message: str, *, attempt_usage: tuple[dict[str, object], ...] = (), estimated_cost_usd: float = 0.0):
        super().__init__(message)
        self.attempt_usage = attempt_usage
        self.estimated_cost_usd = estimated_cost_usd


class ProposalIncompleteError(RuntimeError):
    """`assemble_contract` refuses: at least one slot is `unresolved`, or
    failed a grounding check. Never raised for a caveat (a distinct_overflow
    caveat does not block assembly -- see module docstring).

    `problems` mirrors `ContractValidationError.problems` verbatim when the
    underlying cause was a real `validate_contract` failure (a fully mapped,
    fully grounded proposal whose ASSEMBLED contract is still illegal --
    `_assemble_and_validate`'s own safety net) -- empty for the other raise
    site (unresolved slots / grounding failures, `assemble_contract`'s own
    check, which needs no `validate_contract` call to detect). Read by
    `assemble_provisional_contract`'s own degrade-on-validation-failure path
    to identify exactly which slot(s) are individually at fault, without
    re-parsing this exception's formatted message text."""

    def __init__(self, message: str, *, problems: tuple[str, ...] = ()):
        super().__init__(message)
        self.problems = problems


# ---------------------------------------------------------------------------
# The model's structured output. Every mapping-bearing field reuses
# config_model's own types -- see module docstring.
# ---------------------------------------------------------------------------


class SlotEvidence(BaseModel):
    """What the model looked at to justify one slot's proposal. Every name
    in `columns_cited` is checked against the real header in `check_grounding`
    -- a cited column that doesn't exist is treated as a hallucination, not
    a typo to smooth over."""

    model_config = ConfigDict(extra="forbid")

    columns_cited: list[str] = PydanticField(default_factory=list)
    sample_values_cited: list[str] = PydanticField(default_factory=list)
    note: str


class SlotMapped(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["mapped"]
    mapping: Mapping
    confidence: float = PydanticField(ge=0, le=1)
    evidence: SlotEvidence


class SlotUnresolved(BaseModel):
    """An honest non-answer: no column corresponds to this target, or the
    model could not confidently decide among candidates. Never auto-filled
    -- see module docstring on why `not_collected` and `unresolved` are
    different claims that must not be conflated, even for a slot where
    `not_collected` would otherwise be legal."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["unresolved"]
    candidate_columns: list[str] = PydanticField(default_factory=list)
    reason: str


SlotProposal = Annotated[Union[SlotMapped, SlotUnresolved], PydanticField(discriminator="status")]


class ProposedUnmappedColumn(BaseModel):
    """One column the proposal declares it deliberately does not read.
    `disposition`'s type is imported from `UnmappedColumnEntry` itself
    (config_model.py), not restated, so this can never accept a value the
    real contract grammar would reject."""

    model_config = ConfigDict(extra="forbid")

    disposition: _DISPOSITION_LITERAL
    reason: str
    profile_cited: str


class ProposalMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: str
    description: str
    source_layout: Literal["single_file", "two_file"]
    assets_filename: str
    findings_filename: str
    reasoning_summary: str


class AdapterProposal(BaseModel):
    """The model's entire structured output. `asset`/`finding` keys are
    checked against `ASSET_SLOTS`/`FINDING_SLOTS` exactly -- the same
    completeness `Contract` itself enforces, imported rather than
    re-declared -- but a value may be `SlotUnresolved`, which `Contract`
    itself has no way to represent."""

    model_config = ConfigDict(extra="forbid")

    meta: ProposalMeta
    asset: dict[str, SlotProposal]
    finding: dict[str, SlotProposal]
    derived: dict[str, Derivation] = PydanticField(default_factory=dict)
    asset_grouping: AssetGrouping
    finding_dedup: FindingDedup
    enrichment: Enrichment | None = None
    unmapped_columns: dict[str, dict[str, ProposedUnmappedColumn]] = PydanticField(default_factory=dict)
    open_questions: list[str] = PydanticField(default_factory=list)

    @model_validator(mode="after")
    def _slots_exact(self) -> "AdapterProposal":
        asset_keys, want_asset = set(self.asset), set(ASSET_SLOTS)
        if asset_keys != want_asset:
            raise ValueError(
                f"asset must address exactly {sorted(want_asset)} (mapped or unresolved -- never "
                f"omitted); missing {sorted(want_asset - asset_keys)}, extra {sorted(asset_keys - want_asset)}"
            )
        finding_keys, want_finding = set(self.finding), set(FINDING_SLOTS)
        if finding_keys != want_finding:
            raise ValueError(
                f"finding must address exactly {sorted(want_finding)}; missing "
                f"{sorted(want_finding - finding_keys)}, extra {sorted(finding_keys - want_finding)}"
            )
        return self


@dataclass(frozen=True)
class SavedProposal:
    """The on-disk shape a human hand-corrects between propose runs.
    `generator` is carried alongside `proposal`, never inside it -- the
    model never reports its own cost (module docstring); a human editing a
    saved proposal to fill in an unresolved slot touches only `proposal`.

    `attempt_usage` is a THIRD, separate thing from `generator`'s summed
    totals: one entry per attempt actually made (`{attempt, prompt_tokens,
    completion_tokens, outcome}`), in order, including discarded ones --
    `generator.call_log_digest` proves a discarded attempt happened without
    revealing what it said; this says how expensive it was, without needing
    to reproduce or store the raw text. Deliberately NOT part of `Generator`
    itself: that type is also `Contract.generator` (config_model.py), a
    field on a git-committed, digest-verified artifact two hand-authored
    contracts already carry without this data -- keeping it here instead
    avoids touching that shared, `extra="forbid"` schema for something that
    is audit trail about audit trail, one level removed. Empty for a
    `from_proposal` reuse that made no new attempts, or for a file saved
    before this field existed."""

    proposal: AdapterProposal
    generator: Generator
    attempt_usage: tuple[dict[str, object], ...] = ()


def dump_saved_proposal(saved: SavedProposal) -> dict:
    dumped: dict = {
        "proposal": saved.proposal.model_dump(mode="json", by_alias=True),
        "generator": saved.generator.model_dump(mode="json"),
    }
    if saved.attempt_usage:
        dumped["attempt_usage"] = list(saved.attempt_usage)
    return dumped


def saved_proposal_from_dict(data: Any) -> SavedProposal:
    """The shared validator behind `load_saved_proposal` (a file on disk,
    `rhino adapt propose --from-proposal`) and a browser's resubmitted,
    slot-edited proposal (`_run_ingest_propose`'s `edited_saved_proposal`
    job input, web/jobs.py) -- one place decides whether a dict has the
    saved-proposal shape, so a hand-edited file and a form-submitted edit
    are held to the identical standard, and neither can silently diverge
    from what the other accepts."""
    if not isinstance(data, dict) or "proposal" not in data or "generator" not in data:
        raise SchemaInferenceError(
            "expected a saved proposal with top-level 'proposal' and 'generator' keys "
            "(the shape rhino adapt propose writes) -- edit only the 'proposal' half by hand"
        )
    try:
        return SavedProposal(
            proposal=AdapterProposal.model_validate(data["proposal"]),
            generator=Generator.model_validate(data["generator"]),
            attempt_usage=tuple(data.get("attempt_usage") or ()),
        )
    except ValidationError as exc:
        # A hand-edited proposal is exactly where a typo (a bad `kind`,
        # `parser`, or `case` literal, a missing required field) is likely --
        # wrapped so a caller's existing `except SchemaInferenceError` prints
        # a clean message instead of a raw pydantic traceback.
        raise SchemaInferenceError(f"does not match the saved-proposal shape -- {exc}") from exc


def load_saved_proposal(path: Path) -> SavedProposal:
    import json

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SchemaInferenceError(f"{path}: could not be read -- {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaInferenceError(f"{path}: not valid JSON -- {exc}") from exc
    try:
        return saved_proposal_from_dict(data)
    except SchemaInferenceError as exc:
        raise SchemaInferenceError(f"{path}: {exc}") from exc


# ---------------------------------------------------------------------------
# Evidence grounding (step 4): LLM-free, checked against the real profile.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GroundingIssue:
    slot: str
    severity: Literal["fail", "caveat"]
    message: str


@dataclass(frozen=True)
class GroundingReport:
    issues: list[GroundingIssue] = field(default_factory=list)

    @property
    def failures(self) -> list[GroundingIssue]:
        return [i for i in self.issues if i.severity == "fail"]

    @property
    def caveats(self) -> list[GroundingIssue]:
        return [i for i in self.issues if i.severity == "caveat"]

    @property
    def failed_slots(self) -> frozenset[str]:
        return frozenset(i.slot for i in self.failures)


def _check_column_exists(
    issues: list[GroundingIssue], slot: str, column: str, profile: FileProfile, *, optional: bool = False
) -> bool:
    """Returns True iff `column` is present -- callers use this to decide
    whether it's safe to ground further (e.g. a table) against it. An
    ABSENT `optional` column is not a failure at all (mirrors
    `config_model._compute_not_collected`'s own "optional and missing from
    this header -> always not_collected" rule -- a proposal that legitimately
    marks a slot optional for exactly this export must not be blocked for
    exercising the very escape hatch the design provides); it still returns
    False, since there is nothing there to ground a table against."""
    if column in profile.columns:
        return True
    if not optional:
        issues.append(
            GroundingIssue(
                slot, "fail",
                f"cites column {column!r}, not present in {profile.path.name}'s header {sorted(profile.columns)}",
            )
        )
    return False


def _ground_table(
    issues: list[GroundingIssue], slot: str, column: str, table_keys: list, case: str, profile: FileProfile
) -> None:
    """Every KEY the proposal put in a vocabulary/derivation table must be a
    value the profiler actually measured for `column`, AFTER the same `case`
    transform the real engine applies before ever consulting the table
    (`configured._apply_case`, called ahead of every `table.get(cased)` in
    `configured.py`) -- comparing against the raw, un-cased measured values
    would falsely flag a correct case-normalizing mapping as ungrounded. The
    reverse is not required (an uncovered token is a legal, partial
    vocabulary; it is excluded/refused row-by-row at real ingest time,
    unchanged from today)."""
    col = profile.columns[column]
    cased_observed = {_apply_case(v, case) for v in col.distinct_values}
    keys = [str(k) for k in table_keys]
    missing = [k for k in keys if k not in cased_observed]
    if not missing:
        return
    shown = missing[:5]
    more = f", +{len(missing) - 5} more" if len(missing) > 5 else ""
    if col.distinct_overflow:
        issues.append(
            GroundingIssue(
                slot, "caveat",
                f"{column!r} reached the tracked-distinct-values cap ({len(col.distinct_values)}+ known, "
                f"the true count is larger) -- {len(missing)} of {len(keys)} cited token(s) (post-case) were "
                f"not found among the values tracked so far: {shown}{more}. Grounding is INCOMPLETE for this "
                "column: these could be real values seen later in the file, or hallucinated -- verify by hand.",
            )
        )
    else:
        issues.append(
            GroundingIssue(
                slot, "fail",
                f"{column!r}: {len(missing)} of {len(keys)} cited token(s) (post-case={case!r}) not found "
                f"among its {len(col.distinct_values)} measured distinct value(s): {shown}{more}",
            )
        )


def _ground_literal(issues: list[GroundingIssue], slot: str, value: object, evidence: SlotEvidence, profile: FileProfile) -> None:
    """A `literal` must be grounded in an observed constant -- not merely
    citing SOME constant-tagged column (any column, any value, would have
    passed that alone), but citing one whose single observed value actually
    IS the literal's declared value. `LiteralMapping` carries no `case`
    field (it is never read from a column), so this is a direct string
    comparison, not a cased one."""
    constant_cols = [
        c for c in evidence.columns_cited if c in profile.columns and "constant" in profile.columns[c].looks_like
    ]
    if not constant_cols:
        issues.append(
            GroundingIssue(
                slot, "fail",
                "literal mapping cites no column tagged 'constant' in its evidence "
                f"(columns_cited={evidence.columns_cited!r}) -- a literal must be grounded in an observed "
                "constant, not asserted from nothing",
            )
        )
        return
    matching = [c for c in constant_cols if next(iter(profile.columns[c].distinct_values), None) == str(value)]
    if not matching:
        observed = {c: next(iter(profile.columns[c].distinct_values), None) for c in constant_cols}
        issues.append(
            GroundingIssue(
                slot, "fail",
                f"literal value {value!r} does not match the observed constant value of any cited column: {observed}",
            )
        )


def _ground_derivation(
    issues: list[GroundingIssue], slot: str, derivation_name: str, proposal: AdapterProposal, assets_profile: FileProfile
) -> None:
    derivation = proposal.derived.get(derivation_name)
    if derivation is None:
        issues.append(GroundingIssue(slot, "fail", f"references derived {derivation_name!r}, which this proposal does not define"))
        return
    if _check_column_exists(issues, slot, derivation.column, assets_profile):
        _ground_table(issues, slot, derivation.column, list(derivation.table), derivation.case, assets_profile)


def _ground_enrichment(issues: list[GroundingIssue], enrichment: Enrichment, findings_profile: FileProfile) -> None:
    """`Enrichment`'s three column-reading sub-mappings are always
    finding-side (config_model.py's own `validate_contract` checks each
    against `findings_header_set`) but are not slots in `proposal.asset`/
    `proposal.finding` -- grounded here explicitly so a hallucinated column
    name is reported as a specific, well-labeled grounding issue instead of
    surfacing only as a generic `validate_contract` refusal later."""
    _check_column_exists(issues, "enrichment.severity_score", enrichment.severity_score.column, findings_profile)
    if enrichment.known_exploited is not None:
        _check_column_exists(issues, "enrichment.known_exploited", enrichment.known_exploited.column, findings_profile)
    if enrichment.attack_technique is not None:
        _check_column_exists(
            issues, "enrichment.attack_technique", enrichment.attack_technique.column, findings_profile,
            optional=enrichment.attack_technique.optional,
        )


def _check_alias_contradiction(issues: list[GroundingIssue], slot: str, target: str, table: dict[str, Any], case: str) -> None:
    """A `VocabularyMapping`/`Derivation` table entry whose KEY case-
    normalizes to a known `schema_registry` alias, but whose VALUE disagrees
    with what that alias resolves to, is a genuine contradiction -- a
    grounding FAILURE, never silently corrected. Only `_apply_registry_
    aliases`'s table-augmentation mechanism is allowed to ADD an entry, and
    only when none already exists for that key; this is what happens when
    one already exists and disagrees with the registry.

    Scoped to `REGISTRY_BACKED_TARGETS` -- the four targets this project
    publishes alias data for at all; every other target has no registry
    entry to disagree with, so this is a silent no-op for them.

    Deliberately lives HERE, in `check_grounding`, and not in
    `config_model.validate_contract`: this function runs only during
    `rhino adapt propose`, against a fresh-or-reloaded `AdapterProposal` --
    never against an already-confirmed `Contract`. `bluepeak-gen.json` and
    `mdvm-gen.json` are both already confirmed and never re-proposed, so
    this check can never reach -- and so can never affect -- either one,
    even in principle."""
    if target not in REGISTRY_BACKED_TARGETS:
        return
    for key, declared_value in table.items():
        resolved = (
            resolve_criticality_anchor(key, case) if target == "criticality"
            else resolve_enum_alias(target, key, case)
        )
        if resolved is not None and resolved != declared_value:
            issues.append(
                GroundingIssue(
                    slot, "fail",
                    f"table key {key!r} case-normalizes to a known schema-registry alias that resolves "
                    f"to {resolved!r}, but this table maps it to {declared_value!r} instead -- a real "
                    "disagreement with published schema knowledge, not something to silently correct",
                )
            )


def check_column_mapping_legal_values(
    where: str, target: str, mapping: ColumnMapping, profile: FileProfile
) -> list[str]:
    """The data-dependent half of the same problem `config_model
    ._check_column_mapping_type` (Part B of that fix) catches statically: a
    `ColumnMapping` always writes its raw, case-transformed source value
    VERBATIM (`ColumnMapping`'s own docstring), so a closed, string-shaped
    vocabulary target (`role`, `environment`, `data_sensitivity`,
    `scanner_severity` -- anything with a `TARGET_REGISTRY[...].enum`) is
    only ACTUALLY illegal for one when the column's real, observed values
    (after the mapping's own `case`) fall outside that vocabulary --
    something only real profiled data (`probe.ColumnProfile.distinct_values`)
    can answer. A non-string-shaped target (`criticality`, `internet_exposed`)
    can never even reach here as a `ColumnMapping` in valid output, since
    `_check_column_mapping_type` already forbids that combination outright,
    regardless of data -- so this function only ever has something to say
    about the four registry-enumerated, string-shaped targets above, or any
    other closed `Literal[str, ...]` target this schema later adds.

    Mirrors `config_model.check_slot_mapping_legality`'s own "returns
    list[str], never raises" convention. Returns `[]` when `target` has no
    closed vocabulary at all (`TARGET_REGISTRY.get(target)` is `None` or its
    `.enum` is `None` -- most targets, e.g. free text), or when
    `mapping.column` was not actually profiled -- a missing-column problem
    is `_check_column_exists`'s job; this function does not duplicate it.

    Deliberately does NOT apply `_ground_table`'s own `distinct_overflow`
    caveat treatment. That caveat exists because incomplete sampling cannot
    prove a CITED token is ABSENT from a column (more values may exist past
    the tracked cap, so a "missing" key might still be real). The concern
    here runs the opposite direction: every value this function flags was
    genuinely OBSERVED in the column, so its illegality against a closed
    vocabulary is a certain fact regardless of whether more, as-yet-unseen
    values also exist past the cap -- `distinct_overflow` cannot retroactively
    make an observed-illegal value legal, so it is simply irrelevant here."""
    spec = TARGET_REGISTRY.get(target)
    if spec is None or spec.enum is None:
        return []
    column = profile.columns.get(mapping.column)
    if column is None:
        return []
    legal = {aliased.value for aliased in spec.enum.values}
    cased_observed = {_apply_case(raw, mapping.case) for raw in column.distinct_values}
    illegal = sorted(cased_observed - legal)
    if not illegal:
        return []
    return [
        f"{where}: kind='column' (case={mapping.case!r}) on column {mapping.column!r} passes the "
        f"observed value(s) {illegal} through VERBATIM, but target {target!r}'s closed vocabulary "
        f"only accepts {sorted(legal)} -- a plain 'column' mapping never normalizes a value, so this "
        "will fail at real ingest with a generic pydantic error instead of this specific one. Fix by "
        "setting case='lower'/'upper' if that alone makes every observed value legal, or by using a "
        "'vocabulary' mapping to translate each raw token to a legal value explicitly."
    ]


def _ground_slot(
    issues: list[GroundingIssue],
    slot: str,
    sp: SlotProposal,
    *,
    is_asset: bool,
    proposal: AdapterProposal,
    assets_profile: FileProfile,
    findings_profile: FileProfile,
) -> None:
    own_profile = assets_profile if is_asset else findings_profile
    for column in getattr(sp, "candidate_columns", ()):
        _check_column_exists(issues, slot, column, own_profile)
    if isinstance(sp, SlotUnresolved):
        return

    mapping = sp.mapping
    kind = mapping.kind
    if kind in ("composed", "content_address") and is_asset:
        # Both kinds are legal ONLY on the finding side (config_model.py's
        # own validate_contract refuses either on an asset slot) -- flagged
        # here directly, rather than silently grounding an asset-side
        # citation against the (wrong) findings file and risking a
        # coincidental column-name match reporting false success.
        issues.append(GroundingIssue(slot, "fail", f"{kind} is legal only for a finding.* target, not this asset.* slot"))
        return
    if kind in ("column", "parsed"):
        exists = _check_column_exists(issues, slot, mapping.column, own_profile, optional=mapping.optional)
        if kind == "column" and exists:
            # A "parsed" mapping's output type is already enforced by its
            # own parser (bool/float/date/timestamp/cve_id) -- this concern
            # (a raw column value passed through verbatim to a closed
            # vocabulary target) is specific to "column".
            target = slot.split(".", 1)[1]
            for problem in check_column_mapping_legal_values(slot, target, mapping, own_profile):
                issues.append(GroundingIssue(slot, "fail", problem))
    elif kind == "vocabulary":
        if _check_column_exists(issues, slot, mapping.column, own_profile, optional=mapping.optional):
            _ground_table(issues, slot, mapping.column, list(mapping.table), mapping.case, own_profile)
        _check_alias_contradiction(issues, slot, slot.split(".", 1)[1], mapping.table, mapping.case)
    elif kind == "literal":
        _ground_literal(issues, slot, mapping.value, sp.evidence, own_profile)
    elif kind == "composed":
        for column in _composed_columns(mapping):
            # A placeholder absent from BOTH files simply never contributes
            # (config_model.py's own ComposedMapping docstring) -- not an
            # error. Absent from findings but present in assets is the one
            # real mistake (no cross-file join exists), matching
            # validate_contract's own V16 check exactly.
            if column not in findings_profile.columns and column in assets_profile.columns:
                issues.append(
                    GroundingIssue(
                        slot, "fail",
                        f"cites column {column!r}, which is in {assets_profile.path.name}'s header, not "
                        f"{findings_profile.path.name}'s -- composed has no cross-file join",
                    )
                )
    elif kind == "content_address":
        for column in mapping.columns:
            _check_column_exists(issues, slot, column, findings_profile)
    elif kind == "derived":
        _ground_derivation(issues, slot, mapping.from_, proposal, assets_profile)
        target = slot.split(".", 1)[1]
        derivation = proposal.derived.get(mapping.from_)
        if derivation is not None and len(derivation.outputs) == 1 and derivation.outputs[0] == mapping.output:
            # Single-output derivation: every row's one value directly
            # encodes this target's value, the identical shape
            # _augment_mapped_slot's own DerivedMapping branch requires --
            # a multi-output derivation is out of scope here for the same
            # reason it's out of scope there (see that function's docstring).
            single_output_table = {key: values[0] for key, values in derivation.table.items()}
            _check_alias_contradiction(issues, slot, target, single_output_table, derivation.case)
    elif kind == "default_by":
        _ground_derivation(issues, slot, mapping.keyed_by.from_, proposal, assets_profile)
    elif kind == "not_collected":
        pass  # nothing to ground; gap/absent_fact legality is validate_contract's job (step 7)


def check_grounding(proposal: AdapterProposal, profiles: dict[str, FileProfile]) -> GroundingReport:
    """Step 4. Never raises -- returns every issue found so the human report
    (step 5) can show all of them at once, the same "refuse loudly, name
    every offender" discipline as `ProblemCollector.raise_if_fatal`."""
    issues: list[GroundingIssue] = []
    assets_profile = profiles.get(proposal.meta.assets_filename)
    findings_profile = profiles.get(proposal.meta.findings_filename)
    if assets_profile is None or findings_profile is None:
        raise SchemaInferenceError(
            f"proposal names assets_filename={proposal.meta.assets_filename!r} / "
            f"findings_filename={proposal.meta.findings_filename!r}, not among the profiled file(s) "
            f"{sorted(profiles)} -- profiles must come from the same source the proposal was generated for"
        )

    for target, sp in proposal.asset.items():
        _ground_slot(
            issues, f"asset.{target}", sp, is_asset=True, proposal=proposal,
            assets_profile=assets_profile, findings_profile=findings_profile,
        )
    for target, sp in proposal.finding.items():
        _ground_slot(
            issues, f"finding.{target}", sp, is_asset=False, proposal=proposal,
            assets_profile=assets_profile, findings_profile=findings_profile,
        )

    _check_column_exists(issues, "asset_grouping.key", proposal.asset_grouping.key, assets_profile)
    if proposal.asset_grouping.order_by is not None:
        _check_column_exists(
            issues, "asset_grouping.order_by", proposal.asset_grouping.order_by.column, assets_profile,
            optional=not proposal.asset_grouping.order_by.required,
        )
    if proposal.enrichment is not None:
        _ground_enrichment(issues, proposal.enrichment, findings_profile)

    for filename, entries in proposal.unmapped_columns.items():
        profile = profiles.get(filename)
        if profile is None:
            issues.append(GroundingIssue(f"unmapped_columns[{filename}]", "fail", f"{filename!r} is not among the profiled file(s) {sorted(profiles)}"))
            continue
        for column in entries:
            _check_column_exists(issues, f"unmapped_columns[{filename}]", column, profile)

    return GroundingReport(issues=issues)


def unresolved_slots(proposal: AdapterProposal) -> list[str]:
    out = [f"asset.{t}" for t, sp in proposal.asset.items() if isinstance(sp, SlotUnresolved)]
    out += [f"finding.{t}" for t, sp in proposal.finding.items() if isinstance(sp, SlotUnresolved)]
    return sorted(out)


# ---------------------------------------------------------------------------
# Registry-backed alias resolution (deterministic, no LLM): closes exactly
# the gap that produced an incomplete `role` table and an unresolved
# `criticality` on the real northgate_flat_2.csv case this module's schema
# registry (`adapters/schema_registry.py`) exists to fix -- the model had a
# real column and real values, but no PUBLISHED meaning or known spelling to
# ground a mapping in. `REGISTRY_BACKED_TARGETS` (role/environment/
# data_sensitivity/criticality) are ALL asset-only targets (none appear in
# `FINDING_SLOTS`), so only `proposal.asset` is ever touched here.
# ---------------------------------------------------------------------------


#: Every REGISTRY_BACKED_TARGETS member except `role` has a
#: NOT_COLLECTED_DEFAULTS entry (`GAP_LEGAL_TARGETS`), so `blank="gap"` is
#: the legal, honest policy for a code-derived table on those three. `role`
#: has none -- it is the one `EXCLUDING_TARGETS` member -- so a promoted
#: role mapping instead uses `blank="fatal"`, the identical choice both real
#: confirmed contracts make for this target (e.g. bluepeak-gen.json's own
#: `asset.role`).
def _promoted_blank_policy(target: str) -> str:
    return "fatal" if target in EXCLUDING_TARGETS else "gap"


def _augment_mapped_slot(
    target: str, mapping: Mapping, derived: dict[str, Derivation], assets_profile: FileProfile
) -> Mapping | None:
    """TABLE AUGMENTATION for one already-`SlotMapped` slot. Returns a NEW
    mapping node for the slot itself when its OWN table gained entries
    (a `VocabularyMapping`), or `None` when nothing changed there --
    including the `DerivedMapping` case, where any augmentation happens to
    `derived[mapping.from_]` (mutated in place in the caller-owned `derived`
    dict) rather than to the slot's own mapping node, which never changes.
    Never overwrites an existing table entry with a different value: only
    keys ABSENT from the table are ever added -- a genuine disagreement is
    `check_grounding`'s new alias-contradiction check's job, not this
    function's."""
    if isinstance(mapping, VocabularyMapping):
        column = assets_profile.columns.get(mapping.column)
        if column is None:
            return None
        additions = alias_table_for_column(target, column.distinct_values, mapping.case)
        missing = {k: v for k, v in additions.items() if k not in mapping.table}
        if not missing:
            return None
        merged_table = dict(mapping.table)
        merged_table.update(missing)
        return mapping.model_copy(update={"table": merged_table})

    if isinstance(mapping, DerivedMapping):
        derivation = derived.get(mapping.from_)
        # A multi-output derivation can't be safely augmented here: adding a
        # new row would require inventing a value for every OTHER output
        # too, which is exactly the guessing this module exists to avoid --
        # only a single-output derivation (this target's own table, in every
        # sense that matters) is in scope.
        if derivation is None or len(derivation.outputs) != 1 or derivation.outputs[0] != mapping.output:
            return None
        column = assets_profile.columns.get(derivation.column)
        if column is None:
            return None
        additions = alias_table_for_column(target, column.distinct_values, derivation.case)
        missing = {k: [v] for k, v in additions.items() if k not in derivation.table}
        if not missing:
            return None
        merged_table = dict(derivation.table)
        merged_table.update(missing)
        derived[mapping.from_] = derivation.model_copy(update={"table": merged_table})
        return None

    return None


def _promote_unresolved_slot(target: str, slot: SlotUnresolved, assets_profile: FileProfile) -> SlotMapped | None:
    """SLOT PROMOTION for one `SlotUnresolved` target. Promotes ONLY when
    `full_alias_coverage` achieves a COMPLETE table for EXACTLY ONE of
    `slot.candidate_columns` -- more than one candidate independently
    achieving full coverage is ambiguous, so this stays conservative and
    promotes neither. A candidate column absent from `assets_profile`
    (a hallucinated citation) is simply skipped, never treated as a match.

    Only `case="exact"` is tried: a promoted slot has no model-declared
    `case` to defer to (it was never mapped at all), and the registry's own
    alias spellings are stored in their natural, real-world casing, which is
    also how `probe.py` records a column's own observed distinct values --
    so this is the correct default, not merely the simplest one. A source
    whose real values need `case="lower"`/`"upper"` to match stays
    unresolved, exactly as it would with no registry at all -- a
    conservative shortfall, not a silent wrong answer."""
    achieving: list[tuple[str, dict[str, Any]]] = []
    for column_name in slot.candidate_columns:
        column = assets_profile.columns.get(column_name)
        if column is None:
            continue
        table = full_alias_coverage(target, column.distinct_values, "exact")
        if table is not None:
            achieving.append((column_name, table))
    if len(achieving) != 1:
        return None

    column_name, table = achieving[0]
    mapping = VocabularyMapping(
        kind="vocabulary",
        column=column_name,
        case="exact",
        blank=_promoted_blank_policy(target),
        optional=False,
        table=table,
    )
    return SlotMapped(
        status="mapped",
        mapping=mapping,
        confidence=1.0,
        evidence=SlotEvidence(
            columns_cited=[column_name],
            sample_values_cited=sorted(table)[:6],
            note="resolved via schema registry alias table, no model judgment",
        ),
    )


def _apply_registry_aliases(proposal: AdapterProposal, profiles: dict[str, FileProfile]) -> AdapterProposal:
    """Deterministic, LLM-free pass over the four `REGISTRY_BACKED_TARGETS`
    slots in `proposal.asset` -- table augmentation for an already-mapped
    slot, promotion for a genuinely unresolved one (see
    `_augment_mapped_slot`/`_promote_unresolved_slot`'s own docstrings for
    the two mechanisms). Called exactly ONCE inside `propose_contract`,
    immediately before `check_grounding` -- the one call site that reaches
    both the strict path (`rhino adapt propose`/`--from-proposal`) and, via
    `web/jobs.py`'s `_run_ingest_propose` reusing the identical
    `propose_contract` call, the provisional drop-a-CSV path too.

    Runs unconditionally for BOTH the fresh-LLM branch and the
    `from_proposal` branch -- unlike `_check_mapped_slots_legal`, which is
    deliberately skipped for `from_proposal` (see that call site's own
    comment: a hand-fixed file must still be loadable even when it carries
    a legality violation, so it can reach the degrade-on-validation-failure
    path). Alias resolution never RAISES and never REMOVES anything a human
    or model already decided -- it only adds coverage that was missing --
    so there is nothing unsafe about running it unconditionally against
    already-reviewed input.

    Returns a NEW `AdapterProposal` via `.model_copy(update=...)` -- never
    mutates `proposal` in place, matching this module's existing immutable-
    update idiom (see `_assemble_and_validate`'s own `.model_copy` calls)."""
    assets_profile = profiles.get(proposal.meta.assets_filename)
    if assets_profile is None:
        return proposal  # nothing to ground against -- leave the proposal untouched

    new_asset: dict[str, SlotProposal] = dict(proposal.asset)
    new_derived: dict[str, Derivation] = dict(proposal.derived)

    for target in REGISTRY_BACKED_TARGETS:
        slot = new_asset.get(target)
        if slot is None:
            continue
        if isinstance(slot, SlotMapped):
            new_mapping = _augment_mapped_slot(target, slot.mapping, new_derived, assets_profile)
            if new_mapping is not None:
                new_asset[target] = slot.model_copy(update={"mapping": new_mapping})
        else:
            promoted = _promote_unresolved_slot(target, slot, assets_profile)
            if promoted is not None:
                new_asset[target] = promoted

    return proposal.model_copy(update={"asset": new_asset, "derived": new_derived})


# ---------------------------------------------------------------------------
# Assembly (deterministic, no LLM): a complete, grounded proposal -> Contract.
# ---------------------------------------------------------------------------


def _hash_header(columns: list[str]) -> str:
    """Informational provenance only -- `configured.py` never verifies this
    against anything; only `header.assets.columns`/`.findings.columns` (the
    ordered name list) is checked at ingest time (`_check_header_mode`).
    Recipe: sha256 of the column names newline-joined, so two headers that
    differ only in order or a renamed column produce different digests."""
    return "sha256:" + hashlib.sha256(("\n".join(columns) + "\n").encode("utf-8")).hexdigest()


def _assemble_and_validate(
    proposal: AdapterProposal,
    profiles: dict[str, FileProfile],
    asset_mappings: dict[str, Mapping],
    finding_mappings: dict[str, Mapping],
    mapping_confidence: dict[str, float],
    *,
    generator: Generator,
    generated_at: str,
) -> Contract:
    """The shared tail of `assemble_contract`/`assemble_provisional_contract`
    -- builds `Header`/`Source`, recomputes `not_collected` (V09), and runs
    the real `validate_contract` as the final safety net, exactly as this
    function's own body always has. The two callers differ ONLY in how
    `asset_mappings`/`finding_mappings`/`mapping_confidence` were built
    (every slot resolved by the model, vs. some auto-filled with a legal
    placeholder) -- everything after that point is identical, and drifting
    the two would silently reopen exactly the gaps an adversarial review of
    this module already found and closed once (see the validate_contract
    call below's own comment)."""
    assets_profile = profiles[proposal.meta.assets_filename]
    findings_profile = profiles[proposal.meta.findings_filename]

    unmapped_columns = {
        filename: {col: UnmappedColumnEntry(disposition=e.disposition, reason=e.reason) for col, e in entries.items()}
        for filename, entries in proposal.unmapped_columns.items()
    }

    header = Header(
        mode="declared",
        assets=HeaderSpec(columns=list(dict.fromkeys(assets_profile.header)), sha256=_hash_header(assets_profile.header)),
        findings=(
            None
            if proposal.meta.source_layout == "single_file"
            else HeaderSpec(columns=list(dict.fromkeys(findings_profile.header)), sha256=_hash_header(findings_profile.header))
        ),
    )
    source = Source(
        layout=proposal.meta.source_layout,
        assets_filename=proposal.meta.assets_filename,
        findings_filename=proposal.meta.findings_filename,
        # detect_encoding (ingest.py) can return "utf-32" on a BOM this Source.encoding Literal has
        # no member for; falling back to "auto" there is honest (nothing this contract declares
        # contradicts what open_csv would detect fresh) rather than a Contract construction error
        # over a provenance-only mismatch.
        encoding=assets_profile.encoding if assets_profile.encoding in _VALID_SOURCE_ENCODINGS else "auto",
    )

    contract = Contract(
        config_schema_version=CONFIG_SCHEMA_VERSION,
        version=1,
        format=proposal.meta.format,
        description=proposal.meta.description,
        generated_at=generated_at,
        generator=generator,
        mapping_confidence=mapping_confidence,
        source=source,
        header=header,
        derived=proposal.derived,
        asset=asset_mappings,
        finding=finding_mappings,
        enrichment=proposal.enrichment,
        asset_grouping=proposal.asset_grouping,
        finding_dedup=proposal.finding_dedup,
        unmapped_columns=unmapped_columns,
        not_collected=NotCollectedDerived(),
        review=Review(),
    )
    # V09: recompute not_collected the identical way validate_contract will,
    # so the freshly assembled contract already agrees with itself on the
    # first pass rather than failing that one check needlessly.
    assets_header_set = set(assets_profile.header)
    findings_header_set = set(findings_profile.header)
    expected_not_collected = _compute_not_collected(contract, assets_header_set, findings_header_set)
    contract = contract.model_copy(update={"not_collected": expected_not_collected})

    # Grounding only checks that CITED columns/table-keys are real; it has no
    # way to know a vocabulary VALUE is illegal for its target, that
    # asset_grouping.union_fields/finding_dedup.content_targets are
    # structurally sound, or that a mapping kind sits on the wrong side (an
    # asset-only kind is not asset/finding-checked by grounding at all) --
    # exactly the gaps an adversarial review of this module found. Running
    # the REAL, already-exhaustive validator here, before ever calling this
    # "assembled" to a caller, is what makes "complete and grounded" also
    # mean "actually valid" rather than merely "the parts we checked looked
    # fine". A failure here is reported the same as any other assembly
    # refusal -- not silently downgraded to a caveat.
    #
    # V18 (attestations) is deliberately checked against a PLACEHOLDER copy,
    # never the real `contract`: attestations are a confirm-time human act
    # (config_io's own "Order, which is not negotiable" -- attestations are
    # merged in, THEN validate_contract runs, in `rhino adapt confirm`), so a
    # freshly-proposed contract can never carry one yet. Without this, any
    # proposal using `content_address` for finding_id (exactly the case it
    # exists for: no natural id column) would fail V18 unconditionally and
    # could never be assembled at all -- confirmed by running this against a
    # real source. The placeholder attestations exist only in the copy
    # handed to `validate_contract` here; the `contract` this function
    # returns and the caller writes to disk carries none, so `rhino adapt
    # confirm` still correctly demands the real ones later.
    headers = {proposal.meta.assets_filename: assets_profile.header}
    if proposal.meta.findings_filename != proposal.meta.assets_filename:
        headers[proposal.meta.findings_filename] = findings_profile.header
    placeholder_attestations = [
        Attestation(item=item, text="propose-time structural check only -- not a real attestation", at=generated_at)
        for item in missing_attestations(contract)
    ]
    check_contract = contract.model_copy(update={"attestations": list(contract.attestations) + placeholder_attestations})
    try:
        validate_contract(check_contract, headers)
    except ContractValidationError as exc:
        raise ProposalIncompleteError(
            f"every slot was mapped and grounded, but the assembled contract fails the real contract "
            f"validator (the same check `rhino adapt confirm` would run): {exc}",
            problems=exc.problems,
        ) from exc

    return contract


def assemble_contract(
    proposal: AdapterProposal,
    profiles: dict[str, FileProfile],
    report: GroundingReport,
    *,
    generator: Generator,
    generated_at: str,
) -> Contract:
    """Refuses (`ProposalIncompleteError`) unless every slot is `mapped` AND
    grounding reports zero failures -- a caveat alone never blocks this.
    Never called with a report computed against different profiles than
    `profiles` (the caller, `propose_contract`, always computes both from
    the same profiling pass). See `assemble_provisional_contract` for the
    sibling that degrades instead of refusing -- this function's own
    strictness is unchanged by that sibling existing."""
    blocking = sorted(set(unresolved_slots(proposal)) | {i.slot for i in report.failures})
    if blocking:
        raise ProposalIncompleteError(
            f"{len(blocking)} slot(s)/reference(s) cannot be assembled: {blocking}. Resolve them by hand "
            "in the saved proposal file, then re-run with --from-proposal."
        )

    asset_mappings: dict[str, Mapping] = {t: sp.mapping for t, sp in proposal.asset.items()}
    finding_mappings: dict[str, Mapping] = {t: sp.mapping for t, sp in proposal.finding.items()}
    # `blocking` above already guarantees every slot is `SlotMapped` (an
    # unresolved one would have refused already), so `.confidence` is
    # always present here -- carried into the Contract as audit trail
    # (Contract.mapping_confidence's own docstring), never read by
    # configured.py's engine. This is the ONLY place `.confidence` survives
    # past this function -- assemble_contract's own `asset_mappings`/
    # `finding_mappings` above already discard everything else `SlotMapped`
    # carried (`.evidence`), and that discard is deliberate, not an oversight
    # this line is quietly working around.
    mapping_confidence = {
        f"{section}.{t}": sp.confidence
        for section, slots in (("asset", proposal.asset), ("finding", proposal.finding))
        for t, sp in slots.items()
    }
    return _assemble_and_validate(
        proposal, profiles, asset_mappings, finding_mappings, mapping_confidence,
        generator=generator, generated_at=generated_at,
    )


#: `role`'s legal placeholder when its whole slot is unresolved -- never a
#: guess about any real asset, because `impact_composite` NEUTRALIZES (drops
#: entirely, never reads) any axis in `ProvisionalAssemblyNotes
#: .neutralized_axes`, and `role` is always in that set whenever this value
#: is used. `role` has no `NOT_COLLECTED_DEFAULTS` entry (unlike
#: criticality/environment/data_sensitivity/internet_exposed) -- see
#: `configured.NOT_COLLECTED_DEFAULTS`'s own docstring -- so `not_collected`
#: is not just illegal for it (`GAP_LEGAL_TARGETS`), it would KeyError in the
#: engine. A `literal` mapping is the one grammar-legal way to give it SOME
#: concrete, schema-valid value without asserting a fact about any asset;
#: "workstation" is arbitrary among the 15 legal `AssetRole` values -- any
#: would do, since none of them is ever read for scoring here.
PROVISIONAL_ROLE_PLACEHOLDER = "workstation"

#: Targets whose whole-slot absence CANNOT be represented honestly at all --
#: no `not_collected` default (identity fields are always `blank="fatal"`;
#: `scanner_severity` has no NOT_COLLECTED_DEFAULTS entry and, unlike role,
#: no neutralize path either: severity_base is a Threat/Impact BASE VALUE,
#: not a weighted composite term, so there is nothing to drop it from and
#: renormalize around -- see scoring.impact_composite's own docstring for
#: why neutralizing only makes sense for a weighted-sum term). A provisional
#: assembly refuses (hard stop) rather than assembling around any of these,
#: exactly like assemble_contract does for every slot today -- this is a
#: DELIBERATELY NARROWER set than "everything not otherwise handled," not an
#: oversight: scanner_severity's real-world impact varies per finding (NVD
#: may cover the gap for some), which is a materially different, harder
#: problem than a uniformly-missing field -- CLAUDE.md's own plan for this
#: feature names it as explicitly deferred, not solved here.
_PROVISIONAL_HARD_STOP_TARGETS = frozenset({"asset_id", "hostname", "finding_id", "cve_id", "scanner_severity"})


def _provisional_placeholder_for(target: str) -> "tuple[Mapping, bool] | None":
    """The per-target provisional-degrade decision -- shared by BOTH cases
    that need it: (1) a slot the model left genuinely `unresolved` (the
    main loop below), and (2) a slot the model DID map, but whose mapping
    individually fails `validate_contract` (an illegal `blank` policy, a
    misplaced `timestamp` parser, ...) -- see `_degrade_invalid_slots`. For
    this function's purposes the two are the same problem: no mapping this
    run can honestly trust exists for this target, so the identical
    ordered fallback applies to both. Returns `(placeholder mapping,
    whether to neutralize this axis for scoring)`, or `None` when no legal
    placeholder exists for this target at all -- a hard stop, in both
    callers. See `assemble_provisional_contract`'s own docstring for the
    ordered rule list this implements."""
    if target in _PROVISIONAL_HARD_STOP_TARGETS:
        return None
    if target == "role":
        return LiteralMapping(kind="literal", value=PROVISIONAL_ROLE_PLACEHOLDER), True
    if target in GAP_LEGAL_TARGETS:
        return NotCollectedMapping(kind="not_collected"), (target in IMPACT_AXIS_TARGETS or target in THREAT_AXIS_TARGETS)
    if target in ABSENT_FACT_LEGAL_TARGETS:
        return LiteralMapping(kind="literal", value=""), False
    return None


_SLOT_PROBLEM_PATTERN = re.compile(r"^(asset|finding)\.([A-Za-z0-9_]+):")


def _slot_scoped_problems(problems: tuple[str, ...]) -> "tuple[dict[str, list[str]], list[str]]":
    """Split a `ProposalIncompleteError.problems` tuple into (a) violations
    attributable to exactly one `asset.<target>`/`finding.<target>` slot --
    keyed by that slot name -- and (b) every other, cross-cutting violation
    (a `not_collected`/V09 mismatch, a missing attestation, a digest
    mismatch, ...) that dropping one mapping cannot fix. `validate_contract`
    always prefixes a per-slot violation with this exact `"asset.X: "`/
    `"finding.X: "` text (its own `where` variable, used verbatim as every
    per-slot problem's prefix -- see `check_slot_mapping_legality`) --
    reused here rather than a second classification scheme, so this stays
    in sync with whatever validate_contract actually checks, including any
    new per-slot rule added later."""
    by_slot: dict[str, list[str]] = {}
    unattributed: list[str] = []
    for problem in problems:
        match = _SLOT_PROBLEM_PATTERN.match(problem)
        if match:
            by_slot.setdefault(f"{match.group(1)}.{match.group(2)}", []).append(problem)
        else:
            unattributed.append(problem)
    return by_slot, unattributed


def _dropped_slot_column(mapping: "Mapping") -> str | None:
    """The column a dropped mapping used to read, if it read one at all.
    Every mapping kind `check_slot_mapping_legality` can flag -- column,
    vocabulary, parsed -- carries a plain `.column` attribute; every other
    kind either isn't blank-bearing or isn't a `parsed` mapping, so it can
    never be the offending mapping `_degrade_invalid_slots` is degrading."""
    return getattr(mapping, "column", None)


def _degrade_invalid_slots(
    exc: "ProposalIncompleteError",
    asset_mappings: "dict[str, Mapping]",
    finding_mappings: "dict[str, Mapping]",
    mapping_confidence: dict[str, float],
    neutralized_axes: set[str],
    dropped: set[str],
    dropped_columns: dict[str, set[str]],
    assets_filename: str,
    findings_filename: str,
) -> str | None:
    """The sibling of the main per-slot loop below, for a `SlotMapped`
    mapping that turns out to be individually illegal rather than genuinely
    unresolved. Mutates `asset_mappings`/`finding_mappings`/
    `mapping_confidence`/`neutralized_axes`/`dropped`/`dropped_columns` in
    place; returns `None` on success, or a human-readable hard-stop reason
    when a violation cannot be attributed to a single slot (a whole-contract
    problem no per-mapping change can fix) or a named slot has no legal
    placeholder at all (`_provisional_placeholder_for` returns `None`).

    Validates every named slot has a legal placeholder BEFORE mutating
    anything, so a hard stop never leaves `asset_mappings`/`finding_mappings`
    partially degraded for no benefit."""
    by_slot, unattributed = _slot_scoped_problems(exc.problems)
    if not by_slot or unattributed:
        return str(exc)

    resolved: dict[str, "tuple[Mapping, bool]"] = {}
    for slot in sorted(by_slot):
        _, target = slot.split(".", 1)
        placeholder = _provisional_placeholder_for(target)
        if placeholder is None:
            return (
                f"{slot} individually fails contract validation and has no legal provisional "
                f"placeholder: {'; '.join(by_slot[slot])}"
            )
        resolved[slot] = placeholder

    mapping_dicts = {"asset": asset_mappings, "finding": finding_mappings}
    filenames = {"asset": assets_filename, "finding": findings_filename}
    for slot, (new_mapping, neutralize) in resolved.items():
        section, target = slot.split(".", 1)
        old_mapping = mapping_dicts[section][target]
        column = _dropped_slot_column(old_mapping)
        if column is not None:
            dropped_columns.setdefault(filenames[section], set()).add(column)
        mapping_dicts[section][target] = new_mapping
        mapping_confidence.pop(slot, None)
        dropped.add(slot)
        if neutralize:
            neutralized_axes.add(target)
    return None


_ORPHANED_COLUMN_PATTERN = re.compile(
    r"^(?P<filename_repr>'(?:[^'\\]|\\.)*'): column\(s\) (?P<cols>\[.*\]) are neither mapped nor in unmapped_columns$"
)


def _reconcile_orphaned_columns(
    problems: tuple[str, ...], dropped_columns: dict[str, set[str]]
) -> "dict[str, dict[str, ProposedUnmappedColumn]] | None":
    """Dropping a mapping that read a real column (`_degrade_invalid_slots`)
    can orphan that column: `validate_contract`'s own V08 rule refuses a
    contract with a column neither mapped nor listed in `unmapped_columns`.
    This recovers ONLY that exact, predictable side effect of OUR OWN drop
    -- every remaining problem must be a V08 "neither mapped nor in
    unmapped_columns" message, and every column it names must be one this
    pass itself just orphaned (`dropped_columns`). Anything else (a
    genuinely new problem, or a column this pass has no explanation for) is
    refused, not guessed at -- this is a mechanical accounting fix for a
    column we know the story of, never a judgment call about a column we
    don't. Returns new `unmapped_columns` entries to merge in, or `None` if
    this failure isn't that exact recoverable shape."""
    additions: "dict[str, dict[str, ProposedUnmappedColumn]]" = {}
    for problem in problems:
        match = _ORPHANED_COLUMN_PATTERN.match(problem)
        if not match:
            return None
        try:
            filename = ast.literal_eval(match.group("filename_repr"))
            columns = ast.literal_eval(match.group("cols"))
        except (ValueError, SyntaxError):
            return None
        known = dropped_columns.get(filename, set())
        if not columns or any(c not in known for c in columns):
            return None
        for column in columns:
            additions.setdefault(filename, {})[column] = ProposedUnmappedColumn(
                disposition="deliberately_dropped",
                reason=(
                    "this column fed a mapping that was dropped during provisional assembly because "
                    "that mapping individually failed contract validation"
                ),
                profile_cited="(provisional auto-drop -- no human-reviewed profile citation)",
            )
    return additions or None


@dataclass(frozen=True)
class ProvisionalAssemblyNotes:
    """What `assemble_provisional_contract` had to do to produce a
    contract that never blocks on an unresolved slot -- read by the
    provisional-run path (web/jobs.py) to mark the resulting plan and by
    `export.py` to show the reader what was neutralized, never by
    `configured.py`'s engine (this is reporting, the same "audit trail, not
    input to any decision" role `Contract.generator` already has)."""

    #: Targets scoring.py must treat as absent for every asset in this run
    #: (`scoring.IMPACT_AXIS_TARGETS`/`THREAT_AXIS_TARGETS` -- a subset of
    #: those two sets, never anything outside them). Empty when nothing
    #: needed it.
    neutralized_axes: frozenset[str] = frozenset()
    #: `"asset.<target>"`/`"finding.<target>"` slot names whose ORIGINAL
    #: `SlotMapped` mapping was dropped and replaced with a placeholder
    #: because it individually failed `validate_contract` (an illegal
    #: `blank` policy, a misplaced `timestamp` parser, ...) --
    #: `_degrade_invalid_slots`' own doing. Distinct from `neutralized_axes`:
    #: not every dropped slot is a scoring axis (e.g. `finding.detected_date`
    #: is dropped here but never fed scoring in the first place), so this is
    #: the honest "what did we actually throw away" report the coverage
    #: summary needs, independent of whether scoring cares. Empty when
    #: nothing needed it -- including every unresolved-slot degrade, which
    #: was never something the model actually mapped in the first place.
    invalid_mappings_dropped: frozenset[str] = frozenset()
    #: Set only when assembly could not proceed at all -- a target in
    #: `_PROVISIONAL_HARD_STOP_TARGETS` was unresolved, or the real
    #: `validate_contract` safety net refused for an unrelated reason. When
    #: set, the contract this call returns is `None`; when `None`, it isn't.
    hard_stop_reason: str | None = None


def assemble_provisional_contract(
    proposal: AdapterProposal,
    profiles: dict[str, FileProfile],
    report: GroundingReport,
    *,
    generator: Generator,
    generated_at: str,
) -> tuple[Contract | None, ProvisionalAssemblyNotes]:
    """The degrade-rather-than-block sibling of `assemble_contract` (see its
    own docstring), built for the provisional-run path (CLAUDE.md's "drop a
    CSV, get a plan" spec) -- never called from `rhino adapt propose`/the
    confirm flow, which stay exactly as strict as `assemble_contract` always
    was. Never raises for an incomplete proposal (that's the whole point);
    returns `(None, notes-with-a-reason)` instead, exactly the "refuse
    loudly, but as data, not an exception" shape `check_grounding`/
    `ConfiguredAdapter`'s own probing mode already use elsewhere in this
    codebase.

    A real grounding FAILURE (a cited column/table-key that isn't real, or a
    hallucinated value) is a data-quality problem, not a coverage gap -- it
    stays a hard stop here exactly like it already is in `assemble_contract`,
    never silently degraded around.

    Two, structurally different things get the degrade treatment below,
    both resolved through the identical `_provisional_placeholder_for`
    ordered fallback:

    (A) A genuinely UNRESOLVED slot (the model proposed no mapping at all)
        -- the main loop, immediately below.
    (B) A `SlotMapped` slot whose mapping individually fails
        `validate_contract` on the FIRST assembly attempt (an illegal
        `blank` policy, e.g. `blank='gap'` on `role`, which has no
        `NOT_COLLECTED_DEFAULTS` entry; a misplaced `timestamp` parser,
        legal only inside `asset_grouping.order_by`) -- a fully-mapped,
        fully-grounded proposal can still reach this: grounding only checks
        that a CITED column/table-key is real, never that a mapping's
        `blank`/`parser` choice is legal for its target (`check_grounding`'s
        own docstring). `_degrade_invalid_slots` handles this, reusing the
        SAME `_provisional_placeholder_for` fallback as case (A) -- for
        this purpose a mapped-but-illegal slot is exactly as unusable as
        one the model never proposed. Dropping a column-reading mapping can
        orphan the column it used to read (`validate_contract`'s own V08
        column-accounting rule); `_reconcile_orphaned_columns` recovers
        ONLY that exact, predictable side effect of our own drop, never any
        other new problem.

    Ordered fallback (`_provisional_placeholder_for`), applied to both (A)
    and (B):
    1. In `_PROVISIONAL_HARD_STOP_TARGETS` (an identity field, or
       scanner_severity) -- hard stop, no contract, no guessing.
    2. `role` specifically -- `literal(PROVISIONAL_ROLE_PLACEHOLDER)`,
       neutralized (never read for scoring).
    3. In `GAP_LEGAL_TARGETS` -- `not_collected` (the code-level default is
       legal and constructs a real contract; a target also in
       `IMPACT_AXIS_TARGETS`/`THREAT_AXIS_TARGETS` -- criticality,
       environment, data_sensitivity, internet_exposed -- is ADDITIONALLY
       neutralized, so that default value is never actually trusted for
       scoring, only used to keep the contract structurally legal).
    4. In `ABSENT_FACT_LEGAL_TARGETS` (free text, e.g. product/evidence) --
       `literal("")`, the schema's own "blank is the fact" encoding. Never
       neutralized -- these never feed scoring."""
    if report.failures:
        failing = sorted({i.slot for i in report.failures})
        return None, ProvisionalAssemblyNotes(
            hard_stop_reason=(
                f"{len(failing)} slot(s)/reference(s) failed grounding (a real data-quality problem, not a "
                f"coverage gap): {failing}. Resolve them by hand in the saved proposal file, then re-run with "
                "--from-proposal."
            )
        )

    asset_mappings: dict[str, Mapping] = {}
    finding_mappings: dict[str, Mapping] = {}
    mapping_confidence: dict[str, float] = {}
    neutralized_axes: set[str] = set()
    hard_stop_targets: list[str] = []

    for section, slots, mapping_dict in (
        ("asset", proposal.asset, asset_mappings),
        ("finding", proposal.finding, finding_mappings),
    ):
        for target, sp in slots.items():
            if isinstance(sp, SlotMapped):
                mapping_dict[target] = sp.mapping
                mapping_confidence[f"{section}.{target}"] = sp.confidence
                continue
            # SlotUnresolved from here on.
            placeholder = _provisional_placeholder_for(target)
            if placeholder is None:
                # No legal placeholder exists for this target at all --
                # narrower than _PROVISIONAL_HARD_STOP_TARGETS only in that
                # nothing in this schema is actually expected to land here
                # today (every real ASSET_SLOTS/FINDING_SLOTS member is
                # covered by one of _provisional_placeholder_for's
                # branches); kept as an honest refusal rather than a silent
                # `pass` in case the schema ever grows a field none of them
                # cover.
                hard_stop_targets.append(f"{section}.{target}")
                continue
            mapping, neutralize = placeholder
            mapping_dict[target] = mapping
            if neutralize:
                neutralized_axes.add(target)

    if hard_stop_targets:
        return None, ProvisionalAssemblyNotes(
            hard_stop_reason=(
                f"{len(hard_stop_targets)} slot(s) have no source signal and no legal placeholder: "
                f"{sorted(hard_stop_targets)}. This source cannot be scored, even provisionally, without one of "
                "these -- resolve them by hand in the saved proposal file, then re-run with --from-proposal, or "
                "use the browser slot-resolution form."
            )
        )

    dropped_slots: set[str] = set()
    dropped_columns: dict[str, set[str]] = {}
    try:
        contract = _assemble_and_validate(
            proposal, profiles, asset_mappings, finding_mappings, mapping_confidence,
            generator=generator, generated_at=generated_at,
        )
    except ProposalIncompleteError as exc:
        # Case (B), first attempt failed: at least one FULLY MAPPED slot is
        # individually illegal. Degrade exactly the slot(s) validate_contract
        # named and retry once with the identical proposal otherwise
        # unchanged.
        hard_stop = _degrade_invalid_slots(
            exc, asset_mappings, finding_mappings, mapping_confidence, neutralized_axes,
            dropped_slots, dropped_columns, proposal.meta.assets_filename, proposal.meta.findings_filename,
        )
        if hard_stop is not None:
            return None, ProvisionalAssemblyNotes(hard_stop_reason=hard_stop)

        retry_proposal = proposal
        try:
            contract = _assemble_and_validate(
                retry_proposal, profiles, asset_mappings, finding_mappings, mapping_confidence,
                generator=generator, generated_at=generated_at,
            )
        except ProposalIncompleteError as exc2:
            # The degrade above can orphan the column(s) the dropped
            # mapping(s) used to read (validate_contract's own V08 column-
            # accounting rule) -- recover ONLY that exact, predictable side
            # effect of our own drop, then retry once more.
            additions = _reconcile_orphaned_columns(exc2.problems, dropped_columns)
            if additions is None:
                return None, ProvisionalAssemblyNotes(hard_stop_reason=str(exc2))

            merged_unmapped = {filename: dict(cols) for filename, cols in retry_proposal.unmapped_columns.items()}
            for filename, cols in additions.items():
                merged_unmapped.setdefault(filename, {}).update(cols)
            retry_proposal = retry_proposal.model_copy(update={"unmapped_columns": merged_unmapped})
            try:
                contract = _assemble_and_validate(
                    retry_proposal, profiles, asset_mappings, finding_mappings, mapping_confidence,
                    generator=generator, generated_at=generated_at,
                )
            except ProposalIncompleteError as exc3:
                return None, ProvisionalAssemblyNotes(hard_stop_reason=str(exc3))

    return contract, ProvisionalAssemblyNotes(
        neutralized_axes=frozenset(neutralized_axes), invalid_mappings_dropped=frozenset(dropped_slots),
    )


# ---------------------------------------------------------------------------
# Layout resolution -- deterministic, never guessed (module docstring).
# ---------------------------------------------------------------------------


def _validate_format_name(name: str) -> None:
    """The same three checks `Contract._format_pattern_and_reserved` runs,
    mirrored here so a bad `name` is refused before profiling the source or
    spending an LLM call on it -- not surfaced later as a raw pydantic
    error out of `assemble_contract`, after the expensive part already ran."""
    if not _FORMAT_PATTERN.match(name):
        raise SchemaInferenceError(f"{name!r} does not match {_FORMAT_PATTERN.pattern!r}")
    if name in BUILTIN_ADAPTER_FORMATS:
        raise SchemaInferenceError(f"{name!r} collides with a built-in adapter format {sorted(BUILTIN_ADAPTER_FORMATS)}")
    if name in RESERVED_PROVENANCE_LABELS:
        raise SchemaInferenceError(f"{name!r} is a reserved provenance label {sorted(RESERVED_PROVENANCE_LABELS)}")


def _resolve_layout(
    profiles: dict[str, FileProfile], assets_filename: str | None, findings_filename: str | None
) -> tuple[Literal["single_file", "two_file"], str, str]:
    names = sorted(profiles)
    if len(names) == 1:
        return "single_file", names[0], names[0]
    if assets_filename and findings_filename:
        for name in (assets_filename, findings_filename):
            if name not in profiles:
                raise SchemaInferenceError(f"{name!r} is not among the profiled file(s) {names}")
        return "two_file", assets_filename, findings_filename
    raise SchemaInferenceError(
        f"found {len(names)} CSV file(s) {names} -- ambiguous which is assets and which is findings. "
        "Pass --assets-file NAME --findings-file NAME to disambiguate."
    )


# ---------------------------------------------------------------------------
# Prompt construction and the LLM call itself.
# ---------------------------------------------------------------------------


def _column_summary(col: ColumnProfile, row_count: int) -> str:
    length = f"{col.min_length}-{col.max_length}" if col.min_length is not None else "--"
    distinct = f"{col.distinct_count}{'+' if col.distinct_overflow else ''}"
    samples = ", ".join(col.sample_values[:6])
    return (
        f"  - {col.name}: blank {col.blank}/{row_count}, distinct {distinct}, len {length}, "
        f"looks_like [{', '.join(col.looks_like) or 'none'}], samples: {samples or 'none'}"
    )


def _render_profile(profile: FileProfile) -> str:
    lines = [f"File {profile.path.name!r} -- {profile.row_count} row(s), encoding {profile.encoding!r}:"]
    lines += [_column_summary(profile.columns[name], profile.row_count) for name in dict.fromkeys(profile.header)]
    return "\n".join(lines)


def _sample_rows(profile: FileProfile, n: int) -> str:
    """A bounded, literal read of at most `n` data rows -- for prompt
    context only, never for grounding (which stays on `probe.py`'s already
    bounded, full-file accumulation, per CLAUDE.md Section 1)."""
    try:
        with profile.path.open(newline="", encoding=profile.encoding) as f:
            reader = csv.DictReader(f)
            rows = []
            for i, row in enumerate(reader):
                if i >= n:
                    break
                rows.append(row)
    except OSError:
        return "(sample rows unavailable)"
    if not rows:
        return "(no data rows)"
    lines = [f"First {len(rows)} row(s) of {profile.path.name!r}:"]
    for row in rows:
        lines.append("  " + ", ".join(f"{k}={v!r}" for k, v in row.items()))
    return "\n".join(lines)


#: The four targets `schema_registry.py` publishes meaning/alias data for --
#: the same four `_apply_registry_aliases` (below) resolves against. Named
#: once, here, so the prompt-enrichment section and the deterministic pass
#: can never silently drift onto different target sets.
REGISTRY_BACKED_TARGETS: frozenset[str] = frozenset({"role", "environment", "data_sensitivity", "criticality"})


def _render_enum_target_guidance(target: str) -> str:
    """One registry-backed enum target (`role`/`environment`/
    `data_sensitivity`), rendered as its legal values, each value's real
    meaning, and the real-world source spellings this project has already
    confirmed map to it -- so a proposal has something concrete to ground a
    mapping in, instead of a bare list of legal tokens with no stated
    meaning (the exact gap that produced an incomplete `role` table and an
    unresolved `criticality` in the real northgate_flat_2.csv case this
    module's prompt enrichment exists to close)."""
    spec = TARGET_REGISTRY[target]
    assert spec.enum is not None
    lines = [f"{target} -- legal values, meaning, and known real-world spellings:"]
    for aliased in spec.enum.values:
        meaning = aliased.meaning or "(no published meaning yet)"
        aliases = ", ".join(f"{a!r}" for a in sorted(aliased.aliases)) or "(no known aliases yet)"
        lines.append(f"  - {aliased.value!r}: {meaning} Known real-world spellings: {aliases}.")
    return "\n".join(lines)


def _render_criticality_guidance() -> str:
    """`criticality`'s own guidance is structurally different from the
    other three registry-backed targets: it is a 1-5 NUMBER, not a closed
    string vocabulary, and only its two ends are safe to resolve
    deterministically (`resolve_criticality_anchor`'s own docstring) -- a
    middle word's correct number depends on how many tiers the SOURCE's own
    scale has. This renders that as an explicit, cited fact rather than
    leaving the model to guess blind: two of this project's own confirmed,
    human-reviewed contracts made DIFFERENT correct choices for the exact
    same middle words, which is real, checkable precedent for why this is a
    judgment call and not something this prompt can hand the model a fixed
    answer for."""
    scale = TARGET_REGISTRY["criticality"].criticality
    assert scale is not None
    tier_lines = "\n".join(f"    level {i + 1}: {meaning}" for i, meaning in enumerate(scale.tier_meanings))
    anchor_lines = "\n".join(
        f"    level {anchor.level} ({', '.join(f'{a!r}' for a in sorted(anchor.aliases))}): {anchor.meaning}"
        for anchor in scale.anchors
    )
    return (
        f"criticality -- an integer {scale.low}-{scale.high}. Tier meanings:\n{tier_lines}\n"
        f"Exactly two levels are FIXED, unambiguous facts, safe to map directly regardless of how many "
        f"tiers your source's own scale has:\n{anchor_lines}\n"
        "Every OTHER word your source might use for a middle tier (\"High\", \"Medium\", \"Normal\", "
        "\"Low\", \"Moderate\", or similar) has NO universal correct number -- it depends on how many "
        "other tiers exist in THIS source's own scale, and is your own judgment call. This is not a "
        "hypothetical: two of this project's own confirmed, human-reviewed contracts made DIFFERENT "
        "correct choices for the identical words. A 4-tier source (bluepeak-gen.json) mapped "
        "critical->5, high->4, medium->3, low->2 -- its own table_notes explains why: \"low is "
        "deliberately 2, not 1 -- this source's four tiers do not reach the schema's floor.\" A 3-tier "
        "source (mdvm-gen.json) mapped high->5, normal->3, low->1 instead. Neither is more correct than "
        "the other; reason about how many tiers YOUR source has the same way they did, and mark the "
        "slot unresolved rather than guess if you genuinely cannot tell."
    )


_REGISTRY_GUIDANCE = "\n\n".join(
    [_render_enum_target_guidance("role"), _render_enum_target_guidance("environment"),
     _render_enum_target_guidance("data_sensitivity"), _render_criticality_guidance()]
)


_GRAMMAR_REFERENCE = f"""
TARGET SCHEMA -- every asset.<field> and finding.<field> below must be addressed, each with
EXACTLY one status:
  "mapped": you have identified a real mapping. Supply `mapping` (one of the 9 kinds below),
    a `confidence` in [0, 1] (your own honest estimate -- it is shown to a human, never used to
    decide anything), and `evidence` (columns_cited, sample_values_cited, note).
  "unresolved": you could NOT confidently identify a mapping. Supply `candidate_columns` (columns
    you considered, even if you rejected them) and a `reason`. NEVER fabricate a mapping just to
    avoid this status -- an honest "unresolved" is always preferred to a guess, and a human will
    complete it by hand. This is true even for a field where "not_collected" would be legal: only
    use "not_collected" when you have positively determined the source has no such concept at
    all, never merely because you are unsure.

asset.* targets ({len(ASSET_SLOTS)}): {sorted(ASSET_SLOTS)}
finding.* targets ({len(FINDING_SLOTS)}): {sorted(FINDING_SLOTS)}

REGISTRY-BACKED TARGET GUIDANCE -- {sorted(REGISTRY_BACKED_TARGETS)} each have a published meaning
and known real-world spellings for every legal value below. Use this to ground a real mapping
instead of leaving the slot unresolved for lack of a stated meaning to work from -- but it is still
your job to decide whether a column's actual observed values genuinely match; never force a token
onto this list's spellings that isn't a real match.

{_REGISTRY_GUIDANCE}

MAPPING KINDS (kind, and required fields):
  column: {{kind:"column", column, case:"exact"|"lower"|"upper", blank:"gap"|"absent_fact"|"fatal",
    optional:bool}} -- read a named column, strip it, write verbatim. For a CLOSED-vocabulary target
    (role, environment, data_sensitivity, scanner_severity), "verbatim" means every value the column
    actually contains, AFTER your chosen case transform, must exactly equal one of that target's own
    legal values -- if it does not (e.g. the column says "Critical" but scanner_severity only accepts
    lowercase "critical"), "column" is the wrong kind: use case:"lower"/"upper" if that alone makes
    every observed value match, or "vocabulary" to translate each raw token explicitly. This is
    checked against your ACTUAL profiled data, not merely reviewed for plausibility.
  vocabulary: {{kind:"vocabulary", column, case, blank, optional, table:{{source_token: target_value}}}}
    -- a CLOSED table. A source token you never saw does not need an entry; leaving it out is
    correct, not incomplete -- it will be excluded/refused row-by-row at real ingest time, never
    guessed at. Every table VALUE must be a real value the target field's own vocabulary accepts
    (you are told each enumerated target's allowed values below).
  derived: {{kind:"derived", from:<name in your own "derived" block>, output:<one of that
    derivation's declared outputs>}} -- pulls one output of a `derived[name]` block (see below).
  parsed: {{kind:"parsed", column, case, blank, optional, parser:<one of {sorted(PARSER_NAMES)}>,
    params}} -- parser MUST be one of these names, nothing else: there is no way to supply your own
    regex or date format string anywhere in this grammar. `params` per parser: "bool" takes
    {{"true":[tokens meaning true], "false":[tokens meaning false]}}; "float" takes optional
    {{"min":..., "max":...}}; "date" takes {{"format": one of {sorted(DATE_FORMATS)}}} (default
    "iso"); "timestamp" and "cve_id" take no params. If none of these five fit the column's real
    shape, mark the slot unresolved instead -- do not force the closest-sounding one onto data it
    cannot actually parse.
  literal: {{kind:"literal", value}} -- a constant, never read from a column. ONLY use this when
    `evidence.columns_cited` names a column your own profile data below shows tagged "constant"
    (every row has one identical value) -- a literal not grounded in an observed constant will be
    refused, regardless of confidence.
  composed: {{kind:"composed", join:"; ", max_chars:4096, parts:[...]}} -- LEGAL ONLY for
    finding.evidence. Each part is either {{template, fallback_template, required_non_blank,
    emit_if_any}} ("{{ColumnName}}" placeholders) or {{prefix, join_nonblank:[...], join:" "}}.
  not_collected: {{kind:"not_collected"}} -- "this source has no such column at all." Legal only
    for: {sorted(GAP_LEGAL_TARGETS)}.
  default_by: {{kind:"default_by", table:<name in {sorted(REGISTERED_DEFAULT_TABLES)}>,
    keyed_by:{{from:<derived name>, output:<that derivation's output>}}}} -- may only feed the
    target(s) {sorted(DEFAULT_BY_LEGAL_TARGET.values())}. Today the only registered table is
    ROLE_DEFAULT_BY_OS_CLASS, keyed by OS class ("client"/"server"), whose rows are:
    {ROLE_DEFAULT_BY_OS_CLASS} -- use it only when the source has a general OS-class signal but no
    direct role/device-type column at all.
  content_address: {{kind:"content_address", algorithm:"sha256", columns:[...ordered...], join:"",
    prefix:"", hex_len:8-32, case:"upper"|"lower", recipe_version:1}} -- LEGAL ONLY for
    finding.finding_id, and only when no natural unique id column exists.

"derived" (your own top-level block, optional): {{name: {{column, case, blank:"fatal",
  outputs:[...], table:{{source_token: [one value per output]}} }} }} -- one column mapped to
  several named outputs at once (e.g. an OS-platform string split into a display name and an
  OS class). Every table key must, like a vocabulary table, be a real value you observed in
  that column -- partial coverage is fine, do not invent rows for values you never saw.

"blank" policy (mandatory on column/vocabulary/parsed, no default): "gap" (not collected -- legal
  only for {sorted(GAP_LEGAL_TARGETS)}; a "gap" target that finds no column takes this value on
  every record: {NOT_COLLECTED_DEFAULTS}), "absent_fact" (blank IS the fact, e.g. no port -- legal
  only for {sorted(ABSENT_FACT_LEGAL_TARGETS)}), "fatal" (always legal; refuses the whole batch on
  a blank value).

Special note on "role": if your vocabulary/derived table for asset.role does not cover every
token the column actually contains, an uncovered token causes that ONE asset (and its findings)
to be excluded from the plan and reported, not a whole-batch refusal -- role is the only target
with this softer handling ({sorted(EXCLUDING_TARGETS)}), because forcing an honest blast-radius
weight onto something outside this project's Windows-enterprise role vocabulary would be a
fabrication. Every OTHER vocabulary/derived table's uncovered token instead refuses the WHOLE
batch, so be more conservative about leaving gaps in a non-role vocabulary.

asset_grouping: {{key:<column identifying one physical asset, for collapsing repeated rows>,
  order_by:{{column, parser:"date"|"timestamp", required}} or null, union_fields:[] (may only
  contain {sorted(UNIONABLE_TARGETS)} -- a target may legitimately differ per finding on the same
  asset and should be unioned rather than forced to agree), union_justification:{{}}}}.
finding_dedup: {{content_targets:[...finding.* target names whose values together identify "the
  same finding" for collapsing exact duplicate rows...], on_identical:"collapse_and_count",
  on_conflict:"fatal"}}.
enrichment (OPTIONAL -- only if this source's own rows already carry a CVSS-like score, an
  exploited flag, or an ATT&CK technique of their own, distinct from asking RhinoSecure's usual
  NVD/KEV/EPSS/ATT&CK lookups): {{severity_score:<parsed mapping, parser MUST be "float">,
  known_exploited:<parsed mapping, parser MUST be "bool", or omit>, attack_technique:
  {{column, blank:"absent_fact", pattern:"attack_technique", outputs:[...], on_no_match:"degrade"}}
  or omit}}.

unmapped_columns: {{filename: {{column_name: {{disposition:"ignored"|"evidence_only"|
  "deliberately_dropped", reason, profile_cited:<echo the measured shape that justifies this>}}}}}}
  -- EVERY column in EVERY file must end up either feeding a real mapping (directly, or via a
  composed template/derived block) or listed here. Nothing may be silently absent from both.
""".strip()


def _build_task_description(name: str, layout: str, assets_filename: str, findings_filename: str, profiles: dict[str, FileProfile], sample_rows: int) -> str:
    profile_text = "\n\n".join(_render_profile(profiles[f]) for f in dict.fromkeys([assets_filename, findings_filename]))
    sample_text = "\n\n".join(_sample_rows(profiles[f], sample_rows) for f in dict.fromkeys([assets_filename, findings_filename]))
    return (
        f"Propose an ingest contract named {name!r} for a new vulnerability-scanner source.\n\n"
        f"source_layout: {layout!r}\nassets_filename: {assets_filename!r}\nfindings_filename: {findings_filename!r}\n\n"
        "Your top-level JSON output MUST have exactly this shape -- these are the ONLY top-level "
        "keys, and `meta` has EXACTLY these six keys, spelled exactly this way (the format name "
        f'field is `"format"`, never `"name"`):\n'
        "{\n"
        '  "meta": {\n'
        f'    "format": {name!r}, "description": "<one sentence describing this source>",\n'
        f'    "source_layout": {layout!r}, "assets_filename": {assets_filename!r}, '
        f'"findings_filename": {findings_filename!r},\n'
        '    "reasoning_summary": "<one or two sentences on your overall mapping approach>"\n'
        "  },\n"
        '  "asset": {...one entry per asset.* target, see below...},\n'
        '  "finding": {...one entry per finding.* target, see below...},\n'
        '  "derived": {} ,   "asset_grouping": {...},   "finding_dedup": {...},\n'
        '  "enrichment": null,   "unmapped_columns": {...},   "open_questions": []\n'
        "}\n"
        "The four echoed facts (`format`, `source_layout`, `assets_filename`, `findings_filename`) "
        "are not yours to redecide -- copy them verbatim from above.\n\n"
        f"{profile_text}\n\n{sample_text}\n\n{_GRAMMAR_REFERENCE}\n\n"
        "Map every asset.* and finding.* target to a real column where you can, honestly, and mark it "
        "unresolved where you cannot. Account for every column in unmapped_columns if it feeds no mapping. "
        "Never invent a vocabulary table entry, a literal value, or a derived-table row you did not "
        "observe in the profile or sample rows above."
    )


def build_propose_agent(llm: BaseLLM | None = None) -> Agent:
    return Agent(
        role=ROLE,
        goal=(
            "Propose a complete, honest mapping from an arbitrary CSV source onto RhinoSecure's "
            "Asset/Finding schema, using only the closed set of mapping kinds and parsers this "
            "project's engine already executes. Mark a field unresolved rather than guess."
        ),
        backstory=(
            "A data-integration engineer who has read every hand-written adapter in this codebase "
            "and knows the engine will refuse anything not in its closed grammar -- so a proposal "
            "that leaves gaps honestly marked is more useful than one that looks complete but lies."
        ),
        tools=[],
        llm=llm or get_llm(max_tokens=PROPOSE_MAX_OUTPUT_TOKENS),
        verbose=True,
        max_execution_time=MAX_AGENT_EXECUTION_SECONDS,
    )


def build_propose_task(
    name: str,
    layout: str,
    assets_filename: str,
    findings_filename: str,
    profiles: dict[str, FileProfile],
    sample_rows: int,
    agent: Agent,
    *,
    previous_error: str | None = None,
) -> Task:
    """`previous_error` is `str(exc)` from the prior attempt's
    `AgentOutputParseError`/`_check_meta_matches` `ValueError` -- never
    `.raw` (`AgentOutputParseError`'s own docstring: that is untrusted,
    unbounded model text, deliberately kept out of anywhere it could be
    printed or re-embedded without a caller's explicit choice). Reflecting
    the model's own prior words back to the SAME model in the SAME retry
    loop is not the cross-agent/cross-human trust boundary `agents/
    prompt_safety.py`'s fencing exists for -- it gains the model no
    instructing power over anything it did not already have by generating
    the text once -- so this is appended plainly, just capped defensively."""
    description = _build_task_description(name, layout, assets_filename, findings_filename, profiles, sample_rows)
    if previous_error is not None:
        description += (
            "\n\n---\nYour previous attempt at this exact task failed, and was discarded:\n"
            f"{previous_error[:_MAX_RETRY_ERROR_CHARS]}\n\n"
            "Correct ONLY what caused that failure. Return the complete, corrected JSON in full -- "
            "still exactly the shape described above -- not a diff or an explanation."
        )
    return Task(
        description=description,
        expected_output=(
            "Return ONLY a single JSON object matching AdapterProposal -- not wrapped in any container "
            "key, no markdown code fences, no prose before or after it. Top-level keys: meta, asset, "
            "finding, derived (may be {}), asset_grouping, finding_dedup, enrichment (may be null), "
            "unmapped_columns, open_questions (may be [])."
        ),
        agent=agent,
    )


@dataclass(frozen=True)
class ProposeResult:
    proposal: AdapterProposal
    grounding: GroundingReport
    contract: Contract | None
    generator: Generator
    profiles: dict[str, FileProfile]
    #: Set only when `contract is None` AND the reason isn't already fully
    #: explained by an unresolved slot or a grounding failure -- i.e. the
    #: `validate_contract` safety net inside `assemble_contract` is what
    #: refused (an illegal vocabulary value, an illegal `union_fields`
    #: entry, etc.). Without this, a human sees "0 unresolved, 0 grounding
    #: failures -- NOT written" with no way to tell why.
    incomplete_reason: str | None = None
    #: See `SavedProposal.attempt_usage` -- carried through unchanged from
    #: `from_proposal` when reusing one (no new attempts were made), built
    #: fresh from the real retry loop otherwise.
    attempt_usage: tuple[dict[str, object], ...] = ()


def _check_meta_matches(proposal: AdapterProposal, name: str, layout: str, assets_filename: str, findings_filename: str) -> None:
    problems = []
    if proposal.meta.format != name:
        problems.append(f"meta.format {proposal.meta.format!r} != requested name {name!r}")
    if proposal.meta.source_layout != layout:
        problems.append(f"meta.source_layout {proposal.meta.source_layout!r} != {layout!r}")
    if proposal.meta.assets_filename != assets_filename:
        problems.append(f"meta.assets_filename {proposal.meta.assets_filename!r} != {assets_filename!r}")
    if proposal.meta.findings_filename != findings_filename:
        problems.append(f"meta.findings_filename {proposal.meta.findings_filename!r} != {findings_filename!r}")
    if problems:
        raise ValueError("; ".join(problems))


class MappingLegalityError(ValueError):
    """Raised by `_check_mapped_slots_legal` -- a `ValueError` subclass so
    the retry loop's existing `except (AgentOutputParseError, ValueError)`
    still catches it unchanged, but distinguishable from a plain
    `_check_meta_matches` mismatch for `attempt_usage`'s own `outcome`
    label."""


def _check_mapped_slots_legal(proposal: AdapterProposal, profiles: dict[str, FileProfile]) -> None:
    """Closes the grammar at GENERATION for a FRESH, LLM-driven candidate --
    not only at final contract validation (CLAUDE.md's own framing of this
    gap). Called only from `propose_contract`'s own retry loop, immediately
    after `_check_meta_matches` (never for `from_proposal`-supplied input --
    see that call site's own comment for why): a `SlotMapped` whose mapping
    individually violates a per-target rule `validate_contract` already
    enforces (`blank='gap'` on a target with no `NOT_COLLECTED_DEFAULTS`
    entry, e.g. `role`; a `timestamp` parser outside
    `asset_grouping.order_by`) raises here, exactly like `_check_meta_matches`
    does for a meta-fact mismatch -- caught by the identical
    `except (AgentOutputParseError, ValueError)` handler, so the model gets
    a genuine retry with the SPECIFIC violation fed back
    (`build_propose_task`'s `previous_error`), a real chance to produce a
    CORRECT mapping (e.g. `default_by`/`ROLE_DEFAULT_BY_OS_CLASS` for role,
    or `parser:"date"` for a timestamp-shaped column) instead of losing the
    column entirely to a provisional placeholder. Reuses
    `check_slot_mapping_legality`, the identical function
    `validate_contract`'s own per-slot loops call, so this can never drift
    from what the real engine will eventually refuse anyway.

    `profiles` (keyed by filename, exactly like `check_grounding`'s own
    parameter) lets this ALSO run `check_column_mapping_legal_values` --
    `check_slot_mapping_legality` alone only catches a non-string-shaped
    target statically (config_model.py's Part B); a string-shaped CLOSED
    vocabulary target (`role`/`environment`/`data_sensitivity`/
    `scanner_severity`) fed by a `ColumnMapping` needs real profiled data to
    know whether the column's OBSERVED values actually violate it -- the
    exact bug this function's own module docstring's `northgate_flat_2.csv`
    case demonstrates live (`finding.scanner_severity` as a raw `"column"`
    passthrough over a `"Critical"`-valued column). Picks the correct half
    of `profiles` for each slot the identical way `_ground_slot` does: an
    `asset.*` mapping's column lives in `proposal.meta.assets_filename`, a
    `finding.*` mapping's in `proposal.meta.findings_filename`.

    Deliberately NOT a blanket check on every `AdapterProposal`
    construction (e.g. a pydantic model validator): a `--from-proposal`
    file -- exactly the mechanism this project already uses for a human to
    review and hand-fix a proposal that previously failed to assemble --
    must still be LOADABLE even when it carries this exact violation, so it
    can reach `assemble_provisional_contract`'s own degrade-on-validation-
    failure path (or `assemble_contract`'s ordinary, clearly-worded
    refusal). Gating construction itself would make that review loop
    impossible: the very file a human needs to open and fix would refuse to
    load at all."""
    problems: list[str] = []
    assets_profile = profiles.get(proposal.meta.assets_filename)
    findings_profile = profiles.get(proposal.meta.findings_filename)
    for target, sp in proposal.asset.items():
        if isinstance(sp, SlotMapped):
            where = f"asset.{target}"
            problems.extend(check_slot_mapping_legality(where, target, sp.mapping))
            if isinstance(sp.mapping, ColumnMapping) and assets_profile is not None:
                problems.extend(check_column_mapping_legal_values(where, target, sp.mapping, assets_profile))
    for target, sp in proposal.finding.items():
        if isinstance(sp, SlotMapped):
            where = f"finding.{target}"
            problems.extend(check_slot_mapping_legality(where, target, sp.mapping))
            if isinstance(sp.mapping, ColumnMapping) and findings_profile is not None:
                problems.extend(check_column_mapping_legal_values(where, target, sp.mapping, findings_profile))
    if problems:
        raise MappingLegalityError(
            f"{len(problems)} mapped slot(s) violate the closed contract grammar (the identical "
            f"checks validate_contract itself runs): {problems}"
        )


def _estimate_cost_usd(usage: UsageMetrics | None) -> float:
    if usage is None:
        return 0.0
    return (usage.prompt_tokens / 1_000_000) * _INPUT_USD_PER_MILLION_TOKENS + (
        usage.completion_tokens / 1_000_000
    ) * _OUTPUT_USD_PER_MILLION_TOKENS


def propose_contract(
    data_dir: Path,
    name: str,
    *,
    generated_at: str,
    assets_filename: str | None = None,
    findings_filename: str | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    sample_rows: int = DEFAULT_SAMPLE_ROWS,
    from_proposal: SavedProposal | None = None,
    llm: BaseLLM | None = None,
    model_name: str = DEFAULT_MODEL,
    verbose: bool = False,
) -> ProposeResult:
    """The whole phase-1 pipeline: profile (probe.py, unchanged) -> LLM
    proposal (skipped if `from_proposal` is given) -> grounding (step 4,
    always runs, even against a supplied proposal) -> assembly (only if
    grounding is clean and nothing is unresolved).

    Raises `ProbeError` (an unreadable/empty source), `SchemaInferenceError`
    (ambiguous layout, or a proposal naming files it wasn't asked about), or
    `ProposalGenerationError` (the model's output never parsed/matched the
    requested facts within `max_attempts`). Never raises
    `ProposalIncompleteError` itself -- an incomplete proposal is a normal,
    reportable outcome (`ProposeResult.contract is None`), not a failure of
    this function.
    """
    _validate_format_name(name)
    profiles = {p.path.name: p for p in profile_source(data_dir)}
    layout, resolved_assets, resolved_findings = _resolve_layout(profiles, assets_filename, findings_filename)

    if from_proposal is not None:
        proposal, generator = from_proposal.proposal, from_proposal.generator
        attempt_usage = from_proposal.attempt_usage
        try:
            _check_meta_matches(proposal, name, layout, resolved_assets, resolved_findings)
        except ValueError as exc:
            raise SchemaInferenceError(f"--from-proposal file does not match the requested facts: {exc}") from exc
    else:
        agent = build_propose_agent(llm)
        call_log_parts: list[str] = []
        attempt_usage_list: list[dict[str, object]] = []
        last_error: Exception | None = None
        proposal = None
        task: Task | None = None
        # `agent` (and so `agent.llm`) is deliberately built ONCE and reused
        # across every attempt below, but `crew.usage_metrics` is NOT a
        # per-kickoff figure -- `Crew.calculate_usage_metrics()` (crewai's
        # own crew.py) reads `agent.llm.get_token_usage_summary()` directly,
        # and that summary is explicitly documented as "cumulative for the
        # lifetime of this [LLM] instance" (base_llm.py). Reading `crew
        # .usage_metrics` naively on attempt 2 therefore double-counts
        # attempt 1's tokens, and attempt 3 triple-counts them -- confirmed
        # live (PROGRESS.md 2026-09-06): a real 3-attempt run reported a
        # THIRD attempt alone costing more completion tokens than the
        # entire run's real total. `UsageMetrics.delta_since` (crewai's own
        # documented fix for exactly this reuse pattern) turns the running
        # snapshot into a true per-attempt figure.
        usage_baseline = agent.llm.get_token_usage_summary() if isinstance(agent.llm, BaseLLM) else UsageMetrics()

        for attempt in range(1, max_attempts + 1):
            task = build_propose_task(
                name, layout, resolved_assets, resolved_findings, profiles, sample_rows, agent,
                previous_error=str(last_error) if last_error is not None else None,
            )
            crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=verbose)
            crew.kickoff()
            attempt_prompt_tokens = 0
            attempt_completion_tokens = 0
            if isinstance(agent.llm, BaseLLM):
                usage_now = agent.llm.get_token_usage_summary()
                attempt_delta = usage_now.delta_since(usage_baseline)
                attempt_prompt_tokens = attempt_delta.prompt_tokens
                attempt_completion_tokens = attempt_delta.completion_tokens
                usage_baseline = usage_now
            call_log_parts.append(task.description + "\n---\n" + task.output.raw)
            try:
                candidate = parse_structured_output(task.output.raw, AdapterProposal)
                _check_meta_matches(candidate, name, layout, resolved_assets, resolved_findings)
                _check_mapped_slots_legal(candidate, profiles)
                proposal = candidate
                attempt_usage_list.append(
                    {
                        "attempt": attempt,
                        "prompt_tokens": attempt_prompt_tokens,
                        "completion_tokens": attempt_completion_tokens,
                        "outcome": "parsed",
                    }
                )
                break
            except (AgentOutputParseError, ValueError) as exc:
                last_error = exc
                attempt_usage_list.append(
                    {
                        "attempt": attempt,
                        "prompt_tokens": attempt_prompt_tokens,
                        "completion_tokens": attempt_completion_tokens,
                        "outcome": (
                            "parse_error" if isinstance(exc, AgentOutputParseError)
                            else "illegal_mapping" if isinstance(exc, MappingLegalityError)
                            else "meta_mismatch"
                        ),
                    }
                )

        attempt_usage = tuple(attempt_usage_list)
        # `usage_baseline` is updated to the LLM's cumulative summary at the
        # end of every attempt above, so once the loop ends it already IS
        # the true total across every attempt made -- not re-summed here,
        # for the identical reason a naive re-sum of `crew.usage_metrics`
        # would have overcounted per attempt.
        total_usage = usage_baseline

        if proposal is None:
            raise ProposalGenerationError(
                f"gave up after {max_attempts} attempt(s): {last_error}",
                attempt_usage=attempt_usage,
                estimated_cost_usd=_estimate_cost_usd(total_usage),
            ) from last_error

        generator = Generator(
            tool="rhino-adapt-propose",
            model=model_name,
            prompt_tokens=total_usage.prompt_tokens,
            completion_tokens=total_usage.completion_tokens,
            estimated_cost_usd=_estimate_cost_usd(total_usage),
            attempts=attempt,
            # Every attempt's prompt+response, including failed ones -- a
            # partial-spend retry must not vanish from the audit trail.
            call_log_digest="sha256:" + hashlib.sha256("\n===\n".join(call_log_parts).encode("utf-8")).hexdigest(),
        )

    proposal = _apply_registry_aliases(proposal, profiles)
    report = check_grounding(proposal, profiles)
    incomplete_reason: str | None = None
    try:
        contract = assemble_contract(proposal, profiles, report, generator=generator, generated_at=generated_at)
    except ProposalIncompleteError as exc:
        contract = None
        incomplete_reason = str(exc)

    return ProposeResult(
        proposal=proposal, grounding=report, contract=contract, generator=generator, profiles=profiles,
        incomplete_reason=incomplete_reason, attempt_usage=attempt_usage,
    )
