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

import csv
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal, Union

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
    Contract,
    Derivation,
    Enrichment,
    FindingDedup,
    Generator,
    Header,
    HeaderSpec,
    Mapping,
    NotCollectedDerived,
    Review,
    Source,
    UnmappedColumnEntry,
    _compute_not_collected,  # the exact V09 recomputation validate_contract itself uses
    _composed_columns,  # the exact placeholder-extraction validate_contract itself uses
    _FORMAT_PATTERN,  # the exact pattern Contract.format itself is checked against
    ContractValidationError,
    missing_attestations,
    validate_contract,
)
from rhinosecure.adapters.configured import _apply_case  # the exact case transform applied before any table lookup
from rhinosecure.agents.limits import MAX_AGENT_EXECUTION_SECONDS
from rhinosecure.agents.parsing import AgentOutputParseError, parse_structured_output
from rhinosecure.adapters.probe import ColumnProfile, FileProfile, profile_source
from rhinosecure.llm import DEFAULT_MODEL, get_llm

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
    caveat does not block assembly -- see module docstring)."""


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
        _check_column_exists(issues, slot, mapping.column, own_profile, optional=mapping.optional)
    elif kind == "vocabulary":
        if _check_column_exists(issues, slot, mapping.column, own_profile, optional=mapping.optional):
            _ground_table(issues, slot, mapping.column, list(mapping.table), mapping.case, own_profile)
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
# Assembly (deterministic, no LLM): a complete, grounded proposal -> Contract.
# ---------------------------------------------------------------------------


def _hash_header(columns: list[str]) -> str:
    """Informational provenance only -- `configured.py` never verifies this
    against anything; only `header.assets.columns`/`.findings.columns` (the
    ordered name list) is checked at ingest time (`_check_header_mode`).
    Recipe: sha256 of the column names newline-joined, so two headers that
    differ only in order or a renamed column produce different digests."""
    return "sha256:" + hashlib.sha256(("\n".join(columns) + "\n").encode("utf-8")).hexdigest()


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
    the same profiling pass)."""
    blocking = sorted(set(unresolved_slots(proposal)) | {i.slot for i in report.failures})
    if blocking:
        raise ProposalIncompleteError(
            f"{len(blocking)} slot(s)/reference(s) cannot be assembled: {blocking}. Resolve them by hand "
            "in the saved proposal file, then re-run with --from-proposal."
        )

    assets_profile = profiles[proposal.meta.assets_filename]
    findings_profile = profiles[proposal.meta.findings_filename]

    asset_mappings: dict[str, Mapping] = {t: sp.mapping for t, sp in proposal.asset.items()}
    finding_mappings: dict[str, Mapping] = {t: sp.mapping for t, sp in proposal.finding.items()}
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
            f"validator (the same check `rhino adapt confirm` would run): {exc}"
        ) from exc

    return contract


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

MAPPING KINDS (kind, and required fields):
  column: {{kind:"column", column, case:"exact"|"lower"|"upper", blank:"gap"|"absent_fact"|"fatal",
    optional:bool}} -- read a named column, strip it, write verbatim.
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
                        "outcome": "parse_error" if isinstance(exc, AgentOutputParseError) else "meta_mismatch",
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
