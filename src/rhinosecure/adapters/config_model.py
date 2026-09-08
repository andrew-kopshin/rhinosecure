"""The declarative ingest *contract* -- the artifact format the LLM-assisted
adapter-generation design produces in phase 1 (`rhino adapt propose`) and a
hand-written, LLM-free engine interprets in phase 2. This module is that
engine's other half: the data shape, and the cross-checks that make "the
model silently did the wrong thing" structurally hard to ship.

No engine lives here. `validate_contract` takes `headers` -- the column
list(s) a real CSV would present -- as plain data, not by opening a file;
nothing in this module touches a filesystem, a network, or an LLM. The
engine that actually reads a CSV against a confirmed contract, and the CLI
that drives phase 1, are later, separate pieces of work.

Design provenance: a four-angle design exploration (minimal declarative,
typed transform pipeline, provenance-first ledger, and this one --
"contract and probe") was judged across four adversarial lenses (contract
fidelity, determinism, human review, messy-reality/safety) and synthesized
into the shape below. The decisive property carried through every stage:
**the review artifact must be produced by the same code that executes it**,
so a human never confirms a claim about a mapping, only a measurement of
what it does. This module is the "what it does" half of that -- the
contract's shape and its own internal consistency; the measurement itself
is the probe (a later slice).

Two rules inherited from `adapters/base.py`'s existing discipline, restated
here because they drove several of this module's model choices:

1. Fail loudly on unmappable input; never guess. `extra="forbid"` on every
   structural block means an unknown key is a load-time error, not a typo
   that silently did nothing. Every column-reading mapping's `blank` policy
   is mandatory with no default (V04) -- guessing "gap" for a field that
   means "no restriction" when blank, or "absent_fact" for an enumerated
   field with no blank member, would each assert something false.
2. Represent what the source has no concept of explicitly. `not_collected`
   here is DERIVED from the mapping declarations themselves (V09), never a
   key the model can write -- the same posture `Asset.not_collected` /
   `Finding.not_collected` already take: the claim is a fact about the
   mapping, not something to be silenced or invented.

Fatal vs. exclude, resolved without a config key
-------------------------------------------------
There is no `on_unmapped` key anywhere in this grammar. The two adapters
that exist today (`defender.py`, `bluepeak.py`) each have exactly one
`.exclude` call site, and both feed `Asset.role` -- because
`scoring.ROLE_BLAST_RADIUS` is the one table where an unmappable value would
force fabricating a blast-radius weight for something this project has no
honest weight for, and every other schema vocabulary is universal (every
enterprise asset has *some* environment, *some* sensitivity tier), so a
token outside those means the mapping is wrong, not that the asset is out of
scope. Making that disposition a config key would let either the model or a
human classify a check as "exclude" to make a refusal go away -- exactly the
silent-absorption failure mode this project's whole `ProblemCollector`
discipline exists to prevent. `EXCLUDING_TARGETS` below names the one target
this applies to; the engine (a later slice) forward-traces which vocabulary
feeds it and treats an unmapped value there as scope-exclusion, and every
other vocabulary miss as a fatal, whole-batch refusal -- policy the config
cannot override.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Annotated, Any, Literal, Union, get_args, get_type_hints

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from rhinosecure.adapters import FORMATS as _BUILTIN_ADAPTER_FORMATS
from rhinosecure.adapters.base import AdapterError, NOT_COLLECTED_DEFAULTS, ROLE_DEFAULT_BY_OS_CLASS
from rhinosecure.schema import Asset, Finding

# ---------------------------------------------------------------------------
# Code-owned constants. Each is either derived from schema.py so it can never
# silently drift from the models it describes, or names a decision that is
# deliberately not a config knob -- see the module docstring's "Fatal vs.
# exclude" section for EXCLUDING_TARGETS specifically.
# ---------------------------------------------------------------------------

#: The Asset target-field names a contract's `asset` block must map, exactly
#: -- every non-`not_collected` field the schema has, in schema.py's own
#: declared order. `not_collected` is excluded: it is never a mapping
#: target, it is what `validate_contract` derives (V09).
ASSET_SLOTS: tuple[str, ...] = tuple(k for k in Asset.model_fields if k != "not_collected")

#: The Finding target-field names a contract's `finding` block must map.
#: `not_collected` and `source_enrichment` are excluded -- the latter is
#: populated through the separate, optional `enrichment` block, not through
#: `finding`.
FINDING_SLOTS: tuple[str, ...] = tuple(
    k for k in Finding.model_fields if k not in ("not_collected", "source_enrichment")
)

#: The four fields `SourceEnrichment` actually carries as configurable
#: targets (`severity_label` is not one -- see ENRICHMENT below).
SOURCE_ENRICHMENT_FIELDS: frozenset[str] = frozenset(
    {"severity_score", "known_exploited", "attack_technique_id", "attack_technique_name"}
)

#: `blank: "gap"` is legal only where the target has a documented
#: not-collected default to fall back to -- i.e. is a key of
#: `NOT_COLLECTED_DEFAULTS` (adapters/base.py). Deriving this from that dict,
#: rather than re-declaring the list, is what closes the exact conflation a
#: majority of the source proposals made: `gap` on `product` or `evidence`
#: would be a `KeyError` at engine runtime, not a policy, because neither
#: field has an entry there.
GAP_LEGAL_TARGETS: frozenset[str] = frozenset(NOT_COLLECTED_DEFAULTS)


def _absent_fact_legal_targets() -> frozenset[str]:
    """Every Asset/Finding field whose own pydantic default is `""` -- the
    schema's existing "blank means no restriction/fact" encoding
    (schema.py's own docstring). Computed by introspection, not hand-copied,
    for the same reason as GAP_LEGAL_TARGETS: three of four source proposals
    conflated this set with NOT_COLLECTED_DEFAULTS's keys, and the two sets
    genuinely differ -- `criticality`/`internet_exposed`/`environment`/
    `data_sensitivity`/`os`/`os_build` are gap-legal but have no `""`
    default (an enumerated Literal has no blank member), while `product` and
    `evidence` have a `""` default but no NOT_COLLECTED_DEFAULTS entry."""
    targets: set[str] = set()
    for name, field in Asset.model_fields.items():
        if name != "not_collected" and field.default == "":
            targets.add(name)
    for name, field in Finding.model_fields.items():
        if name not in ("not_collected", "source_enrichment") and field.default == "":
            targets.add(name)
    return frozenset(targets)


ABSENT_FACT_LEGAL_TARGETS: frozenset[str] = _absent_fact_legal_targets()

#: See the module docstring's "Fatal vs. exclude" section. Not consumed by
#: anything in this module -- the engine (a later slice) is what forward-
#: traces which vocabulary feeds this target and applies the exclude
#: disposition there and nowhere else. Defined here because it is a decision
#: about the schema, made once, in the same place every other schema-derived
#: constant lives.
EXCLUDING_TARGETS: frozenset[str] = frozenset({"role"})

#: `asset_grouping.union_fields` may only ever contain this one target.
#: Union is safe only where every additional distinct value monotonically
#: STRENGTHENS `scoring.score_impact`'s compensating-control decay and can
#: never weaken it -- a scoring property, not a contract author's judgment
#: call, so it is not exposed as something a contract can widen.
UNIONABLE_TARGETS: frozenset[str] = frozenset({"compensating_controls"})

#: The one field a failed pattern match may degrade rather than refuse --
#: hard-coded, not a general per-mapping option, because an unparsed
#: technique is a real "no technique reported" fact, not a data-quality
#: problem the way a malformed CVE ID or boolean is.
DEGRADABLE_TARGETS: frozenset[str] = frozenset({"enrichment.attack_technique"})

#: `format` may not claim to be one of the sources scoring.py's rationale
#: already prints unqualified -- see schema.SourceEnrichment's own docstring
#: and scoring._resolve_severity: a vendor's self-reported CVSS must never
#: be printed as if NVD had scored it.
RESERVED_PROVENANCE_LABELS: frozenset[str] = frozenset({"nvd", "nist", "cvss", "scanner", "source"})

#: Registered `default_by` lookup tables, and which single target each one
#: is allowed to feed. `ROLE_DEFAULT_BY_OS_CLASS` is the only member today
#: (adapters/base.py's own "second-order default" -- the OS-class default
#: for `role`, applied when a source has no role signal at all).
REGISTERED_DEFAULT_TABLES: dict[str, dict[str, str]] = {"ROLE_DEFAULT_BY_OS_CLASS": dict(ROLE_DEFAULT_BY_OS_CLASS)}
DEFAULT_BY_LEGAL_TARGET: dict[str, str] = {"ROLE_DEFAULT_BY_OS_CLASS": "role"}

_ASSET_TYPE_HINTS = get_type_hints(Asset)
_FINDING_TYPE_HINTS = get_type_hints(Finding)

_FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FORMAT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_PLACEHOLDER_PATTERN = re.compile(r"\{([^{}]+)\}")

PARSER_NAMES: frozenset[str] = frozenset({"bool", "float", "date", "timestamp", "cve_id"})
DATE_FORMATS: frozenset[str] = frozenset({"iso", "iso_prefix", "us_slash", "eu_slash"})

Case = Literal["exact", "lower", "upper"]
BlankPolicy = Literal["gap", "absent_fact", "fatal"]


class ContractError(AdapterError):
    """The contract's own shape or internal decisions are wrong -- distinct
    from `AdapterError`'s use for a source *file* the adapter refuses.
    Subclasses `AdapterError` (which already subclasses `IngestError`) so a
    bad contract surfaces through the same `except IngestError` handling
    every CLI path already has, once a later slice wires one up."""


class ContractValidationError(ContractError):
    """Every violation `validate_contract` found, named at once -- the same
    "refuse loudly, name every offender in one message" discipline as
    `ProblemCollector.raise_if_fatal` (adapters/base.py). `problems` carries
    the identical violations as a raw tuple of strings, each one prefixed
    `"asset.<target>: "`/`"finding.<target>: "` when it is attributable to
    exactly one slot -- so a caller that needs to ACT on individual
    violations (agents/schema_inference.py's provisional-assembly degrade
    path) can do so without re-parsing this exception's own formatted
    `str(self)` message."""

    def __init__(self, message: str, *, problems: tuple[str, ...] = ()):
        super().__init__(message)
        self.problems = problems


# ---------------------------------------------------------------------------
# Mapping node kinds -- nine, closed. Every column-reading kind carries a
# mandatory `blank`: there is no default, because guessing one would assert
# something about the source no one has stated (see V04 in validate_contract
# and the module docstring's rule 1).
# ---------------------------------------------------------------------------


class ColumnMapping(BaseModel):
    """Read a column, strip it (unconditionally -- not a param, see the
    class docstring below on why `strip` is not itself a knob), apply case,
    write it to the target verbatim."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["column"]
    column: str
    case: Case = "exact"
    blank: BlankPolicy
    optional: bool = False


class VocabularyMapping(BaseModel):
    """A closed source-token -> target-value table. A value not in the table
    is never snapped to a neighbour -- see `validate_contract`'s per-target
    value check, which is what makes this a *closed* vocabulary rather than
    a pass-through with a safety net."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["vocabulary"]
    column: str
    case: Case = "exact"
    blank: BlankPolicy
    optional: bool = False
    table: dict[str, Any]
    table_notes: dict[str, str] | None = None

    @field_validator("table")
    @classmethod
    def _table_non_empty(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not value:
            raise ValueError("table must not be empty")
        return value


class DerivedMapping(BaseModel):
    """Pull one named output of a `derived` block (module-level `derived`
    dict, keyed by derivation name) into this target."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    kind: Literal["derived"]
    from_: str = Field(alias="from")
    output: str


class ParsedMapping(BaseModel):
    """`parser` names an entry in a code-owned catalog (PARSER_NAMES) --
    there is no user-supplied regex or format string anywhere in this
    grammar, at any nesting level. A parse failure is always fatal; it is
    not configurable, because a malformed value is a data-quality problem,
    full stop (the sole exception, `enrichment.attack_technique`'s pattern
    match, is not a `parsed` mapping -- see EnrichmentAttackTechnique)."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["parsed"]
    column: str
    case: Case = "exact"
    blank: BlankPolicy
    optional: bool = False
    parser: Literal["bool", "float", "date", "timestamp", "cve_id"]
    params: dict[str, Any] | None = None


class LiteralMapping(BaseModel):
    """A constant naming something about the source, never a column. Not
    used for `enrichment`'s severity label -- that label *is* the
    contract's own `format` name (see Enrichment below) -- reserved for a
    future slot that genuinely needs a fixed value."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["literal"]
    value: str | int | bool


class ComposedPartTemplate(BaseModel):
    """`template`/`fallback_template` support only `{ColumnName}`
    substitution from the current row, rendered over that row's declared
    columns only -- no functions, no attribute access, no format specs.
    Every placeholder is echo-verified against the real header
    (`validate_contract`'s V01), exactly like any other column reference."""

    model_config = ConfigDict(extra="forbid")

    template: str
    fallback_template: str | None = None
    required_non_blank: list[str] = Field(default_factory=list)
    emit_if_any: list[str] | None = None


class ComposedPartJoin(BaseModel):
    """Joins the non-blank values of `join_nonblank`, in order, with
    `join` -- reproduces `defender.py`'s
    `' '.join(p for p in (vendor, name, version) if p)` exactly, without a
    template's placeholder machinery."""

    model_config = ConfigDict(extra="forbid")

    prefix: str | None = None
    join_nonblank: list[str]
    join: str = " "


class ComposedMapping(BaseModel):
    """Legal only for `finding.evidence` (checked in `validate_contract`,
    not by the model itself, since that check needs to know which slot this
    mapping is attached to). Free text an agent may cite, never a scoring
    input -- a template can never manufacture a number."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["composed"]
    join: str = "; "
    max_chars: int = 4096
    parts: list[ComposedPartTemplate | ComposedPartJoin]

    @field_validator("parts")
    @classmethod
    def _parts_non_empty(cls, value: list[Any]) -> list[Any]:
        if not value:
            raise ValueError("parts must not be empty")
        return value


class NotCollectedMapping(BaseModel):
    """\"This source has no such column at all.\" The value comes from
    `NOT_COLLECTED_DEFAULTS[target]` -- legal only where the target is a key
    of that dict (`validate_contract`'s V05-adjacent check); the contract
    names the field, it never carries the value itself."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["not_collected"]


class DefaultByKeyedBy(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_: str = Field(alias="from")
    output: str


class DefaultByMapping(BaseModel):
    """The one second-order default: `table` must name a dict registered in
    REGISTERED_DEFAULT_TABLES, and `keyed_by` names the `derived` output
    that selects a row of it. The contract never supplies the value itself,
    same discipline as `not_collected`."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["default_by"]
    table: str
    keyed_by: DefaultByKeyedBy


class ContentAddressMapping(BaseModel):
    """`finding.finding_id` only (`validate_contract` enforces this --
    nothing about the shape itself is finding_id-specific). `columns` is
    ORDERED and, once a contract is confirmed, frozen: `memory.decisions`
    keys on the rendered id, so changing this recipe orphans every prior
    decision for this format."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["content_address"]
    algorithm: Literal["sha256"] = "sha256"
    columns: list[str]
    join: str = ""
    prefix: str = ""
    hex_len: int = Field(ge=8, le=32)
    case: Literal["upper", "lower"] = "upper"
    recipe_version: int = 1

    @field_validator("columns")
    @classmethod
    def _columns_non_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("columns must not be empty")
        return value


Mapping = Annotated[
    Union[
        ColumnMapping,
        VocabularyMapping,
        DerivedMapping,
        ParsedMapping,
        LiteralMapping,
        ComposedMapping,
        NotCollectedMapping,
        DefaultByMapping,
        ContentAddressMapping,
    ],
    Field(discriminator="kind"),
]

_BLANK_BEARING_KINDS = (ColumnMapping, VocabularyMapping, ParsedMapping)
_COLUMN_BEARING_KINDS = (ColumnMapping, VocabularyMapping, ParsedMapping)


# ---------------------------------------------------------------------------
# Derivation: one column -> several named outputs. Defender's
# OSPlatform -> (display string, OS class) shape and nothing more general.
# ---------------------------------------------------------------------------


class Derivation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    column: str
    case: Case = "exact"
    blank: Literal["fatal"] = "fatal"
    outputs: list[str]
    table: dict[str, list[Any]]
    table_notes: dict[str, str] | None = None

    @field_validator("outputs")
    @classmethod
    def _outputs_non_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("outputs must not be empty")
        return value

    @model_validator(mode="after")
    def _table_rows_match_outputs(self) -> "Derivation":
        bad = {k: v for k, v in self.table.items() if len(v) != len(self.outputs)}
        if bad:
            raise ValueError(
                f"table row(s) {sorted(bad)} do not have exactly {len(self.outputs)} value(s), "
                f"one per output {self.outputs}"
            )
        return self


# ---------------------------------------------------------------------------
# Provenance, source topology, header contract
# ---------------------------------------------------------------------------


class Generator(BaseModel):
    """Provenance of the phase-1 LLM call. Never read by phase 2 -- this is
    audit trail, not input to any decision the engine makes."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    model: str
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    estimated_cost_usd: float = Field(ge=0)
    attempts: int = Field(ge=1)
    call_log_digest: str


class Source(BaseModel):
    model_config = ConfigDict(extra="forbid")

    layout: Literal["single_file", "two_file"]
    assets_filename: str
    findings_filename: str
    encoding: Literal["auto", "utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be"] = "auto"
    delimiter: str = ","
    quotechar: str = '"'
    first_data_row: int = Field(default=2, ge=2)

    @field_validator("assets_filename", "findings_filename")
    @classmethod
    def _bare_filename(cls, value: str) -> str:
        # A bare filename, no separators, no "..": load_batch does
        # `data_dir / adapter.assets_filename`, which resolves ".."
        # happily, and refusal messages echo cell values verbatim -- a
        # traversing filename would be a file-content leak to stderr.
        if not _FILENAME_PATTERN.match(value):
            raise ValueError(f"{value!r} is not a bare filename (must match {_FILENAME_PATTERN.pattern!r})")
        return value

    @field_validator("delimiter", "quotechar")
    @classmethod
    def _exactly_one_char(cls, value: str) -> str:
        if len(value) != 1:
            raise ValueError("must be exactly one character")
        return value

    @model_validator(mode="after")
    def _layout_filename_biconditional(self) -> "Source":
        equal = self.assets_filename == self.findings_filename
        if self.layout == "single_file" and not equal:
            raise ValueError(
                f"layout is single_file but assets_filename ({self.assets_filename!r}) != "
                f"findings_filename ({self.findings_filename!r})"
            )
        if self.layout == "two_file" and equal:
            raise ValueError(
                f"layout is two_file but assets_filename and findings_filename are both "
                f"{self.assets_filename!r} -- two_file requires two distinct files"
            )
        return self


class HeaderSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    columns: list[str]
    sha256: str


class Header(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["declared", "frozen"] = "declared"
    assets: HeaderSpec
    findings: HeaderSpec | None = None


# ---------------------------------------------------------------------------
# Grouping, dedup, unmapped-column accounting
# ---------------------------------------------------------------------------


class AssetGroupingOrderBy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    column: str
    parser: Literal["date", "timestamp"]
    params: dict[str, Any] | None = None
    required: bool = True


class AssetGrouping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str
    order_by: AssetGroupingOrderBy | None = None
    resolution: Literal["agree_or_recency"] = "agree_or_recency"
    union_fields: list[str] = Field(default_factory=list)
    union_justification: dict[str, str] = Field(default_factory=dict)


class FindingDedup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content_targets: list[str]
    on_identical: Literal["collapse_and_count"] = "collapse_and_count"
    on_conflict: Literal["fatal"] = "fatal"

    @field_validator("content_targets")
    @classmethod
    def _content_targets_non_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("content_targets must not be empty")
        return value


class UnmappedColumnEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disposition: Literal["ignored", "evidence_only", "deliberately_dropped"]
    reason: str

    @field_validator("reason")
    @classmethod
    def _reason_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("reason must be non-empty")
        return value


# ---------------------------------------------------------------------------
# Enrichment -- optional; presence is what sets provides_enrichment
# ---------------------------------------------------------------------------


class EnrichmentAttackTechnique(BaseModel):
    """The one degrade disposition in the whole design, hard-coded to this
    one field with a fixed, code-owned pattern -- an unparsed technique is a
    real "no technique reported" fact, not a data-quality problem."""

    model_config = ConfigDict(extra="forbid")

    column: str
    optional: bool = False
    blank: Literal["absent_fact"] = "absent_fact"
    pattern: Literal["attack_technique"] = "attack_technique"
    outputs: list[str]
    on_no_match: Literal["degrade"] = "degrade"


class Enrichment(BaseModel):
    """Presence of this block is the entire `provides_enrichment` switch --
    there is no separate boolean to drift out of sync with it. No
    `severity_label` key: the label is the contract's own `format` name
    (Contract._format_reserved), so a vendor's self-reported score can never
    be misattributed to NVD. No `attack_prevalence` or `epss` key at any
    level -- both are corpus-wide statistics this project computes itself;
    no source has either to report."""

    model_config = ConfigDict(extra="forbid")

    severity_score: ParsedMapping
    known_exploited: ParsedMapping | None = None
    attack_technique: EnrichmentAttackTechnique | None = None

    @field_validator("severity_score")
    @classmethod
    def _severity_score_is_float(cls, value: ParsedMapping) -> ParsedMapping:
        if value.parser != "float":
            raise ValueError("enrichment.severity_score must use the 'float' parser")
        return value

    @field_validator("known_exploited")
    @classmethod
    def _known_exploited_is_bool(cls, value: ParsedMapping | None) -> ParsedMapping | None:
        if value is not None and value.parser != "bool":
            raise ValueError("enrichment.known_exploited must use the 'bool' parser")
        return value


# ---------------------------------------------------------------------------
# not_collected -- DERIVED. The contract records it; validate_contract
# recomputes it from the mapping declarations and refuses on disagreement
# (V09). There is no key here the model can set to silence a column.
# ---------------------------------------------------------------------------


class NotCollectedDerived(BaseModel):
    model_config = ConfigDict(extra="forbid")

    always_asset: list[str] = Field(default_factory=list)
    always_finding: list[str] = Field(default_factory=list)
    per_row_eligible_asset: list[str] = Field(default_factory=list)
    per_row_eligible_finding: list[str] = Field(default_factory=list)


class Divergence(BaseModel):
    """A place this contract's declared semantics differ from the hand-
    written adapter it is modeled on, with the row count the probe
    measured. Meaningful for a reference contract; optional in general."""

    model_config = ConfigDict(extra="forbid")

    what: str
    rows_affected: int = Field(ge=0)


class ValidatorOverride(BaseModel):
    """A correction code applied to a proposed mapping, kept in the file so
    the model's overreach stays visible rather than silently laundered.
    Nothing in this slice *produces* these -- there is no proposal step yet
    to correct -- but a hand-written or future-generated contract may carry
    them, so the shape is accepted and passed through unchanged. `proposed`/
    `applied` are intentionally loose: what they contain depends on which
    rule fired, and inventing a closed shape for that now would be guessing
    ahead of the rule that will actually populate it."""

    model_config = ConfigDict(extra="allow")

    path: str
    rule: str


ATTESTATION_ITEMS: frozenset[str] = frozenset(
    {"enrichment", "union", "finding_id.synthesized", "exclusions", "low_confidence_mappings"}
)

#: Targets whose value space is closed and code-owned, so showing the values
#: a mapping actually produced is schema information rather than fleet data
#: (`adapters/review.py`'s own `_value_distribution`, moved here so
#: `required_attestations` below can share the identical list rather than
#: keep a second, driftable copy of "which targets feed scoring"). Free text
#: (`hostname`, `owner`, `business_function`, `product`, `evidence`) is
#: never tallied and never leaves the terminal -- CLAUDE.md's trust
#: boundary calls real vulnerability data a map of where an organization is
#: weak, and a contract is committed to git. This is also exactly the set a
#: wrong LOW-CONFIDENCE value silently corrupts a real risk score for,
#: rather than merely showing up wrong in a report -- see
#: `LOW_CONFIDENCE_THRESHOLD` below.
SCORING_ENUM_TARGETS = ("role", "environment", "data_sensitivity", "criticality", "internet_exposed")

#: Below this, a `SlotMapped.confidence` on one of `SCORING_ENUM_TARGETS`
#: triggers the `low_confidence_mappings` attestation (`required_
#: attestations`, below) -- `check_grounding` (agents/schema_inference.py)
#: verifies a vocabulary table's KEYS are real observed source tokens, but
#: has no way to check whether the table's VALUES are semantically right
#: (a scale the model guessed at 0.50 confidence passes grounding cleanly
#: even if it's inverted). A named constant, not a bare literal, for the
#: same reason as scoring.py's PATCH_NOW_THRESHOLD/ACTIONABLE_THRESHOLD:
#: picked from the confidence values two real propose runs against the
#: same real source actually produced (correct mappings clustered
#: 0.85-0.98; guessed enum scales clustered 0.50-0.65 -- PROGRESS.md
#: 2026-09-06), not calibrated against a larger sample. Retuning this
#: against more real runs is a separate, open decision, same as those two.
LOW_CONFIDENCE_THRESHOLD = 0.7


def _observed_exclusion_count(observed: "dict[str, Any] | None") -> tuple[int, list[str]]:
    """`(records observed says were excluded, problems)`.

    `Contract.observed` is `dict[str, Any]` by design, so nothing stops a
    hand-edited contract from storing the `id -> reason` DICT that
    `IngestStats` carries under these identical names. V18 used to add the
    two values directly, which made that case raise a bare `TypeError` out
    of the validator rather than refuse -- an unhandled crash where the
    whole module's discipline is to name the problem. `rhino adapt confirm`
    (adapters/review.py) is the first thing that ever writes this block and
    always writes ints; this makes everything else a refusal."""
    if not observed:
        return 0, []
    total = 0
    problems: list[str] = []
    for key in ("excluded_assets", "excluded_findings"):
        value = observed.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int):
            problems.append(
                f"observed.{key} is a {type(value).__name__}, not an int -- V18 counts excluded "
                "records with it, so it must be a plain count (adapters/review.py writes one)"
            )
            continue
        total += value
    return total, problems


def low_confidence_scoring_slots(contract: Contract) -> dict[str, float]:
    """`"asset.<target>"` -> confidence, for every `SCORING_ENUM_TARGETS`
    slot mapped at or below `LOW_CONFIDENCE_THRESHOLD`. Empty for a
    contract with no `mapping_confidence` at all (never proposed, or
    proposed before this field existed) -- there is nothing to flag, not a
    reason to assume every slot is risky. Public (not `_`-prefixed) for the
    same reason `required_attestations` itself is: a caller (`adapters
    /review.py`, `web/adapters.py`) needs to show WHICH slots and at what
    confidence, not just whether the attestation item is required."""
    confidence = contract.mapping_confidence or {}
    return {
        f"asset.{target}": confidence[f"asset.{target}"]
        for target in SCORING_ENUM_TARGETS
        if f"asset.{target}" in confidence and confidence[f"asset.{target}"] < LOW_CONFIDENCE_THRESHOLD
    }


def required_attestations(contract: Contract) -> dict[str, str]:
    """Which attestation items this contract's own shape demands, mapped to
    the reason each is demanded (V18).

    Extracted so the validator and a caller that must PREDICT it share one
    definition. `adapters/review.py` is that caller: it has to tell a
    reviewer what to attest to *before* the contract is signed, and a second
    copy of this policy would be free to drift from the one that actually
    refuses. Same anti-drift move this module already makes deriving
    `GAP_LEGAL_TARGETS` from `NOT_COLLECTED_DEFAULTS`.

    Insertion order is V18's own emission order, so `validate_contract`'s
    messages stay byte-identical to what they were before this was
    extracted -- `low_confidence_mappings` is new and goes last, so it
    never renumbers or reorders anything V18 already emits."""
    required: dict[str, str] = {}
    if contract.enrichment is not None:
        required["enrichment"] = "the enrichment block is present"
    if contract.asset_grouping.union_fields:
        required["union"] = "asset_grouping.union_fields is non-empty"
    if isinstance(contract.finding.get("finding_id"), ContentAddressMapping):
        required["finding_id.synthesized"] = "finding.finding_id is a content_address"
    excluded, _problems = _observed_exclusion_count(contract.observed)
    if excluded > 0:
        required["exclusions"] = "observed reports excluded record(s)"
    low_confidence = low_confidence_scoring_slots(contract)
    if low_confidence:
        named = ", ".join(f"{slot} ({conf:.2f})" for slot, conf in sorted(low_confidence.items()))
        required["low_confidence_mappings"] = (
            f"{len(low_confidence)} scoring-relevant slot(s) mapped at model confidence below "
            f"{LOW_CONFIDENCE_THRESHOLD}: {named}"
        )
    return required


def missing_attestations(contract: Contract) -> list[str]:
    """The items `required_attestations` demands that the contract does not
    carry -- what V18 will refuse over, computable before anything is
    signed."""
    present = {a.item for a in contract.attestations}
    return [item for item in required_attestations(contract) if item not in present]


class Attestation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item: str
    text: str
    at: str

    @field_validator("text")
    @classmethod
    def _text_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("attestation text must be non-empty")
        return value


class Review(BaseModel):
    """The gate. A contract whose `state` is not `\"confirmed\"` is refused
    by the engine before any file is opened -- a later slice's job; this
    model only enforces that a confirmed review actually carries what
    confirmation means."""

    model_config = ConfigDict(extra="forbid")

    state: Literal["proposed", "confirmed", "stale"] = "proposed"
    confirmed_at: str | None = None
    confirmed_by: str | None = None
    confirmed_version: int | None = None
    content_digest: str | None = None
    decision_digest: str | None = None
    slot_digests: dict[str, str] | None = None

    @model_validator(mode="after")
    def _confirmed_requires_its_fields(self) -> "Review":
        if self.state == "confirmed":
            required = ("confirmed_at", "confirmed_by", "content_digest", "decision_digest")
            missing = [name for name in required if getattr(self, name) is None]
            if missing:
                raise ValueError(f"review.state is 'confirmed' but missing {missing}")
        return self


# ---------------------------------------------------------------------------
# The contract itself
# ---------------------------------------------------------------------------

#: The subtrees `compute_decision_digest` hashes -- every block that
#: represents a mapping DECISION, excluding `observed` (measurement, not
#: decision), `generator`/`generated_at` (provenance, not decision), and
#: `review` itself (the signature can't include what it signs).
DECISION_SUBTREES: tuple[str, ...] = (
    "source",
    "header",
    "derived",
    "asset",
    "finding",
    "enrichment",
    "asset_grouping",
    "finding_dedup",
    "unmapped_columns",
)


class Contract(BaseModel):
    """One ingest contract, in full. `extra=\"forbid\"` throughout the
    blocks that carry mapping decisions -- an unknown key there is a
    decision that silently did nothing, never something to ignore. The
    provenance/measurement blocks (`generator`, `observed`) are loosely
    typed: nothing in this slice computes them, and committing to an exact
    shape for data no code here produces would be guessing ahead of the
    slice that does."""

    model_config = ConfigDict(extra="forbid")

    config_schema_version: str
    version: int = Field(ge=1)
    format: str
    description: str
    generated_at: str
    generator: Generator
    #: `"asset.<target>"` / `"finding.<target>"` -> the model's own
    #: self-reported confidence at proposal time (`SlotMapped.confidence`,
    #: agents/schema_inference.py) -- audit trail, exactly like `generator`,
    #: never read by `configured.py`'s engine or by `required_attestations`
    #: for anything but deciding whether to ASK a human to look, never to
    #: decide anything about the mapping itself. `None` for a contract that
    #: never went through a proposal (bluepeak-gen.json/mdvm-gen.json,
    #: hand-authored before this field existed) -- there is no model
    #: confidence to report for those, so absence is the honest value, not
    #: a fabricated 1.0.
    mapping_confidence: dict[str, float] | None = None
    source: Source
    header: Header
    derived: dict[str, Derivation] = Field(default_factory=dict)
    asset: dict[str, Mapping]
    finding: dict[str, Mapping]
    enrichment: Enrichment | None = None
    asset_grouping: AssetGrouping
    finding_dedup: FindingDedup
    unmapped_columns: dict[str, dict[str, UnmappedColumnEntry]] = Field(default_factory=dict)
    not_collected: NotCollectedDerived = Field(default_factory=NotCollectedDerived)
    validator_overrides: list[ValidatorOverride] = Field(default_factory=list)
    observed: dict[str, Any] | None = None
    divergences: list[Divergence] = Field(default_factory=list)
    attestations: list[Attestation] = Field(default_factory=list)
    review: Review = Field(default_factory=Review)

    @field_validator("format")
    @classmethod
    def _format_pattern_and_reserved(cls, value: str) -> str:
        if not _FORMAT_PATTERN.match(value):
            raise ValueError(f"{value!r} does not match {_FORMAT_PATTERN.pattern!r}")
        if value in _BUILTIN_ADAPTER_FORMATS:
            raise ValueError(f"{value!r} collides with a built-in adapter format {sorted(_BUILTIN_ADAPTER_FORMATS)}")
        if value in RESERVED_PROVENANCE_LABELS:
            raise ValueError(f"{value!r} is a reserved provenance label {sorted(RESERVED_PROVENANCE_LABELS)}")
        return value

    @model_validator(mode="after")
    def _asset_and_finding_slots_exact(self) -> "Contract":
        asset_keys, want_asset = set(self.asset), set(ASSET_SLOTS)
        if asset_keys != want_asset:
            raise ValueError(
                f"asset block must map exactly {sorted(want_asset)}; "
                f"missing {sorted(want_asset - asset_keys)}, extra {sorted(asset_keys - want_asset)}"
            )
        finding_keys, want_finding = set(self.finding), set(FINDING_SLOTS)
        if finding_keys != want_finding:
            raise ValueError(
                f"finding block must map exactly {sorted(want_finding)}; "
                f"missing {sorted(want_finding - finding_keys)}, extra {sorted(finding_keys - want_finding)}"
            )
        return self

    @model_validator(mode="after")
    def _findings_header_matches_layout(self) -> "Contract":
        if self.source.layout == "two_file" and self.header.findings is None:
            raise ValueError("layout is two_file but header.findings is missing")
        if self.source.layout == "single_file" and self.header.findings is not None:
            raise ValueError("layout is single_file but header.findings is present")
        return self


# ---------------------------------------------------------------------------
# Digests -- canonical JSON + sha256, for V19 and for a later slice's
# confirm/rereview flow. Pure functions; no I/O.
# ---------------------------------------------------------------------------


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_content_digest(contract: Contract) -> str:
    """Catches ANY post-write edit -- everything except `review` itself,
    since a signature cannot include what it signs."""
    data = contract.model_dump(mode="json", exclude={"review"})
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(data)).hexdigest()


def compute_decision_digest(contract: Contract) -> str:
    """What a human's confirmation actually binds to: the mapping DECISION
    subtrees only, excluding `observed` (measurement -- moves every time the
    source file is re-probed), `generator`/`generated_at` (provenance), and
    `review`. Re-probing a fresh export changes `content_digest` without
    voiding what was confirmed, because it never touches this digest."""
    full = contract.model_dump(mode="json")
    data = {key: full[key] for key in DECISION_SUBTREES if key in full}
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(data)).hexdigest()


def compute_slot_digests(contract: Contract) -> dict[str, str]:
    """One digest per target slot -- `"asset.<field>"` / `"finding.<field>"`
    -- over that slot's own mapping node alone, nothing else. This is what
    lets a future re-review (`rhino adapt rereview`) show ONLY the slots
    whose decision actually moved: a vendor renaming one unrelated column
    changes `decision_digest` (the whole mapping moved) but leaves every
    OTHER slot's own digest untouched, so a reviewer re-confirms one line
    instead of re-reading the whole contract. Optional on `Review` even
    when confirmed -- a contract that never recorded these falls back to
    the coarser content/decision signal (`assert_confirmed`)."""
    digests: dict[str, str] = {}
    for target, mapping in contract.asset.items():
        data = mapping.model_dump(mode="json")
        digests[f"asset.{target}"] = "sha256:" + hashlib.sha256(_canonical_json_bytes(data)).hexdigest()
    for target, mapping in contract.finding.items():
        data = mapping.model_dump(mode="json")
        digests[f"finding.{target}"] = "sha256:" + hashlib.sha256(_canonical_json_bytes(data)).hexdigest()
    return digests


class ContractNotConfirmedError(ContractError):
    """`review.state` is not `"confirmed"`. There is no `--force`, no env
    var, no partial mode -- see `assert_confirmed`."""


class ContractDigestMismatchError(ContractError):
    """The contract's own recorded digest(s) no longer match its current
    content -- it was hand-edited (or corrupted) after confirmation. See
    `assert_confirmed`."""


def assert_confirmed(contract: Contract) -> None:
    """The engine's construction-time gate. `ConfiguredAdapter.__init__`
    calls this before opening any file or setting any instance attribute:
    refuses to proceed unless `review.state == "confirmed"` AND the
    contract's own stored digests still match its current content.

    Needs no header and touches no file -- digests are computed purely
    from the contract's own fields, so a stale or unconfirmed contract is
    refused before a single byte of the source CSV is read, exactly the
    "checked before any file is opened" property this slice exists to add.

    On a digest mismatch, if the contract recorded `slot_digests` at
    confirmation time, this recomputes them now and names exactly which
    slot(s) changed -- the same per-slot comparison a future `rhino adapt
    rereview` uses to show only what moved. Without `slot_digests` (legal
    -- optional even when confirmed), the message falls back to a coarser
    but still meaningful signal: whether the edit touched a DECISION
    subtree (content_digest AND decision_digest both mismatch) or only
    provenance/measurement outside it (content_digest mismatches alone --
    `observed`/`generator`/`generated_at`/`mapping_confidence` are the
    only fields that could have moved)."""
    if contract.review.state != "confirmed":
        raise ContractNotConfirmedError(
            f"contract {contract.format!r} is not confirmed (review.state={contract.review.state!r}). "
            "Review its mapping and confirm it before it can ingest anything: "
            f"rhino adapt confirm {contract.format} (a later slice's command)."
        )

    problems: list[str] = []
    actual_content = compute_content_digest(contract)
    content_matches = actual_content == contract.review.content_digest
    if not content_matches:
        problems.append(
            f"content_digest mismatch: file says {contract.review.content_digest!r}, "
            f"recomputed {actual_content!r}"
        )

    actual_decision = compute_decision_digest(contract)
    decision_matches = actual_decision == contract.review.decision_digest
    if not decision_matches:
        problems.append(
            f"decision_digest mismatch: file says {contract.review.decision_digest!r}, "
            f"recomputed {actual_decision!r} -- a MAPPING DECISION changed since this was confirmed, "
            "not just measurement or provenance"
        )
        if contract.review.slot_digests:
            actual_slots = compute_slot_digests(contract)
            changed = sorted(
                name for name, stored in contract.review.slot_digests.items() if actual_slots.get(name) != stored
            )
            if changed:
                problems.append(f"changed slot(s): {changed}")
    elif not content_matches:
        problems.append(
            "decision_digest still matches -- the edit is outside the mapping decisions "
            "(observed/generator/generated_at), not a scoring-relevant change"
        )

    if problems:
        raise ContractDigestMismatchError(
            f"contract {contract.format!r} was edited after it was confirmed "
            f"(confirmed_at={contract.review.confirmed_at!r}):\n" + "\n".join(f"  - {p}" for p in problems)
        )


# ---------------------------------------------------------------------------
# Cross-field validation. Structural rules enforceable from the contract
# alone already live as pydantic validators above (V02, V04 [no default],
# V11, V12, V13); everything here needs either the real header(s) or a
# cross-block view pydantic's per-field validators can't see.
# ---------------------------------------------------------------------------


def _target_vocabulary(target: str) -> frozenset[str] | tuple[int, int] | Literal["bool"] | None:
    """What a `vocabulary`/`derived`-output value at `target` is allowed to
    be, or None if the target has no closed constraint this function knows
    to check (a free-text field like `business_function`)."""
    if target == "criticality":
        return (1, 5)  # schema.Asset.criticality: Field(ge=1, le=5)
    if target == "internet_exposed":
        return "bool"
    hints = _ASSET_TYPE_HINTS if target in _ASSET_TYPE_HINTS else _FINDING_TYPE_HINTS
    annotation = hints.get(target)
    if annotation is None:
        return None
    args = get_args(annotation)
    if args and all(isinstance(a, str) for a in args):
        return frozenset(args)
    return None


def describe_target_vocabulary(target: str) -> dict[str, Any] | None:
    """The public, JSON-serializable form of `_target_vocabulary` -- for a
    caller that needs to SHOW a target's legal values (a browser slot-
    resolution form, `web/adapters.py`) rather than check one. Deliberately
    a read of the same registry `check_grounding`/`validate_contract`
    already enforce against, not a second, hand-maintained list: a target
    this function calls an `"enum"` of `{"prod", "staging", "dev"}` is an
    enum of exactly those values to the engine too, by construction, so a
    UI built from this can never offer an option the engine would refuse."""
    vocabulary = _target_vocabulary(target)
    if vocabulary is None:
        return None
    if vocabulary == "bool":
        return {"kind": "bool"}
    if isinstance(vocabulary, tuple):
        low, high = vocabulary
        return {"kind": "range", "min": low, "max": high}
    return {"kind": "enum", "values": sorted(vocabulary)}


def _check_vocabulary_value(problems: list[str], where: str, target: str, value: Any) -> None:
    vocabulary = _target_vocabulary(target)
    if vocabulary is None:
        return
    if vocabulary == "bool":
        if not isinstance(value, bool):
            problems.append(f"{where}: value {value!r} is not a bool, required by target {target!r}")
    elif isinstance(vocabulary, tuple):
        low, high = vocabulary
        if not isinstance(value, int) or isinstance(value, bool) or not (low <= value <= high):
            problems.append(f"{where}: value {value!r} is not an int in [{low}, {high}], required by target {target!r}")
    elif value not in vocabulary:
        problems.append(f"{where}: value {value!r} is not one of {sorted(vocabulary)}, required by target {target!r}")


def _column_of(mapping: Any) -> str | None:
    return mapping.column if isinstance(mapping, _COLUMN_BEARING_KINDS) else None


def _composed_columns(mapping: ComposedMapping) -> set[str]:
    columns: set[str] = set()
    for part in mapping.parts:
        if isinstance(part, ComposedPartTemplate):
            for text in (part.template, part.fallback_template or ""):
                columns.update(_PLACEHOLDER_PATTERN.findall(text))
            columns.update(part.required_non_blank)
            columns.update(part.emit_if_any or ())
        else:
            columns.update(part.join_nonblank)
    return columns


def _compute_not_collected(contract: Contract, assets_header: set[str], findings_header: set[str]) -> NotCollectedDerived:
    always_asset: list[str] = []
    per_row_asset: list[str] = []
    for target, mapping in contract.asset.items():
        if isinstance(mapping, (NotCollectedMapping, DefaultByMapping)):
            always_asset.append(target)
            continue
        column = _column_of(mapping)
        if column is not None and mapping.optional and column not in assets_header:
            always_asset.append(target)
            continue
        if isinstance(mapping, _BLANK_BEARING_KINDS) and mapping.blank == "gap":
            per_row_asset.append(target)

    always_finding: list[str] = []
    per_row_finding: list[str] = []
    for target, mapping in contract.finding.items():
        if isinstance(mapping, (NotCollectedMapping, DefaultByMapping)):
            always_finding.append(target)
            continue
        column = _column_of(mapping)
        if column is not None and mapping.optional and column not in findings_header:
            always_finding.append(target)
            continue
        if isinstance(mapping, _BLANK_BEARING_KINDS) and mapping.blank == "gap":
            per_row_finding.append(target)

    return NotCollectedDerived(
        always_asset=sorted(always_asset),
        always_finding=sorted(always_finding),
        per_row_eligible_asset=sorted(per_row_asset),
        per_row_eligible_finding=sorted(per_row_finding),
    )


def validate_contract(contract: Contract, headers: "dict[str, list[str]]") -> None:
    """Every cross-field and header-dependent rule this design names (V01,
    V03, V05-V10, V14-V16, V18-V19). Raises `ContractValidationError` naming
    every violation found in one pass; returns None on success.

    `headers` maps a filename (matching `source.assets_filename` /
    `findings_filename`) to that file's column names, in order -- a real
    CSV's header, or (as every test in this slice's suite does) a header
    hand-transcribed from the real file, or one a probe measured. Nothing
    here opens a file.

    Deliberately not V02, V04, V11, V12, V13: those are enforced by `Contract`
    itself at construction time (see its field/model validators) because
    they need no header to check. Deliberately not V17 (the full-file
    variance probe): that rule needs real row DATA, not just a header, and
    belongs to the engine slice this module does not implement.

    Deliberately returns `None`, not `list[ValidatorOverride]`: this
    function only checks a contract against a header, it does not correct
    one. A `validator_overrides`-producing correction step needs a
    *proposal* to correct against, which does not exist until the phase-1
    inference agent (a much later slice) does. `Contract.validator_overrides`
    still exists and is still validated as a passive, pass-through record --
    see its own docstring.
    """
    problems: list[str] = []

    for filename, columns in headers.items():
        duplicates = sorted({c for c in columns if columns.count(c) > 1})
        if duplicates:
            problems.append(f"{filename}: header column(s) appear more than once: {duplicates}")

    assets_header = headers.get(contract.source.assets_filename)
    findings_header = headers.get(contract.source.findings_filename)
    if assets_header is None:
        problems.append(f"no header supplied for assets file {contract.source.assets_filename!r}")
    if findings_header is None:
        problems.append(f"no header supplied for findings file {contract.source.findings_filename!r}")
    if assets_header is None or findings_header is None:
        raise ContractValidationError(
            f"{len(problems)} problem(s) validating contract {contract.format!r}:\n"
            + "\n".join(f"  - {p}" for p in problems),
            problems=tuple(problems),
        )

    assets_header_set, findings_header_set = set(assets_header), set(findings_header)
    # Direct: a column read by a mapping attached to an actual target field
    # (column/vocabulary/parsed/content_address/asset_grouping/enrichment).
    # Composed: a column read only through a `composed` template's
    # placeholders or join_nonblank -- tracked separately because the
    # design's "evidence_only" disposition means such a column may
    # LEGITIMATELY also appear in unmapped_columns (BluePeak's
    # Assigned_Team: read into evidence, explicitly not promoted to
    # Asset.owner). A direct mapping has no such allowance -- a column
    # feeding an actual schema slot can never also be "unmapped".
    accounted_assets: set[str] = set()
    accounted_findings: set[str] = set()
    composed_findings: set[str] = set()

    def check_column(
        where: str, column: str, header_set: set[str], accounted: set[str], header_name: str, *, optional: bool = False
    ) -> None:
        accounted.add(column)
        if column not in header_set and not optional:
            problems.append(f"{where}: column {column!r} is not in {header_name}'s header {sorted(header_set)}")
        if column == "not_collected":
            problems.append(f"{where}: 'not_collected' cannot be mapped as a source column")

    # -- derived: columns checked against the assets header (both worked
    # examples derive only from asset-side data; a finding-scoped derivation
    # is not a shape either real adapter needs, so it is out of scope here
    # rather than guessed at).
    for name, derivation in contract.derived.items():
        check_column(f"derived.{name}", derivation.column, assets_header_set, accounted_assets, "assets")

    finding_id_mapping = contract.finding.get("finding_id")

    for target, mapping in contract.asset.items():
        where = f"asset.{target}"
        if isinstance(mapping, ContentAddressMapping):
            problems.append(f"{where}: content_address is legal only for finding.finding_id")
        if isinstance(mapping, ComposedMapping):
            problems.append(f"{where}: composed is legal only for finding.evidence")
        if isinstance(mapping, NotCollectedMapping) and target not in GAP_LEGAL_TARGETS:
            problems.append(f"{where}: not_collected has no NOT_COLLECTED_DEFAULTS entry for {target!r}")
        if isinstance(mapping, DefaultByMapping):
            _check_default_by(problems, where, mapping, target, contract)
        column = _column_of(mapping)
        if column is not None:
            check_column(where, column, assets_header_set, accounted_assets, "assets", optional=mapping.optional)
        problems.extend(check_slot_mapping_legality(where, target, mapping))
        if isinstance(mapping, VocabularyMapping):
            for value in mapping.table.values():
                _check_vocabulary_value(problems, where, target, value)

    for target, mapping in contract.finding.items():
        where = f"finding.{target}"
        if isinstance(mapping, ContentAddressMapping) and target != "finding_id":
            problems.append(f"{where}: content_address is legal only for finding.finding_id")
        if isinstance(mapping, ComposedMapping) and target != "evidence":
            problems.append(f"{where}: composed is legal only for finding.evidence")
        if isinstance(mapping, NotCollectedMapping) and target not in GAP_LEGAL_TARGETS:
            problems.append(f"{where}: not_collected has no NOT_COLLECTED_DEFAULTS entry for {target!r}")
        if isinstance(mapping, ContentAddressMapping):
            for column in mapping.columns:
                check_column(where, column, findings_header_set, accounted_findings, "findings")
        column = _column_of(mapping)
        if column is not None:
            check_column(where, column, findings_header_set, accounted_findings, "findings", optional=mapping.optional)
        if isinstance(mapping, ComposedMapping):
            # A composed template renders over "that row's declared columns"
            # (the model docstring's own wording) -- a placeholder or
            # join_nonblank column the export never carries AT ALL simply
            # never contributes (str.format_map / a dict .get() both treat a
            # missing key as absent, matching defender.py's real
            # `.get("DiskPaths")` behavior), so absence from BOTH headers is
            # not an error. Absence from findings' header while the column
            # IS present in assets' header is a different thing entirely --
            # a two_file layout has no join primitive, so that placeholder
            # can only mean the author reached for the wrong file's column
            # (V16), and THAT stays a hard failure regardless of "optional".
            for placeholder in _composed_columns(mapping):
                composed_findings.add(placeholder)
                if placeholder == "not_collected":
                    problems.append(f"{where}: 'not_collected' cannot be mapped as a source column")
                elif placeholder not in findings_header_set and placeholder in assets_header_set:
                    problems.append(
                        f"{where}: column {placeholder!r} is in the assets header, not findings -- "
                        "composed has no cross-file join; a finding cannot read a column from the other file"
                    )
        problems.extend(check_slot_mapping_legality(where, target, mapping))
        if isinstance(mapping, VocabularyMapping):
            for value in mapping.table.values():
                _check_vocabulary_value(problems, where, target, value)

    check_column("asset_grouping.key", contract.asset_grouping.key, assets_header_set, accounted_assets, "assets")
    if contract.asset_grouping.order_by is not None:
        order_by = contract.asset_grouping.order_by
        check_column(
            "asset_grouping.order_by", order_by.column, assets_header_set, accounted_assets, "assets",
            optional=not order_by.required,
        )

    for field in contract.asset_grouping.union_fields:
        if field not in UNIONABLE_TARGETS:
            problems.append(f"asset_grouping.union_fields: {field!r} is not in UNIONABLE_TARGETS {sorted(UNIONABLE_TARGETS)}")
        justification = contract.asset_grouping.union_justification.get(field, "")
        if not justification.strip():
            problems.append(f"asset_grouping.union_fields: {field!r} has no non-empty union_justification entry")

    if contract.enrichment is not None:
        e = contract.enrichment
        if e.severity_score.blank != "fatal":
            problems.append("enrichment.severity_score: blank must be 'fatal' (no not-collected concept applies)")
        check_column("enrichment.severity_score", e.severity_score.column, findings_header_set, accounted_findings, "findings", optional=e.severity_score.optional)
        if e.known_exploited is not None:
            if e.known_exploited.blank != "fatal":
                problems.append("enrichment.known_exploited: blank must be 'fatal' (no not-collected concept applies)")
            check_column("enrichment.known_exploited", e.known_exploited.column, findings_header_set, accounted_findings, "findings", optional=e.known_exploited.optional)
        if e.attack_technique is not None:
            check_column("enrichment.attack_technique", e.attack_technique.column, findings_header_set, accounted_findings, "findings", optional=e.attack_technique.optional)

    for target in contract.finding_dedup.content_targets:
        if target.startswith("source_enrichment."):
            suffix = target[len("source_enrichment.") :]
            if suffix not in SOURCE_ENRICHMENT_FIELDS:
                problems.append(f"finding_dedup.content_targets: {target!r} is not a source_enrichment field")
            elif contract.enrichment is None:
                problems.append(f"finding_dedup.content_targets: {target!r} needs an enrichment block, which is absent")
        elif target not in FINDING_SLOTS:
            problems.append(f"finding_dedup.content_targets: {target!r} is not a finding target field")

    # -- column accounting complete in both directions (V08)
    unmapped_assets_entries = contract.unmapped_columns.get(contract.source.assets_filename) or {}
    unmapped_findings_entries = contract.unmapped_columns.get(contract.source.findings_filename) or {}
    unmapped_assets = set(unmapped_assets_entries)
    unmapped_findings = set(unmapped_findings_entries)

    unknown_unmapped_assets = unmapped_assets - assets_header_set
    if unknown_unmapped_assets:
        problems.append(f"unmapped_columns[{contract.source.assets_filename!r}]: names column(s) not in the header: {sorted(unknown_unmapped_assets)}")
    unknown_unmapped_findings = unmapped_findings - findings_header_set
    if unknown_unmapped_findings:
        problems.append(f"unmapped_columns[{contract.source.findings_filename!r}]: names column(s) not in the header: {sorted(unknown_unmapped_findings)}")

    # A DIRECTLY mapped column (feeds an actual target field) can never also
    # be listed as unmapped -- that is a real contradiction, not a
    # documented decision.
    direct_overlap_assets = accounted_assets & unmapped_assets
    if direct_overlap_assets:
        problems.append(f"column(s) {sorted(direct_overlap_assets)} are both mapped and listed in unmapped_columns[{contract.source.assets_filename!r}]")
    direct_overlap_findings = accounted_findings & unmapped_findings
    if direct_overlap_findings:
        problems.append(f"column(s) {sorted(direct_overlap_findings)} are both mapped and listed in unmapped_columns[{contract.source.findings_filename!r}]")

    # A column read ONLY through a composed template may also be listed as
    # unmapped, but ONLY under disposition "evidence_only" -- that is
    # precisely what the disposition means (module docstring's BluePeak
    # Assigned_Team example). Any other disposition on a composed-referenced
    # column is a real contradiction: the column is being read, so calling
    # it "ignored" or "deliberately_dropped" is false.
    composed_overlap_findings = (composed_findings & unmapped_findings) - accounted_findings
    for column in composed_overlap_findings:
        disposition = unmapped_findings_entries[column].disposition
        if disposition != "evidence_only":
            problems.append(
                f"column {column!r} is read by a composed template but listed in "
                f"unmapped_columns[{contract.source.findings_filename!r}] with disposition {disposition!r} "
                "(expected 'evidence_only', since the column IS being read)"
            )

    all_findings_accounted = accounted_findings | composed_findings
    if contract.source.layout == "single_file":
        # The same physical file backs both roles -- a column mapped to an
        # asset target and a column mapped to a finding target both come
        # from the one header, so completeness has to be checked against
        # their UNION, not against each half independently (checking
        # independently would report every asset-only column as "missing"
        # from the findings side and vice versa).
        combined_accounted = accounted_assets | all_findings_accounted
        combined_unmapped = unmapped_assets | unmapped_findings
        missing = assets_header_set - combined_accounted - combined_unmapped
        if missing:
            problems.append(f"{contract.source.assets_filename!r}: column(s) {sorted(missing)} are neither mapped nor in unmapped_columns")
    else:
        missing_assets = assets_header_set - accounted_assets - unmapped_assets
        if missing_assets:
            problems.append(f"{contract.source.assets_filename!r}: column(s) {sorted(missing_assets)} are neither mapped nor in unmapped_columns")
        missing_findings = findings_header_set - all_findings_accounted - unmapped_findings
        if missing_findings:
            problems.append(f"{contract.source.findings_filename!r}: column(s) {sorted(missing_findings)} are neither mapped nor in unmapped_columns")

    # -- not_collected recomputed and matching (V09)
    expected = _compute_not_collected(contract, assets_header_set, findings_header_set)
    if expected != contract.not_collected:
        problems.append(
            "not_collected disagrees with what the mappings declare:\n"
            f"      recomputed: {expected.model_dump()}\n"
            f"      in file:    {contract.not_collected.model_dump()}"
        )

    # -- attestations required by the contract's own shape (V18). The policy
    # itself lives in `required_attestations`/`missing_attestations` above, so
    # adapters/review.py can predict this refusal instead of re-deriving it.
    _excluded, observed_problems = _observed_exclusion_count(contract.observed)
    problems.extend(observed_problems)
    reasons = required_attestations(contract)
    for item in missing_attestations(contract):
        problems.append(f"attestations: {item!r} is required because {reasons[item]}")

    # -- digests match, if the contract carries them (V19)
    if contract.review.content_digest is not None:
        actual = compute_content_digest(contract)
        if actual != contract.review.content_digest:
            problems.append(f"review.content_digest mismatch: file says {contract.review.content_digest!r}, recomputed {actual!r}")
    if contract.review.decision_digest is not None:
        actual = compute_decision_digest(contract)
        if actual != contract.review.decision_digest:
            problems.append(f"review.decision_digest mismatch: file says {contract.review.decision_digest!r}, recomputed {actual!r}")

    if problems:
        raise ContractValidationError(
            f"{len(problems)} problem(s) validating contract {contract.format!r}:\n"
            + "\n".join(f"  - {p}" for p in problems),
            problems=tuple(problems),
        )


def _check_blank_policy(problems: list[str], where: str, blank: BlankPolicy, target: str) -> None:
    if blank == "gap" and target not in GAP_LEGAL_TARGETS:
        problems.append(
            f"{where}: blank='gap' is not legal for target {target!r} (not a key of NOT_COLLECTED_DEFAULTS; "
            f"legal targets: {sorted(GAP_LEGAL_TARGETS)})"
        )
    elif blank == "absent_fact" and target not in ABSENT_FACT_LEGAL_TARGETS:
        problems.append(
            f"{where}: blank='absent_fact' is not legal for target {target!r} (schema default is not \"\"; "
            f"legal targets: {sorted(ABSENT_FACT_LEGAL_TARGETS)})"
        )


def _check_parser_placement(problems: list[str], where: str, mapping: Any) -> None:
    """`parser: "timestamp"` is legal only inside `asset_grouping.order_by`
    (`AssetGroupingOrderBy.parser` has its own, separate Literal for that)
    -- never on a plain per-row `parsed` mapping. Factored out of
    `validate_contract`'s own per-slot loops so `check_slot_mapping_legality`
    (below) -- and, through it, `agents/schema_inference.py`'s construction-
    time proposal check -- runs the identical rule rather than a second,
    hand-copied one."""
    if isinstance(mapping, ParsedMapping) and mapping.parser == "timestamp":
        problems.append(f"{where}: parser 'timestamp' is legal only inside asset_grouping.order_by")


def check_slot_mapping_legality(where: str, target: str, mapping: Any) -> list[str]:
    """Every per-mapping legality rule that depends only on `(target,
    mapping)` -- not on the real header, another contract block, or
    anything else needing full contract context. `validate_contract`'s own
    per-slot loops call this so it stays the single source of truth; more
    importantly, `agents/schema_inference.py`'s `AdapterProposal` ALSO runs
    it, at model-construction time, on every `SlotMapped` the model
    proposes -- closing the grammar at generation, not only at final
    contract validation. A proposal that emits `blank='gap'` on a target
    with no `NOT_COLLECTED_DEFAULTS` entry (e.g. `role`), or a `timestamp`
    parser outside `asset_grouping.order_by`, is rejected immediately and
    retried with the specific violation fed back to the model, rather than
    accepted as "resolved" and only failing later when the assembled
    contract reaches this exact same check."""
    problems: list[str] = []
    if isinstance(mapping, _BLANK_BEARING_KINDS):
        _check_blank_policy(problems, where, mapping.blank, target)
    _check_parser_placement(problems, where, mapping)
    return problems


def _check_default_by(problems: list[str], where: str, mapping: DefaultByMapping, target: str, contract: Contract) -> None:
    if mapping.table not in REGISTERED_DEFAULT_TABLES:
        problems.append(f"{where}: default_by.table {mapping.table!r} is not a registered table {sorted(REGISTERED_DEFAULT_TABLES)}")
        return
    legal_target = DEFAULT_BY_LEGAL_TARGET[mapping.table]
    if target != legal_target:
        problems.append(f"{where}: default_by.table {mapping.table!r} may only feed {legal_target!r}, not {target!r}")
    derivation = contract.derived.get(mapping.keyed_by.from_)
    if derivation is None:
        problems.append(f"{where}: keyed_by.from {mapping.keyed_by.from_!r} is not a name in derived")
    elif mapping.keyed_by.output not in derivation.outputs:
        problems.append(f"{where}: keyed_by.output {mapping.keyed_by.output!r} is not one of derived.{mapping.keyed_by.from_}'s outputs {derivation.outputs}")
