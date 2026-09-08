"""What the target schema *means* -- published, not just declared.

`config_model.py`'s grammar already names which `asset.*`/`finding.*` slots
exist and, for a handful of them, which raw token strings a source may use
(`_target_vocabulary`'s enumerated Literal check). What it never published
is the other half a phase-1 proposer (or a human resolving an unresolved
slot by hand) actually needs: what does each legal value *mean*, and what
real-world spellings has this project already seen used for it? A schema
whose only visible contract is "these bare strings are legal" gives a model
nothing to ground a judgment call in -- it can see that `"dc"` is a legal
`asset.role` token, but not that it means "Active Directory domain
controller", nor that "Domain Controller" is a spelling this project has
already confirmed maps to it in a real, human-reviewed contract
(`data/adapters/bluepeak-gen.json`).

This module is that missing half: `TARGET_REGISTRY` is the single published
source of truth for every `asset.*`/`finding.*` slot's accepted Python type,
legal blank policies, and -- for the four targets whose *values* are worth
aliasing (`role`, `environment`, `data_sensitivity`, `criticality`) -- the
real-world spellings a source might use for each legal value. Two
consumers read it: `config_model.py` (re-sourcing `GAP_LEGAL_TARGETS`,
`ABSENT_FACT_LEGAL_TARGETS`, `_target_vocabulary`, `describe_target_vocabulary`,
and `_check_parser_placement` from here instead of deriving them
independently -- a pure relocation, not a behavior change) and
`agents/schema_inference.py` (both to enrich the propose-time prompt with
this same meaning/alias data, and to run a deterministic, LLM-free pass --
`_apply_registry_aliases` -- that closes exactly the gaps a model left
honestly unresolved or incomplete because *it* had nothing to ground a
guess in either).

No I/O, no LLM, no `crewai` import -- this must stay reachable from the
deterministic, LLM-free CLI path exactly as `config_model.py` already does
(this module is a dependency of `config_model.py` itself, so the constraint
is structural, not just a style preference).

Case handling
-------------
Every alias lookup here case-normalizes with the IDENTICAL transform the
real engine applies before its own table lookups (`adapters/configured
._apply_case`) -- imported lazily inside `_cased`, not at module level; see
that function's own docstring for why a top-level import here would
deadlock `config_model.py`'s own import.

The criticality anchor-only scope decision
-------------------------------------------
`CriticalityScale.anchors` deliberately covers ONLY the two unambiguous,
absolute ends of a 1-5 scale -- never a middle word like "High"/"Medium"/
"Normal"/"Low"/"Moderate". This is not an oversight to be filled in later;
it is load-bearing, and the evidence is sitting in this repository's own
two confirmed, human-reviewed contracts:

  - `data/adapters/bluepeak-gen.json` maps its four-tier scale
    critical->5, high->4, medium->3, low->2 -- its own `table_notes` says
    so explicitly: "low is deliberately 2, not 1 -- this source's four
    tiers do not reach the schema's floor."
  - `data/adapters/mdvm-gen.json` maps its three-tier scale high->5,
    normal->3, low->1.

Both real reviewers looked at a middle word and made a DIFFERENT correct
judgment call, because the right number for "Low" or "High" depends on how
many other tiers exist in that source's own scale -- there is no universal
mapping to encode. A deterministic alias table that resolved "Low" to a
fixed number would silently assert one source's judgment as fact for every
future source -- exactly the wrong-but-plausible-number failure the whole
not_collected/refuse-rather-than-guess discipline (`adapters/base.py`,
`config_model.py`'s own module docstring) exists to prevent. "Critical" and
"Informational"/"Minimal"/"Negligible" carry no such ambiguity: they mean
the same absolute thing (the single most/least severe tier, full stop)
regardless of how many tiers a given source's scale has, so -- and only so
-- they are safe to resolve deterministically. Everything in between stays
the model's own judgment call, now INFORMED (the prompt enrichment in
`agents/schema_inference.py` renders the two real, cited scale choices
above as worked precedent) rather than blind, exactly as it was before this
module existed. A later agent expanding this registry with more anchor
words must stay inside this same boundary -- see `resolve_criticality_anchor`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, get_args, get_type_hints

from rhinosecure.adapters.base import NOT_COLLECTED_DEFAULTS
from rhinosecure.schema import Asset, Finding

# ---------------------------------------------------------------------------
# Relocated from config_model.py (its own docstring names these as the four
# names it re-imports and re-exports under identical names, so
# adapters/configured.py and agents/schema_inference.py need zero import
# changes). Kept here, not duplicated, per the module docstring above.
# ---------------------------------------------------------------------------

_ASSET_TYPE_HINTS: dict[str, Any] = get_type_hints(Asset)
_FINDING_TYPE_HINTS: dict[str, Any] = get_type_hints(Finding)

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


# ---------------------------------------------------------------------------
# Case folding -- deferred import to avoid a circular import.
# ---------------------------------------------------------------------------


def _cased(text: str, case: str) -> str:
    """The engine's own `_apply_case` (`adapters/configured.py`), imported
    lazily rather than at module level.

    A top-level `from rhinosecure.adapters.configured import _apply_case`
    here would deadlock `config_model.py`'s own import: `config_model.py`
    must import `ASSET_SLOTS`/`FINDING_SLOTS`/the type-hint dicts from THIS
    module near the very top of its own file (before it defines the
    `Mapping`/`Contract` classes `adapters/configured.py` itself imports
    from `config_model.py`) -- so the import chain would be
    `config_model -> schema_registry -> configured -> config_model`,
    reaching back into a module that has not finished executing yet.
    Deferring this import to call time -- after every module in that cycle
    has already finished importing once -- resolves it from `sys.modules`'s
    cache at negligible cost, and is still the identical function, never
    reimplemented."""
    from rhinosecure.adapters.configured import _apply_case

    return _apply_case(text, case)


# ---------------------------------------------------------------------------
# Dataclasses -- pure data, no behavior beyond what's below.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AliasedValue:
    """One legal target token, what it means, and the real-world source
    spellings this project has already seen (or confidently anticipates)
    for it. `aliases` never includes `value` itself -- resolution checks
    both explicitly (see `resolve_enum_alias`)."""

    value: str
    meaning: str
    aliases: frozenset[str]


@dataclass(frozen=True)
class EnumTargetSpec:
    """A closed-vocabulary target's full, published value set."""

    target: str
    values: tuple[AliasedValue, ...]


@dataclass(frozen=True)
class CriticalityAnchor:
    """One of exactly two unambiguous ends of the 1-5 criticality scale --
    see the module docstring's "criticality anchor-only scope decision".
    `level` is restricted to 1 or 5 by convention (never enforced by a
    runtime check here, since this dataclass has no validator machinery of
    its own the way a pydantic model would -- a later agent adding a third
    anchor at some OTHER level would be violating the documented design
    intent, not tripping a guard rail)."""

    level: int
    meaning: str
    aliases: frozenset[str]


@dataclass(frozen=True)
class CriticalityScale:
    """The schema's numeric criticality scale, published for the prompt:
    `tier_meanings` gives an LLM real prose to reason from for every level
    1..5, while `anchors` gives it (and this module's own deterministic
    resolver) only the two ends it may trust without a judgment call.

    `tier_meanings`/`anchors` are given `()` defaults purely so this
    dataclass's field order can match the brief's stated order (`low`,
    `high` before them) without violating Python's "no required field after
    a defaulted one" rule -- the one real `CriticalityScale` this module
    builds (`_CRITICALITY_SCALE`) always supplies both explicitly; treat an
    all-defaulted instance as a construction convenience, not a meaningful
    empty scale."""

    low: int = 1
    high: int = 5
    tier_meanings: tuple[str, ...] = ()
    anchors: tuple[CriticalityAnchor, ...] = ()


@dataclass(frozen=True)
class TargetSpec:
    """One `asset.*`/`finding.*` slot's published contract: what Python
    type a mapped value must produce, which `blank` policies are legal for
    it, and -- only for the four registry-backed targets -- its enumerated
    value set (`enum`) or its numeric scale (`criticality`). Exactly one of
    `enum`/`criticality` is set for `role`/`environment`/`data_sensitivity`/
    `scanner_severity` (enum) and `criticality` (criticality); both are
    `None` for every free-text, bool, or identity target."""

    target: str
    python_type: Any
    legal_blank_policies: frozenset[str]
    enum: EnumTargetSpec | None = None
    criticality: CriticalityScale | None = None


# ---------------------------------------------------------------------------
# PARSER_POSITIONS -- makes explicit the one rule that previously lived only
# as a hardcoded "if mapping.parser == 'timestamp'" check in
# config_model.py's _check_parser_placement. "row" means a plain per-row
# ColumnMapping/VocabularyMapping/ParsedMapping; "order_by" means
# AssetGroupingOrderBy.parser. A parser legal at "row" but not "order_by"
# (bool/float/cve_id) can never appear in `asset_grouping.order_by` either
# -- that field's own Literal["date", "timestamp"] annotation already
# enforces this structurally, so nothing here needs to check that direction.
# ---------------------------------------------------------------------------

PARSER_POSITIONS: dict[str, frozenset[str]] = {
    "bool": frozenset({"row"}),
    "float": frozenset({"row"}),
    "date": frozenset({"row", "order_by"}),
    "timestamp": frozenset({"order_by"}),
    "cve_id": frozenset({"row"}),
}


# ---------------------------------------------------------------------------
# Blank-policy legality -- re-derived here by introspection, identically to
# config_model.py's PRE-relocation GAP_LEGAL_TARGETS/_absent_fact_legal_targets
# (read that function before touching this one). config_model.py's own
# GAP_LEGAL_TARGETS/ABSENT_FACT_LEGAL_TARGETS now READ this back out of
# TARGET_REGISTRY rather than deriving it a second time -- see that module.
# ---------------------------------------------------------------------------

#: `blank: "gap"` is legal only where the target has a documented
#: not-collected default to fall back to -- i.e. is a key of
#: `NOT_COLLECTED_DEFAULTS` (adapters/base.py). The actual default VALUES
#: stay there; only this legality derivation moves here.
_GAP_LEGAL: frozenset[str] = frozenset(NOT_COLLECTED_DEFAULTS)


def _derive_absent_fact_legal() -> frozenset[str]:
    """Every Asset/Finding field whose own pydantic default is `""` -- the
    schema's existing "blank means no restriction/fact" encoding. Computed
    by introspection, not hand-copied: `GAP_LEGAL_TARGETS` and this set
    genuinely differ (`criticality`/`internet_exposed`/`environment`/
    `data_sensitivity`/`os`/`os_build` are gap-legal but have no `""`
    default; `product` and `evidence` have a `""` default but no
    `NOT_COLLECTED_DEFAULTS` entry) -- see `config_model.py`'s own,
    identically-shaped `_absent_fact_legal_targets()` for the original of
    this exact derivation."""
    targets: set[str] = set()
    for name, model_field in Asset.model_fields.items():
        if name != "not_collected" and model_field.default == "":
            targets.add(name)
    for name, model_field in Finding.model_fields.items():
        if name not in ("not_collected", "source_enrichment") and model_field.default == "":
            targets.add(name)
    return frozenset(targets)


_ABSENT_FACT_LEGAL: frozenset[str] = _derive_absent_fact_legal()


def _legal_blank_policies(target: str) -> frozenset[str]:
    """'fatal' is always legal for every column-reading target -- nothing
    in `config_model.py`'s `_check_blank_policy` restricts it, unlike
    'gap'/'absent_fact'."""
    policies = {"fatal"}
    if target in _GAP_LEGAL:
        policies.add("gap")
    if target in _ABSENT_FACT_LEGAL:
        policies.add("absent_fact")
    return frozenset(policies)


# ---------------------------------------------------------------------------
# Curated alias data for the four registry-backed targets. `role`'s aliases
# are drawn, wherever possible, from `data/adapters/bluepeak-gen.json`'s own
# real, human-reviewed `asset.role` table (a confirmed contract is grounded
# evidence, not a guess) -- its `table_notes` are followed exactly, notably
# "Development Server: file, not dev". `environment`/`data_sensitivity` have
# no comparable real-world table to draw from yet, so their aliases are a
# conservative, deliberately small seed -- a later agent extends all three
# with cited research, per this module's own docstring. `criticality` is
# NOT curated the same way -- see `_CRITICALITY_SCALE` below and the module
# docstring's anchor-only section.
# ---------------------------------------------------------------------------

_ROLE_MEANINGS_AND_ALIASES: dict[str, tuple[str, frozenset[str]]] = {
    "dc": (
        "Active Directory domain controller.",
        frozenset(
            {
                "Domain Controller", "DC", "AD DC", "Active Directory Domain Controller",
                "Global Catalog Server", "RODC", "Read-Only Domain Controller",
            }
        ),
    ),
    "exchange": (
        "Microsoft Exchange mail server -- the mail store itself, not a perimeter mail-security "
        "control (see 'email_gateway').",
        frozenset(
            {
                "Exchange", "Exchange Server", "Mail Server", "Mailbox Server",
                "Microsoft Exchange Server",
            }
        ),
    ),
    "iis_web": (
        "IIS-hosted Windows web server.",
        frozenset({"IIS", "IIS Web Server", "Windows Web Server", "IIS Server", "Windows IIS Server"}),
    ),
    "sql": (
        "SQL Server database host.",
        frozenset(
            {
                "SQL Server", "SQL", "Database Server", "DB Server", "MSSQL", "MSSQL Server",
                "Microsoft SQL Server",
            }
        ),
    ),
    "file": (
        "General-purpose file/application/utility server -- the most generic server role in the "
        "vocabulary.",
        frozenset(
            {
                "File Server", "Application Server", "DNS Server", "Monitoring Server",
                "Network Management Server", "Reporting Server", "Server", "Storage Appliance",
                "Development Server", "NAS", "Print Server", "Backup Server",
            }
        ),
    ),
    "workstation": (
        "End-user Windows workstation or laptop.",
        frozenset(
            {"Workstation", "Laptop", "Desktop", "Privileged Workstation", "PC", "Windows Workstation"}
        ),
    ),
    "dev": (
        "Isolated development/lab box -- distinct from a production-adjacent 'Development Server' "
        "(that maps to 'file'; confirmed real-world precedent: bluepeak-gen.json's own table_notes, "
        "\"Development Server: file, not dev\").",
        frozenset({"Isolated Lab Box", "Sandbox Host"}),
    ),
    "identity_gateway": (
        "SSO/federated-auth gateway, or a cloud administrative control plane.",
        frozenset(
            {
                "Identity Gateway", "Cloud Management Portal", "SSO Gateway", "AD FS", "ADFS",
                "Federation Server", "Identity Provider", "IdP", "Azure AD Connect",
                "Microsoft Entra Connect",
            }
        ),
    ),
    "firewall": (
        "Perimeter firewall / network traffic control.",
        frozenset(
            {
                "Firewall", "Next-Generation Firewall", "NGFW", "Perimeter Firewall",
                "UTM Appliance", "Firewall Appliance", "IP Firewall",
            }
        ),
    ),
    "container_orchestrator": (
        "Kubernetes or similar container-cluster control plane.",
        frozenset(
            {
                "Kubernetes Cluster", "Container Orchestrator", "Kubernetes", "K8s Cluster",
                "Kubernetes Control Plane", "OpenShift Cluster", "EKS Cluster", "AKS Cluster",
                "GKE Cluster", "Container Orchestration Platform",
            }
        ),
    ),
    "email_gateway": (
        "Mail-plane security control (secure email gateway) -- a control layer around the mail "
        "store, not the store itself (see 'exchange').",
        frozenset(
            {
                "Email Security Gateway", "Email Gateway", "Secure Email Gateway", "SEG",
                "Anti-Spam Gateway", "Email Filtering Appliance", "Mail Security Appliance",
            }
        ),
    ),
    "network_appliance": (
        "VPN gateway, wireless controller, reverse proxy, or API/application gateway -- an "
        "access/connectivity chokepoint serving multiple downstream consumers.",
        frozenset(
            {
                "Application Gateway", "Mobile Sync Gateway", "Network Appliance",
                "Reverse Proxy", "Wireless Controller", "VPN Gateway", "Load Balancer",
                "Proxy Server", "VPN Concentrator", "API Gateway", "Application Delivery Controller",
            }
        ),
    ),
    "web_app": (
        "Platform-agnostic web application or API (no IIS/Windows evidence asserted).",
        frozenset({"Web API", "Web Application", "Web Server", "API Server", "App Service"}),
    ),
    "container_host": (
        "A single container host.",
        frozenset({"Container Host", "Docker Host", "Container Server"}),
    ),
    "printer": (
        "Networked printer -- lowest blast-radius tier by design.",
        frozenset({"Printer", "Network Printer", "MFP", "Multi-Function Printer"}),
    ),
}

_ENVIRONMENT_MEANINGS_AND_ALIASES: dict[str, tuple[str, frozenset[str]]] = {
    "prod": ("Production environment.", frozenset({"Production", "Prod", "Live", "PRD"})),
    "staging": (
        "Pre-production staging/UAT environment.",
        frozenset(
            {
                "Staging", "Stage", "UAT", "Pre-Production", "STG", "STAG", "Pre-Prod",
                "Preprod", "User Acceptance Testing",
            }
        ),
    ),
    "dev": (
        "Development environment.",
        frozenset({"Development", "Dev", "Sandbox", "Lab"}),
    ),
}

_DATA_SENSITIVITY_MEANINGS_AND_ALIASES: dict[str, tuple[str, frozenset[str]]] = {
    "none": (
        "No sensitive data.",
        frozenset(
            {
                "None", "Public", "Unclassified", "N/A", "Not Applicable", "Open",
                "Publicly Available", "No Classification",
            }
        ),
    ),
    "internal": (
        "Internal-use-only business data.",
        frozenset(
            {
                "Internal", "Internal Use Only", "Internal Only", "General", "Company Internal",
                "Employees Only", "Staff Only",
            }
        ),
    ),
    "confidential": (
        "Confidential business data.",
        frozenset(
            {
                "Confidential", "Company Confidential", "Proprietary", "Trade Secret",
                "NDA Protected", "Business Confidential", "Internal Confidential",
            }
        ),
    ),
    "regulated": (
        "Regulated data subject to a compliance obligation (PII/PHI/PCI/etc).",
        frozenset(
            {
                "Regulated", "PII", "PHI", "PCI", "Personally Identifiable Information",
                "Protected Health Information", "PCI-DSS", "Cardholder Data", "CHD", "HIPAA",
                "HIPAA-Covered", "GDPR", "GDPR-Scoped", "SOX", "Sarbanes-Oxley", "GLBA", "FERPA",
                "CUI", "Controlled Unclassified Information", "Regulatory Data",
            }
        ),
    ),
}

#: The schema's numeric criticality scale. `tier_meanings` is prose for
#: every level 1..5, for the LLM prompt; `anchors` is deliberately just the
#: two unambiguous ends -- see the module docstring.
_CRITICALITY_SCALE = CriticalityScale(
    low=1,
    high=5,
    tier_meanings=(
        "Minimal criticality: little to no real business function rides on this asset; its "
        "compromise or unavailability would be negligible, easily absorbed, and would not "
        "meaningfully affect operations, revenue, safety, or reputation (e.g. a disposable test "
        "box). This is the absolute floor of the scale.",
        "Marginally critical: this asset plays a limited, mostly localized role; its compromise "
        "or outage would cause minor inconvenience or a small, recoverable disruption with little "
        "lasting business consequence.",
        "Moderately critical: this asset supports specific functions or processes; its compromise "
        "or outage would cause a real but contained impact, felt by a subset of the business "
        "rather than the organization as a whole -- the enterprise's typical/default asset, with "
        "no special designation either way.",
        "Highly critical: this asset underpins one or more core business functions; its "
        "compromise or outage would cause significant, wide-reaching disruption and meaningful "
        "financial, operational, or reputational harm, even though the business could survive it.",
        "Mission-critical: compromise, loss, or extended outage of this asset would cause severe, "
        "immediate damage to the organization's core operations, safety, revenue, or survival, "
        "and demands the fastest possible response regardless of other scheduling constraints "
        "(e.g. a domain controller, the primary database). This is the absolute ceiling of the "
        "scale.",
    ),
    anchors=(
        CriticalityAnchor(
            level=5,
            meaning="The single most severe/critical tier, full stop -- unambiguous regardless of "
            "how many tiers the source's own scale has.",
            aliases=frozenset({"Critical", "Mission Critical"}),
        ),
        CriticalityAnchor(
            level=1,
            meaning="Minimal or no real business impact -- the least severe tier, full stop.",
            aliases=frozenset({"Informational", "Minimal", "Negligible", "Very Low"}),
        ),
    ),
)


def _enum_spec(
    target: str, literal_type: Any, curated: dict[str, tuple[str, frozenset[str]]] | None = None
) -> EnumTargetSpec:
    """Build an `EnumTargetSpec` from a `Literal[...]` type's own legal
    values, layering in curated meaning/alias data where it exists (`role`/
    `environment`/`data_sensitivity`) and leaving it empty otherwise (e.g.
    `scanner_severity`, which is a closed vocabulary but not one of the
    four targets this module resolves aliases for -- see the module
    docstring)."""
    curated = curated or {}
    values = tuple(
        AliasedValue(
            value=v,
            meaning=curated.get(v, ("", frozenset()))[0],
            aliases=curated.get(v, ("", frozenset()))[1],
        )
        for v in get_args(literal_type)
    )
    return EnumTargetSpec(target=target, values=values)


# ---------------------------------------------------------------------------
# TARGET_REGISTRY -- one entry per ASSET_SLOTS/FINDING_SLOTS member.
# ---------------------------------------------------------------------------


def _build_target_registry() -> dict[str, TargetSpec]:
    registry: dict[str, TargetSpec] = {}
    for target in dict.fromkeys((*ASSET_SLOTS, *FINDING_SLOTS)):
        python_type = _ASSET_TYPE_HINTS[target] if target in _ASSET_TYPE_HINTS else _FINDING_TYPE_HINTS[target]
        enum: EnumTargetSpec | None = None
        criticality: CriticalityScale | None = None
        if target == "criticality":
            criticality = _CRITICALITY_SCALE
        elif target == "role":
            enum = _enum_spec(target, python_type, _ROLE_MEANINGS_AND_ALIASES)
        elif target == "environment":
            enum = _enum_spec(target, python_type, _ENVIRONMENT_MEANINGS_AND_ALIASES)
        elif target == "data_sensitivity":
            enum = _enum_spec(target, python_type, _DATA_SENSITIVITY_MEANINGS_AND_ALIASES)
        else:
            args = get_args(python_type)
            if args and all(isinstance(a, str) for a in args):
                # A closed Literal[str, ...] target with no curated alias
                # data (e.g. scanner_severity) -- still published as an
                # enum (describe_target_vocabulary/_check_vocabulary_value
                # need its legal value set), just with no aliases to
                # resolve against.
                enum = _enum_spec(target, python_type)
        registry[target] = TargetSpec(
            target=target,
            python_type=python_type,
            legal_blank_policies=_legal_blank_policies(target),
            enum=enum,
            criticality=criticality,
        )
    return registry


TARGET_REGISTRY: dict[str, TargetSpec] = _build_target_registry()


# ---------------------------------------------------------------------------
# Lookup functions.
# ---------------------------------------------------------------------------


def resolve_enum_alias(target: str, raw_token: str, case: str) -> str | None:
    """`raw_token`, case-normalized exactly as the engine would, resolved
    against `TARGET_REGISTRY[target].enum` -- either a legal value's own
    spelling or one of its known aliases. Returns the resolved target
    value, or `None` when `target` has no `enum` spec, or `raw_token`
    matches neither a value nor an alias of any of its legal values.

    Both sides of every comparison are case-normalized (not just
    `raw_token`): `aliases`/`value` are stored in one canonical spelling
    (typically title case), and a contract's declared `case` may fold
    either side before comparing -- comparing an already-cased `raw_token`
    against an un-cased alias would falsely reject a correct
    case-normalizing mapping."""
    spec = TARGET_REGISTRY.get(target)
    if spec is None or spec.enum is None:
        return None
    cased_token = _cased(raw_token, case)
    for aliased in spec.enum.values:
        if cased_token == _cased(aliased.value, case):
            return aliased.value
        if any(cased_token == _cased(alias, case) for alias in aliased.aliases):
            return aliased.value
    return None


def resolve_criticality_anchor(raw_token: str, case: str) -> int | None:
    """`raw_token` resolved against ONLY the two unambiguous criticality
    anchors (`TARGET_REGISTRY["criticality"].criticality.anchors`) -- never
    a middle tier. See the module docstring's anchor-only scope decision;
    `test_adapters_schema_registry.py` asserts "High"/"Medium"/"Normal"/
    "Low" are NOT resolvable here as a safety property, not an
    implementation detail."""
    spec = TARGET_REGISTRY.get("criticality")
    if spec is None or spec.criticality is None:
        return None
    cased_token = _cased(raw_token, case)
    for anchor in spec.criticality.anchors:
        if any(cased_token == _cased(alias, case) for alias in anchor.aliases):
            return anchor.level
    return None


def _resolve_one(target: str, raw_value: str, case: str) -> Any | None:
    if target == "criticality":
        return resolve_criticality_anchor(raw_value, case)
    return resolve_enum_alias(target, raw_value, case)


def full_alias_coverage(target: str, distinct_values: Iterable[str], case: str) -> dict[str, Any] | None:
    """A COMPLETE table -- every non-blank value in `distinct_values`
    resolves -- or `None`. Never returns a partial table: partial-and-silent
    is unsafe for this function's one real caller, slot PROMOTION
    (`agents/schema_inference._apply_registry_aliases`), which turns a
    genuinely `SlotUnresolved` target into `SlotMapped` and so needs a
    completeness guarantee a partial table could not honestly give -- a
    promoted vocabulary missing a real observed value would silently
    refuse the whole batch the first time real ingest hits that value
    (every non-`role` target refuses rather than excludes on an unmapped
    vocabulary value), which is a worse outcome than staying unresolved.

    Also returns `None` for an empty result (nothing in `distinct_values`
    to resolve) -- `VocabularyMapping.table` itself refuses to be empty, so
    an empty table could never legally be used for promotion either."""
    table: dict[str, Any] = {}
    for raw_value in distinct_values:
        if not raw_value:
            continue
        resolved = _resolve_one(target, raw_value, case)
        if resolved is None:
            return None
        table[raw_value] = resolved
    return table or None


def alias_table_for_column(target: str, distinct_values: Iterable[str], case: str) -> dict[str, Any]:
    """Whichever of `distinct_values` DO resolve -- partial is fine here,
    unlike `full_alias_coverage`. For AUGMENTING an existing, model-authored
    table (`agents/schema_inference._apply_registry_aliases`'s table-
    augmentation mechanism) -- adding entries the model's own table is
    missing, never for constructing a fresh table from scratch (that needs
    `full_alias_coverage`'s completeness guarantee instead, since an
    augmented table already carries the model's own considered judgment for
    everything it DID cover).

    Keyed by the CASE-TRANSFORMED value (`_cased(raw_value, case)`), never
    the raw source value -- the table this feeds (`VocabularyMapping.table`/
    `Derivation.table`) is looked up at runtime via
    `mapping.table.get(_apply_case(raw, mapping.case))`
    (`adapters/configured.py`), so a key stored in its raw casing could
    never match there, and comparing it against an already-cased
    model-authored table's own keys (the caller's "already present" check)
    would be comparing two different casings of the same value. Under
    `case="exact"` this is a no-op (`_cased` returns the text unchanged),
    which is why every existing caller of this function was safe before
    this was made explicit."""
    table: dict[str, Any] = {}
    for raw_value in distinct_values:
        if not raw_value:
            continue
        resolved = _resolve_one(target, raw_value, case)
        if resolved is not None:
            table[_cased(raw_value, case)] = resolved
    return table
