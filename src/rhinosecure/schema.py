"""Record shapes for the two input CSVs and the values they may hold.

Column names deliberately mirror the fields exported by real scanners (Nessus,
Qualys, Rapid7 InsightVM, Microsoft Defender Vulnerability Management) — host
identity, CVE, scanner-reported severity, product/version, port/service,
detection evidence. That is what lets a future ingest adapter translate a real
export into this shape instead of requiring a rewrite of everything downstream.

Nothing in this module may reference a specific asset_id, cve_id, or row
count. The controlled vocabularies below (roles, environments, sensitivity
tiers) are schema-level domain categories, not fixture-specific values.
"""

from __future__ import annotations

from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

AssetRole = Literal["dc", "exchange", "iis_web", "sql", "file", "workstation", "dev"]
Environment = Literal["prod", "staging", "dev"]
DataSensitivity = Literal["none", "internal", "confidential", "regulated"]
ScannerSeverity = Literal["critical", "high", "medium", "low", "informational"]


def _validate_not_collected(model: type[BaseModel], value: frozenset[str]) -> frozenset[str]:
    """`not_collected` may only name fields the model actually has, and
    never its primary key -- a record without identity is not a record with
    a gap, it is unmappable input (adapters/base.py rule 1)."""
    allowed = set(model.model_fields) - {"not_collected"} - set(getattr(model, "_never_not_collected", ()))
    unknown = sorted(value - allowed)
    if unknown:
        raise ValueError(f"not_collected names field(s) {model.__name__} cannot leave uncollected: {unknown}")
    return value


class Asset(BaseModel):
    """One host in the inventory.

    `not_collected` is the set of this model's field names the record's
    source format had no concept of, or left blank on this row. The field's
    *value* is then the documented default (adapters/base.py
    NOT_COLLECTED_DEFAULTS; "" for the free-text fields), which scoring reads
    exactly as it would a native record; only the *claim* differs -- a blank
    patch_window with "patch_window" in not_collected means "unknown", the
    same blank without it means "none declared". Native assets.csv rows leave
    it empty. See adapters/base.py for the full reasoning."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)
    _never_not_collected: ClassVar[frozenset[str]] = frozenset({"asset_id"})

    asset_id: str
    hostname: str
    os: str
    os_build: str
    role: AssetRole
    business_function: str = ""
    criticality: int = Field(ge=1, le=5)
    internet_exposed: bool
    environment: Environment
    data_sensitivity: DataSensitivity
    patch_window: str = ""
    patch_restrictions: str = ""
    compensating_controls: str = ""
    owner: str = ""
    not_collected: frozenset[str] = frozenset()

    @field_validator("not_collected")
    @classmethod
    def _not_collected_names_real_fields(cls, value: frozenset[str]) -> frozenset[str]:
        return _validate_not_collected(cls, value)

    @property
    def compensating_control_list(self) -> tuple[str, ...]:
        raw = self.compensating_controls
        if not raw:
            return ()
        return tuple(part.strip() for part in raw.replace(";", ",").split(",") if part.strip())

    @property
    def has_patch_window(self) -> bool:
        return bool(self.patch_window.strip())


class SourceEnrichment(BaseModel):
    """Threat-intel a pre-enriched source supplied directly on its own
    export, to be trusted rather than fetched (adapters/bluepeak.py, and
    any future adapter shaped like it -- a source whose CVE IDs are
    synthetic, so a live NVD/KEV/EPSS/ATT&CK lookup would just spend
    retries finding nothing). `None` on `Finding` for every other
    adapter; native and defender both still go through the live
    KEV/EPSS/NVD/ATT&CK lookups in `ingest.attach_threat_signals`.

    `severity_label` names which source supplied `severity_score` (e.g.
    "bluepeak") -- kept separate from NVD's own provenance label so
    scoring.py's rationale never misattributes a vendor's self-reported
    number to NVD. See `ingest.attach_source_enrichment` and
    `scoring._resolve_severity`.
    """

    model_config = ConfigDict(frozen=True)

    severity_score: float
    severity_label: str
    known_exploited: bool | None = None
    attack_technique_id: str = ""
    attack_technique_name: str = ""


class Finding(BaseModel):
    """One scanner finding. `not_collected` has the same meaning as on
    `Asset` -- e.g. an agent-based scanner that never observes a listening
    port leaves port/service blank *and* names them here."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)
    _never_not_collected: ClassVar[frozenset[str]] = frozenset({"finding_id", "asset_id", "cve_id"})

    finding_id: str
    asset_id: str
    cve_id: str
    detected_date: str = ""
    scanner_severity: ScannerSeverity
    product: str = ""
    version: str = ""
    port: str = ""
    service: str = ""
    evidence: str = ""
    not_collected: frozenset[str] = frozenset()
    source_enrichment: SourceEnrichment | None = None

    @field_validator("not_collected")
    @classmethod
    def _not_collected_names_real_fields(cls, value: frozenset[str]) -> frozenset[str]:
        return _validate_not_collected(cls, value)


class AttackTechniqueRef(BaseModel):
    """One technique enrich/attack.py's lookup matched to a finding.

    `confidence` is "confirmed" (the CVE is explicitly named in an ATT&CK
    procedure example for this technique) or "candidate" (keyword-matched
    against the finding's product/evidence text, unconfirmed) -- see
    enrich/attack.py's module docstring for why these are never mixed within
    one finding's matches. Only "confirmed" matches feed
    EnrichedFinding.attack_prevalence; "candidate" matches are informational,
    surfaced in rationale but never moving a score.
    """

    model_config = ConfigDict(frozen=True)

    technique_id: str
    name: str
    confidence: str


class EnrichedFinding(BaseModel):
    """A Finding joined to its Asset, plus whatever live threat signals have
    been attached so far.

    `is_kev`/`epss`/`nvd_base_score`/`nvd_severity`/`attack_techniques`/
    `attack_prevalence` are populated by `rhino run` after `join_findings`
    (see `cli.py`) via `enrich/kev.py`, `enrich/epss.py`, `enrich/nvd.py`, and
    `enrich/attack.py`, going through `SnapshotCache` -- ingest.py itself does
    no enrichment or network access.

    `source_severity_score`/`source_severity_label` are the counterpart for
    a pre-enriched source (`finding.source_enrichment`, above): populated by
    `ingest.attach_source_enrichment` instead of `attach_threat_signals`,
    mirroring `nvd_base_score`/`nvd_severity` in shape so
    `scoring._resolve_severity` can treat "source-reported" as a third,
    honestly-labeled severity provenance alongside "nvd" and "scanner" --
    never reusing the NVD-branded fields for a number NVD never scored.
    """

    model_config = ConfigDict(frozen=True)

    finding: Finding
    asset: Asset
    is_kev: bool = False
    epss: float | None = None
    nvd_base_score: float | None = None
    nvd_severity: str | None = None
    attack_techniques: tuple[AttackTechniqueRef, ...] = ()
    attack_prevalence: float | None = None
    source_severity_score: float | None = None
    source_severity_label: str | None = None
