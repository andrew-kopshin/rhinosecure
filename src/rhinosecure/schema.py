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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AssetRole = Literal["dc", "exchange", "iis_web", "sql", "file", "workstation", "dev"]
Environment = Literal["prod", "staging", "dev"]
DataSensitivity = Literal["none", "internal", "confidential", "regulated"]
ScannerSeverity = Literal["critical", "high", "medium", "low", "informational"]


class Asset(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

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

    @property
    def compensating_control_list(self) -> tuple[str, ...]:
        raw = self.compensating_controls
        if not raw:
            return ()
        return tuple(part.strip() for part in raw.replace(";", ",").split(",") if part.strip())

    @property
    def has_patch_window(self) -> bool:
        return bool(self.patch_window.strip())


class Finding(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

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


class EnrichedFinding(BaseModel):
    """A Finding joined to its Asset, plus whatever live threat signals have
    been attached so far.

    `is_kev`/`epss` are populated by `rhino run` after `join_findings`
    (see `cli.py`) via `enrich/kev.py` and `enrich/epss.py`, going through
    `SnapshotCache` -- ingest.py itself does no enrichment or network
    access. NVD and ATT&CK data are still not wired in; this is the seam
    they plug into without scoring.py or ingest.py needing to change shape.
    """

    model_config = ConfigDict(frozen=True)

    finding: Finding
    asset: Asset
    is_kev: bool = False
    epss: float | None = None
