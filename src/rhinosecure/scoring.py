"""Deterministic Risk = Threat x Impact scoring.

No LLM calls anywhere in this module. Same EnrichedFinding plus same
enrichment snapshot must always produce the same score — that is what makes
runs reproducible and what tests in this repo check for.

Slice 1 has no live NVD/KEV/EPSS/ATT&CK data yet, so `ThreatInputs` and
`ImpactInputs` are built from scanner-reported severity and asset context
only; the KEV/EPSS/ATT&CK fields default to "not yet known" (None / False)
rather than being omitted, so Slice 2 can populate them from real enrichment
without changing this module's interface or the shape of a score.

Nothing here may reference a specific asset_id, cve_id, or fixture row. The
lookup tables below are general domain weights (how much a compromised
domain controller matters vs. a workstation), not special cases for any one
record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from rhinosecure.schema import (
    AssetRole,
    DataSensitivity,
    EnrichedFinding,
    Environment,
    ScannerSeverity,
)

# Proxy for a CVSS base/impact score until Slice 2 supplies the real vector.
SEVERITY_BASE_SCORE: dict[ScannerSeverity, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "informational": 0.5,
}

# How much a compromise of this role matters, independent of any one asset.
ROLE_BLAST_RADIUS: dict[AssetRole, float] = {
    "dc": 1.0,
    "exchange": 0.9,
    "sql": 0.85,
    "iis_web": 0.6,
    "file": 0.55,
    "workstation": 0.3,
    "dev": 0.2,
}

ENVIRONMENT_WEIGHT: dict[Environment, float] = {
    "prod": 1.0,
    "staging": 0.6,
    "dev": 0.3,
}

DATA_SENSITIVITY_WEIGHT: dict[DataSensitivity, float] = {
    "regulated": 1.0,
    "confidential": 0.8,
    "internal": 0.5,
    "none": 0.2,
}

INTERNET_EXPOSED_MULTIPLIER = 1.35
NOT_EXPOSED_MULTIPLIER = 0.7
KEV_MULTIPLIER = 1.5
COMPENSATING_CONTROL_DECAY = 0.85  # per control, diminishing, capped below
MAX_CONTROLS_COUNTED = 3

# Theoretical max of score_threat/score_impact with Slice-1 inputs only
# (no EPSS/KEV/ATT&CK yet); used to normalize risk onto a 0-100 scale.
_MAX_THREAT = max(SEVERITY_BASE_SCORE.values()) * INTERNET_EXPOSED_MULTIPLIER
_MAX_IMPACT = max(SEVERITY_BASE_SCORE.values()) * max(ROLE_BLAST_RADIUS.values())
RISK_NORMALIZATION = _MAX_THREAT * _MAX_IMPACT


class Bucket(str, Enum):
    PATCH_NOW = "patch_now"
    NEXT_WINDOW = "next_window"
    MITIGATE_MONITOR = "mitigate_monitor"
    ACCEPT = "accept"


@dataclass(frozen=True)
class ThreatInputs:
    exploitability_base: float
    internet_exposed: bool
    epss: float | None = None  # populated in Slice 2
    is_kev: bool = False  # populated in Slice 2
    attack_prevalence: float | None = None  # populated in Slice 2


@dataclass(frozen=True)
class ImpactInputs:
    impact_base: float
    criticality: int
    environment: Environment
    data_sensitivity: DataSensitivity
    role: AssetRole
    compensating_controls: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ScoredFinding:
    finding_id: str
    cve_id: str
    asset_id: str
    hostname: str
    threat_score: float
    impact_score: float
    risk_score: float
    bucket: Bucket
    rationale: tuple[str, ...]


def score_threat(inputs: ThreatInputs) -> float:
    score = inputs.exploitability_base
    score *= INTERNET_EXPOSED_MULTIPLIER if inputs.internet_exposed else NOT_EXPOSED_MULTIPLIER
    if inputs.is_kev:
        score *= KEV_MULTIPLIER
    if inputs.epss is not None:
        score *= 0.6 + inputs.epss
    if inputs.attack_prevalence is not None:
        score *= 0.8 + 0.4 * inputs.attack_prevalence
    return score


def score_impact(inputs: ImpactInputs) -> float:
    score = inputs.impact_base
    score *= inputs.criticality / 5
    score *= ENVIRONMENT_WEIGHT[inputs.environment]
    score *= DATA_SENSITIVITY_WEIGHT[inputs.data_sensitivity]
    score *= ROLE_BLAST_RADIUS[inputs.role]
    if inputs.compensating_controls:
        score *= COMPENSATING_CONTROL_DECAY ** min(
            len(inputs.compensating_controls), MAX_CONTROLS_COUNTED
        )
    return score


def bucket_for(risk_pct: float, *, has_patch_window: bool, has_compensating_controls: bool) -> Bucket:
    if risk_pct >= 65:
        return Bucket.PATCH_NOW
    if risk_pct >= 35:
        if has_compensating_controls and not has_patch_window:
            return Bucket.MITIGATE_MONITOR
        return Bucket.NEXT_WINDOW
    if risk_pct >= 12:
        if has_compensating_controls:
            return Bucket.MITIGATE_MONITOR
        return Bucket.NEXT_WINDOW
    return Bucket.ACCEPT


def build_threat_inputs(enriched: EnrichedFinding) -> ThreatInputs:
    base = SEVERITY_BASE_SCORE[enriched.finding.scanner_severity]
    return ThreatInputs(
        exploitability_base=base,
        internet_exposed=enriched.asset.internet_exposed,
    )


def build_impact_inputs(enriched: EnrichedFinding) -> ImpactInputs:
    base = SEVERITY_BASE_SCORE[enriched.finding.scanner_severity]
    asset = enriched.asset
    return ImpactInputs(
        impact_base=base,
        criticality=asset.criticality,
        environment=asset.environment,
        data_sensitivity=asset.data_sensitivity,
        role=asset.role,
        compensating_controls=asset.compensating_control_list,
    )


def _rationale(
    enriched: EnrichedFinding, threat: ThreatInputs, impact: ImpactInputs, risk_pct: float
) -> tuple[str, ...]:
    asset = enriched.asset
    lines = [
        f"scanner severity '{enriched.finding.scanner_severity}' -> base score {impact.impact_base:.1f}",
        f"internet_exposed={asset.internet_exposed} ({'x' + str(INTERNET_EXPOSED_MULTIPLIER) if asset.internet_exposed else 'x' + str(NOT_EXPOSED_MULTIPLIER)} threat)",
        f"role={asset.role} (x{ROLE_BLAST_RADIUS[asset.role]} impact, blast radius)",
        f"criticality={asset.criticality}/5",
        f"environment={asset.environment} (x{ENVIRONMENT_WEIGHT[asset.environment]} impact)",
        f"data_sensitivity={asset.data_sensitivity} (x{DATA_SENSITIVITY_WEIGHT[asset.data_sensitivity]} impact)",
    ]
    if impact.compensating_controls:
        decay = COMPENSATING_CONTROL_DECAY ** min(
            len(impact.compensating_controls), MAX_CONTROLS_COUNTED
        )
        lines.append(
            f"compensating_controls={list(impact.compensating_controls)} (x{decay:.2f} impact)"
        )
    lines.append(f"risk_score={risk_pct:.1f}/100")
    return tuple(lines)


def score_finding(enriched: EnrichedFinding) -> ScoredFinding:
    threat_inputs = build_threat_inputs(enriched)
    impact_inputs = build_impact_inputs(enriched)
    threat = score_threat(threat_inputs)
    impact = score_impact(impact_inputs)
    risk = threat * impact
    risk_pct = min(100.0, 100.0 * risk / RISK_NORMALIZATION)
    bucket = bucket_for(
        risk_pct,
        has_patch_window=enriched.asset.has_patch_window,
        has_compensating_controls=bool(impact_inputs.compensating_controls),
    )
    rationale = _rationale(enriched, threat_inputs, impact_inputs, risk_pct)
    return ScoredFinding(
        finding_id=enriched.finding.finding_id,
        cve_id=enriched.finding.cve_id,
        asset_id=enriched.asset.asset_id,
        hostname=enriched.asset.hostname,
        threat_score=threat,
        impact_score=impact,
        risk_score=risk_pct,
        bucket=bucket,
        rationale=rationale,
    )


def rank(scored: list[ScoredFinding]) -> list[ScoredFinding]:
    return sorted(scored, key=lambda s: (-s.risk_score, s.finding_id))
