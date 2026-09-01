"""Deterministic Risk = Threat x Impact scoring.

No LLM calls anywhere in this module, and no network or cache access either
-- `EnrichedFinding.is_kev`/`epss`/`nvd_base_score`/`nvd_severity` arrive
already resolved (see cli.py, which reads them through SnapshotCache
before calling score_finding). Same EnrichedFinding plus same enrichment
snapshot must always produce the same score — that is what makes runs
reproducible and what tests in this repo check for.

KEV and EPSS are wired into the threat term, NVD's authoritative CVSS score
into both Threat and Impact's severity_base (see `_resolve_severity`), and
ATT&CK technique prevalence into the threat term, as of Slice 2.
`ThreatInputs.attack_prevalence` stays None -- a deliberate no-op in
score_threat, not just an unset default -- whenever enrich/attack.py found no
*confirmed* technique mapping for a finding's CVE (see EnrichedFinding and
enrich/attack.py's module docstring): a candidate technique (MMR-reranked
vector retrieval, unconfirmed by any ATT&CK procedure-example citation) is
not confident enough evidence to move a deterministic score, so it stays
visible in rationale without touching attack_prevalence.

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

# Proxy for a CVSS base/impact score, used only when NVD has no CVSS data
# for a CVE. When NVD has scored it, _resolve_severity uses NVD's real
# base_score instead -- see that function.
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

# EPSS and KEV both feed a single "how likely is this to be attacked"
# multiplier, but they are different kinds of claim: EPSS is a model's
# probability estimate, KEV is CISA's record of confirmed real-world
# exploitation. An observation should not be diluted by, or -- worse --
# multiplicatively compounded with, a prediction that disagrees with it.
# So EPSS sets the multiplier (0.6 at epss=0 up to 1.6 at epss=1, unscored
# CVEs get a neutral x1.0 -- same as the pre-Slice-2 no-op), and KEV sets a
# FLOOR under that multiplier rather than stacking another factor on top of
# it. A KEV CVE the model happens to underrate is pulled up to the floor;
# a KEV CVE the model already rates highly is left alone, because the
# floor does not add anything once EPSS already clears it. See
# `_likelihood_multiplier` and CLAUDE.md Section 3.
EPSS_MULTIPLIER_BASELINE = 0.6
KEV_FLOOR_MULTIPLIER = 1.5

COMPENSATING_CONTROL_DECAY = 0.85  # per control, diminishing, capped below
MAX_CONTROLS_COUNTED = 3

# Criticality, environment, data sensitivity, and role blast radius all
# measure the same underlying question -- how much does this asset matter --
# so they are combined as a weighted sum, not multiplied. Multiplying near-1
# factors that overlap in what they measure compounds them into near-zero
# values for any asset that scores low on more than one axis, which
# overstates how much low-end assets differ from each other. Compensating
# controls are not a facet of "how much this asset matters" -- they are an
# actual reduction in realized impact -- so that one stays multiplicative.
IMPACT_COMPOSITE_WEIGHTS: dict[str, float] = {
    "criticality": 0.25,
    "environment": 0.25,
    "data_sensitivity": 0.25,
    "role": 0.25,
}

# The true ceiling severity_base can reach. SEVERITY_BASE_SCORE's own max
# (9.5, "critical") is only the proxy's ceiling -- once NVD has scored a
# CVE, _resolve_severity uses its real CVSS base_score instead, and CVSS
# itself tops out at 10.0. Normalizing against 9.5 would silently
# under-normalize once any finding's authoritative score gets close to
# that true ceiling.
MAX_SEVERITY_BASE = 10.0

# Theoretical max of score_threat/score_impact with everything wired in so
# far (KEV+EPSS+NVD+ATT&CK) -- used to normalize risk onto a 0-100 scale.
# The likelihood multiplier maxes out at EPSS=1.0 (x1.6), which already
# exceeds the KEV floor (x1.5), so the floor never raises the ceiling -- it
# only pulls up cases the model underrates.
_MAX_LIKELIHOOD_MULTIPLIER = max(EPSS_MULTIPLIER_BASELINE + 1.0, KEV_FLOOR_MULTIPLIER)
# attack_prevalence maxes at 1.0 (percentile rank is bounded by construction --
# see enrich/attack.py), giving score_threat's `0.8 + 0.4 * prevalence` term a
# x1.2 ceiling. Omitting this factor here would under-normalize once any
# finding's confirmed technique gets close to it, same failure mode
# MAX_SEVERITY_BASE documents above for NVD's real CVSS scores.
_MAX_ATTACK_MULTIPLIER = 0.8 + 0.4 * 1.0
_MAX_THREAT = (
    MAX_SEVERITY_BASE
    * INTERNET_EXPOSED_MULTIPLIER
    * _MAX_LIKELIHOOD_MULTIPLIER
    * _MAX_ATTACK_MULTIPLIER
)
_MAX_IMPACT_COMPOSITE = (
    IMPACT_COMPOSITE_WEIGHTS["criticality"] * 1.0  # criticality/5 maxes at 5/5
    + IMPACT_COMPOSITE_WEIGHTS["environment"] * max(ENVIRONMENT_WEIGHT.values())
    + IMPACT_COMPOSITE_WEIGHTS["data_sensitivity"] * max(DATA_SENSITIVITY_WEIGHT.values())
    + IMPACT_COMPOSITE_WEIGHTS["role"] * max(ROLE_BLAST_RADIUS.values())
)
_MAX_IMPACT = MAX_SEVERITY_BASE * _MAX_IMPACT_COMPOSITE
RISK_NORMALIZATION = _MAX_THREAT * _MAX_IMPACT


class Bucket(str, Enum):
    PATCH_NOW = "patch_now"
    NEXT_WINDOW = "next_window"
    MITIGATE_MONITOR = "mitigate_monitor"
    ACCEPT = "accept"
    # Not a remediation category -- a "no honest bucket exists" signal.
    # Emitted only for a KEV-listed finding with neither a compensating
    # control nor a declared patch window: confirmed exploitation rules out
    # accept, but there is no control to justify mitigate_monitor and
    # nothing scheduled to justify next_window. See bucket_for and
    # CLAUDE.md Section 6 -- this is the seed case for Slice 4's
    # Tree-of-Thought contested-finding gate.
    CONTESTED = "contested"


@dataclass(frozen=True)
class ThreatInputs:
    exploitability_base: float
    internet_exposed: bool
    epss: float | None = None  # from EnrichedFinding.epss (Slice 2, wired)
    is_kev: bool = False  # from EnrichedFinding.is_kev (Slice 2, wired)
    attack_prevalence: float | None = None  # ATT&CK -- not wired yet


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


def _likelihood_multiplier(epss: float | None, is_kev: bool) -> float:
    """How much more likely this finding is to actually be attacked.

    EPSS sets the base multiplier; KEV sets a floor under it rather than
    multiplying on top of it -- see the constants block above for why.
    """
    multiplier = EPSS_MULTIPLIER_BASELINE + epss if epss is not None else 1.0
    if is_kev:
        multiplier = max(multiplier, KEV_FLOOR_MULTIPLIER)
    return multiplier


def score_threat(inputs: ThreatInputs) -> float:
    score = inputs.exploitability_base
    score *= INTERNET_EXPOSED_MULTIPLIER if inputs.internet_exposed else NOT_EXPOSED_MULTIPLIER
    score *= _likelihood_multiplier(inputs.epss, inputs.is_kev)
    if inputs.attack_prevalence is not None:
        score *= 0.8 + 0.4 * inputs.attack_prevalence
    return score


def impact_composite(inputs: ImpactInputs) -> float:
    """Weighted sum of the four "how much does this asset matter" factors.

    These overlap in what they measure (criticality, environment, data
    sensitivity, and role blast radius are all facets of asset importance),
    so they are added, not multiplied -- an asset should not need to score
    high on every axis at once to register as mattering.
    """
    return (
        IMPACT_COMPOSITE_WEIGHTS["criticality"] * (inputs.criticality / 5)
        + IMPACT_COMPOSITE_WEIGHTS["environment"] * ENVIRONMENT_WEIGHT[inputs.environment]
        + IMPACT_COMPOSITE_WEIGHTS["data_sensitivity"] * DATA_SENSITIVITY_WEIGHT[inputs.data_sensitivity]
        + IMPACT_COMPOSITE_WEIGHTS["role"] * ROLE_BLAST_RADIUS[inputs.role]
    )


def score_impact(inputs: ImpactInputs) -> float:
    score = inputs.impact_base * impact_composite(inputs)
    if inputs.compensating_controls:
        score *= COMPENSATING_CONTROL_DECAY ** min(
            len(inputs.compensating_controls), MAX_CONTROLS_COUNTED
        )
    return score


PATCH_NOW_THRESHOLD = 70
ACTIONABLE_THRESHOLD = 18  # below this, risk is low enough to formally accept


def bucket_for(
    risk_pct: float,
    *,
    has_patch_window: bool,
    has_compensating_controls: bool,
    is_kev: bool = False,
) -> Bucket:
    if risk_pct >= PATCH_NOW_THRESHOLD:
        return Bucket.PATCH_NOW
    # A KEV-listed finding is confirmed exploited in the wild -- that rules
    # out accept ("we are fine with this") on its own, regardless of where
    # raw risk_pct falls. It does not by itself pick which bucket applies;
    # the control/window logic below still decides that, same as it does
    # for any other finding already in this tier.
    if risk_pct >= ACTIONABLE_THRESHOLD or is_kev:
        # mitigate_monitor means "patch blocked or deferred; apply a
        # compensating control and watch" -- it requires both an actual
        # control to point to AND the absence of a patch window (otherwise
        # patching isn't blocked, it's just scheduled).
        if has_compensating_controls and not has_patch_window:
            return Bucket.MITIGATE_MONITOR
        if has_patch_window:
            return Bucket.NEXT_WINDOW
        # No control, no window. For a finding that reached this tier on
        # risk_pct alone, that's "no declared scheduling restriction" and
        # next_window is still honest -- nothing is blocked, there's just
        # no window recorded. For a KEV finding it is not honest: confirmed
        # exploitation with no control to lean on and nothing scheduled is
        # neither "on schedule" nor "monitored via a control." No bucket
        # says that truthfully, so it is surfaced as contested instead of
        # forced into one. See CLAUDE.md Section 6.
        if is_kev:
            return Bucket.CONTESTED
        return Bucket.NEXT_WINDOW
    return Bucket.ACCEPT


def _resolve_severity(enriched: EnrichedFinding) -> tuple[float, str]:
    """The severity_base fed to both Threat and Impact, plus which source
    it came from ("nvd" or "scanner") -- provenance the rationale surfaces.

    NVD's CVSS base score is authoritative when NVD has scored the CVE: a
    real, sourced number, not the fixed per-tier proxy scanner_severity
    maps to (SEVERITY_BASE_SCORE was always documented as a stand-in
    "until Slice 2 supplies the real vector" -- this is that). It
    overrides scanner_severity outright when the two disagree at the tier
    level, and is still preferred for precision when they happen to
    agree. Falls back to the scanner's tier proxy only when NVD has no
    CVSS data for this CVE.
    """
    if enriched.nvd_base_score is not None:
        return enriched.nvd_base_score, "nvd"
    return SEVERITY_BASE_SCORE[enriched.finding.scanner_severity], "scanner"


def build_threat_inputs(enriched: EnrichedFinding) -> ThreatInputs:
    base, _source = _resolve_severity(enriched)
    return ThreatInputs(
        exploitability_base=base,
        internet_exposed=enriched.asset.internet_exposed,
        epss=enriched.epss,
        is_kev=enriched.is_kev,
        attack_prevalence=enriched.attack_prevalence,
    )


def build_impact_inputs(enriched: EnrichedFinding) -> ImpactInputs:
    base, _source = _resolve_severity(enriched)
    asset = enriched.asset
    return ImpactInputs(
        impact_base=base,
        criticality=asset.criticality,
        environment=asset.environment,
        data_sensitivity=asset.data_sensitivity,
        role=asset.role,
        compensating_controls=asset.compensating_control_list,
    )


def _attack_rationale_lines(enriched: EnrichedFinding, threat: ThreatInputs) -> list[str]:
    """Describes what enrich/attack.py matched, and whether it moved the
    score -- see AttackTechniqueRef and CLAUDE.md Section 3's "commonly
    observed" bullet. Confirmed matches drive attack_prevalence; candidate
    matches are shown but never do (see build_threat_inputs)."""
    confirmed = [t for t in enriched.attack_techniques if t.confidence == "confirmed"]
    candidates = [t for t in enriched.attack_techniques if t.confidence == "candidate"]
    lines: list[str] = []
    if confirmed:
        names = ", ".join(f"{t.technique_id} ({t.name})" for t in confirmed)
        multiplier = 0.8 + 0.4 * threat.attack_prevalence if threat.attack_prevalence is not None else 1.0
        lines.append(
            f"ATT&CK: confirmed via procedure example -- {names}, prevalence={threat.attack_prevalence:.3f} "
            f"-> x{multiplier:.3f} threat multiplier"
        )
    elif candidates:
        names = ", ".join(f"{t.technique_id} ({t.name})" for t in candidates)
        lines.append(
            f"ATT&CK: no confirmed technique, {len(candidates)} unconfirmed candidate(s) -- "
            f"{names} -- not used in scoring"
        )
    else:
        lines.append("ATT&CK: no technique mapping found -> no threat adjustment")
    return lines


def _rationale(
    enriched: EnrichedFinding,
    threat: ThreatInputs,
    impact: ImpactInputs,
    risk_pct: float,
    bucket: Bucket,
) -> tuple[str, ...]:
    asset = enriched.asset
    composite = impact_composite(impact)
    epss_multiplier = EPSS_MULTIPLIER_BASELINE + threat.epss if threat.epss is not None else 1.0
    likelihood = _likelihood_multiplier(threat.epss, threat.is_kev)
    epss_desc = f"epss={threat.epss:.3f}" if threat.epss is not None else "epss=unscored"
    if threat.is_kev and epss_multiplier < KEV_FLOOR_MULTIPLIER:
        kev_desc = f"is_kev=True -> KEV floor applies (observation outranks the model's {epss_multiplier:.3f})"
    elif threat.is_kev:
        kev_desc = "is_kev=True -> EPSS already clears the KEV floor, no adjustment needed"
    else:
        kev_desc = "is_kev=False"
    severity_base, severity_source = _resolve_severity(enriched)
    scanner_tier = enriched.finding.scanner_severity
    if severity_source == "nvd":
        nvd_tier = enriched.nvd_severity or "unscored"
        if enriched.nvd_severity and enriched.nvd_severity != scanner_tier:
            severity_line = (
                f"scanner_severity='{scanner_tier}' vs NVD CVSS {severity_base:.1f} ({nvd_tier}) "
                f"-> disagreement: NVD is authoritative, overriding the scanner's call (source=nvd)"
            )
        else:
            severity_line = (
                f"scanner_severity='{scanner_tier}' agrees with NVD's tier ({nvd_tier}) -> using "
                f"NVD's precise CVSS base score {severity_base:.1f} rather than the tier proxy (source=nvd)"
            )
    else:
        severity_line = (
            f"scanner severity '{scanner_tier}' -> base score {severity_base:.1f} "
            f"(source=scanner; NVD has no CVSS data for this CVE)"
        )
    lines = [
        severity_line,
        f"internet_exposed={asset.internet_exposed} ({'x' + str(INTERNET_EXPOSED_MULTIPLIER) if asset.internet_exposed else 'x' + str(NOT_EXPOSED_MULTIPLIER)} threat)",
        f"{epss_desc}, {kev_desc} -> x{likelihood:.3f} likelihood multiplier",
        *_attack_rationale_lines(enriched, threat),
        f"criticality={asset.criticality}/5 (weight {IMPACT_COMPOSITE_WEIGHTS['criticality']} -> +{IMPACT_COMPOSITE_WEIGHTS['criticality'] * (asset.criticality / 5):.3f} to impact composite)",
        f"environment={asset.environment} (weight {IMPACT_COMPOSITE_WEIGHTS['environment']} -> +{IMPACT_COMPOSITE_WEIGHTS['environment'] * ENVIRONMENT_WEIGHT[asset.environment]:.3f} to impact composite)",
        f"data_sensitivity={asset.data_sensitivity} (weight {IMPACT_COMPOSITE_WEIGHTS['data_sensitivity']} -> +{IMPACT_COMPOSITE_WEIGHTS['data_sensitivity'] * DATA_SENSITIVITY_WEIGHT[asset.data_sensitivity]:.3f} to impact composite)",
        f"role={asset.role} (weight {IMPACT_COMPOSITE_WEIGHTS['role']} -> +{IMPACT_COMPOSITE_WEIGHTS['role'] * ROLE_BLAST_RADIUS[asset.role]:.3f} to impact composite, blast radius)",
        f"impact composite={composite:.3f} (of max {_MAX_IMPACT_COMPOSITE:.3f})",
    ]
    if impact.compensating_controls:
        decay = COMPENSATING_CONTROL_DECAY ** min(
            len(impact.compensating_controls), MAX_CONTROLS_COUNTED
        )
        lines.append(
            f"compensating_controls={list(impact.compensating_controls)} (x{decay:.2f} impact, applied after composite)"
        )
    if asset.has_patch_window:
        lines.append(f"patch_window='{asset.patch_window}' declared -> defer to this window")
    else:
        lines.append("no patch_window declared -> no scheduling restriction, may be patched at any time")
    lines.append(f"risk_score={risk_pct:.1f}/100")
    if bucket is Bucket.CONTESTED:
        lines.append(
            "bucket=contested: is_kev=True with no compensating control and no patch window -- "
            "not accept (confirmed exploitation), not mitigate_monitor (no control to point to), "
            "not next_window (nothing scheduled). No bucket honestly describes this; routed to "
            "Tree-of-Thought (Slice 4, not yet built) for human/agent reasoning."
        )
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
        is_kev=threat_inputs.is_kev,
    )
    rationale = _rationale(enriched, threat_inputs, impact_inputs, risk_pct, bucket)
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
