from pathlib import Path

import pytest

from rhinosecure.cli import run as cli_run
from rhinosecure.scoring import (
    ACTIONABLE_THRESHOLD,
    EPSS_MULTIPLIER_BASELINE,
    KEV_FLOOR_MULTIPLIER,
    Bucket,
    CapacityAllocation,
    ImpactInputs,
    RankableFinding,
    ROLE_BLAST_RADIUS,
    ThreatInputs,
    apply_capacity_limit,
    bucket_for,
    contested_rate,
    impact_composite,
    score_threat,
)

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"


# --- role vocabulary: the Windows AD core plus perimeter/platform roles -----


def test_role_blast_radius_covers_the_windows_core_and_the_perimeter_roles():
    """The Windows AD-enterprise core is unchanged; the 8 perimeter/
    platform roles added for adapters/bluepeak.py are all present, each
    below dc's 1.0 ceiling so RISK_NORMALIZATION never moved (this is an
    additive change, not a renormalization -- see CLAUDE.md Section 3)."""
    core = {"dc": 1.0, "exchange": 0.9, "sql": 0.85, "iis_web": 0.6, "file": 0.55, "workstation": 0.3, "dev": 0.2}
    for role, weight in core.items():
        assert ROLE_BLAST_RADIUS[role] == weight

    perimeter = {
        "identity_gateway": 0.9,
        "firewall": 0.85,
        "container_orchestrator": 0.85,
        "email_gateway": 0.75,
        "network_appliance": 0.65,
        "web_app": 0.6,
        "container_host": 0.6,
        "printer": 0.15,
    }
    for role, weight in perimeter.items():
        assert ROLE_BLAST_RADIUS[role] == weight

    assert set(ROLE_BLAST_RADIUS) == set(core) | set(perimeter)
    assert max(ROLE_BLAST_RADIUS.values()) == 1.0  # dc is still the sole ceiling


def test_new_roles_actually_move_the_impact_composite():
    """Not just present in the table -- reachable through the same
    weighted-sum formula every role goes through, at the value the table
    declares."""
    base = dict(impact_base=10.0, criticality=5, environment="prod", data_sensitivity="regulated")
    firewall = impact_composite(ImpactInputs(**base, role="firewall"))
    printer = impact_composite(ImpactInputs(**base, role="printer"))
    dc = impact_composite(ImpactInputs(**base, role="dc"))
    assert printer < firewall < dc


def _scored_by_finding_id():
    # Goes through cli.run(), not raw join_findings+score_finding, so KEV
    # and EPSS are actually attached -- these tests check real end-to-end
    # behavior, not the pre-Slice-2 unenriched shortcut.
    scored = cli_run(DEMO_DIR, seed=42)
    return {s.finding_id: s for s in scored}


def test_anchor_cve_produces_three_distinct_buckets_across_hosts():
    """CVE-2021-26855 (ProxyLogon) appears on three Exchange hosts with
    identical technical severity; only business context differs. That must
    be enough, on its own, to land each in a different bucket.

    ProxyLogon is KEV-listed, so is_kev disqualifies EXCHDEV01's finding
    from accept (see bucket_for) even though its risk_score alone would
    have landed there -- it has a compensating control ("network
    isolated") and no patch window, so it resolves to mitigate_monitor,
    not the "no honest bucket" contested case (that needs no control
    either)."""
    by_id = _scored_by_finding_id()
    anchor_findings = [s for s in by_id.values() if s.cve_id == "CVE-2021-26855"]
    assert len(anchor_findings) == 3

    buckets = {s.bucket for s in anchor_findings}
    assert len(buckets) == 3, f"expected 3 distinct buckets, got {buckets}"

    internet_facing_prod = by_id["F01"]  # EXCH01
    internal_prod = by_id["F02"]  # EXCH02
    isolated_dev = by_id["F03"]  # EXCHDEV01

    assert internet_facing_prod.bucket == Bucket.PATCH_NOW
    assert internal_prod.risk_score < internet_facing_prod.risk_score
    assert isolated_dev.risk_score < internal_prod.risk_score
    assert isolated_dev.bucket == Bucket.MITIGATE_MONITOR


def test_scoring_is_deterministic_across_repeated_runs():
    first = cli_run(DEMO_DIR, seed=42)
    second = cli_run(DEMO_DIR, seed=42)
    assert [(s.finding_id, s.risk_score, s.bucket) for s in first] == [
        (s.finding_id, s.risk_score, s.bucket) for s in second
    ]


def test_seed_does_not_change_output():
    """Slice 1 has no randomness; the seed flag must not silently change scores."""
    a = cli_run(DEMO_DIR, seed=1)
    b = cli_run(DEMO_DIR, seed=999)
    assert [(s.finding_id, s.risk_score) for s in a] == [(s.finding_id, s.risk_score) for s in b]


def test_ranking_is_sorted_descending_by_risk():
    scored = cli_run(DEMO_DIR, seed=42)
    risk_scores = [s.risk_score for s in scored]
    assert risk_scores == sorted(risk_scores, reverse=True)


def test_all_demo_findings_are_scored():
    scored = cli_run(DEMO_DIR, seed=42)
    assert len(scored) == 24


def test_bucket_values_match_spec():
    scored = cli_run(DEMO_DIR, seed=42)
    # contested is not a remediation bucket -- see Bucket.CONTESTED's
    # docstring -- but it is a legitimate value bucket_for can return.
    # deferred_capacity is a legitimate Bucket member too, but only
    # apply_capacity_limit assigns it (see CapacityAllocation tests below)
    # -- bucket_for/score_finding itself never produces it, so it is
    # excluded from `allowed` here on purpose.
    allowed = {"patch_now", "next_window", "mitigate_monitor", "accept", "contested"}
    assert allowed | {"deferred_capacity"} == {b.value for b in Bucket}
    for s in scored:
        assert s.bucket.value in allowed


def _threat(*, epss=None, is_kev=False, exposed=False, attack_prevalence=None):
    return ThreatInputs(
        exploitability_base=9.5,
        internet_exposed=exposed,
        epss=epss,
        is_kev=is_kev,
        attack_prevalence=attack_prevalence,
    )


def test_no_signals_leaves_threat_unchanged():
    """Regression: with no EPSS data and no KEV listing, the likelihood
    multiplier must stay a neutral x1.0 -- the pre-Slice-2 behavior."""
    unenriched = score_threat(_threat())
    baseline = 9.5 * 0.7  # exploitability_base * NOT_EXPOSED_MULTIPLIER
    assert unenriched == pytest.approx(baseline)


def test_kev_alone_uses_the_floor():
    """No EPSS data yet, but KEV-listed: floor applies, matching the old
    flat KEV_MULTIPLIER's value even though the mechanism changed."""
    score = score_threat(_threat(is_kev=True))
    baseline = 9.5 * 0.7
    assert score == pytest.approx(baseline * KEV_FLOOR_MULTIPLIER)


def test_kev_floors_a_low_epss_reading_instead_of_stacking():
    """This is the F15 case: EPSS underrates a confirmed-exploited CVE.
    The floor must pull the multiplier up to KEV_FLOOR_MULTIPLIER, not
    multiply the floor on top of the (already low) EPSS multiplier."""
    low_epss = 0.1  # epss multiplier would be 0.6 + 0.1 = 0.7, well under the floor
    score = score_threat(_threat(epss=low_epss, is_kev=True))
    baseline = 9.5 * 0.7
    assert score == pytest.approx(baseline * KEV_FLOOR_MULTIPLIER)
    # The old design multiplied KEV_MULTIPLIER by the EPSS multiplier
    # (floor * epss multiplier) instead of taking the max of the two. With
    # a below-baseline EPSS reading that stacked product actually comes in
    # *under* the floor guarantee -- exactly the under-counting the floor
    # design exists to prevent.
    stacked = baseline * KEV_FLOOR_MULTIPLIER * (EPSS_MULTIPLIER_BASELINE + low_epss)
    assert stacked < score


# --- ATT&CK prevalence ------------------------------------------------------


def test_no_attack_mapping_leaves_threat_unchanged():
    """None (enrich/attack.py found no *confirmed* technique) must stay a
    no-op, same as unscored EPSS -- a missing/unconfirmed signal is not
    evidence of low prevalence."""
    with_none = score_threat(_threat(attack_prevalence=None))
    baseline = 9.5 * 0.7
    assert with_none == pytest.approx(baseline)


def test_max_attack_prevalence_applies_the_full_multiplier():
    score = score_threat(_threat(attack_prevalence=1.0))
    baseline = 9.5 * 0.7
    assert score == pytest.approx(baseline * 1.2)


def test_zero_attack_prevalence_pulls_the_score_down():
    """A confirmed technique that is nonetheless rarely used by tracked
    groups/software (prevalence near 0) should modestly reduce threat, not
    leave it untouched -- distinguishing 'confirmed but obscure' from 'no
    mapping at all' (which stays neutral, see the None case above)."""
    score = score_threat(_threat(attack_prevalence=0.0))
    baseline = 9.5 * 0.7
    assert score == pytest.approx(baseline * 0.8)
    assert score < baseline


# --- KEV disqualifies accept (bucket_for) -----------------------------------

_LOW_RISK = ACTIONABLE_THRESHOLD - 5  # below the tier on risk alone


def test_non_kev_low_risk_is_accept():
    """Regression: nothing changes for a non-KEV finding below the
    actionable threshold -- accept is still reachable."""
    bucket = bucket_for(
        _LOW_RISK, has_patch_window=False, has_compensating_controls=False, is_kev=False
    )
    assert bucket == Bucket.ACCEPT


def test_kev_with_control_and_no_window_is_mitigate_monitor_even_below_threshold():
    """F03/F08 case: is_kev pulls a below-threshold finding into the
    actionable tier, and a real compensating control makes
    mitigate_monitor an honest bucket for it."""
    bucket = bucket_for(
        _LOW_RISK, has_patch_window=False, has_compensating_controls=True, is_kev=True
    )
    assert bucket == Bucket.MITIGATE_MONITOR


def test_kev_with_window_and_no_control_is_next_window_even_below_threshold():
    """F13 case: a patch window already exists, so next_window is honest
    even though there's no compensating control to point to."""
    bucket = bucket_for(
        _LOW_RISK, has_patch_window=True, has_compensating_controls=False, is_kev=True
    )
    assert bucket == Bucket.NEXT_WINDOW


def test_kev_with_no_control_and_no_window_is_contested():
    """F14 case: confirmed exploitation, no control to lean on, nothing
    scheduled -- no bucket honestly describes this, so it's contested
    rather than forced into next_window."""
    bucket = bucket_for(
        _LOW_RISK, has_patch_window=False, has_compensating_controls=False, is_kev=True
    )
    assert bucket == Bucket.CONTESTED


def test_non_kev_no_control_and_no_window_above_threshold_stays_next_window():
    """Regression: the contested case is specific to is_kev. A non-KEV
    finding with no control and no window above the threshold keeps its
    pre-existing meaning -- no scheduling restriction -- and lands in
    next_window, not contested."""
    bucket = bucket_for(
        ACTIONABLE_THRESHOLD, has_patch_window=False, has_compensating_controls=False, is_kev=False
    )
    assert bucket == Bucket.NEXT_WINDOW


def test_kev_does_not_override_patch_now():
    """A KEV finding whose risk already clears PATCH_NOW_THRESHOLD stays
    patch_now regardless of control/window -- contested only applies
    below that, where the control/window ambiguity actually exists."""
    bucket = bucket_for(
        95, has_patch_window=False, has_compensating_controls=False, is_kev=True
    )
    assert bucket == Bucket.PATCH_NOW


def test_kev_does_not_inflate_an_already_high_epss_reading():
    """This is the F01 case: EPSS already agrees the CVE is dangerous.
    KEV must not multiply another 1.5x on top of that -- the floor is a
    no-op once EPSS alone clears it."""
    high_epss = 0.99996
    with_kev = score_threat(_threat(epss=high_epss, is_kev=True))
    without_kev = score_threat(_threat(epss=high_epss, is_kev=False))
    assert with_kev == pytest.approx(without_kev)


def test_mitigate_monitor_is_reachable_on_the_demo_fixture():
    """A12, the legacy SQL server (SQL02), has a compensating control and no
    declared patch window, at a risk level above the accept threshold --
    the one combination that produces mitigate_monitor. Without it nothing
    in the fixture ever exercises this bucket."""
    by_id = _scored_by_finding_id()
    assert by_id["F15"].bucket == Bucket.MITIGATE_MONITOR


def test_f14_is_contested_on_the_demo_fixture():
    """F14 (CVE-2023-23397 on WKS-FIN12) is KEV-listed with neither a
    compensating control nor a declared patch window -- the demo fixture's
    real instance of the contested case, and the reason it exists."""
    by_id = _scored_by_finding_id()
    f14 = by_id["F14"]
    assert f14.bucket == Bucket.CONTESTED
    assert any("contested" in line for line in f14.rationale)


# --- apply_capacity_limit ---------------------------------------------------


def _rankable(finding_id, risk_score, bucket=Bucket.NEXT_WINDOW):
    return RankableFinding(finding_id=finding_id, risk_score=risk_score, bucket=bucket)


def test_capacity_limit_of_empty_pool_is_empty_not_an_error():
    assert apply_capacity_limit([], limit=5) == []


def test_capacity_limit_zero_defers_everyone():
    findings = [_rankable("F01", 50.0), _rankable("F02", 40.0), _rankable("F03", 30.0)]
    allocations = apply_capacity_limit(findings, limit=0)
    assert len(allocations) == 3
    assert all(a.effective_bucket == Bucket.DEFERRED_CAPACITY for a in allocations)
    assert all(not a.fits for a in allocations)


def test_capacity_limit_at_or_above_pool_size_defers_nobody():
    findings = [_rankable("F01", 50.0), _rankable("F02", 40.0), _rankable("F03", 30.0)]
    allocations = apply_capacity_limit(findings, limit=3)
    assert all(a.effective_bucket == Bucket.NEXT_WINDOW for a in allocations)
    assert all(a.fits for a in allocations)

    allocations_over = apply_capacity_limit(findings, limit=10)
    assert all(a.effective_bucket == Bucket.NEXT_WINDOW for a in allocations_over)
    assert all(a.fits for a in allocations_over)


def test_capacity_limit_boundary_between_fits_and_deferred():
    """limit strictly between 1 and pool_size-1: the finding ranked exactly
    at the limit still fits; the very next one is deferred. Pool of 5,
    limit 2 -- rank 2 fits, rank 3 does not."""
    findings = [
        _rankable("F01", 90.0),
        _rankable("F02", 80.0),
        _rankable("F03", 70.0),
        _rankable("F04", 60.0),
        _rankable("F05", 50.0),
    ]
    allocations = apply_capacity_limit(findings, limit=2)
    by_id = {a.finding_id: a for a in allocations}

    assert by_id["F01"].rank == 1 and by_id["F01"].fits
    assert by_id["F01"].effective_bucket == Bucket.NEXT_WINDOW

    assert by_id["F02"].rank == 2 and by_id["F02"].fits
    assert by_id["F02"].effective_bucket == Bucket.NEXT_WINDOW

    assert by_id["F03"].rank == 3 and not by_id["F03"].fits
    assert by_id["F03"].effective_bucket == Bucket.DEFERRED_CAPACITY

    assert by_id["F04"].rank == 4 and not by_id["F04"].fits
    assert by_id["F05"].rank == 5 and not by_id["F05"].fits

    assert all(a.pool_size == 5 for a in allocations)
    assert all(a.limit == 2 for a in allocations)
    assert all(a.original_bucket == Bucket.NEXT_WINDOW for a in allocations)


def test_capacity_limit_tie_breaks_by_ascending_finding_id():
    """Same tie-break rank() already uses: equal risk_score, ascending
    finding_id gets the better (lower) rank."""
    findings = [_rankable("F02", 50.0), _rankable("F01", 50.0)]
    allocations = apply_capacity_limit(findings, limit=1)
    by_id = {a.finding_id: a for a in allocations}
    assert by_id["F01"].rank == 1
    assert by_id["F01"].fits
    assert by_id["F01"].effective_bucket == Bucket.NEXT_WINDOW
    assert by_id["F02"].rank == 2
    assert not by_id["F02"].fits
    assert by_id["F02"].effective_bucket == Bucket.DEFERRED_CAPACITY


def test_capacity_limit_exempts_non_next_window_buckets_by_construction():
    """The exemption is structural, not a special case: a patch_now finding
    with a very high risk_score never competes for window capacity and
    never appears in apply_capacity_limit's output at all, regardless of
    how low the limit is."""
    findings = [
        _rankable("F01", 99.9, bucket=Bucket.PATCH_NOW),
        _rankable("F02", 60.0, bucket=Bucket.MITIGATE_MONITOR),
        _rankable("F03", 40.0, bucket=Bucket.ACCEPT),
        _rankable("F04", 55.0, bucket=Bucket.CONTESTED),
        _rankable("F05", 50.0, bucket=Bucket.NEXT_WINDOW),
    ]
    allocations = apply_capacity_limit(findings, limit=0)
    ids = {a.finding_id for a in allocations}
    assert ids == {"F05"}
    assert len(allocations) == 1


# --- contested_rate ------------------------------------------------------


def test_contested_rate_counts_only_the_contested_bucket():
    rate = contested_rate(["patch_now", "contested", "accept", "contested", "next_window"])
    assert rate.contested == 2
    assert rate.total == 5
    assert rate.pct == pytest.approx(40.0)


def test_contested_rate_of_empty_input_is_zero_not_a_division_error():
    rate = contested_rate([])
    assert rate.contested == 0
    assert rate.total == 0
    assert rate.pct == 0.0


def test_contested_rate_on_the_demo_fixture_matches_the_known_three():
    """F07, F11, and F14 are the demo fixture's three contested findings
    (PROGRESS.md) -- 3/24, matching the bucket distribution logged after
    every deterministic-pipeline change so far."""
    by_id = _scored_by_finding_id()
    rate = contested_rate(s.bucket.value for s in by_id.values())
    assert rate.contested == 3
    assert rate.total == 24
    assert rate.pct == pytest.approx(12.5)


# --- rationale wording for fields the source never collected ----------------
#
# A blank patch_window means "no declared scheduling restriction" for a
# native record and "nobody recorded one" for a record whose source does
# not export the field (adapters/base.py). The verdict is identical
# either way -- bucket_for reads the value, which is blank in both cases
# -- but the rationale must not claim the stronger of the two.

from rhinosecure.schema import Asset as _Asset  # noqa: E402
from rhinosecure.schema import EnrichedFinding as _EnrichedFinding  # noqa: E402
from rhinosecure.schema import Finding as _Finding  # noqa: E402
from rhinosecure.scoring import score_finding as _score_finding  # noqa: E402

_GAPS = frozenset({"patch_window", "compensating_controls", "role", "environment"})


def _asset(**overrides):
    base = dict(
        asset_id="X1", hostname="host1", os="Windows Server 2019", os_build="17763",
        role="dc", criticality=5, internet_exposed=False, environment="prod",
        data_sensitivity="regulated",
    )
    base.update(overrides)
    return _Asset(**base)


def _scored(asset, *, is_kev=False):
    finding = _Finding(
        finding_id="X-1", asset_id=asset.asset_id, cve_id="CVE-2020-1472",
        scanner_severity="critical", product="p", version="1", evidence="e",
    )
    return _score_finding(_EnrichedFinding(finding=finding, asset=asset, is_kev=is_kev))


def test_native_blank_patch_window_keeps_the_declared_wording():
    rationale = _scored(_asset()).rationale
    assert any(
        line == "no patch_window declared -> no scheduling restriction, may be patched at any time"
        for line in rationale
    )
    assert not any("not collected" in line for line in rationale)


def test_a_not_collected_patch_window_says_so_instead():
    rationale = _scored(_asset(not_collected=_GAPS)).rationale
    assert any(line.startswith("patch window not collected") for line in rationale)
    assert not any("no patch_window declared" in line for line in rationale)
    assert any("unknown, not unrestricted" in line for line in rationale)


def test_not_collected_compensating_controls_are_named_rather_than_left_silent():
    rationale = _scored(_asset(not_collected=_GAPS)).rationale
    assert any(line.startswith("compensating controls not collected") for line in rationale)


def test_a_declared_patch_window_or_control_wins_over_the_marker():
    """If a value is actually present the marker is stale (the constraint
    overlay clears it), and the real value must be reported either way."""
    asset = _asset(
        patch_window="Sun 02:00-06:00", compensating_controls="WAF", not_collected=_GAPS
    )
    rationale = _scored(asset).rationale
    assert any("patch_window='Sun 02:00-06:00' declared" in line for line in rationale)
    assert any("compensating_controls=['WAF']" in line for line in rationale)
    assert not any("not collected" in line for line in rationale)


def test_contested_line_says_collected_only_when_the_field_is_a_gap():
    native = [line for line in _scored(_asset(), is_kev=True).rationale if line.startswith("bucket=contested")]
    assert native and "with no compensating control and no patch window --" in native[0]

    gapped = [
        line
        for line in _scored(_asset(not_collected=_GAPS), is_kev=True).rationale
        if line.startswith("bucket=contested")
    ]
    assert gapped and "no compensating control collected and no patch window collected" in gapped[0]


def test_not_collected_never_changes_a_score_or_a_bucket():
    """The marker is a claim about provenance, not an input to the
    arithmetic -- scoring must read it for wording only."""
    for is_kev in (False, True):
        plain = _scored(_asset(), is_kev=is_kev)
        marked = _scored(_asset(not_collected=_GAPS), is_kev=is_kev)
        assert plain.risk_score == marked.risk_score
        assert plain.threat_score == marked.threat_score
        assert plain.impact_score == marked.impact_score
        assert plain.bucket is marked.bucket
