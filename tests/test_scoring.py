from pathlib import Path

import pytest

from rhinosecure.cli import run as cli_run
from rhinosecure.scoring import (
    ACTIONABLE_THRESHOLD,
    EPSS_MULTIPLIER_BASELINE,
    KEV_FLOOR_MULTIPLIER,
    Bucket,
    ThreatInputs,
    bucket_for,
    score_threat,
)

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"


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
    allowed = {"patch_now", "next_window", "mitigate_monitor", "accept", "contested"}
    assert allowed == {b.value for b in Bucket}
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
