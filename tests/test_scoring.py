from pathlib import Path

import pytest

from rhinosecure.cli import run as cli_run
from rhinosecure.scoring import (
    EPSS_MULTIPLIER_BASELINE,
    KEV_FLOOR_MULTIPLIER,
    Bucket,
    ThreatInputs,
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
    be enough, on its own, to land each in a different bucket."""
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
    assert isolated_dev.bucket == Bucket.ACCEPT


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
    allowed = {b.value for b in Bucket}
    assert allowed == {"patch_now", "next_window", "mitigate_monitor", "accept"}
    for s in scored:
        assert s.bucket.value in allowed


def _threat(*, epss=None, is_kev=False, exposed=False):
    return ThreatInputs(exploitability_base=9.5, internet_exposed=exposed, epss=epss, is_kev=is_kev)


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
