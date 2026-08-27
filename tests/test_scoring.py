from pathlib import Path

from rhinosecure.cli import run as cli_run
from rhinosecure.ingest import join_findings
from rhinosecure.scoring import Bucket, score_finding

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"


def _scored_by_finding_id():
    scored = [score_finding(e) for e in join_findings(DEMO_DIR / "findings.csv", DEMO_DIR / "assets.csv")]
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


def test_mitigate_monitor_is_reachable_on_the_demo_fixture():
    """A12, the legacy SQL server (SQL02), has a compensating control and no
    declared patch window, at a risk level above the accept threshold --
    the one combination that produces mitigate_monitor. Without it nothing
    in the fixture ever exercises this bucket."""
    by_id = _scored_by_finding_id()
    assert by_id["F15"].bucket == Bucket.MITIGATE_MONITOR
