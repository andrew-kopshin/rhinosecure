from pathlib import Path

import pytest

from rhinosecure.enrich.cache import OfflineCacheMissError
from rhinosecure.cli import main, run

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"


def test_offline_flag_is_accepted_and_does_not_error():
    assert main(["run", "--data", "demo", "--seed", "42", "--offline"]) == 0


def test_offline_flag_does_not_change_output_when_snapshots_already_cover_every_cve():
    """Every CVE in the demo fixture already has a committed KEV/EPSS
    snapshot, so both modes are pure cache hits and must agree exactly.
    --offline's real effect -- raising loudly on a genuine miss -- is
    covered separately below and in test_cache.py/test_kev.py/test_epss.py."""
    online = run(DEMO_DIR, seed=42, offline=False)
    offline = run(DEMO_DIR, seed=42, offline=True)
    assert [(s.finding_id, s.risk_score, s.bucket) for s in online] == [
        (s.finding_id, s.risk_score, s.bucket) for s in offline
    ]


def test_offline_flag_fails_loudly_on_a_genuinely_new_cve(tmp_path: Path):
    """A CVE with no committed snapshot anywhere must make --offline raise
    instead of silently reaching the network."""
    (tmp_path / "assets.csv").write_text(
        "asset_id,hostname,os,os_build,role,business_function,criticality,"
        "internet_exposed,environment,data_sensitivity,patch_window,"
        "patch_restrictions,compensating_controls,owner\n"
        "A01,HOST1,Windows Server 2019,17763,dc,DC,5,False,prod,regulated,,,,\n"
    )
    (tmp_path / "findings.csv").write_text(
        "finding_id,asset_id,cve_id,detected_date,scanner_severity,product,"
        "version,port,service,evidence\n"
        "F01,A01,CVE-1999-0001,2026-01-01,high,X,1.0,1,svc,ev\n"
    )

    with pytest.raises(OfflineCacheMissError):
        run(tmp_path, seed=42, offline=True)
