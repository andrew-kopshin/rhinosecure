import inspect
from pathlib import Path

import pytest

from rhinosecure.ingest import IngestError, join_findings, load_assets, load_findings

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"


def test_load_assets_is_lazy():
    """Ingest must be a generator, not a function that reads the whole file
    up front — nothing may assume the dataset fits in memory in one pass."""
    gen = load_assets(DEMO_DIR / "assets.csv")
    assert inspect.isgenerator(gen)


def test_load_findings_is_lazy():
    gen = load_findings(DEMO_DIR / "findings.csv")
    assert inspect.isgenerator(gen)


def test_join_findings_resolves_every_asset():
    joined = list(join_findings(DEMO_DIR / "findings.csv", DEMO_DIR / "assets.csv"))
    assert len(joined) == 15
    for enriched in joined:
        assert enriched.asset.asset_id == enriched.finding.asset_id


def test_unknown_asset_id_raises(tmp_path: Path):
    assets_csv = tmp_path / "assets.csv"
    findings_csv = tmp_path / "findings.csv"
    assets_csv.write_text(
        "asset_id,hostname,os,os_build,role,business_function,criticality,"
        "internet_exposed,environment,data_sensitivity,patch_window,"
        "patch_restrictions,compensating_controls,owner\n"
        "A01,HOST1,Windows Server 2019,17763,dc,DC,5,False,prod,regulated,,,,\n"
    )
    findings_csv.write_text(
        "finding_id,asset_id,cve_id,detected_date,scanner_severity,product,"
        "version,port,service,evidence\n"
        "F01,DOES-NOT-EXIST,CVE-2020-1472,2026-01-01,critical,X,1.0,1,svc,ev\n"
    )
    with pytest.raises(IngestError):
        list(join_findings(findings_csv, assets_csv))


def test_invalid_row_raises_ingest_error(tmp_path: Path):
    assets_csv = tmp_path / "assets.csv"
    assets_csv.write_text(
        "asset_id,hostname,os,os_build,role,business_function,criticality,"
        "internet_exposed,environment,data_sensitivity,patch_window,"
        "patch_restrictions,compensating_controls,owner\n"
        "A01,HOST1,Windows Server 2019,17763,not_a_real_role,DC,5,False,prod,regulated,,,,\n"
    )
    with pytest.raises(IngestError):
        list(load_assets(assets_csv))
