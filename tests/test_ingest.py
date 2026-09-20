import inspect
from pathlib import Path

import pytest

from rhinosecure.ingest import IngestError, attach_threat_signals, join_findings, load_assets, load_findings
from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.enrich.kev import KevCatalog

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"


class _EmptyAttackIndex:
    """Stand-in for enrich.attack.TechniqueIndex -- attach_threat_signals
    only ever calls .lookup(), so a real (payload-constructed) index isn't
    needed to test the KEV/kev_due_date wiring these tests are about."""

    def lookup(self, cve_id, product="", evidence="", *, limit=5):
        return []


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
    assert len(joined) == 24
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


# --- attach_threat_signals: kev_due_date wiring -----------------------------


def _f14():
    by_id = {e.finding.finding_id: e for e in join_findings(DEMO_DIR / "findings.csv", DEMO_DIR / "assets.csv")}
    return by_id["F14"]  # CVE-2023-23397, KEV-listed, real committed snapshot


def test_attach_threat_signals_carries_the_real_kev_due_date():
    """F14/CVE-2023-23397 -- data/snapshots/kev.json's own dateAdded/
    dueDate for this CVE, not a guess."""
    cache = SnapshotCache(offline=True)
    kev_catalog = KevCatalog({"CVE-2023-23397": {"dateAdded": "2023-03-14", "dueDate": "2023-04-04"}})

    enriched = attach_threat_signals(_f14(), kev_catalog, _EmptyAttackIndex(), cache)

    assert enriched.is_kev is True
    assert enriched.kev_due_date == "2023-04-04"


def test_attach_threat_signals_kev_due_date_is_none_when_not_kev_listed():
    cache = SnapshotCache(offline=True)
    empty_kev_catalog = KevCatalog({})  # no entries at all -- CVE-2023-23397 is_listed=False

    enriched = attach_threat_signals(_f14(), empty_kev_catalog, _EmptyAttackIndex(), cache)

    assert enriched.is_kev is False
    assert enriched.kev_due_date is None


# --- identity and duplicate-key gates ---------------------------------------

_ASSET_HEADER = (
    "asset_id,hostname,os,os_build,role,business_function,criticality,"
    "internet_exposed,environment,data_sensitivity,patch_window,"
    "patch_restrictions,compensating_controls,owner\n"
)
_FINDING_HEADER = "finding_id,asset_id,cve_id,detected_date,scanner_severity,product,version,port,service,evidence\n"


def _asset_row(asset_id="A01", owner=""):
    return f"{asset_id},HOST-{asset_id},Windows Server 2019,17763,dc,DC,5,False,prod,regulated,,,,{owner}\n"


def _finding_row(finding_id="F01", asset_id="A01", cve="CVE-2020-1472", severity="critical"):
    return f"{finding_id},{asset_id},{cve},2026-01-01,{severity},X,1.0,1,svc,ev\n"


@pytest.mark.parametrize("cve", ["", "   ", "CVE-2021-1234 (see notes)", "CVE/2021/1234"])
def test_a_blank_or_unsafe_cve_id_is_refused_at_its_row(tmp_path: Path, cve: str):
    """A blank cve_id used to reach the snapshot cache and abort the whole run
    with `ValueError: unsafe snapshot key: ''`; a free-text cell did the same."""
    path = tmp_path / "findings.csv"
    path.write_text(_FINDING_HEADER + _finding_row(cve=cve))
    with pytest.raises(IngestError, match="invalid finding row"):
        list(load_findings(path))


@pytest.mark.parametrize("field", ["finding_id", "asset_id"])
def test_a_blank_finding_key_is_refused(tmp_path: Path, field: str):
    path = tmp_path / "findings.csv"
    row = _finding_row(**{field: ""})
    path.write_text(_FINDING_HEADER + row)
    with pytest.raises(IngestError, match="invalid finding row"):
        list(load_findings(path))


def test_a_blank_asset_id_is_refused(tmp_path: Path):
    path = tmp_path / "assets.csv"
    path.write_text(_ASSET_HEADER + _asset_row(asset_id=""))
    with pytest.raises(IngestError, match="invalid asset row"):
        list(load_assets(path))


def test_conflicting_duplicate_assets_are_refused_and_named(tmp_path: Path):
    """The plain dict this replaced kept whichever row came last, silently."""
    assets = tmp_path / "assets.csv"
    findings = tmp_path / "findings.csv"
    assets.write_text(
        _ASSET_HEADER + _asset_row("A01", owner="infra") + _asset_row("A01", owner="other") + _asset_row("A02")
    )
    findings.write_text(_FINDING_HEADER + _finding_row())
    with pytest.raises(IngestError) as exc:
        list(join_findings(findings, assets))
    assert "'A01'" in str(exc.value) and "owner" in str(exc.value)
    assert "A02" not in str(exc.value)


def test_identical_duplicate_assets_collapse_and_are_counted(tmp_path: Path):
    from rhinosecure.ingest import IngestStats, index_assets

    path = tmp_path / "assets.csv"
    path.write_text(_ASSET_HEADER + _asset_row("A01") + _asset_row("A01") + _asset_row("A02"))
    stats = IngestStats()
    index = index_assets(load_assets(path), source=str(path), stats=stats)
    assert sorted(index) == ["A01", "A02"]
    assert stats.duplicate_assets_collapsed == 1


def test_conflicting_duplicate_findings_are_refused(tmp_path: Path):
    """Two rows sharing a finding_id used to be listed twice in the plan, with
    different scores, while every id-keyed lookup quietly picked one."""
    assets = tmp_path / "assets.csv"
    findings = tmp_path / "findings.csv"
    assets.write_text(_ASSET_HEADER + _asset_row("A01"))
    findings.write_text(_FINDING_HEADER + _finding_row(severity="critical") + _finding_row(severity="low"))
    with pytest.raises(IngestError, match="'F01'.*more than one row"):
        list(join_findings(findings, assets))


def test_identical_duplicate_findings_collapse_and_are_counted(tmp_path: Path):
    from rhinosecure.ingest import IngestStats, unique_findings

    path = tmp_path / "findings.csv"
    path.write_text(_FINDING_HEADER + _finding_row() + _finding_row() + _finding_row("F02"))
    stats = IngestStats()
    kept = list(unique_findings(load_findings(path), source=str(path), stats=stats))
    assert [f.finding_id for f in kept] == ["F01", "F02"]
    assert stats.duplicate_findings_collapsed == 1


def test_load_batch_names_an_empty_inventory_instead_of_blaming_the_findings(tmp_path: Path):
    from rhinosecure.adapters import get_adapter
    from rhinosecure.ingest import load_batch

    (tmp_path / "assets.csv").write_text(_ASSET_HEADER)  # header only
    (tmp_path / "findings.csv").write_text(_FINDING_HEADER + _finding_row())
    with pytest.raises(IngestError, match="contains no asset rows"):
        load_batch(tmp_path, get_adapter("native"))
