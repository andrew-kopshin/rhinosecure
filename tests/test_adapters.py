"""The adapter registry and the native adapter -- the seam itself, as
opposed to test_adapters_defender.py's one concrete format."""

from __future__ import annotations

from pathlib import Path

import pytest

from rhinosecure.adapters import DEFAULT_FORMAT, FORMATS, AdapterError, get_adapter
from rhinosecure.adapters.base import NOT_COLLECTED_DEFAULTS, IngestAdapter
from rhinosecure.adapters.native import NativeAdapter
from rhinosecure.ingest import GapTally, IngestStats, join_findings, load_batch
from rhinosecure.schema import Asset, Finding

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"


def test_native_is_the_default_format_and_defender_is_registered():
    assert DEFAULT_FORMAT == "native"
    assert set(FORMATS) == {"native", "defender"}
    assert all(issubclass(cls, IngestAdapter) for cls in FORMATS.values())
    assert isinstance(get_adapter("native"), NativeAdapter)


def test_unknown_format_is_an_adapter_error():
    with pytest.raises(AdapterError, match="unknown ingest format 'qualys'"):
        get_adapter("qualys")


def test_native_adapter_reproduces_join_findings_exactly_on_the_demo_fixture():
    """Routing the native format through the adapter seam must change
    nothing: same EnrichedFinding objects, same order, no gaps, nothing
    collapsed -- the byte-identical-output guarantee starts here."""
    adapter = get_adapter("native")
    assets, enriched = load_batch(DEMO_DIR, adapter)
    via_adapter = list(enriched)
    direct = list(join_findings(DEMO_DIR / "findings.csv", DEMO_DIR / "assets.csv"))

    assert via_adapter == direct
    assert set(assets) == {e.asset.asset_id for e in direct}
    assert all(e.asset.not_collected == frozenset() for e in via_adapter)
    assert all(e.finding.not_collected == frozenset() for e in via_adapter)
    assert adapter.stats == IngestStats()


def test_native_gap_report_is_empty():
    adapter = get_adapter("native")
    assets, enriched = load_batch(DEMO_DIR, adapter)
    tally = GapTally()
    for e in enriched:
        tally.observe(e.finding)
    report = tally.report("native", assets, adapter.stats)
    assert not report.has_gaps
    assert not report.has_anything_to_report
    assert report.assets_total == len(assets) and report.findings_total == tally.findings_total


def test_every_not_collected_default_is_valid_for_the_schema():
    """The defaults table must produce records the schema accepts, or an
    adapter would fail on the first row of a format that lacks a field."""
    asset_defaults = {k: v for k, v in NOT_COLLECTED_DEFAULTS.items() if k in Asset.model_fields}
    finding_defaults = {k: v for k, v in NOT_COLLECTED_DEFAULTS.items() if k in Finding.model_fields}
    assert set(asset_defaults) | set(finding_defaults) == set(NOT_COLLECTED_DEFAULTS)

    asset = Asset(asset_id="x", hostname="h", os="Windows 10", role="workstation", **asset_defaults,
                  not_collected=frozenset(asset_defaults))
    finding = Finding(finding_id="f", asset_id="x", cve_id="CVE-2020-1472", scanner_severity="high",
                      **finding_defaults, not_collected=frozenset(finding_defaults))
    assert asset.not_collected == set(asset_defaults)
    assert finding.not_collected == set(finding_defaults)


def test_native_csv_cannot_smuggle_a_not_collected_column(tmp_path):
    """not_collected is set by adapters, never read from a native CSV cell
    -- a stray column must fail validation loudly, not be parsed into a
    set of characters."""
    from rhinosecure.ingest import IngestError, load_assets

    path = tmp_path / "assets.csv"
    path.write_text(
        "asset_id,hostname,os,os_build,role,business_function,criticality,internet_exposed,"
        "environment,data_sensitivity,patch_window,patch_restrictions,compensating_controls,owner,not_collected\n"
        "A01,HOST1,Windows Server 2019,17763,dc,DC,5,False,prod,regulated,,,,,patch_window\n"
    )
    with pytest.raises(IngestError):
        list(load_assets(path))
