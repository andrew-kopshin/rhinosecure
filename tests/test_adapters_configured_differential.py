"""ConfiguredAdapter, driven by a hand-written contract, against the two
adapters it is meant to be able to replace -- field for field on the real
committed data, and cell for cell across synthetic scenarios neither real
file happens to trigger.

This is the exit criterion slice 2 was built to satisfy. Real-data
comparisons use the exact `bluepeak-gen`/`mdvm-gen` contracts committed at
data/adapters/ (built from the same dict builders as
test_adapters_config_model.py's own slice-1 fixtures, so a contract change
there is reflected here automatically). Synthetic comparisons reuse the
row-dict builders from test_adapters_bluepeak.py / test_adapters_defender.py
so the SAME input feeds both the hand-written adapter and ConfiguredAdapter
-- an actual differential, not two independently-imagined expectations.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rhinosecure.adapters import get_adapter
from rhinosecure.adapters.base import AdapterError, IngestStats
from rhinosecure.adapters.bluepeak import BluePeakAdapter
from rhinosecure.adapters.config_model import Contract
from rhinosecure.adapters.configured import ConfiguredAdapter
from rhinosecure.adapters.defender import DefenderAdapter
from rhinosecure.ingest import IngestError, load_batch
from rhinosecure.schema import Finding

from test_adapters_bluepeak import FILENAME as BP_FILENAME
from test_adapters_bluepeak import _row as bp_row
from test_adapters_bluepeak import _write as bp_write
from test_adapters_config_model import _confirmed, bluepeak_gen_dict, mdvm_gen_dict
from test_adapters_defender import DC
from test_adapters_defender import DEVICE_COLUMNS as DEF_DEVICE_COLUMNS
from test_adapters_defender import VULN_COLUMNS as DEF_VULN_COLUMNS
from test_adapters_defender import WEB
from test_adapters_defender import _device as def_device
from test_adapters_defender import _vuln as def_vuln
from test_adapters_defender import _write as def_write

DATA_ROOT = Path(__file__).resolve().parents[1] / "data"


def _contract(builder) -> Contract:
    return Contract.model_validate(_confirmed(builder()))


def _load_all(data_dir: Path, adapter) -> None:
    """`load_batch`'s second return value is a lazy generator (`ingest.join`
    wrapping `adapter.load_findings`) -- a finding-level refusal only fires
    once something actually iterates it. Calling `load_batch(...)` alone
    inside `pytest.raises` silently never triggers one; this forces full
    consumption so a finding-side `AdapterError` actually surfaces."""
    _assets, findings = load_batch(data_dir, adapter)
    list(findings)


def _bluepeak_gen_contract() -> Contract:
    return _contract(bluepeak_gen_dict)


def _mdvm_gen_contract() -> Contract:
    return _contract(mdvm_gen_dict)


def _def_sample_dir(tmp_path: Path, devices: list[dict], vulns: list[dict]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    def_write(tmp_path / "devices.csv", DEF_DEVICE_COLUMNS, devices)
    def_write(tmp_path / "vulnerabilities.csv", DEF_VULN_COLUMNS, vulns)
    return tmp_path


def _bp_sample_dir(tmp_path: Path, rows: list[dict]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    bp_write(tmp_path / BP_FILENAME, rows)
    return tmp_path


FINDING_FIELDS = tuple(Finding.model_fields)


# =========================================================================
# Real data: field-for-field, against the committed fixtures
# =========================================================================


def test_bluepeak_gen_json_matches_the_committed_file():
    """The contract committed at data/adapters/bluepeak-gen.json is exactly
    what bluepeak_gen_dict()+_confirmed() would produce today -- catches
    the file silently drifting from the builder that is supposed to be its
    source of truth."""
    on_disk = json.loads((DATA_ROOT / "adapters" / "bluepeak-gen.json").read_text(encoding="utf-8"))
    built = _confirmed(bluepeak_gen_dict())
    assert on_disk == built


def test_mdvm_gen_json_matches_the_committed_file():
    on_disk = json.loads((DATA_ROOT / "adapters" / "mdvm-gen.json").read_text(encoding="utf-8"))
    built = _confirmed(mdvm_gen_dict())
    assert on_disk == built


def test_bluepeak_gen_matches_bluepeak_adapter_on_the_real_file():
    contract = _bluepeak_gen_contract()
    adapter = ConfiguredAdapter(contract)
    cfg_assets, cfg_findings_iter = load_batch(DATA_ROOT / "bluepeak", adapter)
    cfg_findings = [f.finding for f in cfg_findings_iter]

    hw_adapter = BluePeakAdapter()
    hw_assets, hw_findings_iter = load_batch(DATA_ROOT / "bluepeak", hw_adapter)
    hw_findings = [f.finding for f in hw_findings_iter]

    # Exit criterion: 47 assets, 3 collapsed, 50 findings, 0 collapsed, 0 excluded.
    assert adapter.stats == IngestStats(duplicate_assets_collapsed=3, duplicate_findings_collapsed=0, excluded_assets={}, excluded_findings={})
    assert adapter.stats == hw_adapter.stats

    assert set(cfg_assets) == set(hw_assets)
    for asset_id, hw_asset in hw_assets.items():
        assert cfg_assets[asset_id] == hw_asset, asset_id

    assert len(cfg_findings) == len(hw_findings) == 50
    cfg_by_id = {f.finding_id: f for f in cfg_findings}
    hw_by_id = {f.finding_id: f for f in hw_findings}
    assert set(cfg_by_id) == set(hw_by_id)
    for finding_id, hw_finding in hw_by_id.items():
        cfg_finding = cfg_by_id[finding_id]
        for field in FINDING_FIELDS:
            cfg_value, hw_value = getattr(cfg_finding, field), getattr(hw_finding, field)
            if field == "source_enrichment":
                # severity_label is the contract's own format name by design
                # (config_model.py's Enrichment docstring) -- "bluepeak-gen"
                # here, "bluepeak" on the hand-written adapter. Every OTHER
                # source_enrichment field must still match exactly.
                assert cfg_value.severity_label == "bluepeak-gen"
                assert hw_value.severity_label == "bluepeak"
                assert cfg_value.model_copy(update={"severity_label": ""}) == hw_value.model_copy(update={"severity_label": ""})
            else:
                assert cfg_value == hw_value, f"{finding_id}.{field}"


def test_mdvm_gen_matches_defender_adapter_on_the_real_file():
    contract = _mdvm_gen_contract()
    adapter = ConfiguredAdapter(contract)
    cfg_assets, cfg_findings_iter = load_batch(DATA_ROOT / "defender-sample", adapter)
    cfg_findings = [f.finding for f in cfg_findings_iter]

    hw_adapter = DefenderAdapter()
    hw_assets, hw_findings_iter = load_batch(DATA_ROOT / "defender-sample", hw_adapter)
    hw_findings = [f.finding for f in hw_findings_iter]

    # Exit criterion: 5 assets from 6 rows (1 collapsed), 9 findings from 10
    # rows (1 collapsed -- the duplicate CVE-2023-23397), 0 excluded.
    assert adapter.stats == IngestStats(duplicate_assets_collapsed=1, duplicate_findings_collapsed=1, excluded_assets={}, excluded_findings={})
    assert adapter.stats == hw_adapter.stats

    assert set(cfg_assets) == set(hw_assets)
    for asset_id, hw_asset in hw_assets.items():
        assert cfg_assets[asset_id] == hw_asset, asset_id
    # wks-it05's blank AssetValue -> criticality=3 plus a per-row not_collected
    # on that one asset only (the case that falsified one of the four
    # original design proposals -- see CLAUDE.md's own account of it).
    blank_asset_value_id = next(a.asset_id for a in hw_assets.values() if "criticality" in a.not_collected)
    assert "criticality" in cfg_assets[blank_asset_value_id].not_collected
    assert sum(1 for a in hw_assets.values() if "criticality" in a.not_collected) == 1

    assert len(cfg_findings) == len(hw_findings) == 9

    def key(f: Finding) -> tuple:
        return (f.asset_id, f.cve_id, f.product, f.version)

    cfg_by_key = {key(f): f for f in cfg_findings}
    hw_by_key = {key(f): f for f in hw_findings}
    assert set(cfg_by_key) == set(hw_by_key)
    for k, hw_finding in hw_by_key.items():
        cfg_finding = cfg_by_key[k]
        for field in FINDING_FIELDS:
            if field == "finding_id":
                # The declared divergence: MDVMC- vs MDVM- prefix. The digest
                # recipe itself is otherwise byte-identical (same columns,
                # same "\x1f" join, same hex_len/case), so only the prefix
                # may differ -- the hex SUFFIX must match exactly.
                assert cfg_finding.finding_id.startswith("MDVMC-")
                assert hw_finding.finding_id.startswith("MDVM-")
                assert cfg_finding.finding_id.split("-", 1)[1] == hw_finding.finding_id.split("-", 1)[1]
                continue
            assert getattr(cfg_finding, field) == getattr(hw_finding, field), f"{k}.{field}"


def test_configured_adapter_makes_no_network_call_for_a_provides_enrichment_source():
    """provides_enrichment mirrors BluePeakAdapter's own -- both True,
    driven by the same "enrichment block present" rule."""
    contract = _bluepeak_gen_contract()
    assert ConfiguredAdapter(contract).provides_enrichment is True
    assert get_adapter("bluepeak").provides_enrichment is True


def test_run_label_includes_the_contract_revision():
    contract = _bluepeak_gen_contract()
    adapter = ConfiguredAdapter(contract)
    assert adapter.run_label == f"bluepeak-gen@v{contract.version}"
    assert get_adapter("bluepeak").run_label == "bluepeak"  # unversioned built-in, unchanged


# =========================================================================
# Synthetic disposition matrix: BluePeak-shaped
# =========================================================================


def _load_configured_bluepeak(data_dir: Path):
    adapter = ConfiguredAdapter(_bluepeak_gen_contract())
    assets, findings = load_batch(data_dir, adapter)
    return assets, list(findings), adapter


def _load_bluepeak(data_dir: Path):
    adapter = BluePeakAdapter()
    assets, findings = load_batch(data_dir, adapter)
    return assets, list(findings), adapter


def test_blank_department_is_never_marked_not_collected_on_either(tmp_path):
    """Found by this differential, not assumed going in: bluepeak.py's real
    Department mapping is a plain pass-through (`(row.get("Department") or
    "").strip()`) with NO per-row not_collected tracking at all -- its
    not_collected is entirely the fixed ASSET_FIELDS_NEVER_EXPORTED set,
    unlike defender.py's genuinely per-row os_build/internet_exposed/
    criticality. bluepeak-gen's business_function mapping is `absent_fact`
    (not `gap`) precisely to match this -- a blank Department is a
    declared-but-empty fact, not a collection gap, on both."""
    rows = [
        bp_row(record_id="VULN-0001", asset_id="SRV-01", department=""),
        bp_row(record_id="VULN-0002", asset_id="SRV-02", cve="CVE-2099-10002", department="IT Operations"),
    ]
    data_dir_cfg = _bp_sample_dir(tmp_path / "cfg", rows)
    data_dir_hw = _bp_sample_dir(tmp_path / "hw", rows)

    cfg_assets, _cfg_findings, _ = _load_configured_bluepeak(data_dir_cfg)
    hw_assets, _hw_findings, _ = _load_bluepeak(data_dir_hw)

    for assets in (cfg_assets, hw_assets):
        assert "business_function" not in assets["SRV-01"].not_collected
        assert "business_function" not in assets["SRV-02"].not_collected
        assert assets["SRV-01"].business_function == ""
    assert cfg_assets["SRV-01"] == hw_assets["SRV-01"]
    assert cfg_assets["SRV-02"] == hw_assets["SRV-02"]


def test_unmapped_asset_type_excludes_on_both(tmp_path):
    rows = [
        bp_row(record_id="VULN-0001", asset_id="A1"),
        bp_row(record_id="VULN-0002", asset_id="A2", cve="CVE-2099-10002", asset_type="Mainframe"),
    ]
    data_dir_cfg = _bp_sample_dir(tmp_path / "cfg", rows)
    data_dir_hw = _bp_sample_dir(tmp_path / "hw", rows)

    cfg_adapter = ConfiguredAdapter(_bluepeak_gen_contract())
    cfg_assets, cfg_findings = load_batch(data_dir_cfg, cfg_adapter)
    list(cfg_findings)
    hw_adapter = BluePeakAdapter()
    hw_assets, hw_findings = load_batch(data_dir_hw, hw_adapter)
    list(hw_findings)

    assert set(cfg_assets) == set(hw_assets) == {"A1"}
    assert set(cfg_adapter.stats.excluded_assets) == set(hw_adapter.stats.excluded_assets) == {"A2"}
    assert set(cfg_adapter.stats.excluded_findings) == set(hw_adapter.stats.excluded_findings) == {"VULN-0002"}


def test_a_conflicting_asset_row_refuses_on_both(tmp_path):
    """Two rows, same Asset_ID, disagreeing on a non-union field, same
    Last_Observed -- no recency signal to prefer either. Both refuse."""
    rows = [
        bp_row(record_id="VULN-0001", asset_id="A1", criticality="High", last_observed="2026-09-01"),
        bp_row(record_id="VULN-0002", asset_id="A1", cve="CVE-2099-10002", criticality="Low", last_observed="2026-09-01"),
    ]
    data_dir_cfg = _bp_sample_dir(tmp_path / "cfg", rows)
    data_dir_hw = _bp_sample_dir(tmp_path / "hw", rows)

    with pytest.raises(AdapterError):
        load_batch(data_dir_cfg, ConfiguredAdapter(_bluepeak_gen_contract()))
    with pytest.raises(AdapterError):
        load_batch(data_dir_hw, get_adapter("bluepeak"))


def test_recency_resolves_a_conflicting_asset_row_on_both(tmp_path):
    rows = [
        bp_row(record_id="VULN-0001", asset_id="A1", criticality="High", last_observed="2026-09-01"),
        bp_row(record_id="VULN-0002", asset_id="A1", cve="CVE-2099-10002", criticality="Low", last_observed="2026-09-02"),
    ]
    data_dir_cfg = _bp_sample_dir(tmp_path / "cfg", rows)
    data_dir_hw = _bp_sample_dir(tmp_path / "hw", rows)

    cfg_assets, cfg_findings, cfg_adapter = _load_configured_bluepeak(data_dir_cfg)
    list(cfg_findings)
    hw_assets, hw_findings, hw_adapter = _load_bluepeak(data_dir_hw)
    list(hw_findings)

    assert cfg_assets["A1"].criticality == hw_assets["A1"].criticality == 2  # Low wins (later Last_Observed)
    assert cfg_adapter.stats.duplicate_assets_collapsed == hw_adapter.stats.duplicate_assets_collapsed == 1


def test_compensating_control_union_matches_on_both(tmp_path):
    rows = [
        bp_row(record_id="VULN-0001", asset_id="A1", compensating_control="Control B"),
        bp_row(record_id="VULN-0002", asset_id="A1", cve="CVE-2099-10002", compensating_control="Control A"),
    ]
    data_dir_cfg = _bp_sample_dir(tmp_path / "cfg", rows)
    data_dir_hw = _bp_sample_dir(tmp_path / "hw", rows)

    cfg_assets, cfg_findings, _ = _load_configured_bluepeak(data_dir_cfg)
    list(cfg_findings)
    hw_assets, hw_findings, _ = _load_bluepeak(data_dir_hw)
    list(hw_findings)

    assert cfg_assets["A1"].compensating_controls == hw_assets["A1"].compensating_controls == "Control A, Control B"


def test_duplicate_record_id_identical_content_collapses_on_both(tmp_path):
    row = bp_row(record_id="VULN-0001", asset_id="A1")
    data_dir_cfg = _bp_sample_dir(tmp_path / "cfg", [row, dict(row)])
    data_dir_hw = _bp_sample_dir(tmp_path / "hw", [row, dict(row)])

    _cfg_assets, cfg_findings, cfg_adapter = _load_configured_bluepeak(data_dir_cfg)
    _hw_assets, hw_findings, hw_adapter = _load_bluepeak(data_dir_hw)

    assert len(cfg_findings) == len(hw_findings) == 1
    assert cfg_adapter.stats.duplicate_findings_collapsed == hw_adapter.stats.duplicate_findings_collapsed == 1


def test_duplicate_record_id_conflicting_content_refuses_on_both(tmp_path):
    rows = [
        bp_row(record_id="VULN-0001", asset_id="A1", severity="Critical"),
        bp_row(record_id="VULN-0001", asset_id="A1", severity="Low"),
    ]
    data_dir_cfg = _bp_sample_dir(tmp_path / "cfg", rows)
    data_dir_hw = _bp_sample_dir(tmp_path / "hw", rows)

    with pytest.raises(AdapterError):
        _load_all(data_dir_cfg, ConfiguredAdapter(_bluepeak_gen_contract()))
    with pytest.raises(AdapterError):
        _load_all(data_dir_hw, get_adapter("bluepeak"))


def test_a_ragged_row_refuses_through_configured_adapter_too(tmp_path):
    """iter_csv_rows (ingest.py) is shared by every adapter, ConfiguredAdapter
    included -- confirms it actually goes through that path rather than
    reimplementing (and potentially missing) the same guard."""
    data_dir = _bp_sample_dir(tmp_path, [bp_row(record_id="VULN-0001", asset_id="A1")])
    path = data_dir / BP_FILENAME
    text = path.read_text(encoding="utf-8")
    path.write_text(text.rstrip("\n") + ",extra_stray_field\n", encoding="utf-8")
    with pytest.raises(IngestError, match="fields but the header"):
        load_batch(data_dir, ConfiguredAdapter(_bluepeak_gen_contract()))


# =========================================================================
# Synthetic disposition matrix: Defender-shaped
# =========================================================================


def _load_configured_mdvm(data_dir: Path):
    adapter = ConfiguredAdapter(_mdvm_gen_contract())
    assets, findings = load_batch(data_dir, adapter)
    return assets, list(findings), adapter


def _load_defender(data_dir: Path):
    adapter = DefenderAdapter()
    assets, findings = load_batch(data_dir, adapter)
    return assets, list(findings), adapter


def test_unrecognized_os_platform_excludes_via_role_forward_trace_on_both(tmp_path):
    """The load-bearing case for config_model.py's whole "no on_unmapped
    key" design: role comes from a `default_by` keyed to the `os_platform`
    derivation, so an unrecognized OSPlatform must exclude the asset, not
    refuse the batch -- exactly like defender.py's own direct `.exclude`
    call on the same condition."""
    devices = [def_device(device_id=DC), def_device(device_id=WEB, name="web", platform="macOS")]
    vulns = [def_vuln(device_id=DC)]
    data_dir_cfg = _def_sample_dir(tmp_path / "cfg", devices, vulns)
    data_dir_hw = _def_sample_dir(tmp_path / "hw", devices, vulns)

    cfg_assets, cfg_findings, cfg_adapter = _load_configured_mdvm(data_dir_cfg)
    hw_assets, hw_findings, hw_adapter = _load_defender(data_dir_hw)

    assert set(cfg_assets) == set(hw_assets) == {DC}
    assert set(cfg_adapter.stats.excluded_assets) == set(hw_adapter.stats.excluded_assets) == {WEB}
    assert "macOS" in cfg_adapter.stats.excluded_assets[WEB]


def test_blank_asset_value_becomes_a_per_row_gap_on_both(tmp_path):
    devices = [def_device(device_id=DC, asset_value="")]
    vulns = [def_vuln(device_id=DC)]
    data_dir_cfg = _def_sample_dir(tmp_path / "cfg", devices, vulns)
    data_dir_hw = _def_sample_dir(tmp_path / "hw", devices, vulns)

    cfg_assets, _cfg_findings, _ = _load_configured_mdvm(data_dir_cfg)
    hw_assets, _hw_findings, _ = _load_defender(data_dir_hw)

    assert cfg_assets[DC].criticality == hw_assets[DC].criticality == 3
    assert "criticality" in cfg_assets[DC].not_collected
    assert "criticality" in hw_assets[DC].not_collected


def test_recency_resolves_a_conflicting_device_row_on_both(tmp_path):
    devices = [
        def_device(device_id=DC, build="17763", timestamp="2026-08-30T02:00:00Z"),
        def_device(device_id=DC, build="17764", timestamp="2026-08-30T03:00:00Z"),
    ]
    vulns = [def_vuln(device_id=DC)]
    data_dir_cfg = _def_sample_dir(tmp_path / "cfg", devices, vulns)
    data_dir_hw = _def_sample_dir(tmp_path / "hw", devices, vulns)

    cfg_assets, _cfg_findings, cfg_adapter = _load_configured_mdvm(data_dir_cfg)
    hw_assets, _hw_findings, hw_adapter = _load_defender(data_dir_hw)

    assert cfg_assets[DC].os_build == hw_assets[DC].os_build == "17764"
    assert cfg_adapter.stats.duplicate_assets_collapsed == hw_adapter.stats.duplicate_assets_collapsed == 1


def test_duplicate_finding_identical_content_collapses_on_both(tmp_path):
    devices = [def_device(device_id=DC)]
    vuln = def_vuln(device_id=DC)
    data_dir_cfg = _def_sample_dir(tmp_path / "cfg", devices, [vuln, dict(vuln)])
    data_dir_hw = _def_sample_dir(tmp_path / "hw", devices, [vuln, dict(vuln)])

    _cfg_assets, cfg_findings, cfg_adapter = _load_configured_mdvm(data_dir_cfg)
    _hw_assets, hw_findings, hw_adapter = _load_defender(data_dir_hw)

    assert len(cfg_findings) == len(hw_findings) == 1
    assert cfg_adapter.stats.duplicate_findings_collapsed == hw_adapter.stats.duplicate_findings_collapsed == 1


def test_duplicate_finding_conflicting_content_refuses_on_both(tmp_path):
    devices = [def_device(device_id=DC)]
    vulns = [def_vuln(device_id=DC, severity="Critical"), def_vuln(device_id=DC, severity="Low")]
    data_dir_cfg = _def_sample_dir(tmp_path / "cfg", devices, vulns)
    data_dir_hw = _def_sample_dir(tmp_path / "hw", devices, vulns)

    with pytest.raises(AdapterError):
        _load_all(data_dir_cfg, ConfiguredAdapter(_mdvm_gen_contract()))
    with pytest.raises(AdapterError):
        _load_all(data_dir_hw, get_adapter("defender"))


def test_orphaned_finding_refuses_on_both(tmp_path):
    devices = [def_device(device_id=DC)]
    vulns = [def_vuln(device_id=WEB)]  # WEB never appears in devices.csv
    data_dir_cfg = _def_sample_dir(tmp_path / "cfg", devices, vulns)
    data_dir_hw = _def_sample_dir(tmp_path / "hw", devices, vulns)

    with pytest.raises(AdapterError, match="absent from"):
        _load_all(data_dir_cfg, ConfiguredAdapter(_mdvm_gen_contract()))
    with pytest.raises(AdapterError):
        _load_all(data_dir_hw, get_adapter("defender"))


def test_cascading_exclusion_matches_on_both(tmp_path):
    devices = [def_device(device_id=DC), def_device(device_id=WEB, name="web", platform="macOS")]
    vulns = [def_vuln(device_id=DC), def_vuln(device_id=WEB, cve="CVE-2021-1656")]
    data_dir_cfg = _def_sample_dir(tmp_path / "cfg", devices, vulns)
    data_dir_hw = _def_sample_dir(tmp_path / "hw", devices, vulns)

    cfg_assets, cfg_findings, cfg_adapter = _load_configured_mdvm(data_dir_cfg)
    hw_assets, hw_findings, hw_adapter = _load_defender(data_dir_hw)

    assert len(cfg_findings) == len(hw_findings) == 1
    assert "its asset" in next(iter(cfg_adapter.stats.excluded_findings.values()))
    assert "its asset" in next(iter(hw_adapter.stats.excluded_findings.values()))
