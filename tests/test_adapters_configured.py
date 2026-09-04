"""adapters/configured.py in isolation -- ConfiguredAdapter's own mechanics,
independent of whether they happen to match a hand-written adapter (that
comparison is test_adapters_configured_differential.py's job). Every test
here uses the real bluepeak-gen / mdvm-gen contracts (data/adapters/) as a
realistic mapping, but exercises a behavior neither committed real file
happens to trigger -- the header-validation gate, digest-based dedup
identity vs. content comparison, composed-template gating, derivation
caching, and instance-attribute shadowing."""

from __future__ import annotations

from pathlib import Path

import pytest

from rhinosecure.adapters.base import AdapterError, IngestAdapter
from rhinosecure.adapters.config_model import Contract, ContractValidationError
from rhinosecure.adapters.configured import ConfiguredAdapter, _render_composed
from rhinosecure.ingest import load_batch

from test_adapters_bluepeak import COLUMNS as BP_COLUMNS
from test_adapters_bluepeak import FILENAME as BP_FILENAME
from test_adapters_bluepeak import _row as bp_row
from test_adapters_bluepeak import _write as bp_write
from test_adapters_config_model import _confirmed, bluepeak_gen_dict, mdvm_gen_dict
from test_adapters_defender import DC
from test_adapters_defender import DEVICE_COLUMNS as DEF_DEVICE_COLUMNS
from test_adapters_defender import VULN_COLUMNS as DEF_VULN_COLUMNS
from test_adapters_defender import _device as def_device
from test_adapters_defender import _vuln as def_vuln
from test_adapters_defender import _write as def_write

DATA_ROOT = Path(__file__).resolve().parents[1] / "data"


def _bluepeak_gen() -> Contract:
    return Contract.model_validate(_confirmed(bluepeak_gen_dict()))


def _mdvm_gen() -> Contract:
    return Contract.model_validate(_confirmed(mdvm_gen_dict()))


def _bp_dir(tmp_path: Path, rows: list[dict]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    bp_write(tmp_path / BP_FILENAME, rows)
    return tmp_path


def _def_dir(tmp_path: Path, devices: list[dict], vulns: list[dict]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    def_write(tmp_path / "devices.csv", DEF_DEVICE_COLUMNS, devices)
    def_write(tmp_path / "vulnerabilities.csv", DEF_VULN_COLUMNS, vulns)
    return tmp_path


# --- construction and instance-attribute shadowing -----------------------


def test_is_an_ingest_adapter_with_instance_attributes_not_classvars():
    contract = _bluepeak_gen()
    adapter = ConfiguredAdapter(contract)
    assert isinstance(adapter, IngestAdapter)
    assert adapter.format == "bluepeak-gen"
    assert adapter.assets_filename == adapter.findings_filename == "synthetic_cve_inventory_50.csv"
    assert adapter.provides_enrichment is True
    # These are set per-instance, not shared across a second instance built
    # from a different contract -- proves they shadow the base ClassVars
    # rather than mutating them.
    other = ConfiguredAdapter(_mdvm_gen())
    assert other.format == "mdvm-gen"
    assert adapter.format == "bluepeak-gen"  # unchanged by constructing `other`


def test_run_label_includes_revision_and_updates_with_version():
    contract = _bluepeak_gen()
    assert ConfiguredAdapter(contract).run_label == f"bluepeak-gen@v{contract.version}"
    bumped = contract.model_copy(update={"version": contract.version + 1})
    assert ConfiguredAdapter(bumped).run_label == f"bluepeak-gen@v{contract.version + 1}"


def test_provides_enrichment_false_when_no_enrichment_block():
    contract = _mdvm_gen()
    assert contract.enrichment is None
    assert ConfiguredAdapter(contract).provides_enrichment is False


# --- header validation gate ------------------------------------------------


def test_load_assets_validates_the_real_header_before_reading_any_row(tmp_path):
    """A column the contract maps that the real file doesn't have at all
    must be caught by validate_contract, not surface as a KeyError deep in
    row processing."""
    rows = [bp_row(record_id="VULN-0001", asset_id="A1")]
    data_dir = _bp_dir(tmp_path, rows)
    # Drop a column the contract requires by rewriting with a narrower set.
    narrowed = [c for c in BP_COLUMNS if c != "Department"]
    bp_write(data_dir / BP_FILENAME, rows, columns=narrowed)
    with pytest.raises(ContractValidationError, match="Department"):
        load_batch(data_dir, ConfiguredAdapter(_bluepeak_gen()))


def test_load_assets_refuses_a_renamed_column(tmp_path):
    rows = [bp_row(record_id="VULN-0001", asset_id="A1")]
    data_dir = _bp_dir(tmp_path, rows)
    text = (data_dir / BP_FILENAME).read_text(encoding="utf-8")
    (data_dir / BP_FILENAME).write_text(text.replace("Asset_ID", "AssetId"), encoding="utf-8")
    with pytest.raises(ContractValidationError):
        load_batch(data_dir, ConfiguredAdapter(_bluepeak_gen()))


# --- mapping-kind mechanics, exercised directly ---------------------------


def test_not_collected_kind_resolves_to_the_documented_default_regardless_of_the_row(tmp_path):
    contract = _mdvm_gen()
    assert contract.asset["business_function"].kind == "not_collected"
    devices = [def_device(device_id=DC)]
    vulns = [def_vuln(device_id=DC)]
    data_dir = _def_dir(tmp_path, devices, vulns)
    assets, findings = load_batch(data_dir, ConfiguredAdapter(contract))
    list(findings)
    asset = assets[DC]
    assert asset.business_function == ""
    assert "business_function" in asset.not_collected
    # not_collected values come from NOT_COLLECTED_DEFAULTS regardless of
    # anything in the row -- confirmed end to end via the differential
    # suite; here we just confirm the contract shape itself.


def test_composed_template_gate_and_fallback_render_directly():
    """_render_composed exercised directly against both real contracts'
    evidence blocks with hand-built rows, independent of any CSV I/O --
    the fastest way to pin the gating semantics (required_non_blank,
    fallback_template, emit_if_any) precisely."""
    contract = _mdvm_gen()
    evidence_mapping = contract.finding["evidence"]

    both_present = {
        "SoftwareVendor": "microsoft", "SoftwareName": "windows_server_2019", "SoftwareVersion": "10.0",
        "RecommendedSecurityUpdate": "August 2020", "RecommendedSecurityUpdateId": "4565349",
        "DiskPaths": "", "RegistryPaths": "",
    }
    assert _render_composed(evidence_mapping, both_present) == (
        "Defender MDVM: microsoft windows_server_2019 10.0; "
        "recommended update: August 2020 (4565349)"
    )

    id_blank_update_present = dict(both_present, RecommendedSecurityUpdateId="")
    assert _render_composed(evidence_mapping, id_blank_update_present) == (
        "Defender MDVM: microsoft windows_server_2019 10.0; recommended update: August 2020"
    )

    both_blank = dict(both_present, RecommendedSecurityUpdate="", RecommendedSecurityUpdateId="")
    assert _render_composed(evidence_mapping, both_blank) == "Defender MDVM: microsoft windows_server_2019 10.0"

    with_disk = dict(both_blank, DiskPaths="C:\\malware.exe")
    assert _render_composed(evidence_mapping, with_disk) == (
        "Defender MDVM: microsoft windows_server_2019 10.0; disk: C:\\malware.exe"
    )


def test_composed_always_emits_the_first_bluepeak_part_even_with_blank_detection_source():
    contract = _bluepeak_gen()
    evidence_mapping = contract.finding["evidence"]
    row = {
        "Asset_Type": "Server", "Detection_Source": "", "Vulnerability_Description": "A bug.",
        "Exploit_Maturity": "", "Business_Impact": "", "Assigned_Team": "",
    }
    assert _render_composed(evidence_mapping, row) == "[Server] A bug."


def test_role_forward_trace_identifies_the_correct_check_for_each_contract():
    assert _bluepeak_gen().asset["role"].kind == "vocabulary"
    assert ConfiguredAdapter(_bluepeak_gen())._role_reference() == ("vocabulary", "role")
    assert _mdvm_gen().asset["role"].kind == "default_by"
    assert ConfiguredAdapter(_mdvm_gen())._role_reference() == ("derivation", "os_platform")


# --- finding identity vs. content: the bug this file most wants to pin ---


def test_finding_dedup_identity_is_the_full_digest_not_the_content_tuple(tmp_path):
    """The bug slice 2 actually shipped with once, caught by the real-data
    differential (severity+date collisions collapsed unrelated findings on
    Defender's small 10-row sample): two findings on the SAME device with
    DIFFERENT CVEs but the SAME scanner_severity/detected_date must both
    survive, not collapse into one just because their `content_targets`
    tuple happens to match."""
    devices = [def_device(device_id=DC)]
    vulns = [
        def_vuln(device_id=DC, cve="CVE-2020-1472", severity="Critical"),
        def_vuln(device_id=DC, cve="CVE-2021-1656", severity="Critical"),  # same severity, no FirstSeenTimestamp -> same content tuple
    ]
    data_dir = _def_dir(tmp_path, devices, vulns)
    _assets, findings = load_batch(data_dir, ConfiguredAdapter(_mdvm_gen()))
    findings = list(findings)
    assert len(findings) == 2
    assert {f.finding.cve_id for f in findings} == {"CVE-2020-1472", "CVE-2021-1656"}


def test_a_truncation_collision_is_reported_distinctly_from_a_content_conflict(tmp_path):
    """Two rows with genuinely different identities (different CveId) that
    happen to truncate to the same rendered finding_id are a COLLISION
    ("collides" in the message, pointing at the recipe) rather than being
    silently merged as a duplicate or flagged as a content conflict.

    mdvm-gen's own hex_len is 16 (64 bits) -- not brute-forceable in a test
    run. This narrows JUST hex_len to 8 (config_model.py's own `Field(ge=8)`
    floor) on a copy of the real contract, changing nothing else about the
    recipe. These two specific CVE ids are a REAL sha256 collision on the
    first 8 hex characters of the full identity string (DeviceId/vendor/
    name/version held fixed, matching def_vuln's own defaults) -- found
    once by brute-force search, then pinned here as a fixed fixture rather
    than re-searched on every test run."""
    contract = _mdvm_gen()
    narrowed = contract.finding["finding_id"].model_copy(update={"hex_len": 8})
    # review=None resets the digests too -- otherwise V19 (config_model.py's
    # validate_contract) would refuse this modified copy for a stale-digest
    # mismatch before the test ever reaches the collision it's checking for.
    contract = contract.model_copy(
        update={"finding": {**contract.finding, "finding_id": narrowed}, "review": type(contract.review)()}
    )
    devices = [def_device(device_id=DC)]
    vulns = [def_vuln(device_id=DC, cve="CVE-2020-11429"), def_vuln(device_id=DC, cve="CVE-2020-13776")]
    data_dir = _def_dir(tmp_path, devices, vulns)
    with pytest.raises(AdapterError, match="collides"):
        _assets, findings = load_batch(data_dir, ConfiguredAdapter(contract))
        list(findings)
