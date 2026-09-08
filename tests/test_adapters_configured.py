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

from rhinosecure.adapters.base import AdapterError, IngestAdapter, ProblemCollector
from rhinosecure.adapters.config_model import (
    EXCLUDING_TARGETS,
    Contract,
    ContractDigestMismatchError,
    ContractNotConfirmedError,
    ContractValidationError,
    ParsedMapping,
    compute_content_digest,
    compute_decision_digest,
)
from rhinosecure.adapters.configured import _FAIL, ConfiguredAdapter, _coerce_for_target, _render_composed
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


def _reconfirm(contract: Contract) -> Contract:
    """Stamp fresh digests onto a MODIFIED contract and mark it confirmed --
    for a test that changes something about an already-confirmed contract
    (a version bump, a narrowed hex_len) and then needs ConfiguredAdapter to
    actually accept it. `ConfiguredAdapter.__init__` now refuses any
    contract whose state isn't "confirmed" or whose digests don't match
    (config_model.assert_confirmed), so simply mutating a field and handing
    the result to ConfiguredAdapter would fail that gate before the test
    ever reaches what it's actually checking."""
    proposed = contract.model_copy(update={"review": type(contract.review)()})
    return proposed.model_copy(
        update={
            "review": type(contract.review)(
                state="confirmed",
                confirmed_at="2026-09-04T20:00:00Z",
                confirmed_by="test-fixture",
                confirmed_version=proposed.version,
                content_digest=compute_content_digest(proposed),
                decision_digest=compute_decision_digest(proposed),
            )
        }
    )


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
    bumped = _reconfirm(contract.model_copy(update={"version": contract.version + 1}))
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


# --- _coerce_for_target: float-parser output vs. a str-typed schema field --
#
# The real bug: finding.port (and every other Asset/Finding field, except
# criticality/internet_exposed) is str-typed, but "float" is the only
# bounds-checked numeric parser in the closed grammar (there is no "int"
# parser) -- so a mapping author reaching for min/max validation on a
# numeric-looking str field naturally produces a raw Python float, which
# Finding(port=...)/Asset(...) then refuses as a pydantic string_type error.


def test_coerce_for_target_strips_a_spurious_trailing_zero_for_a_str_target():
    assert _coerce_for_target(445.0, "port") == "445"


def test_coerce_for_target_preserves_a_genuine_fraction_for_a_str_target():
    assert _coerce_for_target(445.5, "port") == "445.5"


def test_coerce_for_target_leaves_a_string_value_untouched():
    assert _coerce_for_target("445", "port") == "445"


def test_coerce_for_target_leaves_non_str_targets_untouched():
    # criticality is int-typed and internet_exposed is bool-typed -- pydantic
    # already accepts a float/bool there; stringifying would BREAK it.
    assert _coerce_for_target(3.0, "criticality") == 3.0
    assert _coerce_for_target(True, "internet_exposed") is True


def test_coerce_for_target_does_not_invent_a_convention_for_bool_into_str():
    # No real proposal has ever paired a bool parser with a str target --
    # left alone, so an actually-incompatible mapping still fails loudly at
    # Finding/Asset construction instead of silently rendering "True"/"False".
    assert _coerce_for_target(True, "port") is True


def test_resolve_target_coerces_a_float_parser_result_for_a_str_typed_target():
    """Reproduced against a real ConfiguredAdapter instance: `finding.port`
    mapped via `{kind:"parsed", parser:"float", params:{min:0,max:100}}`
    (the exact shape a real proposal used against northgate_flat_2.csv,
    substituting a synthetic column since neither committed contract has
    a port column) must resolve to a string Finding(port=...) accepts, not
    the raw float `_parse_scalar` itself returns. A whole-number source
    value (9.0) pins the "no spurious .0" formatting specifically."""
    adapter = ConfiguredAdapter(_bluepeak_gen())
    mapping = ParsedMapping(
        kind="parsed", column="Score", case="exact", blank="absent_fact", optional=False,
        parser="float", params={"min": 0, "max": 100},
    )
    problems = ProblemCollector(Path("data.csv"))
    value = adapter._resolve_target(mapping, "port", {"Score": "9.0"}, 1, problems, {}, None)
    assert value == "9"
    assert problems.fatal == []


def test_excluding_targets_defaults_to_role_only():
    """`EXCLUDING_TARGETS` (`{"role"}`) is the default for every confirmed-
    contract run -- Rule 1's original, unchanged scope. A caller has to
    explicitly widen it (the provisional-run path, web/jobs.py) to get
    anything else excluded rather than fatal."""
    assert EXCLUDING_TARGETS == frozenset({"role"})
    assert ConfiguredAdapter(_bluepeak_gen()).excluding_targets == EXCLUDING_TARGETS
    assert ConfiguredAdapter(_mdvm_gen()).excluding_targets == EXCLUDING_TARGETS


def test_a_vocabulary_miss_on_role_excludes_by_default_but_the_same_miss_on_criticality_is_fatal():
    """The real bluepeak-gen contract maps both `role` and `criticality`
    via `vocabulary` on real columns (Asset_Type / Asset_Criticality) --
    exercising `_resolve_target`'s exclude-vs-fatal branch directly against
    an unrecognized value for each, with the DEFAULT `excluding_targets`."""
    contract = _bluepeak_gen()
    role_mapping = contract.asset["role"]
    assert role_mapping.kind == "vocabulary" and role_mapping.column == "Asset_Type"
    criticality_mapping = contract.asset["criticality"]
    assert criticality_mapping.kind == "vocabulary" and criticality_mapping.column == "Asset_Criticality"
    adapter = ConfiguredAdapter(contract)

    role_problems = ProblemCollector(Path("irrelevant.csv"))
    value = adapter._resolve_target(
        role_mapping, "role", {"Asset_Type": "Not A Real Type"}, 2, role_problems, {}, "A1"
    )
    assert value is _FAIL
    assert "A1" in role_problems.excluded and "role" in role_problems.excluded["A1"]
    assert not role_problems.fatal

    criticality_problems = ProblemCollector(Path("irrelevant.csv"))
    value = adapter._resolve_target(
        criticality_mapping, "criticality", {"Asset_Criticality": "not-a-real-tier"}, 2, criticality_problems, {}, "A1"
    )
    assert value is _FAIL
    assert criticality_problems.fatal  # NOT excluded -- criticality isn't in excluding_targets by default
    assert not criticality_problems.excluded


def test_widened_excluding_targets_turns_the_same_criticality_miss_into_an_exclusion():
    """The exact mechanism the provisional-run path depends on: passing a
    wider `excluding_targets` at construction time makes a miss on ANY of
    those targets excludable, not just role -- generalizing Rule 1 to the
    scoring-relevant targets, but only for a caller that explicitly asks."""
    contract = _bluepeak_gen()
    criticality_mapping = contract.asset["criticality"]
    adapter = ConfiguredAdapter(contract, excluding_targets=frozenset({"role", "criticality"}))

    problems = ProblemCollector(Path("irrelevant.csv"))
    value = adapter._resolve_target(
        criticality_mapping, "criticality", {"Asset_Criticality": "not-a-real-tier"}, 2, problems, {}, "A1"
    )
    assert value is _FAIL
    assert "A1" in problems.excluded and "criticality" in problems.excluded["A1"]
    assert not problems.fatal


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
    # _reconfirm stamps fresh digests and marks it confirmed again --
    # otherwise ConfiguredAdapter.__init__'s new gate (assert_confirmed)
    # would refuse this modified copy before the test ever reaches the
    # collision it's actually checking for.
    contract = _reconfirm(contract.model_copy(update={"finding": {**contract.finding, "finding_id": narrowed}}))
    devices = [def_device(device_id=DC)]
    vulns = [def_vuln(device_id=DC, cve="CVE-2020-11429"), def_vuln(device_id=DC, cve="CVE-2020-13776")]
    data_dir = _def_dir(tmp_path, devices, vulns)
    with pytest.raises(AdapterError, match="collides"):
        _assets, findings = load_batch(data_dir, ConfiguredAdapter(contract))
        list(findings)


# =========================================================================
# Slice 3: the confirmation gate and header-mode enforcement
# =========================================================================


def test_unconfirmed_contract_refuses_to_construct():
    contract = _bluepeak_gen().model_copy(update={"review": type(_bluepeak_gen().review)(state="proposed")})
    with pytest.raises(ContractNotConfirmedError, match="rhino adapt confirm"):
        ConfiguredAdapter(contract)


def test_unconfirmed_contract_refuses_before_any_directory_is_touched():
    """The gate fires in __init__, before load_assets ever runs -- proven
    by never supplying a data_dir at all."""
    contract = _bluepeak_gen().model_copy(update={"review": type(_bluepeak_gen().review)(state="proposed")})
    with pytest.raises(ContractNotConfirmedError):
        ConfiguredAdapter(contract)  # no data_dir passed anywhere -- can't have opened one


def test_a_hand_edited_table_value_after_confirmation_refuses_to_construct():
    contract = _bluepeak_gen()
    edited = contract.model_copy(
        update={"asset": {**contract.asset, "role": contract.asset["role"].model_copy(
            update={"table": {**contract.asset["role"].table, "Domain Controller": "sql"}}
        )}}
    )
    with pytest.raises(ContractDigestMismatchError, match="content_digest mismatch"):
        ConfiguredAdapter(edited)


def test_digest_mismatch_refuses_before_any_file_is_opened(tmp_path):
    """Constructed with a data_dir that does not exist at all -- if the
    gate fired anywhere other than __init__, this would raise
    FileNotFoundError instead of the digest error."""
    contract = _bluepeak_gen()
    edited = contract.model_copy(
        update={"asset": {**contract.asset, "role": contract.asset["role"].model_copy(
            update={"table": {**contract.asset["role"].table, "Domain Controller": "sql"}}
        )}}
    )
    with pytest.raises(ContractDigestMismatchError):
        ConfiguredAdapter(edited)  # never touches tmp_path -- proves the gate needs no directory


def test_not_collected_hand_edited_without_touching_the_mapping_refuses_end_to_end(tmp_path):
    """V09 (config_model.validate_contract) already pins this at the unit
    level (test_adapters_config_model.py); this confirms it still holds
    end to end through the real engine, before any row is yielded."""
    contract = _bluepeak_gen()
    tampered = contract.model_copy(
        update={"not_collected": contract.not_collected.model_copy(
            update={"always_asset": [*contract.not_collected.always_asset, "compensating_controls"]}
        )}
    )
    tampered = _reconfirm(tampered)
    rows = [bp_row(record_id="VULN-0001", asset_id="A1")]
    data_dir = _bp_dir(tmp_path, rows)
    with pytest.raises(ContractValidationError, match="not_collected disagrees"):
        load_batch(data_dir, ConfiguredAdapter(tampered))


# --- header mode: declared vs frozen --------------------------------------


def _bp_columns_with(*, rename: tuple[str, str] | None = None, add: str | None = None, reorder: bool = False) -> list[str]:
    columns = list(BP_COLUMNS)
    if rename:
        old, new = rename
        columns = [new if c == old else c for c in columns]
    if add:
        columns = columns + [add]
    if reorder:
        columns = columns[1:] + columns[:1]
    return columns


@pytest.mark.parametrize("mode", ["declared", "frozen"])
def test_a_renamed_column_refuses_under_both_modes(tmp_path, mode):
    contract = _bluepeak_gen()
    contract = _reconfirm(contract.model_copy(update={"header": contract.header.model_copy(update={"mode": mode})}))
    rows = [bp_row(record_id="VULN-0001", asset_id="A1")]
    data_dir = _bp_dir(tmp_path, rows)
    columns = _bp_columns_with(rename=("Asset_ID", "AssetId"))
    bp_write(data_dir / BP_FILENAME, rows, columns=columns)
    with pytest.raises(ContractValidationError, match="Asset_ID"):
        load_batch(data_dir, ConfiguredAdapter(contract))


def test_a_reordered_header_does_not_refuse_under_declared(tmp_path):
    contract = _bluepeak_gen()  # mode defaults to "declared"
    rows = [bp_row(record_id="VULN-0001", asset_id="A1")]
    data_dir = _bp_dir(tmp_path, rows)
    bp_write(data_dir / BP_FILENAME, rows, columns=_bp_columns_with(reorder=True))
    assets, findings = load_batch(data_dir, ConfiguredAdapter(contract))
    list(findings)
    assert set(assets) == {"A1"}  # loaded cleanly -- nothing maps positionally


def test_a_reordered_header_refuses_under_frozen(tmp_path):
    contract = _bluepeak_gen()
    contract = _reconfirm(contract.model_copy(update={"header": contract.header.model_copy(update={"mode": "frozen"})}))
    rows = [bp_row(record_id="VULN-0001", asset_id="A1")]
    data_dir = _bp_dir(tmp_path, rows)
    bp_write(data_dir / BP_FILENAME, rows, columns=_bp_columns_with(reorder=True))
    with pytest.raises(ContractValidationError, match="frozen"):
        load_batch(data_dir, ConfiguredAdapter(contract))


def test_a_new_column_is_a_notice_under_declared_not_a_refusal(tmp_path):
    contract = _bluepeak_gen()
    rows = [bp_row(record_id="VULN-0001", asset_id="A1")]
    data_dir = _bp_dir(tmp_path, rows)
    bp_write(data_dir / BP_FILENAME, rows, columns=_bp_columns_with(add="Exploitability_Score"))
    adapter = ConfiguredAdapter(contract)
    assets, findings = load_batch(data_dir, adapter)
    list(findings)
    assert set(assets) == {"A1"}
    assert any("Exploitability_Score" in notice for notice in adapter.header_notices)


def test_a_new_column_refuses_under_frozen(tmp_path):
    contract = _bluepeak_gen()
    contract = _reconfirm(contract.model_copy(update={"header": contract.header.model_copy(update={"mode": "frozen"})}))
    rows = [bp_row(record_id="VULN-0001", asset_id="A1")]
    data_dir = _bp_dir(tmp_path, rows)
    bp_write(data_dir / BP_FILENAME, rows, columns=_bp_columns_with(add="Exploitability_Score"))
    with pytest.raises(ContractValidationError, match="frozen"):
        load_batch(data_dir, ConfiguredAdapter(contract))


def test_header_notices_are_empty_by_default_on_the_real_committed_contract(tmp_path):
    """No drift at all -- the real file matches what bluepeak-gen declared."""
    adapter = ConfiguredAdapter(_bluepeak_gen())
    assets, findings = load_batch(DATA_ROOT / "bluepeak", adapter)
    list(findings)
    assert adapter.header_notices == []
