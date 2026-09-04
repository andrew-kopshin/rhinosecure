"""adapters/defender.py against synthetic Defender-format samples only --
there is no real export to test against, and CLAUDE.md Section 1 says no
component may assume its input is synthetic, so every test here writes
its own DeviceInfo / DeviceTvmSoftwareVulnerabilities-shaped CSV into
tmp_path with the tables' real column names and checks the adapter's
documented behavior on it: the column mapping, the `not_collected`
representation of fields Defender has no concept of, and the refusal
policy for each messy reality (missing columns and cells, orphaned
findings, duplicate and conflicting rows, non-Windows devices, non-CVE
ids)."""

from __future__ import annotations

import csv
import inspect
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from rhinosecure.adapters import get_adapter
from rhinosecure.adapters.base import NOT_COLLECTED_DEFAULTS, AdapterError
from rhinosecure.adapters.defender import (
    ASSET_FIELDS_NEVER_EXPORTED,
    FINDING_FIELDS_NEVER_EXPORTED,
    OS_PLATFORMS,
    DefenderAdapter,
)
from rhinosecure.ingest import IngestError, load_batch
from rhinosecure.scoring import Bucket

# Synthetic 40-hex DeviceIds, the shape Defender actually emits.
DC = "1a" * 20
WEB = "2b" * 20
WKS = "3c" * 20
GHOST = "9f" * 20  # never in the inventory

DEVICE_COLUMNS = [
    "Timestamp", "DeviceId", "DeviceName", "OSPlatform", "OSBuild", "OSVersion",
    "IsInternetFacing", "AssetValue", "ExposureLevel", "MachineGroup",
]
VULN_COLUMNS = [
    "DeviceId", "DeviceName", "OSPlatform", "OSVersion", "OSArchitecture", "SoftwareVendor",
    "SoftwareName", "SoftwareVersion", "CveId", "VulnerabilitySeverityLevel",
    "RecommendedSecurityUpdate", "RecommendedSecurityUpdateId", "CveTags",
]


def _device(
    device_id=DC, name="dc01.corp.example.com", platform="WindowsServer2019", build="17763",
    internet_facing="false", asset_value="High", timestamp="2026-08-30T02:10:44.1234567Z",
):
    return {
        "Timestamp": timestamp, "DeviceId": device_id, "DeviceName": name, "OSPlatform": platform,
        "OSBuild": build, "OSVersion": "1809", "IsInternetFacing": internet_facing,
        "AssetValue": asset_value, "ExposureLevel": "High", "MachineGroup": "Servers",
    }


def _vuln(
    device_id=DC, cve="CVE-2020-1472", severity="Critical", vendor="microsoft",
    name="windows_server_2019", version="10.0.17763.1339", update="August 2020 Security Updates",
    update_id="4565349", **extra,
):
    row = {
        "DeviceId": device_id, "DeviceName": "dc01.corp.example.com", "OSPlatform": "WindowsServer2019",
        "OSVersion": "1809", "OSArchitecture": "x64", "SoftwareVendor": vendor, "SoftwareName": name,
        "SoftwareVersion": version, "CveId": cve, "VulnerabilitySeverityLevel": severity,
        "RecommendedSecurityUpdate": update, "RecommendedSecurityUpdateId": update_id, "CveTags": "[]",
    }
    row.update(extra)
    return row


def _write(path: Path, columns: list[str], rows: list[dict], *, encoding="utf-8") -> Path:
    with path.open("w", newline="", encoding=encoding) as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in columns})
    return path


def _sample_dir(tmp_path: Path, devices: list[dict], vulns: list[dict], *, device_columns=None, vuln_columns=None) -> Path:
    _write(tmp_path / "devices.csv", device_columns or DEVICE_COLUMNS, devices)
    _write(tmp_path / "vulnerabilities.csv", vuln_columns or VULN_COLUMNS, vulns)
    return tmp_path


def _assets(tmp_path: Path, devices: list[dict], **kw) -> list:
    adapter = DefenderAdapter()
    path = _write(tmp_path / "devices.csv", kw.get("columns", DEVICE_COLUMNS), devices, encoding=kw.get("encoding", "utf-8"))
    return list(adapter.load_assets(path)), adapter


def _findings(tmp_path: Path, vulns: list[dict], asset_ids=(DC, WEB, WKS), *, columns=None) -> tuple[list, DefenderAdapter]:
    adapter = DefenderAdapter()
    path = _write(tmp_path / "vulnerabilities.csv", columns or VULN_COLUMNS, vulns)
    return list(adapter.load_findings(path, set(asset_ids))), adapter


# --- assets: the DeviceInfo mapping -------------------------------------------


def test_maps_deviceinfo_columns_onto_asset(tmp_path):
    assets, _ = _assets(tmp_path, [
        _device(),
        _device(device_id=WKS, name="wks-fin12.corp.example.com", platform="Windows11", build="22631",
                internet_facing="true", asset_value="Normal"),
    ])
    server, client = assets

    assert server.asset_id == DC
    assert server.hostname == "dc01.corp.example.com"
    assert server.os == "Windows Server 2019"
    assert server.os_build == "17763"
    assert server.criticality == 5  # AssetValue High
    assert server.internet_exposed is False
    assert client.os == "Windows 11"
    assert client.criticality == 3  # AssetValue Normal
    assert client.internet_exposed is True


def test_fields_defender_has_no_concept_of_get_defaults_and_are_marked_not_collected(tmp_path):
    """The representation decision (adapters/base.py): the value is the
    schema's absent encoding or the documented modal default, and the
    field name is in not_collected -- never a sentinel in the value."""
    assets, _ = _assets(tmp_path, [_device(), _device(device_id=WKS, name="wks", platform="Windows10")])
    server, client = assets

    for asset in (server, client):
        assert asset.not_collected == ASSET_FIELDS_NEVER_EXPORTED  # no per-row extras on complete rows
        assert asset.patch_window == "" and not asset.has_patch_window
        assert asset.compensating_controls == "" and asset.compensating_control_list == ()
        assert asset.patch_restrictions == "" and asset.business_function == "" and asset.owner == ""
        assert asset.environment == NOT_COLLECTED_DEFAULTS["environment"] == "prod"
        assert asset.data_sensitivity == NOT_COLLECTED_DEFAULTS["data_sensitivity"] == "internal"
    # role is defaulted by OS class, and marked either way
    assert server.role == "file"
    assert client.role == "workstation"
    assert "role" in server.not_collected and "role" in client.not_collected


def test_blank_cells_in_mapped_columns_become_defaults_and_are_marked_per_row(tmp_path):
    assets, _ = _assets(tmp_path, [_device(build="", internet_facing="", asset_value="")])
    (asset,) = assets

    assert asset.os_build == ""
    assert asset.internet_exposed is False
    assert asset.criticality == 3
    assert {"os_build", "internet_exposed", "criticality"} <= asset.not_collected
    assert asset.not_collected == ASSET_FIELDS_NEVER_EXPORTED | {"os_build", "internet_exposed", "criticality"}


def test_asset_value_maps_ends_to_ends_onto_criticality(tmp_path):
    assets, _ = _assets(tmp_path, [
        _device(device_id=DC, asset_value="Low"),
        _device(device_id=WEB, name="web", asset_value="Normal"),
        _device(device_id=WKS, name="wks", asset_value="high"),  # case-insensitive
    ])
    assert [a.criticality for a in assets] == [1, 3, 5]
    assert all("criticality" not in a.not_collected for a in assets)


def test_every_os_platform_in_the_table_maps_to_a_windows_os_string(tmp_path):
    rows = [
        _device(device_id=f"{i:02x}" * 20, name=f"h{i}", platform=platform)
        for i, platform in enumerate(OS_PLATFORMS)
    ]
    assets, _ = _assets(tmp_path, rows)
    assert [a.os for a in assets] == [OS_PLATFORMS[p][0] for p in OS_PLATFORMS]
    assert all(a.os.startswith("Windows") for a in assets)


def test_bom_prefixed_export_is_tolerated(tmp_path):
    """Excel and PowerShell both write a UTF-8 BOM; without utf-8-sig the
    first header would read as '\\ufeffTimestamp' and DeviceId would
    still be found -- but a BOM on a file whose first column is DeviceId
    would not, so the tolerance is checked with DeviceId first."""
    columns = ["DeviceId"] + [c for c in DEVICE_COLUMNS if c != "DeviceId"]
    assets, _ = _assets(tmp_path, [_device()], columns=columns, encoding="utf-8-sig")
    assert assets[0].asset_id == DC


# --- assets: refusals -------------------------------------------------------------


def test_missing_required_column_is_refused_at_the_header_listing_found_columns(tmp_path):
    """A portal-grid export uses display names ('Device name'); it must
    fail as 'not this export', not as 40 rows of blank identity."""
    columns = ["Device name", "Device ID", "OS platform", "OS build", "Internet facing", "Device value"]
    path = _write(tmp_path / "devices.csv", columns, [{"Device name": "dc01", "Device ID": DC}])
    with pytest.raises(AdapterError) as excinfo:
        list(DefenderAdapter().load_assets(path))
    message = str(excinfo.value)
    assert "not a DeviceInfo export" in message
    assert "'DeviceId'" in message and "'OSPlatform'" in message  # what is missing
    assert "'Device name'" in message  # what was found instead


def test_non_windows_platforms_are_excluded_not_fatal(tmp_path):
    """Scope boundary, not data quality (adapters/base.py's "Two kinds of
    refusal"): the Windows device still loads and scores; the two
    non-Windows ones are skipped and recorded, not fatal to the batch."""
    assets, adapter = _assets(tmp_path, [
        _device(),
        _device(device_id=WEB, name="mac01.corp.example.com", platform="macOS"),
        _device(device_id=WKS, name="lnx01.corp.example.com", platform="Linux"),
    ])
    assert [a.asset_id for a in assets] == [DC]
    assert set(adapter.stats.excluded_assets) == {WEB, WKS}
    assert "'macOS'" in adapter.stats.excluded_assets[WEB]
    assert "'Linux'" in adapter.stats.excluded_assets[WKS]
    assert "is not a Windows platform this adapter maps" in adapter.stats.excluded_assets[WEB]


def test_blank_identity_cell_is_fatal_not_a_gap(tmp_path):
    with pytest.raises(AdapterError, match=r"blank identity column\(s\) \['DeviceName'\]"):
        _assets(tmp_path, [_device(name="")])


def test_unparseable_boolean_or_asset_value_is_refused_not_coerced(tmp_path):
    with pytest.raises(AdapterError) as excinfo:
        _assets(tmp_path, [
            _device(internet_facing="maybe"),
            _device(device_id=WEB, name="web", asset_value="Critical"),
        ])
    message = str(excinfo.value)
    assert "IsInternetFacing 'maybe' is not a boolean" in message
    assert "AssetValue 'Critical' is not one of" in message


def test_repeated_device_rows_collapse_to_the_latest_timestamp(tmp_path):
    """DeviceInfo is a per-report snapshot table: an unsummarized export
    carries several rows per device. Latest Timestamp wins -- Microsoft's
    own sample query does exactly arg_max(Timestamp, *) by DeviceId."""
    assets, adapter = _assets(tmp_path, [
        _device(build="19044", timestamp="2026-08-29T23:59:59.0000000Z"),
        _device(device_id=WEB, name="web"),
        _device(build="19045", timestamp="2026-08-30T03:00:00.0000000Z"),  # newer report, later in file
        _device(build="19043", timestamp="2026-08-28T00:00:00Z"),  # older report, even later in file
    ])
    assert [a.asset_id for a in assets] == [DC, WEB]  # first-appearance order kept
    assert assets[0].os_build == "19045"
    assert adapter.stats.duplicate_assets_collapsed == 2


def test_identical_repeated_device_rows_collapse_without_a_timestamp(tmp_path):
    columns = [c for c in DEVICE_COLUMNS if c != "Timestamp"]
    assets, adapter = _assets(tmp_path, [_device(), _device()], columns=columns)
    assert len(assets) == 1
    assert adapter.stats.duplicate_assets_collapsed == 1


def test_conflicting_device_rows_with_nothing_to_order_them_are_refused(tmp_path):
    columns = [c for c in DEVICE_COLUMNS if c != "Timestamp"]
    with pytest.raises(AdapterError, match="no later Timestamp to prefer"):
        _assets(tmp_path, [_device(build="19044"), _device(build="19045")], columns=columns)


def test_unparseable_timestamp_is_refused(tmp_path):
    with pytest.raises(AdapterError, match="Timestamp 'last tuesday' is not ISO 8601"):
        _assets(tmp_path, [_device(timestamp="last tuesday")])


# --- findings: the DeviceTvmSoftwareVulnerabilities mapping -----------------------


def test_maps_vulnerability_columns_onto_finding(tmp_path):
    findings, _ = _findings(tmp_path, [_vuln(cve="cve-2020-1472")])
    (finding,) = findings

    assert re.fullmatch(r"MDVM-[0-9A-F]{16}", finding.finding_id)
    assert finding.asset_id == DC
    assert finding.cve_id == "CVE-2020-1472"  # upper-cased: NVD/KEV/EPSS snapshots are keyed that way
    assert finding.scanner_severity == "critical"
    assert finding.product == "windows_server_2019"
    assert finding.version == "10.0.17763.1339"
    assert finding.port == "" and finding.service == ""
    assert finding.evidence == (
        "Defender MDVM: microsoft windows_server_2019 10.0.17763.1339; "
        "recommended update: August 2020 Security Updates (4565349)"
    )


def test_fields_defender_findings_have_no_concept_of_are_marked(tmp_path):
    """The hunting table has no timestamp at all, so detected_date is not
    collected for every row; port/service never are (agent-based)."""
    findings, _ = _findings(tmp_path, [_vuln(), _vuln(cve="CVE-2021-1656", version="")])
    with_version, without_version = findings
    assert with_version.detected_date == ""
    assert with_version.not_collected == FINDING_FIELDS_NEVER_EXPORTED | {"detected_date"}
    assert without_version.not_collected == FINDING_FIELDS_NEVER_EXPORTED | {"detected_date", "version"}


def test_first_seen_timestamp_from_the_assessment_api_export_becomes_detected_date(tmp_path):
    columns = VULN_COLUMNS + ["FirstSeenTimestamp", "DiskPaths", "RegistryPaths"]
    findings, _ = _findings(
        tmp_path,
        [_vuln(FirstSeenTimestamp="2020-11-03 10:13:34.8476880", DiskPaths='["C:\\\\Windows\\\\System32\\\\lsass.exe"]')],
        columns=columns,
    )
    (finding,) = findings
    assert finding.detected_date == "2020-11-03"
    assert "detected_date" not in finding.not_collected
    assert finding.evidence.endswith('disk: ["C:\\\\Windows\\\\System32\\\\lsass.exe"]')


def test_blank_first_seen_timestamp_is_a_gap_and_a_bad_one_is_refused(tmp_path):
    columns = VULN_COLUMNS + ["FirstSeenTimestamp"]
    findings, _ = _findings(tmp_path, [_vuln(FirstSeenTimestamp="")], columns=columns)
    assert "detected_date" in findings[0].not_collected

    with pytest.raises(AdapterError, match="FirstSeenTimestamp 'yesterday' is not ISO 8601"):
        _findings(tmp_path, [_vuln(FirstSeenTimestamp="yesterday")], columns=columns)


def test_finding_id_is_content_addressed_and_stable_across_row_order(tmp_path):
    rows = [_vuln(), _vuln(cve="CVE-2021-1656"), _vuln(device_id=WEB, cve="CVE-2022-21907")]
    first, _ = _findings(tmp_path, rows)
    second, _ = _findings(tmp_path, list(reversed(rows)))
    assert {f.finding_id for f in first} == {f.finding_id for f in second}
    assert len({f.finding_id for f in first}) == 3


def test_finding_id_distinguishes_the_same_cve_on_two_products_and_two_devices(tmp_path):
    findings, _ = _findings(tmp_path, [
        _vuln(name="office", version="16.0.1"),
        _vuln(name="outlook", version="16.0.1"),
        _vuln(device_id=WEB, name="office", version="16.0.1"),
    ])
    assert len({f.finding_id for f in findings}) == 3


def test_load_findings_is_lazy(tmp_path):
    path = _write(tmp_path / "vulnerabilities.csv", VULN_COLUMNS, [_vuln()])
    assert inspect.isgenerator(DefenderAdapter().load_findings(path, {DC}))


# --- findings: messy realities ----------------------------------------------------


def test_exact_duplicate_finding_rows_collapse_and_are_counted(tmp_path):
    """Same identity, same severity/date -- including a row that differs
    only in evidence columns -- is one finding; the first row's evidence
    is kept and the collapse is counted, not hidden."""
    findings, adapter = _findings(tmp_path, [
        _vuln(),
        _vuln(),
        _vuln(update_id="9999999"),  # evidence-only difference
        _vuln(cve="CVE-2021-1656"),
    ])
    assert [f.cve_id for f in findings] == ["CVE-2020-1472", "CVE-2021-1656"]
    assert "(4565349)" in findings[0].evidence
    assert adapter.stats.duplicate_findings_collapsed == 2


def test_conflicting_duplicate_findings_are_refused(tmp_path):
    with pytest.raises(AdapterError, match="conflicts with row 2 -- same DeviceId"):
        _findings(tmp_path, [_vuln(severity="Critical"), _vuln(severity="High")])


def test_orphaned_findings_are_refused_with_every_device_listed(tmp_path):
    other_ghost = "8e" * 20
    with pytest.raises(AdapterError) as excinfo:
        _findings(tmp_path, [
            _vuln(),
            _vuln(device_id=GHOST),
            _vuln(device_id=GHOST, cve="CVE-2021-1656"),
            _vuln(device_id=other_ghost),
        ])
    message = str(excinfo.value)
    assert "3 finding row(s) reference 2 DeviceId(s) absent from devices.csv" in message
    assert f"{other_ghost} (1 finding(s))" in message
    assert f"{GHOST} (2 finding(s))" in message
    assert "re-export DeviceInfo" in message


def test_non_cve_advisory_ids_are_refused(tmp_path):
    with pytest.raises(AdapterError, match="CveId 'ADV200002' is not a CVE identifier"):
        _findings(tmp_path, [_vuln(cve="ADV200002")])


def test_unknown_severity_is_refused_not_coerced(tmp_path):
    with pytest.raises(AdapterError, match="VulnerabilitySeverityLevel 'Severe' is not one of"):
        _findings(tmp_path, [_vuln(severity="Severe")])


def test_blank_identity_cell_in_a_finding_is_fatal(tmp_path):
    with pytest.raises(AdapterError, match=r"blank identity column\(s\) \['SoftwareName'\]"):
        _findings(tmp_path, [_vuln(name="")])


def test_missing_required_finding_column_is_refused_at_the_header(tmp_path):
    columns = [c for c in VULN_COLUMNS if c != "CveId"]
    with pytest.raises(AdapterError, match=r"not a DeviceTvmSoftwareVulnerabilities export -- missing required column\(s\) \['CveId'\]"):
        _findings(tmp_path, [_vuln()], columns=columns)


def test_every_problem_is_reported_at_once_and_nothing_is_yielded_first(tmp_path):
    """One export, three different problems: the operator gets all three
    in one message, and the generator raises before its first yield --
    no finding reaches enrichment from a batch that is about to abort."""
    path = _write(tmp_path / "vulnerabilities.csv", VULN_COLUMNS, [
        _vuln(),
        _vuln(device_id=GHOST),
        _vuln(cve="CVE-2021-1656", severity="Severe"),
        _vuln(cve="not-a-cve"),
    ])
    gen = DefenderAdapter().load_findings(path, {DC})
    with pytest.raises(AdapterError) as excinfo:
        next(gen)
    message = str(excinfo.value)
    assert "3 problem(s)" in message
    assert "absent from devices.csv" in message
    assert "'Severe'" in message
    assert "'not-a-cve'" in message


def test_adapter_error_is_an_ingest_error(tmp_path):
    """cli.py maps IngestError to 'ingest error' / exit 1; an adapter
    refusal must ride the same path."""
    with pytest.raises(IngestError):
        _findings(tmp_path, [_vuln(device_id=GHOST)])


# --- end to end through load_batch and the deterministic scorer -------------------


def test_load_batch_joins_and_scores_a_defender_export_offline(tmp_path):
    """The whole point of the adapter: an export scored through the
    identical, untouched pipeline. Uses CVEs with committed snapshots so
    the run is offline. Two consequences of the not_collected
    representation are checked here because they are the ones a reader
    of the plan must understand: bucket verdicts follow the blank values
    (a blank patch_window is still 'no window' to bucket_for), and every
    KEV finding on an asset with no known window or control therefore
    lands contested -- the honest verdict when nobody has said whether a
    window or a control exists -- rather than being forced into
    next_window."""
    from rhinosecure.cli import run_with_report

    data_dir = _sample_dir(
        tmp_path,
        [_device(), _device(device_id=WKS, name="wks-fin12.corp.example.com", platform="Windows10", build="19045", asset_value="Normal")],
        [
            _vuln(),  # ZeroLogon on the server -- KEV-listed
            _vuln(cve="CVE-2021-1656", severity="Medium"),  # mundane, not KEV
            _vuln(device_id=WKS, name="outlook", version="16.0.1", cve="CVE-2023-23397", severity="Critical"),  # KEV
            _vuln(device_id=WKS, name="outlook", version="16.0.1", cve="CVE-2023-23397", severity="Critical"),  # dup
        ],
    )
    result = run_with_report(data_dir, seed=42, offline=True, fmt="defender")

    assert len(result.scored) == 3
    assert result.report.format == "defender"
    assert result.report.assets_total == 2 and result.report.findings_total == 3
    assert result.report.duplicate_findings_collapsed == 1
    assert result.report.asset_gaps["patch_window"] == 2
    assert result.report.asset_gaps["compensating_controls"] == 2
    assert result.report.finding_gaps["port"] == 3
    assert set(result.not_collected_by_finding) == {s.finding_id for s in result.scored}
    by_cve = {s.cve_id: s for s in result.scored}
    for kev_cve in ("CVE-2020-1472", "CVE-2023-23397"):
        assert by_cve[kev_cve].bucket in (Bucket.PATCH_NOW, Bucket.CONTESTED)
        assert by_cve[kev_cve].bucket is not Bucket.NEXT_WINDOW  # never "on schedule" with no schedule known
    assert by_cve["CVE-2021-1656"].bucket in (Bucket.ACCEPT, Bucket.NEXT_WINDOW)
    # The scorer says "not collected", not "none declared" -- the claim the
    # export actually supports (scoring._rationale reads Asset.not_collected).
    rationale = by_cve["CVE-2020-1472"].rationale
    assert any("patch window not collected" in line for line in rationale)
    assert any("compensating controls not collected" in line for line in rationale)
    assert not any("no patch_window declared" in line for line in rationale)
    contested = [line for line in rationale if line.startswith("bucket=contested")]
    assert contested and "no patch window collected" in contested[0]


def test_load_batch_excludes_a_non_windows_devices_findings_not_orphans_them(tmp_path):
    """A finding whose device was scope-excluded (not Windows) is
    excluded too, cascading -- distinct from a true orphan (GHOST below,
    which was never a device row at all and stays fatal)."""
    data_dir = _sample_dir(
        tmp_path,
        [_device(), _device(device_id=WEB, name="mac01.corp.example.com", platform="macOS")],
        [_vuln(), _vuln(device_id=WEB, cve="CVE-2021-1656")],
    )
    adapter = get_adapter("defender")
    assets, enriched = load_batch(data_dir, adapter)
    findings = list(enriched)

    assert set(assets) == {DC}
    assert [f.finding.asset_id for f in findings] == [DC]
    assert set(adapter.stats.excluded_assets) == {WEB}
    (excluded_finding_id,) = adapter.stats.excluded_findings  # exactly one -- CVE-2021-1656 on WEB
    assert f"its asset ({WEB}) was excluded" in adapter.stats.excluded_findings[excluded_finding_id]


def test_load_batch_refuses_before_any_enrichment_when_the_export_is_bad(tmp_path):
    data_dir = _sample_dir(tmp_path, [_device()], [_vuln(device_id=GHOST)])
    assets, enriched = load_batch(data_dir, get_adapter("defender"))
    assert set(assets) == {DC}
    with pytest.raises(AdapterError):
        next(enriched)


# --- schema: the not_collected contract ------------------------------------------


def test_not_collected_may_only_name_real_non_key_fields():
    from rhinosecure.schema import Asset, Finding

    base = dict(asset_id="x", hostname="h", os="Windows 10", os_build="1", role="workstation",
                criticality=3, internet_exposed=False, environment="prod", data_sensitivity="internal")
    assert Asset(**base, not_collected=frozenset({"patch_window"})).not_collected == {"patch_window"}
    with pytest.raises(ValidationError, match="cannot leave uncollected: \\['nonesuch'\\]"):
        Asset(**base, not_collected=frozenset({"nonesuch"}))
    with pytest.raises(ValidationError, match="asset_id"):
        Asset(**base, not_collected=frozenset({"asset_id"}))
    with pytest.raises(ValidationError, match="cve_id"):
        Finding(finding_id="f", asset_id="x", cve_id="CVE-2020-1472", scanner_severity="high",
                not_collected=frozenset({"cve_id"}))


def test_not_collected_survives_the_constraint_overlays_model_copy():
    """agents/constraint_intake.apply_constraints builds the overlaid asset
    with model_copy(update=...); the marker must ride along, or a
    constraint would silently un-mark every other gap on the asset."""
    from rhinosecure.schema import Asset

    asset = Asset(asset_id="x", hostname="h", os="Windows 10", os_build="1", role="workstation",
                  criticality=3, internet_exposed=False, environment="prod", data_sensitivity="internal",
                  not_collected=frozenset({"patch_window", "compensating_controls"}))
    overlaid = asset.model_copy(update={"patch_window": "Sun 02:00-06:00"})
    assert overlaid.has_patch_window
    assert overlaid.not_collected == {"patch_window", "compensating_controls"}
