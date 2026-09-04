"""adapters/bluepeak.py -- a single-file, pre-enriched synthetic source.
Every test writes its own synthetic_cve_inventory-shaped CSV into tmp_path,
matching the real data/bluepeak/synthetic_cve_inventory_50.csv column names
(CLAUDE.md Section 1: no component may assume its input is synthetic, so the
adapter is tested against the shape, not the frozen file)."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from rhinosecure.adapters import get_adapter
from rhinosecure.adapters.base import NOT_COLLECTED_DEFAULTS, AdapterError
from rhinosecure.adapters.bluepeak import (
    ASSET_FIELDS_NEVER_EXPORTED,
    FINDING_FIELDS_NEVER_EXPORTED,
    ROLE_BY_ASSET_TYPE,
    BluePeakAdapter,
)
from rhinosecure.ingest import IngestError, attach_source_enrichment, load_batch
from rhinosecure.scoring import score_finding

FILENAME = "synthetic_cve_inventory_50.csv"

COLUMNS = [
    "Company", "Record_ID", "CVE_ID", "Is_Synthetic", "Vulnerability_Title",
    "Vulnerability_Description", "CWE_ID", "MITRE_ATTACK_Technique", "Affected_Product",
    "Affected_Version", "Asset_ID", "Asset_Hostname", "Asset_Type", "Department",
    "Environment", "Asset_Criticality", "Internet_Exposed", "Detection_Source",
    "First_Detected", "Last_Observed", "CVSS_Base_Score", "Severity", "Exploit_Maturity",
    "Known_Exploited", "Patch_Available", "Compensating_Control", "Patch_Window",
    "Remediation_Status", "Assigned_Team", "SLA_Days", "Target_Remediation_Date",
    "Business_Impact", "Recommended_Action", "Data_Source",
]


def _row(
    record_id="VULN-0001",
    cve="CVE-2099-10001",
    description="A crafted request could execute code.",
    technique="T1210 - Exploitation of Remote Services",
    product="Widget Service",
    version="1.2.3",
    asset_id="SRV-01",
    hostname="srv-01.bluepeak.local",
    asset_type="Server",
    department="IT Operations",
    environment="Production",
    criticality="Critical",
    internet_exposed="No",
    detection_source="Vulnerability Scanner",
    first_detected="2026-08-20",
    last_observed="2026-09-04",
    cvss="9.8",
    severity="Critical",
    exploit_maturity="Active exploitation",
    known_exploited="Yes",
    compensating_control="",
    patch_window="Sun 01:00-05:00",
    assigned_team="Infrastructure Engineering",
    business_impact="Full server compromise.",
    **extra,
) -> dict:
    row = {
        "Company": "BluePeak Technologies (Fictional)",
        "Record_ID": record_id,
        "CVE_ID": cve,
        "Is_Synthetic": "TRUE",
        "Vulnerability_Title": "Synthetic finding",
        "Vulnerability_Description": description,
        "CWE_ID": "CWE-787",
        "MITRE_ATTACK_Technique": technique,
        "Affected_Product": product,
        "Affected_Version": version,
        "Asset_ID": asset_id,
        "Asset_Hostname": hostname,
        "Asset_Type": asset_type,
        "Department": department,
        "Environment": environment,
        "Asset_Criticality": criticality,
        "Internet_Exposed": internet_exposed,
        "Detection_Source": detection_source,
        "First_Detected": first_detected,
        "Last_Observed": last_observed,
        "CVSS_Base_Score": cvss,
        "Severity": severity,
        "Exploit_Maturity": exploit_maturity,
        "Known_Exploited": known_exploited,
        "Patch_Available": "Yes",
        "Compensating_Control": compensating_control,
        "Patch_Window": patch_window,
        "Remediation_Status": "Open",
        "Assigned_Team": assigned_team,
        "SLA_Days": "7",
        "Target_Remediation_Date": "2026-08-27",
        "Business_Impact": business_impact,
        "Recommended_Action": "Patch it.",
        "Data_Source": "Synthetic internal training record; not an NVD, CISA, or vendor CVE entry.",
    }
    row.update(extra)
    return row


def _write(path: Path, rows: list[dict], *, columns: list[str] | None = None) -> Path:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns or COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in (columns or COLUMNS)})
    return path


def _sample_dir(tmp_path: Path, rows: list[dict], *, columns: list[str] | None = None) -> Path:
    _write(tmp_path / FILENAME, rows, columns=columns)
    return tmp_path


# --- registration -------------------------------------------------------


def test_registered_as_bluepeak_and_provides_enrichment():
    adapter = get_adapter("bluepeak")
    assert isinstance(adapter, BluePeakAdapter)
    assert adapter.format == "bluepeak"
    assert adapter.provides_enrichment is True
    assert adapter.assets_filename == adapter.findings_filename == FILENAME


# --- happy path -----------------------------------------------------------


def test_valid_row_maps_asset_and_finding_with_source_enrichment(tmp_path):
    data_dir = _sample_dir(tmp_path, [_row()])
    adapter = get_adapter("bluepeak")
    assets, enriched = load_batch(data_dir, adapter)
    findings = list(enriched)

    assert set(assets) == {"SRV-01"}
    asset = assets["SRV-01"]
    assert asset.hostname == "srv-01.bluepeak.local"
    assert asset.role == "file"
    assert asset.business_function == "IT Operations"
    assert asset.criticality == 5
    assert asset.internet_exposed is False
    assert asset.environment == "prod"
    assert asset.patch_window == "Sun 01:00-05:00"
    assert asset.compensating_controls == ""
    assert asset.owner == ""
    assert asset.not_collected == ASSET_FIELDS_NEVER_EXPORTED

    assert len(findings) == 1
    finding = findings[0].finding
    assert finding.finding_id == "VULN-0001"
    assert finding.cve_id == "CVE-2099-10001"
    assert finding.scanner_severity == "critical"
    assert finding.product == "Widget Service"
    assert finding.version == "1.2.3"
    assert finding.detected_date == "2026-08-20"
    assert finding.not_collected == FINDING_FIELDS_NEVER_EXPORTED
    assert "Infrastructure Engineering" in finding.evidence
    assert "Active exploitation" in finding.evidence
    assert "Full server compromise." in finding.evidence
    assert "Recommended_Action" not in finding.evidence  # excluded on purpose
    assert "Patch it." not in finding.evidence

    source = finding.source_enrichment
    assert source is not None
    assert source.severity_score == 9.8
    assert source.severity_label == "bluepeak"
    assert source.known_exploited is True
    assert source.attack_technique_id == "T1210"
    assert source.attack_technique_name == "Exploitation of Remote Services"


def test_attach_source_enrichment_feeds_scoring_without_any_live_lookup(tmp_path):
    """The end-to-end point of provides_enrichment: score_finding sees a
    real KEV=True and the source's own precise CVSS, with zero network or
    cache access -- attach_source_enrichment never touches SnapshotCache."""
    data_dir = _sample_dir(tmp_path, [_row(cvss="9.6", known_exploited="Yes")])
    adapter = get_adapter("bluepeak")
    _assets, enriched = load_batch(data_dir, adapter)
    (e,) = list(enriched)

    resolved = attach_source_enrichment(e)
    assert resolved.is_kev is True
    assert resolved.source_severity_score == 9.6
    assert resolved.source_severity_label == "bluepeak"
    assert resolved.attack_techniques[0].technique_id == "T1210"
    assert resolved.attack_techniques[0].confidence == "source_reported"
    assert resolved.attack_prevalence is None  # no local corpus stat for a source-reported technique
    assert resolved.nvd_base_score is None  # never touched -- not this finding's provenance

    scored = score_finding(resolved)
    assert "bluepeak-reported CVSS 9.6" in "\n".join(scored.rationale)
    assert scored.bucket.value in {"patch_now", "next_window", "mitigate_monitor", "contested"}


# --- the role boundary ----------------------------------------------------


def test_every_documented_role_mapping_is_accepted(tmp_path):
    rows = [
        _row(record_id=f"VULN-{i:04d}", asset_id=f"A{i}", hostname=f"h{i}.bluepeak.local", asset_type=t)
        for i, t in enumerate(sorted(ROLE_BY_ASSET_TYPE), start=1)
    ]
    data_dir = _sample_dir(tmp_path, rows)
    assets, enriched = load_batch(data_dir, get_adapter("bluepeak"))
    list(enriched)
    assert {a.role for a in assets.values()} == set(ROLE_BY_ASSET_TYPE.values())


def test_unmapped_asset_type_is_excluded_not_fatal(tmp_path):
    """Scope boundary, not data quality (adapters/base.py's "Two kinds of
    refusal"): the mappable row still scores; a genuinely out-of-
    vocabulary Asset_Type (ROLE_BY_ASSET_TYPE now covers every type in
    the real 50-row file, so this uses one that will never be in it) is
    excluded and reported, not fatal to the batch."""
    data_dir = _sample_dir(
        tmp_path,
        [_row(record_id="VULN-0001", asset_id="A1"), _row(record_id="VULN-0002", asset_id="A2", cve="CVE-2099-10002", asset_type="Mainframe")],
    )
    adapter = get_adapter("bluepeak")
    assets, enriched = load_batch(data_dir, adapter)
    findings = list(enriched)

    assert set(assets) == {"A1"}
    assert [f.finding.finding_id for f in findings] == ["VULN-0001"]
    assert set(adapter.stats.excluded_assets) == {"A2"}
    assert "Mainframe" in adapter.stats.excluded_assets["A2"]
    assert "has no honest equivalent" in adapter.stats.excluded_assets["A2"]
    assert adapter.stats.excluded_findings == {
        "VULN-0002": "its asset (A2) was excluded: " + adapter.stats.excluded_assets["A2"]
    }


def test_unmapped_asset_type_alongside_a_fatal_problem_still_refuses_everything(tmp_path):
    """A real data-quality problem elsewhere in the batch still blocks
    everything, exclusions included -- raise_if_fatal only looks at
    .fatal, and a fatal batch never gets far enough to report .excluded."""
    data_dir = _sample_dir(
        tmp_path,
        [
            _row(record_id="VULN-0001", asset_id="A1", asset_type="Mainframe"),
            _row(record_id="VULN-0002", asset_id="A2", cve="CVE-2099-10002", criticality="not-a-tier"),
        ],
    )
    with pytest.raises(AdapterError, match="Asset_Criticality"):
        load_batch(data_dir, get_adapter("bluepeak"))


def test_perimeter_and_platform_asset_types_map_to_their_new_roles(tmp_path):
    """The role vocabulary extension this adapter exists to demonstrate --
    CLAUDE.md Section 3 has the weight table and reasoning; this only
    checks the name mapping, not the weights themselves (scoring.py's own
    tests do that)."""
    perimeter_types = {
        "Identity Gateway": "identity_gateway",
        "Cloud Management Portal": "identity_gateway",
        "Firewall": "firewall",
        "Kubernetes Cluster": "container_orchestrator",
        "Email Security Gateway": "email_gateway",
        "Network Appliance": "network_appliance",
        "Application Gateway": "network_appliance",
        "Wireless Controller": "network_appliance",
        "Reverse Proxy": "network_appliance",
        "Mobile Sync Gateway": "network_appliance",
        "Web Application": "web_app",
        "Web API": "web_app",
        "Web Server": "web_app",
        "Container Host": "container_host",
        "Printer": "printer",
    }
    rows = [
        _row(record_id=f"VULN-{i:04d}", asset_id=f"A{i}", hostname=f"h{i}.bluepeak.local", asset_type=t)
        for i, t in enumerate(sorted(perimeter_types), start=1)
    ]
    data_dir = _sample_dir(tmp_path, rows)
    adapter = get_adapter("bluepeak")
    assets, enriched = load_batch(data_dir, adapter)
    list(enriched)

    assert not adapter.stats.excluded_assets  # every type above now maps
    by_hostname_index = {a.asset_id: a.role for a in assets.values()}
    for i, asset_type in enumerate(sorted(perimeter_types), start=1):
        assert by_hostname_index[f"A{i}"] == perimeter_types[asset_type]


# --- messy realities --------------------------------------------------


def test_missing_required_column_is_refused_at_the_header(tmp_path):
    columns = [c for c in COLUMNS if c != "CVSS_Base_Score"]
    data_dir = _sample_dir(tmp_path, [_row()], columns=columns)
    with pytest.raises(AdapterError, match="missing required column"):
        load_batch(data_dir, get_adapter("bluepeak"))


def test_blank_identity_columns_are_fatal(tmp_path):
    data_dir = _sample_dir(tmp_path, [_row(asset_id="")])
    with pytest.raises(AdapterError, match="blank identity column"):
        load_batch(data_dir, get_adapter("bluepeak"))


def test_non_cve_id_is_refused(tmp_path):
    data_dir = _sample_dir(tmp_path, [_row(cve="ADV-2099-001")])
    with pytest.raises(AdapterError, match="is not a CVE identifier"):
        list(load_batch(data_dir, get_adapter("bluepeak"))[1])


@pytest.mark.parametrize(
    ("field", "bad_value", "match"),
    [
        ("Asset_Criticality", "Severe", "Asset_Criticality"),
        ("Internet_Exposed", "maybe", "is not a boolean"),
        ("Environment", "Sandbox", "Environment"),
        ("Severity", "Extreme", "Severity"),
        ("Known_Exploited", "probably", "is not a boolean"),
        ("CVSS_Base_Score", "eleven", "is not a number"),
        ("CVSS_Base_Score", "11.5", "is not a number"),
        ("First_Detected", "08/20/2026", "is not ISO 8601"),
    ],
)
def test_unrecognized_or_malformed_values_are_refused(tmp_path, field, bad_value, match):
    row = _row(**{field: bad_value})
    data_dir = _sample_dir(tmp_path, [row])
    with pytest.raises(AdapterError, match=match):
        _assets, enriched = load_batch(data_dir, get_adapter("bluepeak"))
        list(enriched)


def test_unparsable_attack_technique_is_not_fatal(tmp_path):
    """Supplementary color, not identity -- degrades to "no technique",
    the raw text still reaches evidence via Vulnerability_Description."""
    data_dir = _sample_dir(tmp_path, [_row(technique="not a real technique string")])
    assets, enriched = load_batch(data_dir, get_adapter("bluepeak"))
    (e,) = list(enriched)
    assert e.finding.source_enrichment.attack_technique_id == ""


def test_repeated_asset_id_with_identical_facts_collapses(tmp_path):
    rows = [_row(record_id="VULN-0001"), _row(record_id="VULN-0002", cve="CVE-2099-10002")]
    data_dir = _sample_dir(tmp_path, rows)
    adapter = get_adapter("bluepeak")
    assets, enriched = load_batch(data_dir, adapter)
    findings = list(enriched)
    assert len(assets) == 1
    assert len(findings) == 2
    assert adapter.stats.duplicate_assets_collapsed == 1


def test_repeated_asset_id_with_conflicting_core_facts_refuses(tmp_path):
    rows = [
        _row(record_id="VULN-0001", criticality="Critical"),
        _row(record_id="VULN-0002", cve="CVE-2099-10002", criticality="Low", last_observed=""),
    ]
    data_dir = _sample_dir(tmp_path, rows)
    with pytest.raises(AdapterError, match="also appears on row"):
        load_batch(data_dir, get_adapter("bluepeak"))


def test_repeated_asset_id_prefers_the_later_last_observed(tmp_path):
    rows = [
        _row(record_id="VULN-0001", criticality="Low", last_observed="2026-01-01"),
        _row(record_id="VULN-0002", cve="CVE-2099-10002", criticality="Critical", last_observed="2026-06-01"),
    ]
    data_dir = _sample_dir(tmp_path, rows)
    assets, enriched = load_batch(data_dir, get_adapter("bluepeak"))
    list(enriched)
    assert assets["SRV-01"].criticality == 5  # the later (2026-06-01) row's Critical wins


def test_compensating_controls_union_across_an_assets_findings(tmp_path):
    """A real, both-true case from the shipped fixture: two different
    controls, each covering a different finding on the same asset --
    unioned, not refused. See the module docstring."""
    rows = [
        _row(record_id="VULN-0001", compensating_control="SMB access segmented by department"),
        _row(record_id="VULN-0002", cve="CVE-2099-10002", compensating_control="Archive extraction limited to authenticated file services"),
    ]
    data_dir = _sample_dir(tmp_path, rows)
    assets, enriched = load_batch(data_dir, get_adapter("bluepeak"))
    list(enriched)
    controls = assets["SRV-01"].compensating_control_list
    assert set(controls) == {"SMB access segmented by department", "Archive extraction limited to authenticated file services"}


@pytest.mark.parametrize("bad_control", ["Segmented, monitored, and alerted", "WAF; rate limiting also applied"])
def test_a_control_containing_a_comma_or_semicolon_is_refused(tmp_path, bad_control):
    """The bug this guards: compensating_control_list splits on comma AND
    semicolon to recover a UNIONED value's individual controls, so a single
    control whose own English-language description contains one of those
    characters would be silently split into multiple fake controls on the
    very next read -- deepening score_impact's decay for a fact the file
    never declared. Refused rather than joined into the union unremarked."""
    rows = [_row(compensating_control=bad_control)]
    data_dir = _sample_dir(tmp_path, rows)
    with pytest.raises(IngestError, match="contains a ',' or ';'"):
        load_batch(data_dir, get_adapter("bluepeak"))


def test_a_control_free_of_the_forbidden_characters_is_unaffected(tmp_path):
    """The guard must not false-positive on ordinary text with no comma or
    semicolon, however long or descriptive."""
    rows = [_row(compensating_control="Traffic filtered and alerted at the WAF")]
    data_dir = _sample_dir(tmp_path, rows)
    assets, enriched = load_batch(data_dir, get_adapter("bluepeak"))
    list(enriched)
    assert assets["SRV-01"].compensating_control_list == ("Traffic filtered and alerted at the WAF",)


def test_assigned_team_differing_per_finding_does_not_conflict(tmp_path):
    """The other real fixture case: Assigned_Team is per-finding
    remediation ownership, not asset ownership -- it must never block the
    batch on its own."""
    rows = [
        _row(record_id="VULN-0001", assigned_team="Endpoint Engineering"),
        _row(record_id="VULN-0002", cve="CVE-2099-10002", assigned_team="Database Operations"),
    ]
    data_dir = _sample_dir(tmp_path, rows)
    assets, enriched = load_batch(data_dir, get_adapter("bluepeak"))
    findings = list(enriched)
    assert assets["SRV-01"].owner == ""
    assert "owner" in assets["SRV-01"].not_collected
    texts = {f.finding.finding_id: f.finding.evidence for f in findings}
    assert "Endpoint Engineering" in texts["VULN-0001"]
    assert "Database Operations" in texts["VULN-0002"]


def test_duplicate_record_id_with_identical_content_collapses(tmp_path):
    row = _row()
    data_dir = _sample_dir(tmp_path, [row, dict(row)])
    adapter = get_adapter("bluepeak")
    _assets, enriched = load_batch(data_dir, adapter)
    findings = list(enriched)
    assert len(findings) == 1
    assert adapter.stats.duplicate_findings_collapsed == 1


def test_duplicate_record_id_with_different_content_refuses(tmp_path):
    rows = [_row(severity="Critical"), _row(severity="Low")]
    data_dir = _sample_dir(tmp_path, rows)
    with pytest.raises(AdapterError, match="also appears on row"):
        list(load_batch(data_dir, get_adapter("bluepeak"))[1])


def test_data_dir_missing_the_file_is_a_clean_ingest_error(tmp_path):
    with pytest.raises(IngestError, match="needs synthetic_cve_inventory_50.csv"):
        load_batch(tmp_path, get_adapter("bluepeak"))


# --- not_collected defaults are schema-valid -------------------------------


def test_asset_never_exported_fields_use_documented_defaults(tmp_path):
    data_dir = _sample_dir(tmp_path, [_row()])
    assets, enriched = load_batch(data_dir, get_adapter("bluepeak"))
    list(enriched)
    asset = assets["SRV-01"]
    assert asset.os == NOT_COLLECTED_DEFAULTS["os"]
    assert asset.os_build == NOT_COLLECTED_DEFAULTS["os_build"]
    assert asset.data_sensitivity == NOT_COLLECTED_DEFAULTS["data_sensitivity"]
    assert asset.patch_restrictions == NOT_COLLECTED_DEFAULTS["patch_restrictions"]
