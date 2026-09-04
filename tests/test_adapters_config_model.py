"""adapters/config_model.py -- the ingest-contract data shape and its
cross-field validator. No engine, no CLI, no LLM: everything here is either
a pydantic construction check or a call to `validate_contract` against a
hand-supplied header, matching the two files' real column lists. Zero I/O.

The two worked contracts below are hand-transcribed from the design's own
`bluepeak-gen` (single-file, pre-enriched) and `mdvm-gen` (two-file,
Defender-shaped) examples, each checked line-for-line against the real
files at data/bluepeak/synthetic_cve_inventory_50.csv and
data/defender-sample/. They are the exit criterion this slice was built to
satisfy: both must validate with zero problems against the real headers."""

from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from rhinosecure.adapters.config_model import (
    ABSENT_FACT_LEGAL_TARGETS,
    ASSET_SLOTS,
    FINDING_SLOTS,
    GAP_LEGAL_TARGETS,
    Contract,
    ContractValidationError,
    compute_content_digest,
    compute_decision_digest,
    validate_contract,
)

# --- the real headers, transcribed verbatim from the committed data files ---

BLUEPEAK_HEADER = [
    "Company", "Record_ID", "CVE_ID", "Is_Synthetic", "Vulnerability_Title",
    "Vulnerability_Description", "CWE_ID", "MITRE_ATTACK_Technique", "Affected_Product",
    "Affected_Version", "Asset_ID", "Asset_Hostname", "Asset_Type", "Department",
    "Environment", "Asset_Criticality", "Internet_Exposed", "Detection_Source",
    "First_Detected", "Last_Observed", "CVSS_Base_Score", "Severity", "Exploit_Maturity",
    "Known_Exploited", "Patch_Available", "Compensating_Control", "Patch_Window",
    "Remediation_Status", "Assigned_Team", "SLA_Days", "Target_Remediation_Date",
    "Business_Impact", "Recommended_Action", "Data_Source",
]

DEVICES_HEADER = [
    "Timestamp", "DeviceId", "DeviceName", "OSPlatform", "OSBuild", "OSVersion",
    "IsInternetFacing", "AssetValue", "ExposureLevel", "MachineGroup",
]

VULNERABILITIES_HEADER = [
    "DeviceId", "DeviceName", "OSPlatform", "OSVersion", "OSArchitecture", "SoftwareVendor",
    "SoftwareName", "SoftwareVersion", "CveId", "VulnerabilitySeverityLevel",
    "RecommendedSecurityUpdate", "RecommendedSecurityUpdateId", "CveTags",
]


def _generator() -> dict:
    return {
        "tool": "rhino adapt propose", "model": "claude-sonnet-5",
        "prompt_tokens": 14208, "completion_tokens": 3117,
        "estimated_cost_usd": 0.089, "attempts": 1,
        "call_log_digest": "sha256:6d1f0c93a77b41e2c0f5b8a9d2e34f7011ab5c6d7e8f90a1b2c3d4e5f6a7b8c9",
    }


def bluepeak_gen_dict() -> dict:
    """The design's `bluepeak-gen` example, transcribed in full (minus the
    illustrative/placeholder `observed` block and digests, which are
    computed fresh in `_confirmed` below rather than copied verbatim --
    see that function's docstring)."""
    return {
        "config_schema_version": "1.0.0",
        "version": 2,
        "format": "bluepeak-gen",
        "description": "BluePeak Technologies (fictional) pre-enriched single-file CVE inventory",
        "generated_at": "2026-09-04T18:22:41Z",
        "generator": _generator(),
        "source": {
            "layout": "single_file",
            "assets_filename": "synthetic_cve_inventory_50.csv",
            "findings_filename": "synthetic_cve_inventory_50.csv",
            "encoding": "auto", "delimiter": ",", "quotechar": '"', "first_data_row": 2,
        },
        "header": {
            "mode": "declared",
            "assets": {"columns": BLUEPEAK_HEADER, "sha256": "sha256:094187d066e180adb184ed7120b2e45e6255c1b5ec1908476ee5402e224c92db"},
        },
        "derived": {},
        "asset": {
            "asset_id": {"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"},
            "hostname": {"kind": "column", "column": "Asset_Hostname", "case": "exact", "blank": "fatal"},
            "os": {"kind": "not_collected"},
            "os_build": {"kind": "not_collected"},
            "role": {
                "kind": "vocabulary", "column": "Asset_Type", "case": "exact", "blank": "fatal",
                "table": {
                    "Domain Controller": "dc", "Database Server": "sql",
                    "Workstation": "workstation", "Laptop": "workstation",
                    "Privileged Workstation": "workstation",
                    "Server": "file", "Storage Appliance": "file", "Application Server": "file",
                    "Monitoring Server": "file", "Reporting Server": "file",
                    "Network Management Server": "file", "DNS Server": "file", "Development Server": "file",
                    "Identity Gateway": "identity_gateway", "Cloud Management Portal": "identity_gateway",
                    "Firewall": "firewall", "Kubernetes Cluster": "container_orchestrator",
                    "Email Security Gateway": "email_gateway",
                    "Network Appliance": "network_appliance", "Application Gateway": "network_appliance",
                    "Wireless Controller": "network_appliance", "Reverse Proxy": "network_appliance",
                    "Mobile Sync Gateway": "network_appliance",
                    "Web Application": "web_app", "Web API": "web_app", "Web Server": "web_app",
                    "Container Host": "container_host", "Printer": "printer",
                },
                "table_notes": {
                    "Cloud Management Portal": "identity_gateway, not container_orchestrator",
                    "Development Server": "file, not dev",
                    "Server": "the most generic server weight",
                },
            },
            "business_function": {"kind": "column", "column": "Department", "case": "exact", "blank": "gap"},
            "criticality": {
                "kind": "vocabulary", "column": "Asset_Criticality", "case": "lower", "blank": "fatal",
                "table": {"critical": 5, "high": 4, "medium": 3, "low": 2},
                "table_notes": {"low": "2, not 1 -- this source's four tiers do not reach the schema's floor"},
            },
            "internet_exposed": {
                "kind": "parsed", "column": "Internet_Exposed", "case": "lower", "blank": "fatal",
                "parser": "bool", "params": {"true": ["yes", "true", "1"], "false": ["no", "false", "0"]},
            },
            "environment": {
                "kind": "vocabulary", "column": "Environment", "case": "lower", "blank": "fatal",
                "table": {"production": "prod", "development": "dev", "staging": "staging"},
                "table_notes": {"staging": "added by the reviewer -- not witnessed in this file"},
            },
            "data_sensitivity": {"kind": "not_collected"},
            "patch_window": {"kind": "column", "column": "Patch_Window", "case": "exact", "blank": "absent_fact"},
            "patch_restrictions": {"kind": "not_collected"},
            "compensating_controls": {"kind": "column", "column": "Compensating_Control", "case": "exact", "blank": "absent_fact"},
            "owner": {"kind": "not_collected"},
        },
        "finding": {
            "finding_id": {"kind": "column", "column": "Record_ID", "case": "exact", "blank": "fatal"},
            "asset_id": {"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"},
            "cve_id": {"kind": "parsed", "column": "CVE_ID", "case": "upper", "blank": "fatal", "parser": "cve_id"},
            "detected_date": {
                "kind": "parsed", "column": "First_Detected", "case": "exact", "blank": "fatal",
                "parser": "date", "params": {"format": "iso"},
            },
            "scanner_severity": {
                "kind": "vocabulary", "column": "Severity", "case": "lower", "blank": "fatal",
                "table": {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "informational"},
                "table_notes": {"informational": "added by the reviewer; not witnessed in this file"},
            },
            "product": {"kind": "column", "column": "Affected_Product", "case": "exact", "blank": "absent_fact"},
            "version": {"kind": "column", "column": "Affected_Version", "case": "exact", "blank": "gap"},
            "port": {"kind": "not_collected"},
            "service": {"kind": "not_collected"},
            "evidence": {
                "kind": "composed", "join": "; ", "max_chars": 4096,
                "parts": [
                    {"template": "[{Asset_Type}] {Detection_Source}: {Vulnerability_Description}",
                     "fallback_template": "[{Asset_Type}] {Vulnerability_Description}",
                     "required_non_blank": ["Detection_Source"]},
                    {"template": "exploit maturity (source-reported): {Exploit_Maturity}",
                     "required_non_blank": ["Exploit_Maturity"]},
                    {"template": "business impact (source-reported): {Business_Impact}",
                     "required_non_blank": ["Business_Impact"]},
                    {"template": "assigned team (source-reported): {Assigned_Team}",
                     "required_non_blank": ["Assigned_Team"]},
                ],
            },
        },
        "enrichment": {
            "severity_score": {
                "kind": "parsed", "column": "CVSS_Base_Score", "case": "exact", "blank": "fatal",
                "parser": "float", "params": {"min": 0.0, "max": 10.0},
            },
            "known_exploited": {
                "kind": "parsed", "column": "Known_Exploited", "case": "lower", "blank": "fatal",
                "parser": "bool", "params": {"true": ["yes", "true", "1"], "false": ["no", "false", "0"]},
            },
            "attack_technique": {
                "column": "MITRE_ATTACK_Technique", "optional": True, "blank": "absent_fact",
                "pattern": "attack_technique",
                "outputs": ["attack_technique_id", "attack_technique_name"],
                "on_no_match": "degrade",
            },
        },
        "asset_grouping": {
            "key": "Asset_ID",
            "order_by": {"column": "Last_Observed", "parser": "date", "params": {"format": "iso"}, "required": True},
            "resolution": "agree_or_recency",
            "union_fields": ["compensating_controls"],
            "union_justification": {
                "compensating_controls": "FILE-SRV-01 declares two different, both-real controls on two rows with the same Last_Observed; the union asserts nothing new.",
            },
        },
        "finding_dedup": {
            "content_targets": ["scanner_severity", "detected_date", "product", "version",
                                 "source_enrichment.severity_score", "source_enrichment.known_exploited"],
            "on_identical": "collapse_and_count",
            "on_conflict": "fatal",
        },
        "unmapped_columns": {
            "synthetic_cve_inventory_50.csv": {
                "Assigned_Team": {"disposition": "evidence_only", "reason": "per-finding remediation owner, not asset owner"},
                "Recommended_Action": {"disposition": "deliberately_dropped", "reason": "the source's own remediation verdict"},
                "SLA_Days": {"disposition": "deliberately_dropped", "reason": "the source's own prioritisation output"},
                "Company": {"disposition": "ignored", "reason": "one constant value on all 50 rows"},
                "Is_Synthetic": {"disposition": "ignored", "reason": "constant TRUE"},
                "Vulnerability_Title": {"disposition": "ignored", "reason": "a restatement of Vulnerability_Description"},
                "CWE_ID": {"disposition": "ignored", "reason": "weakness taxonomy; no schema field"},
                "Patch_Available": {"disposition": "ignored", "reason": "remediation-workflow state"},
                "Remediation_Status": {"disposition": "ignored", "reason": "the source's own workflow state"},
                "Target_Remediation_Date": {"disposition": "ignored", "reason": "derived from SLA_Days"},
                "Data_Source": {"disposition": "ignored", "reason": "a constant disclaimer sentence"},
            },
        },
        "not_collected": {
            "always_asset": ["data_sensitivity", "os", "os_build", "owner", "patch_restrictions"],
            "always_finding": ["port", "service"],
            "per_row_eligible_asset": ["business_function"],
            "per_row_eligible_finding": ["version"],
        },
        "validator_overrides": [],
        "observed": None,
        "divergences": [
            {"what": "A blank Asset_Type is fatal here, where adapters/bluepeak.py excludes it.", "rows_affected": 0},
        ],
        "attestations": [
            {"item": "enrichment",
             "text": "Every CVE_ID in this export matches CVE-2099-NNNNN; trusting the export's own CVSS/exploitation/technique fields instead of a live lookup.",
             "at": "2026-09-04T18:31:02Z"},
            {"item": "union",
             "text": "Compensating_Control is declared per finding; FILE-SRV-01 declares two different real controls on two rows with the same Last_Observed. No control string in this file contains a comma or semicolon.",
             "at": "2026-09-04T18:31:02Z"},
        ],
        "review": {"state": "proposed"},
    }


def mdvm_gen_dict() -> dict:
    """The design's `mdvm-gen` example (two-file, Defender-shaped),
    transcribed in full against the real data/defender-sample/ headers."""
    return {
        "config_schema_version": "1.0.0",
        "version": 1,
        "format": "mdvm-gen",
        "description": "Microsoft Defender Vulnerability Management: DeviceInfo + DeviceTvmSoftwareVulnerabilities",
        "generated_at": "2026-09-04T19:00:00Z",
        "generator": _generator(),
        "source": {
            "layout": "two_file",
            "assets_filename": "devices.csv",
            "findings_filename": "vulnerabilities.csv",
            "encoding": "auto", "delimiter": ",", "quotechar": '"', "first_data_row": 2,
        },
        "header": {
            "mode": "declared",
            "assets": {"columns": DEVICES_HEADER, "sha256": "sha256:76ae45c5008e9ed975d32808cc1c63fbf45328e2d83cb487a732036b123993e3"},
            "findings": {"columns": VULNERABILITIES_HEADER, "sha256": "sha256:c68625dc7909dd5ad77c4417ce8276eba55015494f021e562b99ac0ef7ab7de0"},
        },
        "derived": {
            "os_platform": {
                "column": "OSPlatform", "case": "exact", "blank": "fatal",
                "outputs": ["os", "os_class"],
                "table": {
                    "Windows7": ["Windows 7", "client"], "Windows8.1": ["Windows 8.1", "client"],
                    "Windows10": ["Windows 10", "client"], "Windows11": ["Windows 11", "client"],
                    "WindowsServer2008R2": ["Windows Server 2008 R2", "server"],
                    "WindowsServer2012": ["Windows Server 2012", "server"],
                    "WindowsServer2012R2": ["Windows Server 2012 R2", "server"],
                    "WindowsServer2016": ["Windows Server 2016", "server"],
                    "WindowsServer2019": ["Windows Server 2019", "server"],
                    "WindowsServer2022": ["Windows Server 2022", "server"],
                    "WindowsServer2025": ["Windows Server 2025", "server"],
                },
                "table_notes": {"Windows10": "case:'exact' on purpose -- Microsoft's exact tokens"},
            },
        },
        "asset": {
            "asset_id": {"kind": "column", "column": "DeviceId", "case": "exact", "blank": "fatal"},
            "hostname": {"kind": "column", "column": "DeviceName", "case": "exact", "blank": "fatal"},
            "os": {"kind": "derived", "from": "os_platform", "output": "os"},
            "os_build": {"kind": "column", "column": "OSBuild", "case": "exact", "blank": "gap"},
            "role": {"kind": "default_by", "table": "ROLE_DEFAULT_BY_OS_CLASS", "keyed_by": {"from": "os_platform", "output": "os_class"}},
            "criticality": {
                "kind": "vocabulary", "column": "AssetValue", "case": "lower", "blank": "gap",
                "table": {"low": 1, "normal": 3, "high": 5},
                "table_notes": {"normal": "Defender's own documented default tier"},
            },
            "internet_exposed": {
                "kind": "parsed", "column": "IsInternetFacing", "case": "lower", "blank": "gap",
                "parser": "bool", "params": {"true": ["true", "yes", "1"], "false": ["false", "no", "0"]},
            },
            "business_function": {"kind": "not_collected"},
            "environment": {"kind": "not_collected"},
            "data_sensitivity": {"kind": "not_collected"},
            "patch_window": {"kind": "not_collected"},
            "patch_restrictions": {"kind": "not_collected"},
            "compensating_controls": {"kind": "not_collected"},
            "owner": {"kind": "not_collected"},
        },
        "finding": {
            "finding_id": {
                "kind": "content_address", "algorithm": "sha256",
                "columns": ["DeviceId", "SoftwareVendor", "SoftwareName", "SoftwareVersion", "CveId"],
                "join": "", "prefix": "MDVMC-", "hex_len": 16, "case": "upper", "recipe_version": 1,
            },
            "asset_id": {"kind": "column", "column": "DeviceId", "case": "exact", "blank": "fatal"},
            "cve_id": {"kind": "parsed", "column": "CveId", "case": "upper", "blank": "fatal", "parser": "cve_id"},
            "detected_date": {
                "kind": "parsed", "column": "FirstSeenTimestamp", "case": "exact", "optional": True,
                "blank": "gap", "parser": "date", "params": {"format": "iso_prefix"},
            },
            "scanner_severity": {
                "kind": "vocabulary", "column": "VulnerabilitySeverityLevel", "case": "lower", "blank": "fatal",
                "table": {"critical": "critical", "high": "high", "medium": "medium", "low": "low"},
                "table_notes": {"low": "Defender exports no 'informational' tier"},
            },
            "product": {"kind": "column", "column": "SoftwareName", "case": "exact", "blank": "fatal"},
            "version": {"kind": "column", "column": "SoftwareVersion", "case": "exact", "blank": "gap"},
            "port": {"kind": "not_collected"},
            "service": {"kind": "not_collected"},
            "evidence": {
                "kind": "composed", "join": "; ", "max_chars": 4096,
                "parts": [
                    {"prefix": "Defender MDVM: ", "join_nonblank": ["SoftwareVendor", "SoftwareName", "SoftwareVersion"], "join": " "},
                    {"template": "recommended update: {RecommendedSecurityUpdate} ({RecommendedSecurityUpdateId})",
                     "fallback_template": "recommended update: {RecommendedSecurityUpdate}",
                     "required_non_blank": ["RecommendedSecurityUpdateId"],
                     "emit_if_any": ["RecommendedSecurityUpdate", "RecommendedSecurityUpdateId"]},
                    {"template": "disk: {DiskPaths}", "required_non_blank": ["DiskPaths"]},
                    {"template": "registry: {RegistryPaths}", "required_non_blank": ["RegistryPaths"]},
                ],
            },
        },
        "asset_grouping": {
            "key": "DeviceId",
            "order_by": {"column": "Timestamp", "parser": "timestamp", "required": False},
            "resolution": "agree_or_recency",
            "union_fields": [],
            "union_justification": {},
        },
        "finding_dedup": {
            "content_targets": ["scanner_severity", "detected_date"],
            "on_identical": "collapse_and_count",
            "on_conflict": "fatal",
        },
        "unmapped_columns": {
            "devices.csv": {
                "OSVersion": {"disposition": "ignored", "reason": "a display alias for OSBuild"},
                "ExposureLevel": {"disposition": "deliberately_dropped", "reason": "Defender's own computed exposure verdict"},
                "MachineGroup": {"disposition": "deliberately_dropped", "reason": "a Defender RBAC scope, not a documented role vocabulary"},
            },
            "vulnerabilities.csv": {
                "DeviceName": {"disposition": "ignored", "reason": "denormalised copy of devices.csv"},
                "OSPlatform": {"disposition": "ignored", "reason": "denormalised copy; scope vocabulary is evaluated on the asset side"},
                "OSVersion": {"disposition": "ignored", "reason": "denormalised copy"},
                "OSArchitecture": {"disposition": "ignored", "reason": "no schema field, no scoring axis"},
                "CveTags": {"disposition": "ignored", "reason": "a JSON array in a cell; no multi-value reader"},
            },
        },
        "not_collected": {
            "always_asset": ["business_function", "compensating_controls", "data_sensitivity",
                             "environment", "owner", "patch_restrictions", "patch_window", "role"],
            "always_finding": ["detected_date", "port", "service"],
            "per_row_eligible_asset": ["criticality", "internet_exposed", "os_build"],
            "per_row_eligible_finding": ["version"],
        },
        "validator_overrides": [
            {"path": "asset.role",
             "proposed": {"kind": "vocabulary", "column": "MachineGroup"},
             "applied": {"kind": "default_by", "table": "ROLE_DEFAULT_BY_OS_CLASS"},
             "rule": "the reviewer moved MachineGroup to unmapped_columns and accepted the OS-class default"},
        ],
        "observed": None,
        "divergences": [
            {"what": "finding_id prefix is MDVMC-, not MDVM- -- a contract-driven adapter never mints into the hand-written adapter's id space.", "rows_affected": 9},
        ],
        "attestations": [
            {"item": "finding_id.synthesized",
             "text": "Defender exports no stable per-finding id; the id is a sha256 over DeviceId/SoftwareVendor/SoftwareName/SoftwareVersion/CveId, frozen on confirmation. SoftwareVendor is an OPTIONAL column inside that tuple.",
             "at": "2026-09-04T19:09:44Z"},
        ],
        "review": {"state": "proposed"},
    }


def _confirmed(contract_dict: dict) -> dict:
    """Stamp a real, self-consistent `review` block onto a contract dict --
    computed from THIS contract's own content, not copied from the design
    doc's illustrative (and deliberately fake) digest strings, which would
    fail the very digest check this module implements."""
    contract_dict = copy.deepcopy(contract_dict)
    contract_dict["review"] = {"state": "proposed"}
    proposed = Contract.model_validate(contract_dict)
    contract_dict["review"] = {
        "state": "confirmed",
        "confirmed_at": "2026-09-04T20:00:00Z",
        "confirmed_by": "andy.kopshin@gmail.com",
        "confirmed_version": contract_dict["version"],
        "content_digest": compute_content_digest(proposed),
        "decision_digest": compute_decision_digest(proposed),
    }
    return contract_dict


# --- the exit criterion: both worked contracts validate with zero problems ---


def test_bluepeak_gen_validates_against_the_real_header():
    contract = Contract.model_validate(bluepeak_gen_dict())
    validate_contract(contract, {"synthetic_cve_inventory_50.csv": BLUEPEAK_HEADER})


def test_mdvm_gen_validates_against_the_real_headers():
    contract = Contract.model_validate(mdvm_gen_dict())
    validate_contract(contract, {"devices.csv": DEVICES_HEADER, "vulnerabilities.csv": VULNERABILITIES_HEADER})


def test_bluepeak_gen_confirmed_with_real_digests_validates():
    contract = Contract.model_validate(_confirmed(bluepeak_gen_dict()))
    validate_contract(contract, {"synthetic_cve_inventory_50.csv": BLUEPEAK_HEADER})
    assert contract.review.state == "confirmed"


def test_mdvm_gen_confirmed_with_real_digests_validates():
    contract = Contract.model_validate(_confirmed(mdvm_gen_dict()))
    validate_contract(contract, {"devices.csv": DEVICES_HEADER, "vulnerabilities.csv": VULNERABILITIES_HEADER})


# --- every legal (target, blank) pair actually resolves ------------------
# The check that catches the NOT_COLLECTED_DEFAULTS-vs-""-default conflation
# a majority of the source design proposals made.


ALL_TARGETS = ASSET_SLOTS + FINDING_SLOTS
IDENTITY_TARGETS = frozenset({"asset_id", "hostname", "finding_id", "cve_id"})  # never blank-eligible at all


#: Verified against the real dicts: every free-text field whose
#: NOT_COLLECTED_DEFAULTS entry is "" is legal for BOTH policies -- gap
#: ("nobody collected this") and absent_fact ("this asset genuinely has
#: none") are different CLAIMS about the same blank, not competing types,
#: so a field can honestly support either. This is the set where they
#: overlap; it is not empty and that is correct, not a bug.
GAP_AND_ABSENT_FACT_BOTH_LEGAL = frozenset(
    {"business_function", "compensating_controls", "detected_date", "owner",
     "patch_restrictions", "patch_window", "port", "service", "version"}
)
#: Enumerated/typed fields with a NOT_COLLECTED_DEFAULTS entry but no ""
#: default -- a Literal has no blank member, so only gap makes sense.
GAP_ONLY = frozenset({"criticality", "internet_exposed", "environment", "data_sensitivity", "os", "os_build"})
#: Free-text fields with their own "" default but no NOT_COLLECTED_DEFAULTS
#: entry -- gap would KeyError, so only absent_fact makes sense.
ABSENT_FACT_ONLY = frozenset({"product", "evidence"})


def test_gap_legal_targets_match_the_three_verified_partitions():
    assert GAP_LEGAL_TARGETS == GAP_ONLY | GAP_AND_ABSENT_FACT_BOTH_LEGAL


def test_absent_fact_legal_targets_match_the_three_verified_partitions():
    assert ABSENT_FACT_LEGAL_TARGETS == ABSENT_FACT_ONLY | GAP_AND_ABSENT_FACT_BOTH_LEGAL


@pytest.mark.parametrize("target", sorted(GAP_ONLY))
def test_gap_only_targets_reject_absent_fact(target):
    with pytest.raises(ContractValidationError, match="not legal for target"):
        validate_contract(
            Contract.model_validate(_minimal_contract_mapping_one_target(target, "absent_fact")),
            {"data.csv": _MINIMAL_HEADER},
        )


@pytest.mark.parametrize("target", sorted(ABSENT_FACT_ONLY))
def test_absent_fact_only_targets_reject_gap(target):
    with pytest.raises(ContractValidationError, match="not legal for target"):
        validate_contract(
            Contract.model_validate(_minimal_contract_mapping_one_target(target, "gap")),
            {"data.csv": _MINIMAL_HEADER},
        )


@pytest.mark.parametrize("target", sorted(GAP_AND_ABSENT_FACT_BOTH_LEGAL))
@pytest.mark.parametrize("blank", ["gap", "absent_fact"])
def test_both_legal_targets_accept_either_policy(target, blank):
    validate_contract(
        Contract.model_validate(_minimal_contract_mapping_one_target(target, blank)),
        {"data.csv": _MINIMAL_HEADER},
    )


def test_identity_targets_are_in_neither_legal_set():
    """hostname and role (Asset) / the identity fields (Finding) have no
    absent encoding at all -- their blank must always be fatal."""
    for target in ("hostname",) :
        assert target not in GAP_LEGAL_TARGETS
        assert target not in ABSENT_FACT_LEGAL_TARGETS
    assert "role" not in GAP_LEGAL_TARGETS
    assert "role" not in ABSENT_FACT_LEGAL_TARGETS


@pytest.mark.parametrize("target", sorted(GAP_LEGAL_TARGETS))
def test_gap_is_accepted_for_every_gap_legal_target(target):
    """Build the smallest possible single-file contract mapping ONE target
    via 'column'/blank:'gap' (or 'parsed' for internet_exposed, the one
    bool-typed member) and confirm validate_contract accepts it."""
    contract_dict = _minimal_contract_mapping_one_target(target, "gap")
    contract = Contract.model_validate(contract_dict)
    validate_contract(contract, {"data.csv": _MINIMAL_HEADER})


@pytest.mark.parametrize("target", sorted(ABSENT_FACT_LEGAL_TARGETS))
def test_absent_fact_is_accepted_for_every_absent_fact_legal_target(target):
    contract_dict = _minimal_contract_mapping_one_target(target, "absent_fact")
    contract = Contract.model_validate(contract_dict)
    validate_contract(contract, {"data.csv": _MINIMAL_HEADER})


_MINIMAL_HEADER = ["Asset_ID", "Hostname", "Finding_ID", "Cve", "Col"]


def _minimal_contract_mapping_one_target(target: str, blank: str) -> dict:
    """A tiny, otherwise-valid single-file contract where every target
    EXCEPT the one under test uses a permissive kind (not_collected, or a
    trivial column for identity fields), and the target under test uses
    'column' (or 'vocabulary'/'parsed' where the target's own type demands
    it) with the given blank policy. `not_collected` is filled in by
    recomputing it directly (`_compute_not_collected`), the same function
    `validate_contract` itself uses for V09 -- so these tests exercise the
    blank-policy legality check specifically, not V09 as a side effect."""
    from rhinosecure.adapters.config_model import _compute_not_collected

    is_asset_target = target in ASSET_SLOTS
    asset: dict = {}
    for slot in ASSET_SLOTS:
        if slot in ("asset_id", "hostname"):
            asset[slot] = {"kind": "column", "column": "Asset_ID" if slot == "asset_id" else "Hostname", "case": "exact", "blank": "fatal"}
        elif slot == "role":
            asset[slot] = {"kind": "vocabulary", "column": "Col", "case": "exact", "blank": "fatal", "table": {"x": "dc"}}
        elif slot == target:
            pass  # filled below
        else:
            asset[slot] = {"kind": "not_collected"}
    finding: dict = {}
    for slot in FINDING_SLOTS:
        if slot in ("finding_id", "asset_id"):
            finding[slot] = {"kind": "column", "column": "Finding_ID" if slot == "finding_id" else "Asset_ID", "case": "exact", "blank": "fatal"}
        elif slot == "cve_id":
            finding[slot] = {"kind": "parsed", "column": "Cve", "case": "upper", "blank": "fatal", "parser": "cve_id"}
        elif slot == target:
            pass  # filled below
        elif slot == "scanner_severity":
            # Not gap-legal (no NOT_COLLECTED_DEFAULTS entry) -- unlike every
            # other non-identity Finding slot, this one needs a real
            # mapping, not the not_collected fallback below.
            finding[slot] = {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"x": "low"}}
        elif slot in ("product", "evidence"):
            # Also not gap-legal, but "" is each field's own default, so
            # absent_fact (not not_collected) is the permissive filler.
            finding[slot] = {"kind": "column", "column": "Col", "case": "exact", "blank": "absent_fact"}
        else:
            finding[slot] = {"kind": "not_collected"}

    if target == "internet_exposed":
        mapping = {"kind": "parsed", "column": "Col", "case": "lower", "blank": blank, "parser": "bool", "params": {"true": ["yes"], "false": ["no"]}}
    elif target == "criticality":
        mapping = {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": blank, "table": {"high": 4}}
    elif target in ("environment", "data_sensitivity", "scanner_severity"):
        mapping = {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": blank, "table": {"x": {"environment": "prod", "data_sensitivity": "internal", "scanner_severity": "low"}[target]}}
    else:
        mapping = {"kind": "column", "column": "Col", "case": "exact", "blank": blank}

    if is_asset_target:
        asset[target] = mapping
    else:
        finding[target] = mapping

    contract_dict = {
        "config_schema_version": "1.0.0", "version": 1, "format": "min-test",
        "description": "minimal fixture", "generated_at": "2026-09-04T00:00:00Z",
        "generator": _generator(),
        "source": {"layout": "single_file", "assets_filename": "data.csv", "findings_filename": "data.csv"},
        "header": {"mode": "declared", "assets": {"columns": _MINIMAL_HEADER, "sha256": "sha256:x"}},
        "derived": {}, "asset": asset, "finding": finding,
        "asset_grouping": {"key": "Asset_ID", "resolution": "agree_or_recency"},
        "finding_dedup": {"content_targets": ["scanner_severity"], "on_identical": "collapse_and_count", "on_conflict": "fatal"},
        "unmapped_columns": {},
        "not_collected": {},
        "review": {"state": "proposed"},
    }
    header_set = set(_MINIMAL_HEADER)
    expected = _compute_not_collected(Contract.model_validate(contract_dict), header_set, header_set)
    contract_dict["not_collected"] = expected.model_dump()
    return contract_dict


# --- deliberately broken contracts: one violated rule, one exact refusal ---


def _break(base: dict, **overrides) -> dict:
    """Deep-copy `base` and apply a dotted-path override, e.g.
    _break(d, **{"asset.role.blank": "gap"})."""
    result = copy.deepcopy(base)
    for path, value in overrides.items():
        node = result
        parts = path.split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value
    return result


BLUEPEAK_HEADERS = {"synthetic_cve_inventory_50.csv": BLUEPEAK_HEADER}


def test_invented_column_is_refused():
    d = _break(bluepeak_gen_dict())
    d["asset"]["business_function"] = {"kind": "column", "column": "Does_Not_Exist", "case": "exact", "blank": "gap"}
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="Does_Not_Exist"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_unaccounted_column_is_refused():
    d = copy.deepcopy(bluepeak_gen_dict())
    del d["unmapped_columns"]["synthetic_cve_inventory_50.csv"]["Data_Source"]
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="Data_Source"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_column_both_mapped_and_unmapped_is_refused():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["unmapped_columns"]["synthetic_cve_inventory_50.csv"]["Asset_ID"] = {"disposition": "ignored", "reason": "x"}
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="both mapped and listed"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_missing_blank_on_a_column_mapping_is_rejected_at_construction():
    d = copy.deepcopy(bluepeak_gen_dict())
    del d["asset"]["business_function"]["blank"]
    with pytest.raises(ValidationError, match="blank"):
        Contract.model_validate(d)


def test_gap_on_product_is_illegal_no_not_collected_defaults_entry():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["finding"]["product"]["blank"] = "gap"
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="not legal for target 'product'"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_absent_fact_on_criticality_is_illegal_no_empty_string_default():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["asset"]["criticality"]["blank"] = "absent_fact"
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="not legal for target 'criticality'"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_union_on_owner_is_refused():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["asset_grouping"]["union_fields"] = ["owner"]
    d["asset_grouping"]["union_justification"] = {"owner": "because"}
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="not in UNIONABLE_TARGETS"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_role_and_os_both_not_collected_still_validates_scope_is_an_engine_concern():
    """Slice 1 does not enforce that SOME scope vocabulary exists -- that is
    the engine's forward-trace (module docstring's 'Fatal vs. exclude'),
    not a contract-shape rule. A role mapped via vocabulary (as bluepeak-gen
    already does) is the normal case; this test only documents that a
    not_collected role is legal per this module's own rules (GAP_LEGAL_
    TARGETS excludes role, so not_collected there is actually illegal --
    see the next test)."""
    d = copy.deepcopy(bluepeak_gen_dict())
    d["asset"]["role"] = {"kind": "not_collected"}
    d["not_collected"]["always_asset"] = sorted(d["not_collected"]["always_asset"] + ["role"])
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="no NOT_COLLECTED_DEFAULTS entry for 'role'"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_table_value_outside_asset_role_literal_is_refused():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["asset"]["role"]["table"]["Domain Controller"] = "mainframe"
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="is not one of"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_criticality_table_value_out_of_range_is_refused():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["asset"]["criticality"]["table"]["critical"] = 7
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match=r"not an int in \[1, 5\]"):
        validate_contract(contract, BLUEPEAK_HEADERS)


@pytest.mark.parametrize("bad_format", ["nvd", "native", "defender", "bluepeak", "scanner", "source", "cvss", "nist"])
def test_reserved_or_builtin_format_name_is_rejected_at_construction(bad_format):
    d = copy.deepcopy(bluepeak_gen_dict())
    d["format"] = bad_format
    with pytest.raises(ValidationError):
        Contract.model_validate(d)


def test_path_traversing_filename_is_rejected_at_construction():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["source"]["assets_filename"] = "../../../etc/passwd"
    d["source"]["findings_filename"] = "../../../etc/passwd"
    with pytest.raises(ValidationError, match="bare filename"):
        Contract.model_validate(d)


def test_timestamp_parser_outside_order_by_is_refused():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["finding"]["detected_date"] = {"kind": "parsed", "column": "First_Detected", "case": "exact", "blank": "fatal", "parser": "timestamp"}
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="legal only inside asset_grouping.order_by"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_not_collected_target_cannot_be_mapped():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["asset"]["business_function"] = {"kind": "column", "column": "not_collected", "case": "exact", "blank": "gap"}
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="'not_collected' cannot be mapped as a source column"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_two_file_composed_placeholder_naming_the_other_files_column_is_refused():
    d = copy.deepcopy(mdvm_gen_dict())
    d["finding"]["evidence"]["parts"].append({"template": "asset value: {AssetValue}", "required_non_blank": ["AssetValue"]})
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="AssetValue"):
        validate_contract(contract, {"devices.csv": DEVICES_HEADER, "vulnerabilities.csv": VULNERABILITIES_HEADER})


def test_duplicate_header_column_is_refused():
    contract = Contract.model_validate(bluepeak_gen_dict())
    dup_header = BLUEPEAK_HEADER + ["Asset_ID"]
    with pytest.raises(ContractValidationError, match="appear more than once"):
        validate_contract(contract, {"synthetic_cve_inventory_50.csv": dup_header})


def test_content_address_illegal_outside_finding_id():
    d = copy.deepcopy(mdvm_gen_dict())
    d["finding"]["product"] = {
        "kind": "content_address", "algorithm": "sha256", "columns": ["SoftwareName"],
        "hex_len": 16, "case": "upper",
    }
    d["unmapped_columns"]["vulnerabilities.csv"]["SoftwareName"] = {"disposition": "ignored", "reason": "x"}
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="content_address is legal only for finding.finding_id"):
        validate_contract(contract, {"devices.csv": DEVICES_HEADER, "vulnerabilities.csv": VULNERABILITIES_HEADER})


def test_composed_illegal_outside_evidence():
    d = copy.deepcopy(mdvm_gen_dict())
    d["finding"]["product"] = {"kind": "composed", "join": " ", "parts": [{"join_nonblank": ["SoftwareName"], "join": " "}]}
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="composed is legal only for finding.evidence"):
        validate_contract(contract, {"devices.csv": DEVICES_HEADER, "vulnerabilities.csv": VULNERABILITIES_HEADER})


def test_missing_asset_slot_is_rejected_at_construction():
    d = copy.deepcopy(bluepeak_gen_dict())
    del d["asset"]["owner"]
    with pytest.raises(ValidationError, match="asset block must map exactly"):
        Contract.model_validate(d)


def test_extra_asset_slot_is_rejected_at_construction():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["asset"]["made_up_field"] = {"kind": "not_collected"}
    with pytest.raises(ValidationError, match="asset block must map exactly"):
        Contract.model_validate(d)


def test_single_file_layout_requires_equal_filenames():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["source"]["findings_filename"] = "other.csv"
    with pytest.raises(ValidationError, match="single_file"):
        Contract.model_validate(d)


def test_two_file_layout_forbids_equal_filenames():
    d = copy.deepcopy(mdvm_gen_dict())
    d["source"]["findings_filename"] = d["source"]["assets_filename"]
    with pytest.raises(ValidationError, match="two_file"):
        Contract.model_validate(d)


def test_two_file_layout_requires_a_findings_header():
    d = copy.deepcopy(mdvm_gen_dict())
    del d["header"]["findings"]
    with pytest.raises(ValidationError, match="header.findings is missing"):
        Contract.model_validate(d)


def test_single_file_layout_forbids_a_findings_header():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["header"]["findings"] = d["header"]["assets"]
    with pytest.raises(ValidationError, match="header.findings is present"):
        Contract.model_validate(d)


def test_default_by_illegal_target():
    d = copy.deepcopy(mdvm_gen_dict())
    d["asset"]["business_function"] = {"kind": "default_by", "table": "ROLE_DEFAULT_BY_OS_CLASS", "keyed_by": {"from": "os_platform", "output": "os_class"}}
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="may only feed 'role'"):
        validate_contract(contract, {"devices.csv": DEVICES_HEADER, "vulnerabilities.csv": VULNERABILITIES_HEADER})


def test_default_by_unregistered_table():
    d = copy.deepcopy(mdvm_gen_dict())
    d["asset"]["role"]["table"] = "SOME_OTHER_TABLE"
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="is not a registered table"):
        validate_contract(contract, {"devices.csv": DEVICES_HEADER, "vulnerabilities.csv": VULNERABILITIES_HEADER})


def test_missing_union_attestation_is_refused():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["attestations"] = [a for a in d["attestations"] if a["item"] != "union"]
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="'union' is required"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_missing_enrichment_attestation_is_refused():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["attestations"] = [a for a in d["attestations"] if a["item"] != "enrichment"]
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="'enrichment' is required"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_missing_finding_id_synthesized_attestation_is_refused():
    d = copy.deepcopy(mdvm_gen_dict())
    d["attestations"] = []
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="'finding_id.synthesized' is required"):
        validate_contract(contract, {"devices.csv": DEVICES_HEADER, "vulnerabilities.csv": VULNERABILITIES_HEADER})


def test_not_collected_disagreeing_with_mappings_is_refused():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["not_collected"]["always_asset"] = []
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="not_collected disagrees"):
        validate_contract(contract, BLUEPEAK_HEADERS)


# --- confirmation gate and digests ---------------------------------------


def test_confirmed_state_requires_confirmation_fields():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["review"] = {"state": "confirmed"}
    with pytest.raises(ValidationError, match="missing"):
        Contract.model_validate(d)


def test_content_digest_mismatch_is_refused():
    d = _confirmed(bluepeak_gen_dict())
    d["review"]["content_digest"] = "sha256:" + "0" * 64
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="content_digest mismatch"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_decision_digest_mismatch_is_refused():
    d = _confirmed(bluepeak_gen_dict())
    d["review"]["decision_digest"] = "sha256:" + "0" * 64
    contract = Contract.model_validate(d)
    with pytest.raises(ContractValidationError, match="decision_digest mismatch"):
        validate_contract(contract, BLUEPEAK_HEADERS)


def test_a_hand_edit_after_confirmation_invalidates_content_digest_but_not_decision_digest():
    """The two-digest split's whole point: re-probing (which only touches
    `observed`) must not void what a human confirmed."""
    confirmed = _confirmed(bluepeak_gen_dict())
    confirmed["observed"] = {"data_rows": 50, "fatal_problems": 0}
    contract = Contract.model_validate(confirmed)
    # content_digest now mismatches (observed changed)...
    with pytest.raises(ContractValidationError, match="content_digest mismatch"):
        validate_contract(contract, BLUEPEAK_HEADERS)
    # ...but decision_digest, which excludes observed, still matches.
    from rhinosecure.adapters.config_model import compute_decision_digest as _cdd
    assert _cdd(contract) == contract.review.decision_digest


def test_a_typo_fix_in_an_unmapped_column_reason_is_a_real_decision_change():
    """Unlike `observed`, unmapped_columns IS a decision subtree -- editing
    its reason text changes decision_digest too. This documents the
    boundary the digest split draws, rather than asserting it is invisible
    everywhere."""
    confirmed = _confirmed(bluepeak_gen_dict())
    contract_before = Contract.model_validate(confirmed)
    edited = copy.deepcopy(confirmed)
    edited["unmapped_columns"]["synthetic_cve_inventory_50.csv"]["Company"]["reason"] = "renamed reason"
    contract_after = Contract.model_validate(edited)
    from rhinosecure.adapters.config_model import compute_decision_digest as _cdd
    assert _cdd(contract_before) != _cdd(contract_after)


# --- unknown keys are refused everywhere, not silently ignored -----------


def test_unknown_top_level_key_is_rejected():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["totally_made_up_block"] = {}
    with pytest.raises(ValidationError):
        Contract.model_validate(d)


def test_unknown_key_on_a_mapping_node_is_rejected():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["asset"]["business_function"]["typo_key"] = "oops"
    with pytest.raises(ValidationError):
        Contract.model_validate(d)


def test_unknown_kind_is_rejected():
    d = copy.deepcopy(bluepeak_gen_dict())
    d["asset"]["business_function"] = {"kind": "regex_extract", "column": "Department", "blank": "gap"}
    with pytest.raises(ValidationError):
        Contract.model_validate(d)
