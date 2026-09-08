"""Slice 8 of docs/adapter-generation.md: `agents/schema_inference.py`'s
phase-1 proposal schema, its LLM-free evidence-grounding pass, and
deterministic assembly into a real `Contract`. No test here makes a real
LLM call -- `propose_contract`'s own tests monkeypatch `Crew` the same way
`test_coordinator.py` already does for every other agent, and every other
test drives `check_grounding`/`assemble_contract` directly against
`probe.profile_source` output over tmp_path CSVs."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from crewai.types.usage_metrics import UsageMetrics

import rhinosecure.agents.schema_inference as schema_inference_module
from rhinosecure.adapters.config_model import ASSET_SLOTS, FINDING_SLOTS, ColumnMapping, Contract, validate_contract
from rhinosecure.adapters.probe import profile_source
from rhinosecure.agents.schema_inference import (
    PROVISIONAL_ROLE_PLACEHOLDER,
    AdapterProposal,
    Generator,
    MappingLegalityError,
    ProposalGenerationError,
    ProposalIncompleteError,
    ProvisionalAssemblyNotes,
    SavedProposal,
    SchemaInferenceError,
    SlotMapped,
    SlotUnresolved,
    _apply_registry_aliases,
    _check_mapped_slots_legal,
    _reconcile_redundant_structural_columns,
    _resolve_layout,
    _validate_format_name,
    assemble_contract,
    assemble_provisional_contract,
    check_column_mapping_legal_values,
    check_grounding,
    dump_saved_proposal,
    load_saved_proposal,
    propose_contract,
    unresolved_slots,
)

_HEADER = ["Asset_ID", "Hostname", "Finding_ID", "Cve", "Col"]
_GENERATED_AT = "2026-09-04T00:00:00Z"


def _generator() -> Generator:
    return Generator(
        tool="rhino-adapt-propose", model="claude-sonnet-5", prompt_tokens=100, completion_tokens=50,
        estimated_cost_usd=0.001, attempts=1, call_log_digest="sha256:" + "a" * 64,
    )


def _mapped(mapping: dict, *, confidence: float = 0.9, columns_cited: list[str] | None = None) -> dict:
    return {
        "status": "mapped", "mapping": mapping, "confidence": confidence,
        "evidence": {"columns_cited": columns_cited or [], "sample_values_cited": [], "note": "test"},
    }


def _unresolved(reason: str = "no corresponding column", candidates: list[str] | None = None) -> dict:
    return {"status": "unresolved", "candidate_columns": candidates or [], "reason": reason}


def _full_proposal_dict(*, name: str = "min-test", overrides_asset: dict | None = None, overrides_finding: dict | None = None) -> dict:
    """Every asset/finding slot addressed: identity fields get a real
    'column'/'parsed' mapping over the shared fixture header, role/severity
    get a trivial single-entry vocabulary, and everything else is
    'not_collected' (all are gap-legal in this fixture's construction --
    mirrors test_adapters_config_model.py's own `_minimal_contract_mapping_one_target`
    helper) unless overridden by the caller for one specific test."""
    asset: dict = {}
    for slot in ASSET_SLOTS:
        if slot == "asset_id":
            asset[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Asset_ID"])
        elif slot == "hostname":
            asset[slot] = _mapped({"kind": "column", "column": "Hostname", "case": "exact", "blank": "fatal"}, columns_cited=["Hostname"])
        elif slot == "role":
            asset[slot] = _mapped(
                {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc"}},
                columns_cited=["Col"],
            )
        else:
            asset[slot] = _mapped({"kind": "not_collected"})
    finding: dict = {}
    for slot in FINDING_SLOTS:
        if slot == "finding_id":
            finding[slot] = _mapped({"kind": "column", "column": "Finding_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Finding_ID"])
        elif slot == "asset_id":
            finding[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Asset_ID"])
        elif slot == "cve_id":
            finding[slot] = _mapped({"kind": "parsed", "column": "Cve", "case": "upper", "blank": "fatal", "parser": "cve_id"}, columns_cited=["Cve"])
        elif slot == "scanner_severity":
            finding[slot] = _mapped(
                {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "low"}},
                columns_cited=["Col"],
            )
        elif slot in ("product", "evidence"):
            finding[slot] = _mapped({"kind": "column", "column": "Col", "case": "exact", "blank": "absent_fact"}, columns_cited=["Col"])
        else:
            finding[slot] = _mapped({"kind": "not_collected"})

    asset.update(overrides_asset or {})
    finding.update(overrides_finding or {})

    return {
        "meta": {
            "format": name, "description": "test fixture", "source_layout": "single_file",
            "assets_filename": "data.csv", "findings_filename": "data.csv", "reasoning_summary": "test",
        },
        "asset": asset, "finding": finding, "derived": {},
        "asset_grouping": {"key": "Asset_ID", "resolution": "agree_or_recency"},
        "finding_dedup": {"content_targets": ["scanner_severity"], "on_identical": "collapse_and_count", "on_conflict": "fatal"},
        "unmapped_columns": {},
        "open_questions": [],
    }


def _write_csv(directory: Path, header: list[str], rows: list[list[str]], name: str = "data.csv") -> Path:
    path = directory / name
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    return path


@pytest.fixture
def data_dir(tmp_path) -> Path:
    _write_csv(tmp_path, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks"],
    ])
    return tmp_path


@pytest.fixture
def profiles(data_dir):
    return {p.path.name: p for p in profile_source(data_dir)}


# --- AdapterProposal: completeness -------------------------------------------


def test_adapter_proposal_requires_every_asset_slot():
    data = _full_proposal_dict()
    del data["asset"]["role"]
    with pytest.raises(Exception, match="asset must address exactly"):
        AdapterProposal.model_validate(data)


def test_adapter_proposal_requires_every_finding_slot():
    data = _full_proposal_dict()
    del data["finding"]["cve_id"]
    with pytest.raises(Exception, match="finding must address exactly"):
        AdapterProposal.model_validate(data)


def test_adapter_proposal_accepts_unresolved_for_a_gap_legal_slot():
    data = _full_proposal_dict(overrides_asset={"patch_window": _unresolved()})
    proposal = AdapterProposal.model_validate(data)
    assert unresolved_slots(proposal) == ["asset.patch_window"]


def test_full_proposal_fixture_parses_cleanly():
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    assert unresolved_slots(proposal) == []


# --- check_grounding ----------------------------------------------------------


def test_grounding_is_clean_for_the_fully_valid_fixture(profiles):
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    report = check_grounding(proposal, profiles)
    assert report.failures == []
    assert report.caveats == []


def test_grounding_fails_on_a_hallucinated_column(profiles):
    data = _full_proposal_dict(overrides_asset={
        "owner": _mapped({"kind": "column", "column": "Owner_Column_That_Does_Not_Exist", "case": "exact", "blank": "gap"}),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "asset.owner" in report.failed_slots
    assert any("Owner_Column_That_Does_Not_Exist" in i.message for i in report.failures)


def test_grounding_fails_when_vocabulary_key_not_among_measured_values(profiles):
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc", "nonexistent-token": "sql"}},
            columns_cited=["Col"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "asset.role" in report.failed_slots
    assert any("nonexistent-token" in i.message for i in report.failures)


def test_grounding_passes_when_every_vocabulary_key_was_measured(profiles):
    # "srv" and "wks" are the only two values the fixture's Col column takes.
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc", "wks": "workstation"}},
            columns_cited=["Col"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert report.failures == []


def test_grounding_fails_when_literal_cites_no_constant_column(profiles):
    data = _full_proposal_dict(overrides_asset={
        "environment": _mapped({"kind": "literal", "value": "prod"}, columns_cited=[]),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "asset.environment" in report.failed_slots
    assert any("literal mapping cites no column tagged 'constant'" in i.message for i in report.failures)


def test_grounding_passes_when_literal_value_matches_the_measured_constant(tmp_path):
    _write_csv(tmp_path, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "srv"],
    ])
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}
    # "Hostname" is not constant across the two rows, so use a genuinely
    # constant column instead: with Col == "srv" on every row, Col is constant
    # -- and the literal's own value must match that observed constant, not
    # merely cite a column that happens to be constant.
    data = _full_proposal_dict(overrides_asset={
        "environment": _mapped({"kind": "literal", "value": "srv"}, columns_cited=["Col"]),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles_map)
    assert "asset.environment" not in report.failed_slots


def test_grounding_fails_when_literal_value_does_not_match_the_measured_constant(tmp_path):
    """The literal must be grounded in what the column actually observed,
    not merely cite SOME constant-tagged column regardless of its value --
    a model could otherwise cite a real constant column while asserting any
    value at all."""
    _write_csv(tmp_path, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "srv"],
    ])
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_asset={
        "environment": _mapped({"kind": "literal", "value": "prod"}, columns_cited=["Col"]),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles_map)
    assert "asset.environment" in report.failed_slots
    assert any("does not match the observed constant value" in i.message for i in report.failures)


def test_grounding_checks_unresolved_candidate_columns_too(profiles):
    data = _full_proposal_dict(overrides_asset={
        "owner": _unresolved(candidates=["Nonexistent_Column"]),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "asset.owner" in report.failed_slots


def test_grounding_checks_unmapped_columns_keys_exist(profiles):
    data = _full_proposal_dict()
    data["unmapped_columns"] = {"data.csv": {"Ghost_Column": {"disposition": "ignored", "reason": "test", "profile_cited": "n/a"}}}
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert any("Ghost_Column" in i.message for i in report.failures)


def test_grounding_distinct_overflow_is_a_caveat_not_a_failure(tmp_path):
    from rhinosecure.adapters.probe import MAX_DISTINCT_TRACKED

    rows = [["A%03d" % i, f"HOST{i}", "F%03d" % i, "CVE-2021-0001", f"role-{i}"] for i in range(MAX_DISTINCT_TRACKED + 5)]
    _write_csv(tmp_path, _HEADER, rows)
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}
    assert profiles_map["data.csv"].columns["Col"].distinct_overflow

    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"role-0": "dc", "a-token-never-seen": "sql"}},
            columns_cited=["Col"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles_map)
    assert "asset.role" not in report.failed_slots  # never blocks assembly
    assert any("asset.role" == i.slot for i in report.caveats)
    assert any("INCOMPLETE" in i.message for i in report.caveats)


# --- assemble_contract --------------------------------------------------------


def test_assemble_contract_refuses_when_a_slot_is_unresolved(profiles):
    data = _full_proposal_dict(overrides_asset={"owner": _unresolved()})
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    with pytest.raises(ProposalIncompleteError, match="asset.owner"):
        assemble_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)


def test_assemble_contract_refuses_when_grounding_failed(profiles):
    data = _full_proposal_dict(overrides_asset={
        "owner": _mapped({"kind": "column", "column": "Ghost", "case": "exact", "blank": "gap"}),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    with pytest.raises(ProposalIncompleteError, match="asset.owner"):
        assemble_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)


def test_assemble_contract_succeeds_and_the_result_validates(profiles):
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    report = check_grounding(proposal, profiles)
    contract = assemble_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert isinstance(contract, Contract)
    assert contract.review.state == "proposed"
    assert contract.format == "min-test"
    validate_contract(contract, {"data.csv": _HEADER})


def test_assemble_contract_carries_every_slots_confidence_into_the_contract(profiles):
    """`asset_mappings`/`finding_mappings` (assemble_contract's own local
    variables, right above where mapping_confidence is built) keep only
    `.mapping`, discarding `.confidence`/`.evidence` from every SlotMapped
    -- mapping_confidence is the ONE place `.confidence` survives past this
    function, carried forward as Contract audit trail (never read by
    configured.py's engine) so a browser/CLI reviewer can see it without
    needing the original proposal file, which a hand-authored contract
    (bluepeak-gen.json/mdvm-gen.json) never had in the first place."""
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc"}},
            confidence=0.55, columns_cited=["Col"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    contract = assemble_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract.mapping_confidence["asset.role"] == 0.55
    assert contract.mapping_confidence["asset.asset_id"] == 0.9  # _mapped's own default
    assert contract.mapping_confidence["finding.cve_id"] == 0.9
    assert len(contract.mapping_confidence) == len(ASSET_SLOTS) + len(FINDING_SLOTS)


def test_a_low_confidence_scoring_slot_requires_attestation_before_it_can_confirm(profiles):
    from rhinosecure.adapters.config_model import missing_attestations

    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc"}},
            confidence=0.5, columns_cited=["Col"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    contract = assemble_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert "low_confidence_mappings" in missing_attestations(contract)


# --- assemble_provisional_contract -------------------------------------------


def test_provisional_assembly_neutralizes_an_entirely_unresolved_scoring_field(profiles):
    """criticality is gap-legal (NOT_COLLECTED_DEFAULTS has an entry), so it
    gets a real not_collected mapping (the contract stays constructible) --
    but it's ALSO a scoring input, so it lands in neutralized_axes too:
    the placeholder default is never trusted for the risk number itself."""
    data = _full_proposal_dict(overrides_asset={"criticality": _unresolved()})
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    contract, notes = assemble_provisional_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is not None
    assert notes.hard_stop_reason is None
    assert notes.neutralized_axes == frozenset({"criticality"})
    assert contract.asset["criticality"].kind == "not_collected"
    validate_contract(contract, {"data.csv": _HEADER})


def test_provisional_assembly_gives_role_a_literal_placeholder_and_neutralizes_it(profiles):
    """role has no NOT_COLLECTED_DEFAULTS entry at all -- a bare not_collected
    mapping would be illegal (and would KeyError in the engine before that).
    literal(PROVISIONAL_ROLE_PLACEHOLDER) is the one grammar-legal way to
    give it a real, schema-valid value without asserting a fact -- and it's
    always neutralized, so that placeholder is never actually read."""
    data = _full_proposal_dict(overrides_asset={"role": _unresolved()})
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    contract, notes = assemble_provisional_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is not None
    assert notes.neutralized_axes == frozenset({"role"})
    role_mapping = contract.asset["role"]
    assert role_mapping.kind == "literal"
    assert role_mapping.value == PROVISIONAL_ROLE_PLACEHOLDER
    validate_contract(contract, {"data.csv": _HEADER})


def test_provisional_assembly_auto_fills_a_non_scoring_gap_legal_field_without_neutralizing(profiles):
    """owner is gap-legal but never feeds scoring.py at all -- auto-filled
    exactly like a Defender export already does unconditionally, and never
    added to neutralized_axes (there is no axis for it to neutralize)."""
    data = _full_proposal_dict(overrides_asset={"owner": _unresolved()})
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    contract, notes = assemble_provisional_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is not None
    assert notes.neutralized_axes == frozenset()
    assert contract.asset["owner"].kind == "not_collected"


def test_provisional_assembly_auto_fills_absent_fact_only_fields_via_empty_literal(profiles):
    """product has NO not_collected default (config_model.GAP_LEGAL_TARGETS
    excludes it) but IS in ABSENT_FACT_LEGAL_TARGETS -- the schema's own
    'blank is the fact' encoding, so literal("") is the honest fill."""
    data = _full_proposal_dict(overrides_finding={"product": _unresolved()})
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    contract, notes = assemble_provisional_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is not None
    product_mapping = contract.finding["product"]
    assert product_mapping.kind == "literal"
    assert product_mapping.value == ""


@pytest.mark.parametrize("target", ["asset_id", "hostname"])
def test_provisional_assembly_hard_stops_on_an_unresolved_asset_identity_field(profiles, target):
    data = _full_proposal_dict(overrides_asset={target: _unresolved()})
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    contract, notes = assemble_provisional_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is None
    assert notes.hard_stop_reason is not None
    assert f"asset.{target}" in notes.hard_stop_reason


def test_provisional_assembly_hard_stops_on_unresolved_scanner_severity(profiles):
    """Deliberately NOT neutralized -- severity_base is a base value, not a
    weighted composite term, and scanner_severity's real impact varies per
    finding (NVD may cover the gap for some), unlike a uniformly-missing
    Impact axis. See _PROVISIONAL_HARD_STOP_TARGETS' own docstring."""
    data = _full_proposal_dict(overrides_finding={"scanner_severity": _unresolved()})
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    contract, notes = assemble_provisional_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is None
    assert "finding.scanner_severity" in notes.hard_stop_reason


def test_provisional_assembly_still_refuses_a_real_grounding_failure(profiles):
    """A genuine data-quality problem (a cited column that isn't real) is
    not a coverage gap -- it stays a hard stop, exactly like
    assemble_contract, never silently degraded around."""
    data = _full_proposal_dict(overrides_asset={
        "owner": _mapped({"kind": "column", "column": "Ghost", "case": "exact", "blank": "gap"}),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert report.failures
    contract, notes = assemble_provisional_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is None
    assert "asset.owner" in notes.hard_stop_reason
    assert notes.neutralized_axes == frozenset()


def test_provisional_assembly_of_a_fully_resolved_proposal_behaves_like_assemble_contract(profiles):
    """No unresolved slots at all -- the provisional path should produce
    the identical contract assemble_contract would, with an empty notes
    object, never a spurious neutralization."""
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    report = check_grounding(proposal, profiles)
    contract, notes = assemble_provisional_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is not None
    assert notes == ProvisionalAssemblyNotes()
    strict_contract = assemble_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract.asset == strict_contract.asset
    assert contract.finding == strict_contract.finding


# --- assemble_provisional_contract: a SlotMapped mapping that is individually
# illegal (the real bug: every slot mapped and grounded, but the assembled
# contract still fails validate_contract) -------------------------------------


def test_provisional_assembly_drops_a_mapped_but_illegal_blank_policy_and_reports_it(tmp_path):
    """The real bug this fix closes: the model fully MAPPED asset.role (a
    real vocabulary reading a real column) but declared blank='gap',
    illegal for role (no NOT_COLLECTED_DEFAULTS entry). check_grounding
    cannot catch this -- it only checks that cited columns/table-keys are
    real -- so this reaches assemble_provisional_contract as a SlotMapped,
    not an unresolved one. The dropped mapping's own column
    ("RoleColUnique", read by nothing else here) becomes orphaned; the fix
    must reconcile that too, not just replace the mapping."""
    header = _HEADER + ["RoleColUnique"]
    _write_csv(tmp_path, header, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv", "Workstation"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks", "Workstation"],
    ])
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}

    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "RoleColUnique", "case": "exact", "blank": "gap", "optional": True,
             "table": {"Workstation": "workstation"}},
            columns_cited=["RoleColUnique"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)  # must NOT raise -- --from-proposal must stay loadable
    report = check_grounding(proposal, profiles_map)
    assert report.failures == []  # grounding cannot see this; it's a legality problem, not a hallucination

    with pytest.raises(ProposalIncompleteError, match="asset.role"):
        assemble_contract(proposal, profiles_map, report, generator=_generator(), generated_at=_GENERATED_AT)

    contract, notes = assemble_provisional_contract(proposal, profiles_map, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is not None
    assert notes.hard_stop_reason is None
    assert notes.invalid_mappings_dropped == frozenset({"asset.role"})
    assert notes.neutralized_axes == frozenset({"role"})
    role_mapping = contract.asset["role"]
    assert role_mapping.kind == "literal"
    assert role_mapping.value == PROVISIONAL_ROLE_PLACEHOLDER
    assert "RoleColUnique" in contract.unmapped_columns["data.csv"]
    assert contract.unmapped_columns["data.csv"]["RoleColUnique"].disposition == "deliberately_dropped"
    validate_contract(contract, {"data.csv": header})


def test_provisional_assembly_drops_a_mapped_but_illegal_parser_and_reports_it(tmp_path):
    """finding.detected_date mapped with parser='timestamp' -- legal ONLY
    inside asset_grouping.order_by, illegal on a plain per-row `parsed`
    mapping. detected_date is gap-legal but not a scoring axis, so it is
    dropped (not_collected) WITHOUT being neutralized -- distinct from
    role, and exactly why invalid_mappings_dropped exists separately from
    neutralized_axes."""
    header = _HEADER + ["DateColUnique"]
    _write_csv(tmp_path, header, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv", "2026-01-01T00:00:00Z"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks", "2026-01-02T00:00:00Z"],
    ])
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}

    data = _full_proposal_dict(overrides_finding={
        "detected_date": _mapped(
            {"kind": "parsed", "column": "DateColUnique", "case": "exact", "blank": "gap", "optional": True, "parser": "timestamp"},
            columns_cited=["DateColUnique"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles_map)
    assert report.failures == []

    contract, notes = assemble_provisional_contract(proposal, profiles_map, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is not None
    assert notes.hard_stop_reason is None
    assert notes.invalid_mappings_dropped == frozenset({"finding.detected_date"})
    assert notes.neutralized_axes == frozenset()
    assert contract.finding["detected_date"].kind == "not_collected"
    assert "DateColUnique" in contract.unmapped_columns["data.csv"]
    validate_contract(contract, {"data.csv": header})


def test_provisional_assembly_drops_multiple_illegal_mappings_in_one_pass(tmp_path):
    """The real bug, reproduced directly: a proposal with EVERY slot mapped
    and grounded, but TWO independently illegal mappings (role's blank
    policy, detected_date's parser placement), each orphaning its own
    column. validate_contract's own "name every offender in one message"
    discipline means both are reported together; one degrade pass must fix
    both and reconcile both orphaned columns in the same retry."""
    header = _HEADER + ["RoleColUnique", "DateColUnique"]
    _write_csv(tmp_path, header, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv", "Workstation", "2026-01-01T00:00:00Z"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks", "Workstation", "2026-01-02T00:00:00Z"],
    ])
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}

    data = _full_proposal_dict(
        overrides_asset={
            "role": _mapped(
                {"kind": "vocabulary", "column": "RoleColUnique", "case": "exact", "blank": "gap", "optional": True,
                 "table": {"Workstation": "workstation"}},
                columns_cited=["RoleColUnique"],
            ),
        },
        overrides_finding={
            "detected_date": _mapped(
                {"kind": "parsed", "column": "DateColUnique", "case": "exact", "blank": "gap", "optional": True, "parser": "timestamp"},
                columns_cited=["DateColUnique"],
            ),
        },
    )
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles_map)
    assert report.failures == []

    with pytest.raises(ProposalIncompleteError) as excinfo:
        assemble_contract(proposal, profiles_map, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert "asset.role" in str(excinfo.value)
    assert "finding.detected_date" in str(excinfo.value)

    contract, notes = assemble_provisional_contract(proposal, profiles_map, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is not None
    assert notes.hard_stop_reason is None
    assert notes.invalid_mappings_dropped == frozenset({"asset.role", "finding.detected_date"})
    assert notes.neutralized_axes == frozenset({"role"})
    assert contract.asset["role"].kind == "literal"
    assert contract.finding["detected_date"].kind == "not_collected"
    assert set(contract.unmapped_columns["data.csv"]) >= {"RoleColUnique", "DateColUnique"}
    validate_contract(contract, {"data.csv": header})


def test_reconcile_redundant_structural_columns_only_drops_genuinely_structural_columns():
    """`_reconcile_redundant_structural_columns` never guesses: every
    remaining problem must be the exact V08 "both mapped and listed"
    message, for the assets file specifically, naming only columns
    `structural_site_columns` actually recognizes -- anything else declines
    (`None`), the same "recover only the exact known shape" discipline
    `_reconcile_orphaned_columns` already applies to the mirror-image
    case."""
    from rhinosecure.adapters.config_model import AssetGrouping, AssetGroupingOrderBy

    ag = AssetGrouping(key="Asset_ID", order_by=AssetGroupingOrderBy(column="Last_Observed", parser="timestamp"))

    assert _reconcile_redundant_structural_columns(
        ("column(s) ['Last_Observed'] are both mapped and listed in unmapped_columns['data.csv']",),
        ag, "data.csv",
    ) == frozenset({"Last_Observed"})

    # wrong file -- asset_grouping has no finding-side equivalent
    assert _reconcile_redundant_structural_columns(
        ("column(s) ['Last_Observed'] are both mapped and listed in unmapped_columns['other.csv']",),
        ag, "data.csv",
    ) is None

    # a column that is NOT actually a structural site -- a real, different
    # mistake, never silently absorbed
    assert _reconcile_redundant_structural_columns(
        ("column(s) ['Something_Else'] are both mapped and listed in unmapped_columns['data.csv']",),
        ag, "data.csv",
    ) is None

    # a genuinely unrelated (differently-shaped) problem alongside a real
    # match -- PARTITIONS rather than declining entirely: the redundant
    # column is still resolved, the unrelated problem is simply left for
    # whatever the caller runs next (_degrade_invalid_slots). This is the
    # real, live shape: both problems in the SAME validate_contract failure.
    assert _reconcile_redundant_structural_columns(
        (
            "column(s) ['Last_Observed'] are both mapped and listed in unmapped_columns['data.csv']",
            "finding.detected_date: parser 'timestamp' is legal only inside asset_grouping.order_by, "
            "never on a per-row mapping -- for a per-row target, use one of these parsers instead: "
            "['bool', 'cve_id', 'date', 'float']",
        ),
        ag, "data.csv",
    ) == frozenset({"Last_Observed"})

    # a "both mapped and listed" problem that DOES match the shape but
    # names a non-structural column ALONGSIDE an unrelated one -- still
    # refused outright (unlike the case above): this is a real, different
    # contradiction this function has no business silently resolving.
    assert _reconcile_redundant_structural_columns(
        (
            "column(s) ['Something_Else'] are both mapped and listed in unmapped_columns['data.csv']",
            "finding.detected_date: parser 'timestamp' is legal only inside asset_grouping.order_by, "
            "never on a per-row mapping -- for a per-row target, use one of these parsers instead: "
            "['bool', 'cve_id', 'date', 'float']",
        ),
        ag, "data.csv",
    ) is None


def test_provisional_assembly_degrades_a_redundant_order_by_column_alongside_an_illegal_slot(tmp_path):
    """The exact real, live-reported shape (job a03c6bf6289346e1b84d48ef0a4cab64,
    northgate_flat_3.csv): a column used ONLY by asset_grouping.order_by
    (parser='timestamp', legal there) is ALSO redundantly listed in
    unmapped_columns, in the SAME proposal as a genuinely illegal per-row
    mapping (finding.detected_date, parser='timestamp', illegal there).
    Before structural_site_columns existed, the redundant-column problem
    was UNATTRIBUTED, so _degrade_invalid_slots's own gate ("if not by_slot
    or unattributed: return str(exc)") refused the WHOLE batch outright --
    even though the slot-level problem was, on its own, exactly as
    mechanically recoverable as any other illegal mapping. Both are now
    resolved in one pass, and assembly succeeds."""
    header = _HEADER + ["Last_Observed"]
    _write_csv(tmp_path, header, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv", "2026-01-01T00:00:00Z"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks", "2026-01-02T00:00:00Z"],
    ])
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}

    data = _full_proposal_dict(overrides_finding={
        "detected_date": _mapped(
            {"kind": "parsed", "column": "Col", "case": "exact", "blank": "gap", "parser": "timestamp"},
            columns_cited=["Col"],
        ),
    })
    data["asset_grouping"] = {
        "key": "Asset_ID",
        "order_by": {"column": "Last_Observed", "parser": "timestamp", "required": False},
        "resolution": "agree_or_recency",
    }
    data["unmapped_columns"] = {
        "data.csv": {
            "Last_Observed": {
                "disposition": "evidence_only",
                "reason": "Used only as the order_by column -- not mapped to any target field directly.",
                "profile_cited": "test",
            },
        },
    }
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles_map)
    assert report.failures == []  # purely a legality/accounting problem, not a grounding one

    with pytest.raises(ProposalIncompleteError) as excinfo:
        assemble_contract(proposal, profiles_map, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert "both mapped and listed" in str(excinfo.value)
    assert "finding.detected_date" in str(excinfo.value)

    contract, notes = assemble_provisional_contract(proposal, profiles_map, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is not None
    assert notes.hard_stop_reason is None
    assert notes.invalid_mappings_dropped == frozenset({"finding.detected_date"})
    assert "Last_Observed" not in contract.unmapped_columns.get("data.csv", {})
    validate_contract(contract, {"data.csv": header})


def test_provisional_assembly_hard_stops_when_an_illegal_mapping_has_no_placeholder(tmp_path):
    """finding.cve_id is a hard-stop identity target -- an illegal mapping
    on it (parser='timestamp', legal only in asset_grouping.order_by)
    cannot be silently dropped to a placeholder the way role/detected_date
    can; assemble_provisional_contract must hard-stop, not guess."""
    _write_csv(tmp_path, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks"],
    ])
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_finding={
        "cve_id": _mapped({"kind": "parsed", "column": "Cve", "case": "upper", "blank": "fatal", "parser": "timestamp"}, columns_cited=["Cve"]),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles_map)
    assert report.failures == []

    contract, notes = assemble_provisional_contract(proposal, profiles_map, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract is None
    assert "finding.cve_id" in notes.hard_stop_reason
    assert "no legal provisional placeholder" in notes.hard_stop_reason


# --- _check_mapped_slots_legal: closing the grammar at FRESH generation ------


def test_check_mapped_slots_legal_flags_an_illegal_mapping(profiles):
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped({"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "gap", "table": {"srv": "dc"}}, columns_cited=["Col"]),
    })
    proposal = AdapterProposal.model_validate(data)  # must NOT raise -- see module docstring
    with pytest.raises(MappingLegalityError, match="asset.role"):
        _check_mapped_slots_legal(proposal, profiles)


def test_check_mapped_slots_legal_passes_the_valid_fixture(profiles):
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    _check_mapped_slots_legal(proposal, profiles)  # must not raise


def test_assemble_contract_a_caveat_alone_does_not_block(tmp_path):
    from rhinosecure.adapters.probe import MAX_DISTINCT_TRACKED

    rows = [["A%03d" % i, f"HOST{i}", "F%03d" % i, "CVE-2021-0001", "srv" if i == 0 else f"role-{i}"] for i in range(MAX_DISTINCT_TRACKED + 5)]
    _write_csv(tmp_path, _HEADER, rows)
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}

    data = _full_proposal_dict(overrides_asset={
        "role": _mapped({"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc"}}, columns_cited=["Col"]),
    })
    finding = data["finding"]
    finding["scanner_severity"] = _mapped({"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "low"}}, columns_cited=["Col"])
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles_map)
    assert report.failures == []
    contract = assemble_contract(proposal, profiles_map, report, generator=_generator(), generated_at=_GENERATED_AT)
    validate_contract(contract, {"data.csv": _HEADER})


# --- _resolve_layout / _validate_format_name ----------------------------------


def test_resolve_layout_single_csv_is_single_file(tmp_path):
    _write_csv(tmp_path, _HEADER, [["A01", "H", "F01", "CVE-2021-0001", "x"]])
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}
    layout, assets_f, findings_f = _resolve_layout(profiles_map, None, None)
    assert layout == "single_file"
    assert assets_f == findings_f == "data.csv"


def test_resolve_layout_two_csvs_requires_explicit_filenames(tmp_path):
    _write_csv(tmp_path, ["Asset_ID"], [["A01"]], name="assets.csv")
    _write_csv(tmp_path, ["Finding_ID"], [["F01"]], name="findings.csv")
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}
    with pytest.raises(SchemaInferenceError, match="ambiguous"):
        _resolve_layout(profiles_map, None, None)
    layout, assets_f, findings_f = _resolve_layout(profiles_map, "assets.csv", "findings.csv")
    assert layout == "two_file"
    assert (assets_f, findings_f) == ("assets.csv", "findings.csv")


def test_resolve_layout_rejects_an_unknown_filename(tmp_path):
    _write_csv(tmp_path, ["Asset_ID"], [["A01"]], name="assets.csv")
    _write_csv(tmp_path, ["Finding_ID"], [["F01"]], name="findings.csv")
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}
    with pytest.raises(SchemaInferenceError):
        _resolve_layout(profiles_map, "nope.csv", "findings.csv")


@pytest.mark.parametrize("name", ["Bad-Name", "-leading-dash", "UPPERCASE"])
def test_validate_format_name_rejects_bad_pattern(name):
    with pytest.raises(SchemaInferenceError):
        _validate_format_name(name)


def test_validate_format_name_rejects_builtin_collision():
    with pytest.raises(SchemaInferenceError, match="built-in"):
        _validate_format_name("native")


def test_validate_format_name_rejects_reserved_label():
    with pytest.raises(SchemaInferenceError, match="reserved"):
        _validate_format_name("nvd")


def test_validate_format_name_accepts_a_good_name():
    _validate_format_name("my-new-source")  # must not raise


# --- SavedProposal round-trip --------------------------------------------------


def test_saved_proposal_round_trips_through_json(tmp_path):
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    saved = SavedProposal(proposal=proposal, generator=_generator())
    path = tmp_path / "saved.json"
    path.write_text(json.dumps(dump_saved_proposal(saved)), encoding="utf-8")
    loaded = load_saved_proposal(path)
    assert loaded.proposal == proposal
    assert loaded.generator == saved.generator


def test_load_saved_proposal_rejects_a_file_missing_the_expected_shape(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"proposal": {}}), encoding="utf-8")
    with pytest.raises(SchemaInferenceError, match="'proposal' and 'generator'"):
        load_saved_proposal(path)


# --- propose_contract: LLM call is faked, mirroring test_coordinator.py -------


class _QueuedFakeCrew:
    """`kickoff()` increments the REAL agent's `agent.llm`'s own cumulative
    usage counter (`_track_token_usage_internal`, crewai's own method) by a
    fixed 111/22 per call, mirroring exactly what a real Anthropic response
    would do -- production code now reads per-attempt usage via `agent.llm
    .get_token_usage_summary().delta_since(baseline)` (schema_inference.py),
    not `crew.usage_metrics`, because `crew.usage_metrics` is documented as
    cumulative for the LLM instance's lifetime, and this suite's own agent
    is deliberately reused across every retry attempt (the identical reuse
    that made a real 3-attempt run's completion-token count for attempt 3
    alone exceed the whole run's real total -- PROGRESS.md 2026-09-06).
    Setting `self.usage_metrics` too, for any future direct caller of it."""

    queue: list = []
    instantiations: int = 0
    descriptions: list = []

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.agents = agents
        self.tasks = tasks
        self.usage_metrics = UsageMetrics(prompt_tokens=111, completion_tokens=22, total_tokens=133)
        type(self).instantiations += 1

    def kickoff(self):
        for agent in self.agents:
            agent.llm._track_token_usage_internal(
                {"prompt_tokens": 111, "completion_tokens": 22, "total_tokens": 133}
            )
        for task in self.tasks:
            _QueuedFakeCrew.descriptions.append(task.description)
            task.output = SimpleNamespace(raw=_QueuedFakeCrew.queue.pop(0))
        return None


@pytest.fixture(autouse=True)
def fake_crew(monkeypatch):
    _QueuedFakeCrew.queue = []
    _QueuedFakeCrew.instantiations = 0
    _QueuedFakeCrew.descriptions = []
    monkeypatch.setattr(schema_inference_module, "Crew", _QueuedFakeCrew)
    return _QueuedFakeCrew


UNPARSEABLE = "this is not json and will never parse"


def test_propose_contract_happy_path_parses_first_try(data_dir):
    _QueuedFakeCrew.queue = [json.dumps(_full_proposal_dict())]
    result = propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT)
    assert result.contract is not None
    assert result.grounding.failures == []
    assert result.generator.prompt_tokens == 111
    assert result.generator.attempts == 1
    assert _QueuedFakeCrew.instantiations == 1


def test_propose_contract_retries_on_unparseable_output_then_succeeds(data_dir):
    _QueuedFakeCrew.queue = [UNPARSEABLE, json.dumps(_full_proposal_dict())]
    result = propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, max_attempts=3)
    assert result.contract is not None
    assert result.generator.attempts == 2
    assert _QueuedFakeCrew.instantiations == 2


def test_propose_contract_gives_up_after_max_attempts(data_dir):
    _QueuedFakeCrew.queue = [UNPARSEABLE, UNPARSEABLE]
    with pytest.raises(ProposalGenerationError, match="gave up after 2 attempt"):
        propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, max_attempts=2)


def test_propose_contract_degrades_instead_of_raising_when_retries_exhaust_on_an_illegal_mapping(data_dir):
    """The regression this guards against: `_check_mapped_slots_legal` now
    catches an individually-illegal mapping INSIDE the retry loop, before
    `_check_mapped_slots_legal` existed the same mapping would sail through
    to `assemble_contract`'s own `validate_contract` safety net, which
    already treats this as a normal, non-raising 'incomplete' `ProposeResult`
    (see `test_propose_contract_reports_an_incomplete_proposal_without_
    raising`) -- never a hard `ProposalGenerationError`. Catching the
    problem EARLIER must not make a degradable failure FATAL: if the model
    keeps re-proposing the same illegal mapping across every attempt (no
    legal alternative in view -- see the parser-placement message fix
    below), retry exhaustion must fall through to that identical
    non-raising outcome, not kill the job. That is what lets a caller's
    provisional-path degrade mechanism (`assemble_provisional_contract`)
    drop just this one slot and keep the rest of the run -- a bad mapping
    should cost one field, not the job. Reproduces the real reported shape
    exactly: `finding.detected_date` mapped with `parser='timestamp'`, legal
    only inside `asset_grouping.order_by`, never on a per-row mapping."""
    illegal = json.dumps(_full_proposal_dict(overrides_finding={
        "detected_date": _mapped(
            {"kind": "parsed", "column": "Col", "case": "exact", "blank": "gap", "parser": "timestamp"},
            columns_cited=["Col"],
        ),
    }))
    _QueuedFakeCrew.queue = [illegal, illegal, illegal]
    result = propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, max_attempts=3)
    assert result.contract is None
    assert result.incomplete_reason is not None
    assert "finding.detected_date" in result.incomplete_reason
    assert "parser 'timestamp'" in result.incomplete_reason
    assert result.generator.attempts == 3
    assert _QueuedFakeCrew.instantiations == 3
    assert [entry["outcome"] for entry in result.attempt_usage] == ["illegal_mapping"] * 3


def test_propose_contract_still_raises_when_no_attempt_ever_produced_a_usable_candidate(data_dir):
    """The degrade fallback is scoped to `MappingLegalityError` specifically
    -- a candidate that parsed and matched the requested meta facts, just
    with one individually-illegal slot. A genuine parse failure never
    produces an `AdapterProposal` at all, so there is nothing to degrade;
    this must still raise exactly as before."""
    _QueuedFakeCrew.queue = [UNPARSEABLE, UNPARSEABLE, UNPARSEABLE]
    with pytest.raises(ProposalGenerationError, match="gave up after 3 attempt"):
        propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, max_attempts=3)


def test_a_total_failure_still_reports_what_every_discarded_attempt_cost(data_dir):
    """The real gap found running this exact path live (PROGRESS.md
    2026-09-06): a TOTAL failure used to raise before per-attempt usage was
    attached to anything, discarding the one number a human most needs
    when nothing got written. Confirmed on the exception itself, not just
    on a successful `ProposeResult` (`test_propose_contract_records_one_
    usage_entry_per_attempt`, above)."""
    _QueuedFakeCrew.queue = [UNPARSEABLE, UNPARSEABLE]
    with pytest.raises(ProposalGenerationError) as excinfo:
        propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, max_attempts=2)
    exc = excinfo.value
    assert [entry["attempt"] for entry in exc.attempt_usage] == [1, 2]
    assert all(entry["outcome"] == "parse_error" for entry in exc.attempt_usage)
    assert all(
        entry["prompt_tokens"] == 111 and entry["completion_tokens"] == 22 for entry in exc.attempt_usage
    )
    assert exc.estimated_cost_usd > 0


def test_propose_contract_treats_a_meta_mismatch_as_a_retryable_failure(data_dir):
    wrong_meta = _full_proposal_dict(name="a-different-name")
    right_meta = _full_proposal_dict(name="min-test")
    _QueuedFakeCrew.queue = [json.dumps(wrong_meta), json.dumps(right_meta)]
    result = propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, max_attempts=3)
    assert result.proposal.meta.format == "min-test"
    assert _QueuedFakeCrew.instantiations == 2


def test_propose_contract_reports_an_incomplete_proposal_without_raising(data_dir):
    data = _full_proposal_dict(overrides_asset={"owner": _unresolved()})
    _QueuedFakeCrew.queue = [json.dumps(data)]
    result = propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT)
    assert result.contract is None
    assert "asset.owner" in unresolved_slots(result.proposal)


def test_propose_contract_from_proposal_skips_the_llm_entirely(data_dir):
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    saved = SavedProposal(proposal=proposal, generator=_generator())
    result = propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, from_proposal=saved)
    assert result.contract is not None
    assert _QueuedFakeCrew.instantiations == 0


def test_propose_contract_from_proposal_rejects_a_mismatched_name(data_dir):
    proposal = AdapterProposal.model_validate(_full_proposal_dict(name="min-test"))
    saved = SavedProposal(proposal=proposal, generator=_generator())
    with pytest.raises(SchemaInferenceError):
        propose_contract(data_dir, "a-completely-different-name", generated_at=_GENERATED_AT, from_proposal=saved)


def test_propose_contract_rejects_a_bad_format_name_before_touching_the_llm(data_dir):
    with pytest.raises(SchemaInferenceError):
        propose_contract(data_dir, "native", generated_at=_GENERATED_AT)  # collides with a built-in format
    assert _QueuedFakeCrew.instantiations == 0


# --- fixes from the post-implementation adversarial review --------------------
# Everything below targets a specific gap that review surfaced: case-transform
# grounding, optional-column grounding, enrichment grounding, derived/
# default_by/composed/content_address coverage, a genuine two-file layout run
# end to end, and assemble_contract's new validate_contract safety net.


def test_grounding_applies_case_before_checking_vocabulary_table_keys(tmp_path):
    """A vocabulary table's keys are matched against the CASED observed
    values, not the raw ones -- configured.py applies the same case
    transform before its own table.get(...) lookup, so grounding must
    mirror that or it wrongly rejects a correct, working mapping."""
    _write_csv(tmp_path, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "SRV"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "WKS"],
    ])
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc", "wks": "workstation"}},
            columns_cited=["Col"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles_map)
    assert report.failures == []


def test_grounding_fails_a_vocabulary_table_key_case_mismatch_only_when_case_is_exact(tmp_path):
    """The reverse: with case='exact' (no transform), a table key that
    disagrees with the raw observed casing is genuinely ungrounded."""
    _write_csv(tmp_path, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "SRV"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "WKS"],
    ])
    profiles_map = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "Col", "case": "exact", "blank": "fatal", "table": {"srv": "dc"}},
            columns_cited=["Col"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles_map)
    assert "asset.role" in report.failed_slots


def test_grounding_does_not_fail_an_optional_column_absent_from_this_export(profiles):
    """Mirrors config_model._compute_not_collected's own rule: an optional
    mapping whose column the header lacks is a legitimate not-collected
    case, not a hallucination -- grounding must not block it."""
    data = _full_proposal_dict(overrides_asset={
        "owner": _mapped({"kind": "column", "column": "Owner_Not_In_This_Export", "case": "exact", "blank": "gap", "optional": True}),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "asset.owner" not in report.failed_slots


def test_grounding_still_fails_a_required_missing_column(profiles):
    """Same missing column, but NOT marked optional -- still a failure."""
    data = _full_proposal_dict(overrides_asset={
        "owner": _mapped({"kind": "column", "column": "Owner_Not_In_This_Export", "case": "exact", "blank": "gap", "optional": False}),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "asset.owner" in report.failed_slots


def test_grounding_checks_enrichment_columns(profiles):
    data = _full_proposal_dict()
    data["enrichment"] = {
        "severity_score": {"kind": "parsed", "column": "Ghost_Score_Column", "case": "exact", "blank": "fatal", "parser": "float"},
    }
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "enrichment.severity_score" in report.failed_slots


def test_grounding_passes_a_real_enrichment_column(profiles):
    data = _full_proposal_dict()
    data["enrichment"] = {
        "severity_score": {"kind": "parsed", "column": "Col", "case": "exact", "blank": "fatal", "parser": "float"},
    }
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "enrichment.severity_score" not in report.failed_slots


def test_grounding_derived_mapping_checks_the_referenced_derivation(profiles):
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped({"kind": "derived", "from": "os_class", "output": "role_guess"}),
    })
    data["derived"] = {
        "os_class": {
            "column": "Col", "case": "lower", "blank": "fatal",
            "outputs": ["role_guess"], "table": {"srv": ["dc"], "wks": ["workstation"]},
        },
    }
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert report.failures == []


def test_grounding_derived_mapping_fails_when_the_derivation_name_is_undefined(profiles):
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped({"kind": "derived", "from": "does_not_exist", "output": "role_guess"}),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "asset.role" in report.failed_slots
    assert any("does not define" in i.message for i in report.failures)


def test_grounding_derived_mapping_fails_when_the_derivation_table_has_a_hallucinated_key(profiles):
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped({"kind": "derived", "from": "os_class", "output": "role_guess"}),
    })
    data["derived"] = {
        "os_class": {
            "column": "Col", "case": "lower", "blank": "fatal",
            "outputs": ["role_guess"], "table": {"srv": ["dc"], "made-up-token": ["workstation"]},
        },
    }
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "asset.role" in report.failed_slots


def test_grounding_default_by_mapping_checks_the_same_derivation(profiles):
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped({"kind": "default_by", "table": "ROLE_DEFAULT_BY_OS_CLASS", "keyed_by": {"from": "os_class", "output": "class"}}),
    })
    data["derived"] = {
        "os_class": {"column": "Col", "case": "lower", "blank": "fatal", "outputs": ["class"], "table": {"srv": ["server"], "wks": ["client"]}},
    }
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert report.failures == []


def test_grounding_composed_mapping_does_not_fail_a_placeholder_absent_from_both_headers(profiles):
    """Mirrors validate_contract's own leniency here (ComposedMapping's own
    docstring in config_model.py): a composed template placeholder that no
    file carries at all simply never contributes -- absence from both
    headers is not an error (only cross-file confusion is)."""
    data = _full_proposal_dict(overrides_finding={
        "evidence": _mapped(
            {"kind": "composed", "join": "; ", "max_chars": 4096, "parts": [
                {"template": "seen on {Column_In_Neither_File}", "required_non_blank": [], "emit_if_any": None},
            ]},
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "finding.evidence" not in report.failed_slots


def test_grounding_composed_mapping_fails_a_placeholder_from_the_wrong_file(two_file_profiles):
    """The real mistake this check exists for: a placeholder column that
    genuinely exists, just in the ASSETS file -- composed has no cross-file
    join (config_model.py's own V16), so this must fail, not be treated the
    same as an honestly-absent-everywhere placeholder. Needs a genuine
    two-file fixture: single_file's assets/findings profile are the same
    object, so this distinction can't even be expressed there."""
    data = _two_file_proposal_dict()
    data["finding"]["evidence"] = _mapped(
        {"kind": "composed", "join": "; ", "max_chars": 4096, "parts": [
            {"template": "seen on {Hostname}", "required_non_blank": [], "emit_if_any": None},  # Hostname is assets-only
        ]},
    )
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, two_file_profiles)
    assert "finding.evidence" in report.failed_slots
    assert any("no cross-file join" in i.message for i in report.failures)


def test_grounding_content_address_mapping_checks_every_listed_column(profiles):
    data = _full_proposal_dict(overrides_finding={
        "finding_id": _mapped(
            {"kind": "content_address", "algorithm": "sha256", "columns": ["Asset_ID", "Ghost_Column"], "join": "", "prefix": "", "hex_len": 16, "case": "upper", "recipe_version": 1},
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "finding.finding_id" in report.failed_slots


def test_grounding_refuses_composed_on_an_asset_slot(profiles):
    """composed is legal only for finding.evidence -- proposing it on an
    asset slot is refused directly by grounding, rather than silently
    checked against the wrong (findings) file."""
    data = _full_proposal_dict(overrides_asset={
        "owner": _mapped({"kind": "composed", "join": "; ", "max_chars": 4096, "parts": [{"prefix": None, "join_nonblank": ["Col"], "join": " "}]}),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "asset.owner" in report.failed_slots
    assert any("legal only for a finding.* target" in i.message for i in report.failures)


# --- assemble_contract now runs the real validator (Fix 2) -------------------


def test_assemble_contract_refuses_an_illegal_vocabulary_value_even_if_grounding_is_clean(profiles):
    """check_grounding only verifies a table's KEYS were observed; it has no
    opinion on whether a table's VALUE is legal for the target's own
    vocabulary. assemble_contract must still refuse this via the real
    validate_contract, not report it as assembled and clean."""
    data = _full_proposal_dict(overrides_asset={
        "environment": _mapped(
            {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "not-a-real-environment"}},
            columns_cited=["Col"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert report.failures == []  # grounding itself sees nothing wrong
    with pytest.raises(ProposalIncompleteError, match="fails the real contract validator"):
        assemble_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)


def test_assemble_contract_refuses_an_illegal_union_field_even_if_grounding_is_clean(profiles):
    data = _full_proposal_dict()
    data["asset_grouping"] = {"key": "Asset_ID", "resolution": "agree_or_recency", "union_fields": ["role"], "union_justification": {}}
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert report.failures == []
    with pytest.raises(ProposalIncompleteError, match="fails the real contract validator"):
        assemble_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)


# --- a genuine two-file layout, end to end ------------------------------------


def _two_file_proposal_dict() -> dict:
    asset: dict = {}
    for slot in ASSET_SLOTS:
        if slot == "asset_id":
            asset[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Asset_ID"])
        elif slot == "hostname":
            asset[slot] = _mapped({"kind": "column", "column": "Hostname", "case": "exact", "blank": "fatal"}, columns_cited=["Hostname"])
        elif slot == "role":
            asset[slot] = _mapped({"kind": "vocabulary", "column": "Asset_Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc"}}, columns_cited=["Asset_Col"])
        else:
            asset[slot] = _mapped({"kind": "not_collected"})
    finding: dict = {}
    for slot in FINDING_SLOTS:
        if slot == "finding_id":
            finding[slot] = _mapped({"kind": "column", "column": "Finding_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Finding_ID"])
        elif slot == "asset_id":
            finding[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Asset_ID"])
        elif slot == "cve_id":
            finding[slot] = _mapped({"kind": "parsed", "column": "Cve", "case": "upper", "blank": "fatal", "parser": "cve_id"}, columns_cited=["Cve"])
        elif slot == "scanner_severity":
            finding[slot] = _mapped({"kind": "vocabulary", "column": "Finding_Col", "case": "lower", "blank": "fatal", "table": {"srv": "low"}}, columns_cited=["Finding_Col"])
        elif slot in ("product", "evidence"):
            finding[slot] = _mapped({"kind": "column", "column": "Finding_Col", "case": "exact", "blank": "absent_fact"}, columns_cited=["Finding_Col"])
        else:
            finding[slot] = _mapped({"kind": "not_collected"})
    return {
        "meta": {
            "format": "two-file-test", "description": "two-file fixture", "source_layout": "two_file",
            "assets_filename": "assets.csv", "findings_filename": "findings.csv", "reasoning_summary": "test",
        },
        "asset": asset, "finding": finding, "derived": {},
        "asset_grouping": {"key": "Asset_ID", "resolution": "agree_or_recency"},
        "finding_dedup": {"content_targets": ["scanner_severity"], "on_identical": "collapse_and_count", "on_conflict": "fatal"},
        "unmapped_columns": {}, "open_questions": [],
    }


@pytest.fixture
def two_file_profiles(tmp_path):
    _write_csv(tmp_path, ["Asset_ID", "Hostname", "Asset_Col"], [["A01", "HOST01", "srv"], ["A02", "HOST02", "wks"]], name="assets.csv")
    _write_csv(tmp_path, ["Finding_ID", "Asset_ID", "Cve", "Finding_Col"], [["F01", "A01", "CVE-2021-0001", "srv"], ["F02", "A02", "CVE-2021-0002", "wks"]], name="findings.csv")
    return {p.path.name: p for p in profile_source(tmp_path)}


def test_two_file_layout_grounds_asset_slots_against_the_assets_file_only(two_file_profiles):
    """A column that exists only in findings.csv must not ground an asset
    slot's citation -- proves is_asset actually selects the right profile
    rather than the two single-file tests being unable to distinguish
    'checked the right file' from 'checked the only file'."""
    data = _two_file_proposal_dict()
    data["asset"]["owner"] = _mapped({"kind": "column", "column": "Finding_Col", "case": "exact", "blank": "gap"})  # exists only in findings.csv
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, two_file_profiles)
    assert "asset.owner" in report.failed_slots


def test_two_file_layout_grounds_finding_slots_against_the_findings_file_only(two_file_profiles):
    data = _two_file_proposal_dict()
    data["finding"]["version"] = _mapped({"kind": "column", "column": "Asset_Col", "case": "exact", "blank": "gap"})  # exists only in assets.csv
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, two_file_profiles)
    assert "finding.version" in report.failed_slots


def test_two_file_layout_assembles_and_validates_end_to_end(two_file_profiles):
    proposal = AdapterProposal.model_validate(_two_file_proposal_dict())
    report = check_grounding(proposal, two_file_profiles)
    assert report.failures == []
    contract = assemble_contract(proposal, two_file_profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract.source.layout == "two_file"
    assert contract.header.findings is not None
    validate_contract(contract, {
        "assets.csv": ["Asset_ID", "Hostname", "Asset_Col"],
        "findings.csv": ["Finding_ID", "Asset_ID", "Cve", "Finding_Col"],
    })


def test_assemble_contract_succeeds_with_a_content_address_finding_id_and_no_attestations(profiles):
    """A real-world regression, caught only by actually running propose
    against the Defender fixture: `validate_contract`'s V18 requires a
    `finding_id.synthesized` attestation whenever finding.finding_id is a
    content_address -- but attestations are a confirm-time human act
    (config_io's own "attestations merge in, THEN validate_contract runs"
    ordering) and a freshly assembled proposal can never carry one yet.
    Without the placeholder-attestation workaround in assemble_contract,
    EVERY proposal using content_address (exactly the case it exists for:
    no natural finding-id column) would fail assembly unconditionally."""
    data = _full_proposal_dict(overrides_finding={
        "finding_id": _mapped(
            {"kind": "content_address", "algorithm": "sha256", "columns": ["Asset_ID", "Cve"], "join": "", "prefix": "", "hex_len": 16, "case": "upper", "recipe_version": 1},
            columns_cited=["Asset_ID", "Cve"],
        ),
    })
    # Finding_ID's own column is no longer consumed by the overridden finding_id mapping above --
    # account for it so this test isolates the attestation fix, not a stray V08 column-accounting gap.
    data["unmapped_columns"] = {"data.csv": {"Finding_ID": {"disposition": "ignored", "reason": "test", "profile_cited": "n/a"}}}
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert report.failures == []
    contract = assemble_contract(proposal, profiles, report, generator=_generator(), generated_at=_GENERATED_AT)
    assert contract.attestations == []  # the real, written contract carries no placeholder
    # Exactly what `rhino adapt confirm` must still refuse until a human supplies the real
    # attestation -- the placeholder trick is scoped to assemble_contract's own internal
    # structural check and must never leak into the contract this function returns.
    from rhinosecure.adapters.config_model import ContractValidationError as _CVE

    with pytest.raises(_CVE, match="finding_id.synthesized"):
        validate_contract(contract, {"data.csv": _HEADER})


# --- load_saved_proposal: a hand-edited file with a real schema error --------


def test_load_saved_proposal_wraps_a_pydantic_error_from_a_hand_edited_file(tmp_path):
    data = _full_proposal_dict()
    data["asset"]["role"]["mapping"]["kind"] = "not-a-real-kind"  # a plausible hand-edit typo
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"proposal": data, "generator": _generator().model_dump(mode="json")}), encoding="utf-8")
    with pytest.raises(SchemaInferenceError, match="does not match the saved-proposal shape"):
        load_saved_proposal(path)


# --- build_propose_agent: the tool-call retry cap item -----------------------


def test_build_propose_agent_has_a_max_execution_time():
    from rhinosecure.agents.limits import MAX_AGENT_EXECUTION_SECONDS
    from rhinosecure.agents.schema_inference import build_propose_agent
    from rhinosecure.llm import LLMConfig, get_llm

    agent = build_propose_agent(llm=get_llm(LLMConfig(model="claude-sonnet-5", api_key="sk-test-key")))
    assert agent.max_execution_time == MAX_AGENT_EXECUTION_SECONDS


def test_build_propose_agent_default_caps_max_tokens(monkeypatch):
    """The cost-fix item (PROGRESS.md 2026-09-06): left to its own default,
    claude-sonnet-5 gets a 128,000-token ceiling per call, which let a
    wayward attempt burn ~50k completion tokens before being discarded. The
    propose agent's own default `llm` (no explicit override) must cap this."""
    from rhinosecure.agents.schema_inference import PROPOSE_MAX_OUTPUT_TOKENS, build_propose_agent

    monkeypatch.delenv("RHINO_LLM_MODEL", raising=False)
    monkeypatch.delenv("RHINO_LLM_BASE_URL", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")

    agent = build_propose_agent()
    assert agent.llm.max_tokens == PROPOSE_MAX_OUTPUT_TOKENS


# --- propose_contract: retry feedback and per-attempt usage ------------------


def test_propose_contract_feeds_the_previous_failure_into_the_retry_prompt(data_dir):
    _QueuedFakeCrew.queue = [UNPARSEABLE, json.dumps(_full_proposal_dict())]
    propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, max_attempts=3)
    assert len(_QueuedFakeCrew.descriptions) == 2
    assert "your previous attempt" not in _QueuedFakeCrew.descriptions[0].lower()
    assert "your previous attempt" in _QueuedFakeCrew.descriptions[1].lower()
    assert "no valid json object found" in _QueuedFakeCrew.descriptions[1].lower()


def test_propose_contract_never_feeds_back_the_raw_agent_output(data_dir):
    """`AgentOutputParseError.raw` is untrusted, unbounded model text
    (its own docstring) -- only `str(exc)`, the short bounded summary,
    may reach the next attempt's prompt."""
    _QueuedFakeCrew.queue = [UNPARSEABLE, json.dumps(_full_proposal_dict())]
    propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, max_attempts=3)
    assert UNPARSEABLE not in _QueuedFakeCrew.descriptions[1]


def test_propose_contract_records_one_usage_entry_per_attempt(data_dir):
    _QueuedFakeCrew.queue = [UNPARSEABLE, json.dumps(_full_proposal_dict())]
    result = propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, max_attempts=3)
    assert [entry["attempt"] for entry in result.attempt_usage] == [1, 2]
    assert [entry["outcome"] for entry in result.attempt_usage] == ["parse_error", "parsed"]
    assert all(
        entry["prompt_tokens"] == 111 and entry["completion_tokens"] == 22 for entry in result.attempt_usage
    )


def test_propose_contract_records_a_meta_mismatch_outcome(data_dir):
    wrong_meta = _full_proposal_dict(name="a-different-name")
    right_meta = _full_proposal_dict(name="min-test")
    _QueuedFakeCrew.queue = [json.dumps(wrong_meta), json.dumps(right_meta)]
    result = propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, max_attempts=3)
    assert [entry["outcome"] for entry in result.attempt_usage] == ["meta_mismatch", "parsed"]


def test_propose_contract_attempt_usage_is_empty_when_from_proposal_skips_the_llm(data_dir):
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    saved = SavedProposal(proposal=proposal, generator=_generator())
    result = propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, from_proposal=saved)
    assert result.attempt_usage == ()
    assert _QueuedFakeCrew.instantiations == 0


def test_propose_contract_carries_forward_a_saved_proposals_own_attempt_usage(data_dir):
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    prior_usage = ({"attempt": 1, "prompt_tokens": 10, "completion_tokens": 5, "outcome": "parsed"},)
    saved = SavedProposal(proposal=proposal, generator=_generator(), attempt_usage=prior_usage)
    result = propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, from_proposal=saved)
    assert result.attempt_usage == prior_usage


def test_saved_proposal_round_trips_attempt_usage_through_json(tmp_path):
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    usage = ({"attempt": 1, "prompt_tokens": 111, "completion_tokens": 22, "outcome": "parsed"},)
    saved = SavedProposal(proposal=proposal, generator=_generator(), attempt_usage=usage)
    path = tmp_path / "saved.json"
    path.write_text(json.dumps(dump_saved_proposal(saved)), encoding="utf-8")
    loaded = load_saved_proposal(path)
    assert loaded.attempt_usage == usage


def test_dump_saved_proposal_omits_attempt_usage_key_when_empty():
    """No trailing empty list cluttering every saved proposal that never
    retried -- matches `dump_saved_proposal`'s existing minimal-shape style."""
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    saved = SavedProposal(proposal=proposal, generator=_generator())
    assert "attempt_usage" not in dump_saved_proposal(saved)


# --- _apply_registry_aliases: table augmentation ----------------------------


def test_apply_registry_aliases_augments_an_incomplete_role_table(tmp_path):
    """The exact real-world shape (a smaller, synthetic version of the
    northgate_flat_2.csv case): the model correctly mapped 'Workstation' but
    left 'Domain Controller' out of the table for lack of a known target
    token -- augmentation adds it, without touching the entry already there."""
    _write_csv(tmp_path, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "Workstation"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "Domain Controller"],
    ])
    profiles = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "Col", "case": "exact", "blank": "fatal", "table": {"Workstation": "workstation"}},
            columns_cited=["Col"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    new_proposal = _apply_registry_aliases(proposal, profiles)
    slot = new_proposal.asset["role"]
    assert isinstance(slot, SlotMapped)
    assert slot.mapping.table == {"Workstation": "workstation", "Domain Controller": "dc"}


def test_apply_registry_aliases_never_overwrites_a_disagreeing_existing_entry(tmp_path):
    """A genuine disagreement between the model's table and the registry is
    `check_grounding`'s new alias-contradiction check's job, never something
    augmentation silently 'fixes' -- only entries ABSENT from the table are
    ever added."""
    _write_csv(tmp_path, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "Domain Controller"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "Domain Controller"],
    ])
    profiles = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "Col", "case": "exact", "blank": "fatal", "table": {"Domain Controller": "workstation"}},
            columns_cited=["Col"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    new_proposal = _apply_registry_aliases(proposal, profiles)
    assert new_proposal.asset["role"].mapping.table == {"Domain Controller": "workstation"}


def test_apply_registry_aliases_leaves_an_already_complete_table_unchanged(profiles):
    """`data_dir`'s Col column only ever takes 'srv'/'wks' (`_full_proposal_dict`'s
    own role table already covers 'srv'); neither is a registry alias, so
    augmentation has nothing to add and the table is returned unchanged."""
    data = _full_proposal_dict()
    proposal = AdapterProposal.model_validate(data)
    new_proposal = _apply_registry_aliases(proposal, profiles)
    assert new_proposal.asset["role"].mapping.table == proposal.asset["role"].mapping.table


# --- _apply_registry_aliases: slot promotion --------------------------------


def test_apply_registry_aliases_promotes_a_fully_resolvable_unresolved_criticality(tmp_path):
    _write_csv(tmp_path, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "Critical"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "Critical"],
    ])
    profiles = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_asset={
        "criticality": _unresolved("no numeric scale specified", candidates=["Col"]),
    })
    proposal = AdapterProposal.model_validate(data)
    new_proposal = _apply_registry_aliases(proposal, profiles)
    slot = new_proposal.asset["criticality"]
    assert isinstance(slot, SlotMapped)
    assert slot.mapping.table == {"Critical": 5}
    assert slot.mapping.blank == "gap"  # criticality IS gap-legal (a NOT_COLLECTED_DEFAULTS key)
    assert slot.confidence == 1.0
    assert "no model judgment" in slot.evidence.note


def test_apply_registry_aliases_promotes_role_with_blank_fatal_not_gap(tmp_path):
    """`role` has no `NOT_COLLECTED_DEFAULTS` entry -- `blank='gap'` would be
    illegal for it (`config_model.GAP_LEGAL_TARGETS`); a promoted role
    mapping must use `blank='fatal'` instead, the same choice both real
    confirmed contracts make for this target."""
    _write_csv(tmp_path, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "Domain Controller"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "Domain Controller"],
    ])
    profiles = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_asset={
        "role": _unresolved("no verified target token", candidates=["Col"]),
    })
    proposal = AdapterProposal.model_validate(data)
    new_proposal = _apply_registry_aliases(proposal, profiles)
    slot = new_proposal.asset["role"]
    assert isinstance(slot, SlotMapped)
    assert slot.mapping.table == {"Domain Controller": "dc"}
    assert slot.mapping.blank == "fatal"


def test_apply_registry_aliases_does_not_promote_partial_coverage():
    """The real northgate case, in miniature: exactly one candidate column,
    two observed values, only one of which (Critical) is a registry anchor.
    `full_alias_coverage` correctly refuses to return a partial table, so
    the slot stays unresolved rather than being promoted with a table that
    would fatal-refuse the whole batch the first time real ingest saw the
    OTHER value."""
    def _profiles(tmp_path):
        _write_csv(tmp_path, _HEADER, [
            ["A01", "HOST01", "F01", "CVE-2021-0001", "Critical"],
            ["A02", "HOST02", "F02", "CVE-2021-0002", "Low"],
        ])
        return {p.path.name: p for p in profile_source(tmp_path)}

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        profiles = _profiles(Path(tmp))
        data = _full_proposal_dict(overrides_asset={
            "criticality": _unresolved("scale not specified", candidates=["Col"]),
        })
        proposal = AdapterProposal.model_validate(data)
        new_proposal = _apply_registry_aliases(proposal, profiles)
        assert isinstance(new_proposal.asset["criticality"], SlotUnresolved)


def test_apply_registry_aliases_does_not_promote_when_two_candidates_both_achieve_full_coverage(tmp_path):
    """More than one candidate column independently achieving full coverage
    is ambiguous -- stay conservative, promote neither."""
    header = ["Asset_ID", "Hostname", "Finding_ID", "Cve", "Col", "ColA", "ColB"]
    _write_csv(tmp_path, header, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv", "Critical", "Critical"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks", "Critical", "Critical"],
    ], name="data.csv")
    profiles = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_asset={
        "criticality": _unresolved("ambiguous source", candidates=["ColA", "ColB"]),
    })
    proposal = AdapterProposal.model_validate(data)
    new_proposal = _apply_registry_aliases(proposal, profiles)
    assert isinstance(new_proposal.asset["criticality"], SlotUnresolved)


def test_apply_registry_aliases_skips_a_hallucinated_candidate_column(tmp_path):
    _write_csv(tmp_path, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "Critical"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "Critical"],
    ])
    profiles = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_asset={
        "criticality": _unresolved("scale not specified", candidates=["Column_That_Does_Not_Exist"]),
    })
    proposal = AdapterProposal.model_validate(data)
    new_proposal = _apply_registry_aliases(proposal, profiles)
    assert isinstance(new_proposal.asset["criticality"], SlotUnresolved)


def test_apply_registry_aliases_runs_unconditionally_for_from_proposal(data_dir, profiles):
    """Unlike `_check_mapped_slots_legal`, `_apply_registry_aliases` is
    documented to run for BOTH branches of `propose_contract` -- verified
    end to end via `propose_contract(..., from_proposal=...)` itself,
    monkeypatching nothing (no LLM call happens on that path at all)."""
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "Col", "case": "exact", "blank": "fatal", "table": {"wks": "workstation"}},
            columns_cited=["Col"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    saved = SavedProposal(proposal=proposal, generator=_generator())
    result = propose_contract(data_dir, "min-test", generated_at=_GENERATED_AT, from_proposal=saved)
    # the fixture's Col column also contains "srv" -- not a registry alias,
    # so nothing new resolves here; this just confirms the call site runs
    # without error on the from_proposal branch and grounding still passes.
    assert result.grounding.failures == []


# --- check_grounding: the new alias-contradiction check ---------------------


#: A second, dedicated role column, distinct from `_HEADER`'s own "Col" --
#: `_full_proposal_dict`'s DEFAULT `finding.scanner_severity` mapping also
#: reads "Col" (expecting only "srv"/"wks"), so a test that repurposes "Col"
#: itself for role values and then asserts a CLEAN `check_grounding` result
#: would spuriously fail on that unrelated, pre-existing mapping instead.
_ROLE_HEADER = ["Asset_ID", "Hostname", "Finding_ID", "Cve", "Col", "RoleCol"]


def test_check_grounding_flags_alias_contradiction_for_role(tmp_path):
    _write_csv(tmp_path, _ROLE_HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv", "Domain Controller"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks", "Domain Controller"],
    ])
    profiles = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "RoleCol", "case": "exact", "blank": "fatal", "table": {"Domain Controller": "workstation"}},
            columns_cited=["RoleCol"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert "asset.role" in report.failed_slots
    assert any("Domain Controller" in i.message and "'dc'" in i.message for i in report.failures)


def test_check_grounding_does_not_flag_a_correct_alias_mapping(tmp_path):
    _write_csv(tmp_path, _ROLE_HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv", "Domain Controller"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks", "Domain Controller"],
    ])
    profiles = {p.path.name: p for p in profile_source(tmp_path)}
    data = _full_proposal_dict(overrides_asset={
        "role": _mapped(
            {"kind": "vocabulary", "column": "RoleCol", "case": "exact", "blank": "fatal", "table": {"Domain Controller": "dc"}},
            columns_cited=["RoleCol"],
        ),
    })
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert report.failures == []


def test_check_grounding_alias_contradiction_is_a_no_op_for_a_non_registry_target(profiles):
    """`scanner_severity` is a closed Literal vocabulary too, but not one of
    the four REGISTRY_BACKED_TARGETS -- no alias data exists to disagree
    with, so a table using an unrelated key can never trip this check."""
    data = _full_proposal_dict()  # scanner_severity is already mapped with table {"srv": "low"}
    proposal = AdapterProposal.model_validate(data)
    report = check_grounding(proposal, profiles)
    assert report.failures == []


# --- real-fixture regression: northgate_flat_2.csv --------------------------


def test_apply_registry_aliases_against_the_real_northgate_saved_proposal():
    """Offline, LLM-free regression test against a REAL saved proposal from
    a live LLM run: `out/baseline-flat2/propose_upload-366ed3c04d4645a09fdbc6ed.json`,
    the exact case that motivated `adapters/schema_registry.py`'s existence
    (one domain-controller asset, one dev workstation, same CVE). Loads the
    saved proposal and runs THIS module's own deterministic functions
    directly against it -- no live model call, no crewai involved.

    Both `out/` and `data/uploads/` are gitignored (CLAUDE.md's own repo
    layout names `out/` as generated and gitignored), so this real artifact
    is only present in a working tree that already has it -- skipped, not
    failed, when it's absent (a fresh checkout or CI runner without it)."""
    repo_root = Path(__file__).resolve().parents[1]
    saved_path = repo_root / "out" / "baseline-flat2" / "propose_upload-366ed3c04d4645a09fdbc6ed.json"
    real_data_dir = repo_root / "data" / "uploads" / "366ed3c04d4645a09fdbc6edd76f48e0"
    if not saved_path.exists() or not real_data_dir.is_dir():
        pytest.skip(f"{saved_path} / {real_data_dir} not present in this working tree (both gitignored)")

    saved = load_saved_proposal(saved_path)
    real_profiles = {p.path.name: p for p in profile_source(real_data_dir)}

    new_proposal = _apply_registry_aliases(saved.proposal, real_profiles)

    # TABLE AUGMENTATION: "Domain Controller" was cited in evidence but left
    # out of the model's own table for lack of a verified target token --
    # the registry now supplies one.
    role_slot = new_proposal.asset["role"]
    assert isinstance(role_slot, SlotMapped)
    assert role_slot.mapping.table == {"Workstation": "workstation", "Domain Controller": "dc"}

    # SLOT PROMOTION does NOT fire here, correctly: the source's own "Asset
    # Criticality" column has exactly two observed values, Critical and
    # Low, and "Low" is deliberately not a registry alias (the anchor-only
    # scope decision -- see schema_registry.py's own module docstring).
    # full_alias_coverage can never return a COMPLETE table for this single
    # candidate column, so the slot correctly stays unresolved rather than
    # being promoted with a table that would fatal-refuse the whole batch
    # the moment real ingest saw "Low".
    criticality_slot = new_proposal.asset["criticality"]
    assert isinstance(criticality_slot, SlotUnresolved)

    # The augmentation introduced no new grounding failures.
    report = check_grounding(new_proposal, real_profiles)
    assert report.failures == []


# --- real-fixture regression: the scanner_severity case-mismatch bug --------
#
# northgate_flat_2.csv's real "Risk" column holds "Critical" (title case) on
# both real rows; schema.ScannerSeverity only accepts lowercase tokens. A
# "column" mapping (kind="column", case="exact") never normalizes a value --
# it is a raw passthrough -- so this is STRUCTURALLY legal grammar (nothing
# about the mapping's own shape is wrong) but produces an illegal value at
# real ingest. These tests build a minimal, otherwise-valid AdapterProposal
# against the REAL profiled CSV (not the out/baseline-flat2/ saved proposal,
# which is shape reference only -- see this module's docstring above -- and,
# separately, is not a clean fixture: it carries its OWN pre-existing,
# unrelated legality violations from an earlier model run, e.g. asset.role's
# blank='gap', which would contaminate an assertion that the WHOLE proposal
# passes cleanly). This proposal's only interesting slot is
# finding.scanner_severity; every other slot is deliberately simple so a
# passing/failing assertion can only be about the one slot under test.


def _real_northgate_profiles():
    repo_root = Path(__file__).resolve().parents[1]
    real_data_dir = repo_root / "data" / "uploads" / "366ed3c04d4645a09fdbc6edd76f48e0"
    if not real_data_dir.is_dir():
        pytest.skip(f"{real_data_dir} not present in this working tree (gitignored)")
    return {p.path.name: p for p in profile_source(real_data_dir)}


_NORTHGATE_FILE = "northgate_flat_2.csv"


def _northgate_proposal_dict(scanner_severity: dict) -> dict:
    """A minimal, otherwise-valid proposal dict against the real
    `northgate_flat_2.csv` header: identity fields get a real column/parsed/
    content_address mapping, `asset.role` gets a small legal vocabulary
    table, everything else is `not_collected` (all gap-legal, mirroring
    `_full_proposal_dict`'s own convention), and `finding.scanner_severity`
    is exactly `scanner_severity` -- the one slot each test varies."""
    asset: dict = {}
    for slot in ASSET_SLOTS:
        if slot == "asset_id":
            asset[slot] = _mapped({"kind": "column", "column": "Host", "case": "exact", "blank": "fatal"}, columns_cited=["Host"])
        elif slot == "hostname":
            asset[slot] = _mapped({"kind": "column", "column": "DNS Name", "case": "exact", "blank": "fatal"}, columns_cited=["DNS Name"])
        elif slot == "role":
            asset[slot] = _mapped(
                {"kind": "vocabulary", "column": "Asset Role", "case": "exact", "blank": "fatal", "table": {"Workstation": "workstation"}},
                columns_cited=["Asset Role"],
            )
        else:
            asset[slot] = _mapped({"kind": "not_collected"})

    finding: dict = {}
    for slot in FINDING_SLOTS:
        if slot == "finding_id":
            finding[slot] = _mapped(
                {
                    "kind": "content_address", "algorithm": "sha256", "columns": ["Host", "Port", "CVE"],
                    "hex_len": 16, "case": "lower",
                },
                columns_cited=["Host", "Port", "CVE"],
            )
        elif slot == "asset_id":
            finding[slot] = _mapped({"kind": "column", "column": "Host", "case": "exact", "blank": "fatal"}, columns_cited=["Host"])
        elif slot == "cve_id":
            finding[slot] = _mapped({"kind": "parsed", "column": "CVE", "case": "upper", "blank": "fatal", "parser": "cve_id"}, columns_cited=["CVE"])
        elif slot == "scanner_severity":
            finding[slot] = scanner_severity
        elif slot in ("product", "evidence"):
            finding[slot] = _mapped({"kind": "column", "column": "Name", "case": "exact", "blank": "absent_fact"}, columns_cited=["Name"])
        else:
            finding[slot] = _mapped({"kind": "not_collected"})

    return {
        "meta": {
            "format": "northgate-min-test", "description": "test fixture", "source_layout": "single_file",
            "assets_filename": _NORTHGATE_FILE, "findings_filename": _NORTHGATE_FILE, "reasoning_summary": "test",
        },
        "asset": asset, "finding": finding, "derived": {},
        "asset_grouping": {"key": "Host", "resolution": "agree_or_recency"},
        "finding_dedup": {"content_targets": ["asset_id", "cve_id"], "on_identical": "collapse_and_count", "on_conflict": "fatal"},
        "unmapped_columns": {},
        "open_questions": [],
    }


def _buggy_column_scanner_severity(*, case: str) -> dict:
    """The exact bug shape observed live: a raw `column` passthrough over
    the real `Risk` column (whose only real value is "Critical")."""
    return _mapped({"kind": "column", "column": "Risk", "case": case, "blank": "fatal"}, columns_cited=["Risk"])


def _correct_vocabulary_scanner_severity() -> dict:
    return _mapped(
        {"kind": "vocabulary", "column": "Risk", "case": "exact", "blank": "fatal", "table": {"Critical": "critical"}},
        columns_cited=["Risk"],
    )


def test_check_grounding_flags_a_column_mapping_whose_observed_values_are_illegal():
    real_profiles = _real_northgate_profiles()
    data = _northgate_proposal_dict(_buggy_column_scanner_severity(case="exact"))
    proposal = AdapterProposal.model_validate(data)

    report = check_grounding(proposal, real_profiles)

    assert "finding.scanner_severity" in report.failed_slots
    messages = [i.message for i in report.failures if i.slot == "finding.scanner_severity"]
    assert any("Critical" in m for m in messages)


def test_check_mapped_slots_legal_flags_the_same_candidate_at_generation():
    real_profiles = _real_northgate_profiles()
    data = _northgate_proposal_dict(_buggy_column_scanner_severity(case="exact"))
    proposal = AdapterProposal.model_validate(data)

    with pytest.raises(MappingLegalityError, match="finding.scanner_severity"):
        _check_mapped_slots_legal(proposal, real_profiles)


def test_lowercasing_the_case_transform_fixes_both_checks():
    """Same candidate, `case="lower"` instead of `"exact"` -- "Critical"
    case-folds to "critical", a legal `ScannerSeverity` value, so both the
    terminal grounding check and the retry-loop legality check must now
    pass cleanly. Proves the fix's own suggested remedy actually works, not
    only that the bug is detected."""
    real_profiles = _real_northgate_profiles()
    data = _northgate_proposal_dict(_buggy_column_scanner_severity(case="lower"))
    proposal = AdapterProposal.model_validate(data)

    report = check_grounding(proposal, real_profiles)
    assert "finding.scanner_severity" not in report.failed_slots

    _check_mapped_slots_legal(proposal, real_profiles)  # must not raise -- every slot is clean


def test_vocabulary_mapping_for_scanner_severity_is_unaffected_by_the_new_check():
    """A `vocabulary` mapping over the identical real column/value
    (`{"Critical": "critical"}`) is grounded by its own, pre-existing
    key-matching path (`_ground_table`) -- this new check must never touch
    it, and both the grounding and legality checks stay clean."""
    real_profiles = _real_northgate_profiles()
    data = _northgate_proposal_dict(_correct_vocabulary_scanner_severity())
    proposal = AdapterProposal.model_validate(data)

    report = check_grounding(proposal, real_profiles)
    assert "finding.scanner_severity" not in report.failed_slots
    _check_mapped_slots_legal(proposal, real_profiles)  # must not raise


def test_check_column_mapping_legal_values_direct():
    """Unit-level check of the shared function itself: exact inputs, exact
    expected output, isolated from any full proposal."""
    real_profiles = _real_northgate_profiles()
    profile = real_profiles[_NORTHGATE_FILE]

    illegal_mapping = ColumnMapping(kind="column", column="Risk", case="exact", blank="fatal")
    problems = check_column_mapping_legal_values("finding.scanner_severity", "scanner_severity", illegal_mapping, profile)
    assert len(problems) == 1
    assert "Critical" in problems[0]
    assert "scanner_severity" in problems[0]

    legal_mapping = ColumnMapping(kind="column", column="Risk", case="lower", blank="fatal")
    assert check_column_mapping_legal_values("finding.scanner_severity", "scanner_severity", legal_mapping, profile) == []

    # No closed vocabulary for this target at all -> always [].
    assert check_column_mapping_legal_values("asset.owner", "owner", illegal_mapping, profile) == []

    # Column not actually profiled -> always [].
    missing_column_mapping = ColumnMapping(kind="column", column="Does Not Exist", case="exact", blank="fatal")
    assert (
        check_column_mapping_legal_values("finding.scanner_severity", "scanner_severity", missing_column_mapping, profile)
        == []
    )
