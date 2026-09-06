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
from rhinosecure.adapters.config_model import ASSET_SLOTS, FINDING_SLOTS, Contract, validate_contract
from rhinosecure.adapters.probe import profile_source
from rhinosecure.agents.schema_inference import (
    AdapterProposal,
    Generator,
    ProposalGenerationError,
    ProposalIncompleteError,
    SavedProposal,
    SchemaInferenceError,
    _resolve_layout,
    _validate_format_name,
    assemble_contract,
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
