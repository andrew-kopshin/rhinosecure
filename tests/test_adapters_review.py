"""adapters/review.py -- Slice 7's measurement, drift diff, attestation
gate and the single write. No CLI here (tests/test_cli_adapt.py covers the
verbs); every test drives the library directly against tmp_path copies with
an explicit `at=`, exactly as tests/test_adapters_config_io.py does, so
nothing here mocks a clock.

The two committed contracts under data/adapters/ are used READ-ONLY, and one
test asserts that outright: they are pinned byte-for-byte by
tests/test_adapters_configured_differential.py, and a command that rewrote
one to make its own output look good is precisely what CLAUDE.md Section 8
rule 1 forbids."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_adapters_config_model import bluepeak_gen_dict, mdvm_gen_dict

from rhinosecure.adapters.config_io import read_contract, write_contract
from rhinosecure.adapters.config_model import Contract, assert_confirmed, required_attestations
from rhinosecure.adapters.configured import ConfiguredAdapter
from rhinosecure.adapters.review import (
    PROVISIONAL_BY,
    Measurement,
    ReviewError,
    build_observed,
    carried_attestations,
    compute_drift,
    measure,
    parse_attestations,
    partition_slots,
    review_contract,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
BLUEPEAK_DIR = REPO_ROOT / "data" / "bluepeak"
DEFENDER_DIR = REPO_ROOT / "data" / "defender-sample"
COMMITTED = REPO_ROOT / "data" / "adapters"

AT = "2026-09-05T12:00:00Z"
BY = "reviewer@example.com"

BLUEPEAK_ATTESTS = [
    "enrichment=The export carries its own CVSS and exploitation status; trusting it.",
    "union=Compensating_Control is declared per finding and unioned per asset.",
]
MDVM_ATTEST = "finding_id.synthesized=sha256 over the documented per-device uniqueness key."


def _unconfirmed(builder, tmp_path: Path, name: str) -> Path:
    path = tmp_path / f"{name}.json"
    write_contract(path, Contract.model_validate(builder()))
    return path


def _bluepeak(tmp_path: Path) -> Path:
    return _unconfirmed(bluepeak_gen_dict, tmp_path, "bluepeak-gen")


def _mdvm(tmp_path: Path) -> Path:
    return _unconfirmed(mdvm_gen_dict, tmp_path, "mdvm-gen")


def _bluepeak_source(tmp_path: Path, *, mutate=None) -> Path:
    """A writable copy of the real BluePeak file, optionally mutated."""
    data = tmp_path / "src"
    data.mkdir(exist_ok=True)
    source = BLUEPEAK_DIR / "synthetic_cve_inventory_50.csv"
    rows = list(csv.DictReader(source.open(newline="", encoding="utf-8")))
    header = list(rows[0])
    if mutate is not None:
        mutate(rows)
    with (data / source.name).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)
    return data


# --- measure ----------------------------------------------------------------


def test_measure_runs_an_unconfirmed_contract_the_engine_would_refuse(tmp_path):
    """The chicken-and-egg this module exists to resolve: ConfiguredAdapter
    refuses an unconfirmed contract outright, yet the measurement has to
    happen before anyone signs one."""
    contract = read_contract(_bluepeak(tmp_path))
    assert contract.review.state == "proposed"
    with pytest.raises(Exception):
        ConfiguredAdapter(contract)  # ContractNotConfirmedError

    m = measure(contract, BLUEPEAK_DIR)
    assert m.is_clean
    assert m.assets_loaded > 0 and m.findings_loaded > 0


def test_measure_matches_what_a_real_run_reports(tmp_path):
    """The design's decisive property: the artifact a human signs is
    produced by the code that executes the mapping, so the numbers must be
    the same ones `rhino run` prints."""
    from rhinosecure.cli import run_with_report

    result = run_with_report(BLUEPEAK_DIR, 42, adapter_config=str(COMMITTED / "bluepeak-gen.json"))
    m = measure(read_contract(_bluepeak(tmp_path)), BLUEPEAK_DIR)
    assert m.assets_loaded == result.report.assets_total
    assert m.findings_loaded == result.report.findings_total
    assert m.duplicate_assets_collapsed == result.report.duplicate_assets_collapsed
    assert m.asset_gaps == result.report.asset_gaps


def test_measure_never_writes_and_never_returns_the_provisional_contract(tmp_path):
    path = _bluepeak(tmp_path)
    before = path.read_bytes()
    m = measure(read_contract(path), BLUEPEAK_DIR)
    assert path.read_bytes() == before
    assert PROVISIONAL_BY not in json.dumps(m.__dict__, default=str)


def test_measure_collects_every_problem_rather_than_stopping_at_the_first(tmp_path):
    def corrupt(rows):
        rows[0]["CVSS_Base_Score"] = "not-a-number"
        rows[1]["CVSS_Base_Score"] = "also-not-a-number"

    data = _bluepeak_source(tmp_path, mutate=corrupt)
    m = measure(read_contract(_bluepeak(tmp_path)), data)
    assert not m.is_clean
    assert len(m.fatal_problems) == 2, m.fatal_problems
    assert len(m.fatal_problems) == len(set(m.fatal_problems))  # de-duplicated


def test_measure_reports_a_halting_error_separately_from_accumulated_ones(tmp_path):
    """A --data pointed at a directory this contract's files aren't in
    halts before any row is read; that is a different kind of fact from a
    problem the collectors accumulated."""
    m = measure(read_contract(_bluepeak(tmp_path)), REPO_ROOT / "data" / "demo")
    assert m.halted_by is not None
    assert not m.is_clean


def test_measure_records_scope_exclusions_with_their_reasons(tmp_path):
    def unmappable(rows):
        rows[0]["Asset_Type"] = "Quantum Toaster"

    data = _bluepeak_source(tmp_path, mutate=unmappable)
    m = measure(read_contract(_bluepeak(tmp_path)), data)
    assert m.is_clean  # a scope boundary is not a data-quality problem
    assert len(m.excluded_assets) == 1
    assert "Quantum Toaster" in next(iter(m.excluded_assets.values()))
    assert len(m.excluded_findings) == 1  # cascaded


def test_measure_tallies_values_only_for_enumerated_targets(tmp_path):
    """Free text (hostname, owner, business_function) must never be tallied
    -- a contract is committed to git and real fleet data is not."""
    m = measure(read_contract(_mdvm(tmp_path)), DEFENDER_DIR)
    assert set(m.value_distribution) == {
        "role", "environment", "data_sensitivity", "criticality", "internet_exposed",
    }
    assert m.value_distribution["environment"] == {"prod": m.assets_loaded}


def test_measure_profiles_the_columns_the_contract_says_it_ignores(tmp_path):
    m = measure(read_contract(_mdvm(tmp_path)), DEFENDER_DIR)
    keys = {k.split(":", 1)[1] for k in m.unmapped_profiles}
    assert "ExposureLevel" in keys
    profile = m.unmapped_profiles["devices.csv:ExposureLevel"]
    assert profile["reason"]  # the contract's own prose claim
    assert profile["distinct"] >= 1  # measured beside it


def test_measure_records_the_engines_filtered_header_view(tmp_path):
    m = measure(read_contract(_mdvm(tmp_path)), DEFENDER_DIR)
    assert set(m.headers) == {"devices.csv", "vulnerabilities.csv"}
    assert "DeviceId" in m.headers["devices.csv"]


# --- build_observed ---------------------------------------------------------


def test_observed_exclusion_counts_are_ints_because_v18_adds_them(tmp_path):
    def unmappable(rows):
        rows[0]["Asset_Type"] = "Quantum Toaster"

    data = _bluepeak_source(tmp_path, mutate=unmappable)
    contract = read_contract(_bluepeak(tmp_path))
    observed = build_observed(measure(contract, data), contract, at=AT, by=BY, command="confirm")
    assert isinstance(observed["excluded_assets"], int)
    assert isinstance(observed["excluded_findings"], int)
    assert observed["excluded_assets"] == 1


def test_observed_records_asset_side_reasons_but_no_record_ids(tmp_path):
    def unmappable(rows):
        rows[0]["Asset_Type"] = "Quantum Toaster"

    data = _bluepeak_source(tmp_path, mutate=unmappable)
    contract = read_contract(_bluepeak(tmp_path))
    m = measure(contract, data)
    observed = build_observed(m, contract, at=AT, by=BY, command="confirm")
    blob = json.dumps(observed)
    assert "Quantum Toaster" in blob  # the schema-level reason IS recorded
    for asset_id in m.excluded_assets:
        assert asset_id not in blob  # the record identity is not
    assert "excluded_finding_reasons" not in observed  # cascaded reasons embed an asset id


def test_observed_is_flat_so_v18_can_read_it(tmp_path):
    contract = read_contract(_bluepeak(tmp_path))
    observed = build_observed(measure(contract, BLUEPEAK_DIR), contract, at=AT, by=BY, command="confirm")
    stamped = contract.model_copy(update={"observed": observed})
    assert "exclusions" not in required_attestations(stamped)  # nothing excluded here


# --- drift and the slot partition -------------------------------------------


def test_a_never_confirmed_contract_is_not_reported_as_drifted(tmp_path):
    drift = compute_drift(read_contract(_bluepeak(tmp_path)))
    assert drift.was_confirmed is False
    assert drift.decisions_moved is False  # nothing to have moved FROM
    assert drift.slots.available is False


def test_the_committed_contracts_have_no_slot_digests_which_is_legal(tmp_path):
    """C5 is the state of both committed contracts today, not a
    hypothetical -- the fallback has to work on real artifacts."""
    for name in ("bluepeak-gen", "mdvm-gen"):
        drift = compute_drift(read_contract(COMMITTED / f"{name}.json"))
        assert drift.was_confirmed
        assert drift.content_matches and drift.decision_matches
        assert drift.slots.available is False


def test_confirming_records_slot_digests_so_the_fallback_is_hit_at_most_once(tmp_path):
    path = _bluepeak(tmp_path)
    outcome = review_contract(path, read_contract(path), BLUEPEAK_DIR, at=AT, by=BY, sign=True)
    assert outcome.written
    assert partition_slots(read_contract(path)).available is True


def test_a_changed_mapping_shows_only_that_slot_as_moved(tmp_path):
    """The whole point of merge-by-slot-digest: a reviewer re-reads one
    line, not the whole contract."""
    path = _bluepeak(tmp_path)
    review_contract(path, read_contract(path), BLUEPEAK_DIR, at=AT, by=BY, sign=True)
    edited = json.loads(path.read_text(encoding="utf-8"))
    # `case` rather than a column rename: a real, hashed mapping decision
    # that leaves V08's column accounting alone, so this test isolates the
    # partition rather than also tripping the validator.
    edited["asset"]["hostname"]["case"] = "lower"
    path.write_text(json.dumps(edited, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    partition = partition_slots(read_contract(path))
    assert partition.changed == ["asset.hostname"]
    assert len(partition.unchanged) == 23
    assert partition.new == [] and partition.orphaned == []


# --- attestation carry-forward ----------------------------------------------


def test_everything_carries_when_no_decision_moved(tmp_path):
    contract = read_contract(COMMITTED / "bluepeak-gen.json")
    kept, dropped = carried_attestations(contract, compute_drift(contract))
    assert [a.item for a in kept] == [a.item for a in contract.attestations]
    assert dropped == []


def test_a_never_confirmed_contracts_attestations_simply_stand(tmp_path):
    """There is no prior signature to have carried them FROM -- treating
    them as dropped would discard the author's own work."""
    contract = read_contract(_bluepeak(tmp_path))
    kept, dropped = carried_attestations(contract, compute_drift(contract))
    assert len(kept) == len(contract.attestations)
    assert dropped == []


def test_finding_id_attestation_carries_only_while_its_own_slot_is_unchanged(tmp_path):
    path = _mdvm(tmp_path)
    review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, attest=[MDVM_ATTEST])

    edited = json.loads(path.read_text(encoding="utf-8"))
    edited["asset"]["hostname"]["case"] = "lower"  # an UNRELATED slot moves
    path.write_text(json.dumps(edited, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    contract = read_contract(path)
    kept, _dropped = carried_attestations(contract, compute_drift(contract))
    assert "finding_id.synthesized" in {a.item for a in kept}

    edited["finding"]["finding_id"]["hex_len"] = 24  # now the attested slot itself moves
    path.write_text(json.dumps(edited, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    contract = read_contract(path)
    kept, dropped = carried_attestations(contract, compute_drift(contract))
    assert "finding_id.synthesized" not in {a.item for a in kept}
    assert any("finding_id.synthesized" in reason for reason in dropped)


# --- parse_attestations -----------------------------------------------------


def test_attest_splits_on_the_first_equals_only():
    parsed = parse_attestations(["union=a=b=c"], at=AT)
    assert parsed[0].text == "a=b=c"


def test_attest_validates_the_item_against_the_known_set():
    """ATTESTATION_ITEMS' first consumer. Attestation.item is a bare str, so
    without this a typo constructs happily and V18 then refuses for a
    missing item while the file visibly contains an attestation."""
    with pytest.raises(ReviewError, match="not an attestation item"):
        parse_attestations(["exclusion=typo in the item name"], at=AT)


def test_every_bad_attest_argument_is_named_in_one_message():
    with pytest.raises(ReviewError) as excinfo:
        parse_attestations(["nope", "exclusion=x", "union="], at=AT)
    message = str(excinfo.value)
    assert "expected ITEM=TEXT" in message
    assert "not an attestation item" in message
    assert "empty" in message


def test_the_same_item_twice_in_one_invocation_is_refused():
    with pytest.raises(ReviewError, match="more than once"):
        parse_attestations(["union=first", "union=second"], at=AT)


# --- review_contract: the gates ---------------------------------------------


def test_confirm_signs_an_unconfirmed_contract_and_the_engine_accepts_it(tmp_path):
    path = _mdvm(tmp_path)
    outcome = review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, attest=[MDVM_ATTEST])
    assert outcome.written and not outcome.refusals
    written = read_contract(path)
    assert written.review.state == "confirmed"
    assert written.review.confirmed_by == BY
    assert written.review.confirmed_at == AT
    assert written.review.confirmed_version == written.version
    assert_confirmed(written)
    ConfiguredAdapter(written)  # the engine's own gate accepts what we wrote


def test_confirm_refuses_an_already_confirmed_contract_without_reconfirm(tmp_path):
    path = _mdvm(tmp_path)
    review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, attest=[MDVM_ATTEST])
    before = path.read_bytes()
    outcome = review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True)
    assert not outcome.written
    assert any("--reconfirm" in r for r in outcome.refusals)
    assert path.read_bytes() == before


def test_reconfirm_allows_it(tmp_path):
    path = _mdvm(tmp_path)
    review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, attest=[MDVM_ATTEST])
    outcome = review_contract(
        path, read_contract(path), DEFENDER_DIR, at="2026-09-06T00:00:00Z", by="second@example.com",
        sign=True, reconfirm=True,
    )
    assert outcome.written
    assert read_contract(path).review.confirmed_by == "second@example.com"


def test_a_changed_finding_id_recipe_is_refused_without_reset_identity(tmp_path):
    path = _mdvm(tmp_path)
    review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, attest=[MDVM_ATTEST])
    edited = json.loads(path.read_text(encoding="utf-8"))
    edited["finding"]["finding_id"]["hex_len"] = 24
    path.write_text(json.dumps(edited, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    outcome = review_contract(
        path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, reconfirm=True, attest=[MDVM_ATTEST]
    )
    assert not outcome.written
    assert any("memory.decisions" in r for r in outcome.refusals)

    allowed = review_contract(
        path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, reconfirm=True,
        reset_identity=True, attest=[MDVM_ATTEST],
    )
    assert allowed.written


def test_fatal_problems_refuse_and_write_nothing(tmp_path):
    def corrupt(rows):
        rows[0]["CVSS_Base_Score"] = "not-a-number"

    data = _bluepeak_source(tmp_path, mutate=corrupt)
    path = _bluepeak(tmp_path)
    before = path.read_bytes()
    outcome = review_contract(path, read_contract(path), data, at=AT, by=BY, sign=True)
    assert not outcome.written
    assert any("fatal problems" in r for r in outcome.refusals)
    assert path.read_bytes() == before


def test_a_newly_measured_exclusion_demands_an_attestation_then_accepts_one(tmp_path):
    """The C3 ordering hazard, end to end: the requirement cannot be known
    until the measurement exists, so shot one refuses with the exclusions
    named and shot two supplies the sentence."""
    def unmappable(rows):
        rows[0]["Asset_Type"] = "Quantum Toaster"

    data = _bluepeak_source(tmp_path, mutate=unmappable)
    path = _bluepeak(tmp_path)

    first = review_contract(path, read_contract(path), data, at=AT, by=BY, sign=True)
    assert not first.written
    assert first.still_missing == ["exclusions"]
    assert "exclusions" in first.required

    second = review_contract(
        path, read_contract(path), data, at=AT, by=BY, sign=True,
        attest=["exclusions=One asset is outside the role vocabulary; its finding is out of scope."],
    )
    assert second.written
    written = read_contract(path)
    assert written.observed["excluded_assets"] == 1
    assert "exclusions" in {a.item for a in written.attestations}


def test_an_attestation_for_a_condition_that_does_not_hold_is_refused(tmp_path):
    """A signed acknowledgment of something that never happened reads later
    as evidence someone looked at something."""
    path = _bluepeak(tmp_path)
    outcome = review_contract(
        path, read_contract(path), BLUEPEAK_DIR, at=AT, by=BY, sign=True,
        attest=["exclusions=nothing was actually excluded here"],
    )
    assert not outcome.written
    assert any("do not require" in r for r in outcome.refusals)


def test_replacing_an_existing_attestation_is_reported_not_silent(tmp_path):
    path = _bluepeak(tmp_path)
    outcome = review_contract(
        path, read_contract(path), BLUEPEAK_DIR, at=AT, by=BY, sign=True,
        attest=["union=a freshly worded justification"],
    )
    assert outcome.written
    assert [new.item for _old, new in outcome.attestations_replaced] == ["union"]


def test_rereview_never_writes_even_when_everything_would_pass(tmp_path):
    path = _mdvm(tmp_path)
    before = path.read_bytes()
    outcome = review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, sign=False, attest=[MDVM_ATTEST])
    assert outcome.written is False
    assert outcome.signed is None
    assert path.read_bytes() == before


def test_rereview_requires_no_identity(tmp_path):
    path = _mdvm(tmp_path)
    outcome = review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, sign=False)
    assert outcome.measurement.is_clean


def test_signing_without_an_identity_is_a_programming_error(tmp_path):
    path = _mdvm(tmp_path)
    with pytest.raises(ReviewError, match="identity"):
        review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, by=None, sign=True)


def test_the_written_file_keeps_the_from_alias(tmp_path):
    """mdvm-gen has a `derived` block, and confirm is the first command
    that ever writes one back to disk."""
    path = _mdvm(tmp_path)
    review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, attest=[MDVM_ATTEST])
    assert "from_" not in path.read_text(encoding="utf-8")


# --- defects found by the adversarial review of this slice -------------------


def test_a_contract_carrying_no_attestations_yet_can_still_be_confirmed(tmp_path):
    """Found by review. V18 runs inside `measure` (ConfiguredAdapter.load_assets
    calls validate_contract on every load), and its STRUCTURAL requirements
    depend only on the contract's shape -- so measuring the pre-merge contract
    made --attest unable to ever help: the pass halted with 0 rows and the
    refusal blamed the source. That is the normal state of a freshly proposed
    contract, so it would have blocked the whole propose -> confirm flow."""
    from test_adapters_config_model import bluepeak_gen_dict as _builder

    bare = _builder()
    bare["attestations"] = []
    path = tmp_path / "bare.json"
    write_contract(path, Contract.model_validate(bare))

    outcome = review_contract(
        path, read_contract(path), BLUEPEAK_DIR, at=AT, by=BY, sign=True, attest=BLUEPEAK_ATTESTS
    )
    assert outcome.written, outcome.refusals
    assert outcome.measurement.assets_loaded > 0  # the pass actually ran
    assert {a.item for a in read_contract(path).attestations} == {"enrichment", "union"}


def test_the_missing_attestation_refusal_is_listed_before_the_generic_one(tmp_path):
    """A missing attestation can be the CAUSE of the halt, not a second
    problem -- leading with "fatal problems on this source" points the reader
    at the export when the fix is a sentence."""
    from test_adapters_config_model import bluepeak_gen_dict as _builder

    bare = _builder()
    bare["attestations"] = []
    path = tmp_path / "bare.json"
    write_contract(path, Contract.model_validate(bare))

    outcome = review_contract(path, read_contract(path), BLUEPEAK_DIR, at=AT, by=BY, sign=True)
    assert not outcome.written
    assert "missing attestation" in outcome.refusals[0]


def test_a_moved_decision_without_slot_digests_refuses_on_the_identity_recipe(tmp_path):
    """Found by review. The freeze checked `finding.finding_id in
    slots.changed`, which is unreachable when no slot digests were recorded --
    so a changed identity recipe would have been re-signed in silence,
    orphaning every decision memory.decisions holds for the format."""
    path = _mdvm(tmp_path)
    review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, attest=[MDVM_ATTEST])

    edited = json.loads(path.read_text(encoding="utf-8"))
    edited["review"].pop("slot_digests")  # a pre-slot_digests confirmation
    edited["asset"]["hostname"]["case"] = "lower"  # and a moved decision
    path.write_text(json.dumps(edited, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    outcome = review_contract(
        path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, reconfirm=True, attest=[MDVM_ATTEST]
    )
    assert not outcome.written
    assert any("memory.decisions" in r and "no slot_digests" in r for r in outcome.refusals)

    allowed = review_contract(
        path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, reconfirm=True,
        reset_identity=True, attest=[MDVM_ATTEST],
    )
    assert allowed.written


def test_deleting_the_identity_slot_digest_does_not_get_past_the_freeze(tmp_path):
    """Found by review. `review` sits outside BOTH digests, so slot_digests is
    unsigned evidence -- deleting just that one entry made `partition_slots`
    call the slot `new` rather than `changed`, and a gate keyed on `changed`
    let a re-keyed recipe through in silence. The gate is now phrased as
    "refuse unless provably unchanged"."""
    path = _mdvm(tmp_path)
    review_contract(path, read_contract(path), DEFENDER_DIR, at=AT, by=BY, sign=True, attest=[MDVM_ATTEST])

    edited = json.loads(path.read_text(encoding="utf-8"))
    edited["finding"]["finding_id"]["columns"] = ["DeviceId", "CveId"]
    del edited["review"]["slot_digests"]["finding.finding_id"]  # the one piece of evidence
    path.write_text(json.dumps(edited, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    contract = read_contract(path)
    assert "finding.finding_id" in partition_slots(contract).new  # not `changed`
    outcome = review_contract(
        path, contract, DEFENDER_DIR, at=AT, by=BY, sign=True, reconfirm=True, attest=[MDVM_ATTEST]
    )
    assert not outcome.written
    assert any("memory.decisions" in r for r in outcome.refusals)


def test_an_unchanged_confirmed_contract_never_hits_the_identity_gate(tmp_path):
    """Guard on the fix above: the no-slot_digests refusal must fire only
    when a decision actually moved, or every re-confirm of the two committed
    contracts would demand --reset-identity."""
    for name, data_dir in (("bluepeak-gen", BLUEPEAK_DIR), ("mdvm-gen", DEFENDER_DIR)):
        contract = read_contract(COMMITTED / f"{name}.json")
        assert contract.review.slot_digests is None
        outcome = review_contract(COMMITTED / f"{name}.json", contract, data_dir, at=AT, sign=False)
        assert not any("reset-identity" in r for r in outcome.refusals)


def test_the_committed_contracts_are_never_written_by_a_review(tmp_path):
    """They are pinned byte-for-byte by the differential suite. rereview
    cannot write at all, and confirm refuses a confirmed contract without
    --reconfirm -- so this holds mechanically, not by discipline."""
    for name, data_dir in (("bluepeak-gen", BLUEPEAK_DIR), ("mdvm-gen", DEFENDER_DIR)):
        path = COMMITTED / f"{name}.json"
        before = path.read_bytes()
        review_contract(path, read_contract(path), data_dir, at=AT, sign=False)
        outcome = review_contract(path, read_contract(path), data_dir, at=AT, by=BY, sign=True)
        assert not outcome.written
        assert path.read_bytes() == before
