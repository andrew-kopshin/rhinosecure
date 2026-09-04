"""adapters/config_io.py -- file read/write and the confirm workflow for
ingest contracts. No CLI here (a later slice's job); every test drives the
three functions directly against tmp_path, using the real bluepeak-gen
contract (unconfirmed, freshly re-derived from its own builder) as a
realistic starting point."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from rhinosecure.adapters.config_io import (
    ContractIOError,
    IdentityRecipeChangedError,
    check_identity_recipe_unchanged,
    confirm_contract,
    overwrite_contract,
    read_contract,
    write_contract,
)
from rhinosecure.adapters.config_model import Contract, assert_confirmed

sys.path.insert(0, str(Path(__file__).parent))
from test_adapters_config_model import bluepeak_gen_dict, mdvm_gen_dict


def _unconfirmed_bluepeak() -> Contract:
    return Contract.model_validate(bluepeak_gen_dict())


def _unconfirmed_mdvm() -> Contract:
    return Contract.model_validate(mdvm_gen_dict())


# --- read_contract ---------------------------------------------------------


def test_read_contract_round_trips_a_written_one(tmp_path):
    contract = _unconfirmed_bluepeak()
    path = tmp_path / "bluepeak-gen.json"
    path.write_text(json.dumps(contract.model_dump(mode="json"), indent=2, sort_keys=True), encoding="utf-8")
    loaded = read_contract(path)
    assert loaded == contract


def test_read_contract_missing_file_raises_contract_io_error(tmp_path):
    with pytest.raises(ContractIOError, match="could not be read"):
        read_contract(tmp_path / "does-not-exist.json")


def test_read_contract_invalid_json_raises_contract_io_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ContractIOError, match="not valid JSON"):
        read_contract(path)


def test_read_contract_structurally_invalid_raises_validation_error(tmp_path):
    path = tmp_path / "wrong-shape.json"
    path.write_text(json.dumps({"format": "x"}), encoding="utf-8")
    with pytest.raises(ValidationError):
        read_contract(path)


# --- write_contract: atomic write + version bump ----------------------------


def test_first_write_is_version_1(tmp_path):
    contract = _unconfirmed_bluepeak().model_copy(update={"version": 99})  # caller's version is not trusted
    path = tmp_path / "bluepeak-gen.json"
    written = write_contract(path, contract)
    assert written.version == 1
    assert read_contract(path).version == 1


def test_second_write_bumps_the_existing_version_not_the_caller_supplied_one(tmp_path):
    path = tmp_path / "bluepeak-gen.json"
    write_contract(path, _unconfirmed_bluepeak().model_copy(update={"version": 1}))
    written = write_contract(path, _unconfirmed_bluepeak().model_copy(update={"version": 1}))
    assert written.version == 2
    assert read_contract(path).version == 2
    # A third write, even if the caller's own copy still claims version 1,
    # bumps from what is actually on disk (2), not from the caller's stale copy.
    written_again = write_contract(path, _unconfirmed_bluepeak().model_copy(update={"version": 1}))
    assert written_again.version == 3


def test_write_is_atomic_no_tmp_file_left_behind(tmp_path):
    path = tmp_path / "bluepeak-gen.json"
    write_contract(path, _unconfirmed_bluepeak())
    assert path.exists()
    assert not path.with_name(path.name + ".tmp").exists()


def test_write_creates_parent_directories(tmp_path):
    path = tmp_path / "nested" / "dir" / "bluepeak-gen.json"
    write_contract(path, _unconfirmed_bluepeak())
    assert path.exists()


def test_write_over_a_corrupt_existing_file_resets_to_version_1_rather_than_blocking(tmp_path):
    path = tmp_path / "bluepeak-gen.json"
    path.write_text("{not valid json", encoding="utf-8")
    written = write_contract(path, _unconfirmed_bluepeak())
    assert written.version == 1
    assert read_contract(path).version == 1


def test_written_file_is_pretty_printed_and_sorted_with_trailing_newline(tmp_path):
    path = tmp_path / "bluepeak-gen.json"
    written = write_contract(path, _unconfirmed_bluepeak())
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert len(text.splitlines()) > 1  # pretty-printed, not one line
    # by_alias -- see _dump_for_disk. Identical to a plain dump for THIS
    # contract (bluepeak-gen has no `derived`/`default_by` block, so no
    # aliased field exists to differ), which is exactly why the alias bug
    # below went unnoticed; asserted in the aliased form anyway so this pins
    # the intent rather than passing coincidentally.
    assert text == json.dumps(written.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n"
    assert '"asset"' in text.splitlines()[1]  # sorted keys -> "asset" sorts first, right after the opening brace


# --- the `from`/`from_` alias, found while building slice 7 -----------------
#
# DerivedMapping.from_ / DefaultByKeyedBy.from_ carry alias="from" (a Python
# keyword). A plain model_dump() emits the field name, so writing a contract
# that HAS a derived block turned `"from"` into `"from_"` on disk -- a key
# neither the design document nor any hand-written contract uses. Latent
# since slice 3, because nothing wrote such a contract back until `rhino
# adapt confirm`. The bluepeak contract cannot catch it (no derived block);
# every test below uses mdvm, which has one.


def test_writing_a_contract_with_a_derived_block_keeps_the_from_alias(tmp_path):
    path = tmp_path / "mdvm-gen.json"
    write_contract(path, _unconfirmed_mdvm())
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["asset"]["os"] == {"kind": "derived", "from": "os_platform", "output": "os"}
    assert on_disk["asset"]["role"]["keyed_by"]["from"] == "os_platform"
    assert "from_" not in json.dumps(on_disk)


def test_overwrite_contract_keeps_the_from_alias_too(tmp_path):
    path = tmp_path / "mdvm-gen.json"
    overwrite_contract(path, _unconfirmed_mdvm())
    assert "from_" not in path.read_text(encoding="utf-8")


def test_the_alias_round_trips_without_disturbing_either_digest(tmp_path):
    """The fix must be digest-neutral: digests hash the NON-aliased dump, so
    what a confirmation signs is unchanged by how the file spells `from`."""
    from rhinosecure.adapters.config_model import compute_content_digest, compute_decision_digest

    original = _unconfirmed_mdvm()
    path = tmp_path / "mdvm-gen.json"
    overwrite_contract(path, original)
    reloaded = read_contract(path)
    assert reloaded == original
    assert compute_content_digest(reloaded) == compute_content_digest(original)
    assert compute_decision_digest(reloaded) == compute_decision_digest(original)


def test_a_confirmed_contract_survives_a_write_read_round_trip(tmp_path):
    """End to end: confirm, persist, re-read, and the engine's own gate still
    accepts it -- the property `rhino adapt confirm` depends on."""
    path = tmp_path / "mdvm-gen.json"
    confirmed = confirm_contract(_unconfirmed_mdvm(), at="2026-09-05T00:00:00Z", by="x")
    overwrite_contract(path, confirmed)
    assert_confirmed(read_contract(path))  # must not raise


# --- confirm_contract --------------------------------------------------------


def test_confirm_contract_stamps_state_and_digests():
    contract = _unconfirmed_bluepeak()
    assert contract.review.state == "proposed"
    confirmed = confirm_contract(contract, at="2026-09-05T00:00:00Z", by="andy.kopshin@gmail.com")
    assert confirmed.review.state == "confirmed"
    assert confirmed.review.confirmed_at == "2026-09-05T00:00:00Z"
    assert confirmed.review.confirmed_by == "andy.kopshin@gmail.com"
    assert confirmed.review.confirmed_version == contract.version
    assert confirmed.review.content_digest is not None
    assert confirmed.review.decision_digest is not None
    assert confirmed.review.slot_digests


def test_confirm_contract_result_passes_assert_confirmed():
    confirmed = confirm_contract(_unconfirmed_bluepeak(), at="2026-09-05T00:00:00Z", by="x")
    assert_confirmed(confirmed)  # must not raise


def test_confirm_contract_slot_digests_cover_every_asset_and_finding_target():
    confirmed = confirm_contract(_unconfirmed_bluepeak(), at="2026-09-05T00:00:00Z", by="x")
    slots = confirmed.review.slot_digests
    assert set(slots) == {f"asset.{t}" for t in confirmed.asset} | {f"finding.{t}" for t in confirmed.finding}


def test_confirm_contract_does_not_mutate_the_original():
    contract = _unconfirmed_bluepeak()
    confirm_contract(contract, at="2026-09-05T00:00:00Z", by="x")
    assert contract.review.state == "proposed"  # unchanged


def test_propose_then_confirm_then_read_round_trips_through_configured_adapter(tmp_path):
    """The realistic end-to-end path this module exists for: propose
    (write_contract, mints version 1) -> read back -> confirm (digests
    computed against that exact version) -> persist the signed result
    (overwrite_contract -- NOT write_contract, which would bump the
    version the digests were just computed against and immediately
    invalidate them) -> read again -> hand to the engine."""
    from rhinosecure.adapters.configured import ConfiguredAdapter

    path = tmp_path / "bluepeak-gen.json"
    proposed = write_contract(path, _unconfirmed_bluepeak())
    assert proposed.version == 1

    reloaded = read_contract(path)
    confirmed = confirm_contract(reloaded, at="2026-09-05T00:00:00Z", by="andy.kopshin@gmail.com")
    assert confirmed.version == 1  # confirming does not itself mint a new revision
    overwrite_contract(path, confirmed)

    final = read_contract(path)
    assert final.version == 1
    adapter = ConfiguredAdapter(final)  # must not raise
    assert adapter.format == "bluepeak-gen"


def test_write_contract_after_confirming_would_invalidate_the_signature(tmp_path):
    """Documents WHY overwrite_contract exists, by showing what goes wrong
    without it: write_contract's blind version bump silently moves the
    contract to a version its own just-computed digests were never
    computed against."""
    path = tmp_path / "bluepeak-gen.json"
    write_contract(path, _unconfirmed_bluepeak())
    confirmed = confirm_contract(read_contract(path), at="2026-09-05T00:00:00Z", by="x")
    write_contract(path, confirmed)  # the wrong function for this step, on purpose
    with pytest.raises(Exception):  # ContractDigestMismatchError, via ConfiguredAdapter's constructor gate
        from rhinosecure.adapters.configured import ConfiguredAdapter

        ConfiguredAdapter(read_contract(path))


# --- check_identity_recipe_unchanged -----------------------------------------


def test_no_op_when_finding_id_is_not_content_address_on_either_side():
    old = _unconfirmed_bluepeak()  # finding_id is a plain column, not content_address
    new = old.model_copy()
    check_identity_recipe_unchanged(old, new)  # must not raise


def test_no_op_when_the_recipe_is_identical():
    old = _unconfirmed_mdvm()
    new = old.model_copy(deep=True)
    check_identity_recipe_unchanged(old, new)  # must not raise


def test_no_op_when_only_recipe_version_differs():
    old = _unconfirmed_mdvm()
    bumped_mapping = old.finding["finding_id"].model_copy(update={"recipe_version": 2})
    new = old.model_copy(update={"finding": {**old.finding, "finding_id": bumped_mapping}})
    check_identity_recipe_unchanged(old, new)  # must not raise


def test_changing_hex_len_on_a_confirmed_contract_is_refused():
    """The exit criterion, literally: hex_len changes -> refused, naming
    memory.decisions."""
    old = _unconfirmed_mdvm()
    changed_mapping = old.finding["finding_id"].model_copy(update={"hex_len": 24})
    new = old.model_copy(update={"finding": {**old.finding, "finding_id": changed_mapping}})
    with pytest.raises(IdentityRecipeChangedError, match="memory.decisions"):
        check_identity_recipe_unchanged(old, new)


@pytest.mark.parametrize(
    "field,value",
    [
        ("columns", ["DeviceId", "CveId"]),
        ("join", "-"),
        ("prefix", "MDVM2-"),
        ("case", "lower"),
        ("algorithm", "sha256"),  # only legal value today, but exercises the field-name path
    ],
)
def test_changing_any_recipe_field_is_refused(field, value):
    old = _unconfirmed_mdvm()
    changed_mapping = old.finding["finding_id"].model_copy(update={field: value})
    new = old.model_copy(update={"finding": {**old.finding, "finding_id": changed_mapping}})
    if getattr(old.finding["finding_id"], field) == value:
        pytest.skip("value identical to the original -- not a real change for this field")
    with pytest.raises(IdentityRecipeChangedError):
        check_identity_recipe_unchanged(old, new)


def test_allow_reset_permits_a_changed_recipe():
    old = _unconfirmed_mdvm()
    changed_mapping = old.finding["finding_id"].model_copy(update={"hex_len": 24})
    new = old.model_copy(update={"finding": {**old.finding, "finding_id": changed_mapping}})
    check_identity_recipe_unchanged(old, new, allow_reset=True)  # must not raise


def test_error_names_the_changed_fields():
    old = _unconfirmed_mdvm()
    changed_mapping = old.finding["finding_id"].model_copy(update={"hex_len": 24, "prefix": "X-"})
    new = old.model_copy(update={"finding": {**old.finding, "finding_id": changed_mapping}})
    with pytest.raises(IdentityRecipeChangedError) as excinfo:
        check_identity_recipe_unchanged(old, new)
    message = str(excinfo.value)
    assert "hex_len" in message
    assert "prefix" in message
