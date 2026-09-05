"""`rhino adapt list` / `rhino adapt probe <name>` -- cli.py's own concerns
(argument wiring, directory discovery, output formatting, exit codes).
adapters/probe.py's own profiling correctness is covered by
test_adapters_probe.py; this file only exercises the CLI layer around it."""

from __future__ import annotations

from pathlib import Path

import pytest

from rhinosecure.cli import ProbeSource, _discover_probe_sources, main

REPO_ROOT = Path(__file__).resolve().parents[1]


# --- rhino adapt list --------------------------------------------------------


def test_adapt_list_exits_zero_and_prints_a_table(capsys):
    assert main(["adapt", "list"]) == 0
    out = capsys.readouterr().out
    assert "name" in out and "known format" in out


def test_adapt_list_finds_the_real_committed_sources(capsys):
    """Structural, not fixture-value coupled: just that the demo, bluepeak,
    and defender-sample directories -- which must exist for the rest of the
    suite to run at all -- show up as candidates."""
    main(["adapt", "list"])
    out = capsys.readouterr().out
    assert "demo" in out
    assert "bluepeak" in out
    assert "defender-sample" in out


def test_adapt_list_annotates_known_formats(capsys):
    main(["adapt", "list"])
    out = capsys.readouterr().out
    lines = {line.split()[0]: line for line in out.splitlines() if line.strip()}
    assert "native" in lines["demo"]
    assert "bluepeak" in lines["bluepeak"]
    assert "defender" in lines["defender-sample"]


def test_discover_probe_sources_skips_directories_with_no_csv(tmp_path, monkeypatch):
    import rhinosecure.cli as cli_module

    monkeypatch.setattr(cli_module, "REPO_ROOT", tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "has_csv").mkdir()
    (tmp_path / "data" / "has_csv" / "a.csv").write_text("x\n1\n")
    (tmp_path / "data" / "no_csv").mkdir()
    (tmp_path / "data" / "no_csv" / "notes.txt").write_text("nothing here")

    sources = _discover_probe_sources()
    assert [s.name for s in sources] == ["has_csv"]


def test_discover_probe_sources_no_data_dir_returns_empty(tmp_path, monkeypatch):
    import rhinosecure.cli as cli_module

    monkeypatch.setattr(cli_module, "REPO_ROOT", tmp_path)  # tmp_path/data does not exist
    assert _discover_probe_sources() == []


def test_adapt_list_reports_nothing_found_message(tmp_path, monkeypatch, capsys):
    import rhinosecure.cli as cli_module

    monkeypatch.setattr(cli_module, "REPO_ROOT", tmp_path)
    assert main(["adapt", "list"]) == 0
    out = capsys.readouterr().out
    assert "No candidate sources found" in out


def test_probe_source_dataclass_matches_format_is_a_subset_check(tmp_path, monkeypatch):
    """A directory with EXTRA unrelated CSVs alongside a full native set
    still counts as a native match -- the check is 'has at least', not
    'has exactly'."""
    import rhinosecure.cli as cli_module

    monkeypatch.setattr(cli_module, "REPO_ROOT", tmp_path)
    (tmp_path / "data" / "mixed").mkdir(parents=True)
    (tmp_path / "data" / "mixed" / "assets.csv").write_text("x\n")
    (tmp_path / "data" / "mixed" / "findings.csv").write_text("x\n")
    (tmp_path / "data" / "mixed" / "extra.csv").write_text("x\n")

    sources = _discover_probe_sources()
    assert sources == [ProbeSource(name="mixed", csv_files=("assets.csv", "extra.csv", "findings.csv"), matches_format=("native",))]


# --- rhino adapt probe <name> ------------------------------------------------


def test_adapt_probe_resolves_name_under_data_dir(capsys):
    assert main(["adapt", "probe", "bluepeak"]) == 0
    out = capsys.readouterr().out
    assert "synthetic_cve_inventory_50.csv" in out
    assert "CVE_ID" in out


def test_adapt_probe_prints_column_table_with_looks_like_and_samples(capsys):
    main(["adapt", "probe", "demo"])
    out = capsys.readouterr().out
    assert "looks_like" in out and "samples" in out
    assert "identity_candidate" in out  # asset_id/hostname in the real fixture


def test_adapt_probe_two_file_source_profiles_both_files(capsys):
    main(["adapt", "probe", "defender-sample"])
    out = capsys.readouterr().out
    assert "devices.csv" in out
    assert "vulnerabilities.csv" in out


def test_adapt_probe_deduplicates_a_repeated_header_name_in_the_display(tmp_path, capsys):
    """A duplicated column name must not print two identical rows in the
    table -- the 'observation' text already explains the duplication."""
    (tmp_path / "weird.csv").write_text("a,b,a\n1,2,3\n")
    assert main(["adapt", "probe", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    column_a_rows = [line for line in out.splitlines() if line.split()[:1] == ["a"]]
    assert len(column_a_rows) == 1


def test_adapt_probe_reports_observations(tmp_path, capsys):
    (tmp_path / "ragged.csv").write_text("a,b\n1,2\n3\n")
    assert main(["adapt", "probe", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "observation(s)" in out
    assert "expected 2 field" in out


def test_adapt_probe_no_observations_says_so(capsys):
    main(["adapt", "probe", "bluepeak"])
    out = capsys.readouterr().out
    assert "No observations." in out


def test_adapt_probe_nonexistent_data_set_exits_nonzero_via_shared_resolver():
    """--data's own resolution (_resolve_data_dir) is reused verbatim --
    same error shape as `rhino run --data <bad name>`."""
    with pytest.raises(SystemExit):
        main(["adapt", "probe", "no-such-dataset-anywhere"])


def test_adapt_probe_directory_with_no_csv_is_a_clean_error_not_a_traceback(tmp_path, capsys):
    assert main(["adapt", "probe", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "probe error" in err
    assert "no .csv file" in err


def test_adapt_probe_path_argument_works_not_just_a_bare_name(capsys):
    assert main(["adapt", "probe", str(REPO_ROOT / "data" / "bluepeak")]) == 0
    out = capsys.readouterr().out
    assert "synthetic_cve_inventory_50.csv" in out


# --- argument wiring ----------------------------------------------------------


def test_adapt_with_no_subcommand_is_rejected_by_argparse():
    with pytest.raises(SystemExit):
        main(["adapt"])


def test_adapt_probe_with_no_name_is_rejected_by_argparse():
    with pytest.raises(SystemExit):
        main(["adapt", "probe"])


# --- rhino adapt confirm / rereview ------------------------------------------
#
# Slice 7. The library's own correctness is tests/test_adapters_review.py;
# this section is CLI-only -- flag wiring, exit codes, and what prints. Every
# write happens against a tmp_path copy: the two committed contracts are
# pinned byte-for-byte by the differential suite, and rewriting one so a new
# command's output looks good is what CLAUDE.md Section 8 rule 1 forbids.

import json as _json
import sys as _sys
from datetime import datetime

from rhinosecure.adapters.config_io import read_contract, write_contract
from rhinosecure.adapters.config_model import Contract

BLUEPEAK_DATA = str(REPO_ROOT / "data" / "bluepeak")
COMMITTED_DIR = REPO_ROOT / "data" / "adapters"


def _scratch_contract(tmp_path):
    _sys.path.insert(0, str(REPO_ROOT / "tests"))
    from test_adapters_config_model import bluepeak_gen_dict

    path = tmp_path / "scratch-gen.json"
    write_contract(path, Contract.model_validate(bluepeak_gen_dict()))
    return path


def test_rereview_of_a_committed_contract_exits_zero_and_writes_nothing(capsys):
    path = COMMITTED_DIR / "mdvm-gen.json"
    before = path.read_bytes()
    assert main(["adapt", "rereview", "mdvm-gen", "--data", "defender-sample"]) == 0
    out = capsys.readouterr().out
    assert "Measurement" in out
    assert "No drift and no problems." in out
    assert path.read_bytes() == before


def test_rereview_reports_the_measurement_before_the_contracts_own_claims(capsys):
    """A reviewer should form an impression from measurements, not from
    assurances -- so the measured section must come first."""
    main(["adapt", "rereview", "mdvm-gen", "--data", "defender-sample"])
    out = capsys.readouterr().out
    assert out.index("Measurement") < out.index("Contract state")


def test_rereview_shows_which_scoring_inputs_are_documented_defaults(capsys):
    """The line a claim-only review cannot produce: a mapping can run
    perfectly clean while every Impact input is fabricated."""
    main(["adapt", "rereview", "mdvm-gen", "--data", "defender-sample"])
    out = capsys.readouterr().out
    assert "Values produced for the scoring inputs" in out
    assert "not collected -- documented default" in out


def test_rereview_prints_each_ignored_columns_measured_shape_beside_its_reason(capsys):
    main(["adapt", "rereview", "mdvm-gen", "--data", "defender-sample"])
    out = capsys.readouterr().out
    assert "Columns this contract declares it does not read" in out
    assert "ExposureLevel" in out
    assert "measured:" in out


def test_rereview_says_so_when_no_slot_digests_were_recorded(capsys):
    """C5: the state both committed contracts are actually in."""
    main(["adapt", "rereview", "bluepeak-gen", "--data", "bluepeak"])
    out = capsys.readouterr().out
    assert "recorded no slot_digests" in out


def test_rereview_does_not_accept_an_identity():
    with pytest.raises(SystemExit):
        main(["adapt", "rereview", "mdvm-gen", "--data", "defender-sample", "--by", "someone"])


def test_confirm_requires_by():
    with pytest.raises(SystemExit):
        main(["adapt", "confirm", "mdvm-gen", "--data", "defender-sample"])


def test_confirm_requires_data():
    with pytest.raises(SystemExit):
        main(["adapt", "confirm", "mdvm-gen", "--by", "someone"])


def test_confirm_signs_a_scratch_contract_and_exits_zero(tmp_path, capsys):
    path = _scratch_contract(tmp_path)
    assert main(["adapt", "confirm", str(path), "--data", BLUEPEAK_DATA, "--by", "r@example.com"]) == 0
    out = capsys.readouterr().out
    assert "Signed:" in out and "slot digest(s) recorded" in out
    written = read_contract(path)
    assert written.review.state == "confirmed"
    assert written.review.confirmed_by == "r@example.com"
    assert written.observed["assets_loaded"] > 0


def test_confirm_refuses_an_already_confirmed_contract_and_exits_one(tmp_path, capsys):
    path = _scratch_contract(tmp_path)
    main(["adapt", "confirm", str(path), "--data", BLUEPEAK_DATA, "--by", "r@example.com"])
    capsys.readouterr()
    before = path.read_bytes()
    assert main(["adapt", "confirm", str(path), "--data", BLUEPEAK_DATA, "--by", "r@example.com"]) == 1
    err = capsys.readouterr().err
    assert "--reconfirm" in err
    assert path.read_bytes() == before


def test_reconfirm_signs_again(tmp_path, capsys):
    path = _scratch_contract(tmp_path)
    main(["adapt", "confirm", str(path), "--data", BLUEPEAK_DATA, "--by", "first@example.com"])
    capsys.readouterr()
    assert (
        main([
            "adapt", "confirm", str(path), "--data", BLUEPEAK_DATA,
            "--by", "second@example.com", "--reconfirm",
        ])
        == 0
    )
    assert read_contract(path).review.confirmed_by == "second@example.com"


def test_confirm_records_a_real_utc_timestamp(tmp_path, capsys):
    """cli.py is where the clock is read (config_io.py's docstring reserves
    it for exactly here), so the stamped time must be a real one."""
    path = _scratch_contract(tmp_path)
    main(["adapt", "confirm", str(path), "--data", BLUEPEAK_DATA, "--by", "r@example.com"])
    capsys.readouterr()
    datetime.strptime(read_contract(path).review.confirmed_at, "%Y-%m-%dT%H:%M:%SZ")  # must not raise


def test_a_bad_attest_argument_is_refused_before_anything_is_written(tmp_path, capsys):
    path = _scratch_contract(tmp_path)
    before = path.read_bytes()
    assert (
        main([
            "adapt", "confirm", str(path), "--data", BLUEPEAK_DATA, "--by", "r@example.com",
            "--attest", "not-an-item=text",
        ])
        == 1
    )
    err = capsys.readouterr().err
    assert "not an attestation item" in err
    assert path.read_bytes() == before


def test_a_missing_contract_is_a_clean_error_not_a_traceback(tmp_path, capsys):
    assert main(["adapt", "confirm", str(tmp_path / "nope.json"), "--data", BLUEPEAK_DATA, "--by", "x"]) == 1
    err = capsys.readouterr().err
    assert "contract error" in err
    assert "Traceback" not in err


def test_a_structurally_broken_contract_is_a_clean_error(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text('{"format": "x"}', encoding="utf-8")
    assert main(["adapt", "rereview", str(path), "--data", BLUEPEAK_DATA]) == 1
    err = capsys.readouterr().err
    assert "contract error" in err
    assert "Traceback" not in err


def test_data_pointed_at_the_wrong_fleet_refuses_and_exits_one(tmp_path, capsys):
    path = _scratch_contract(tmp_path)
    assert main(["adapt", "rereview", str(path), "--data", "demo"]) == 1
    assert "HALTED" in capsys.readouterr().err


def test_rereview_exits_one_when_a_mapping_decision_has_moved(tmp_path, capsys):
    path = _scratch_contract(tmp_path)
    main(["adapt", "confirm", str(path), "--data", BLUEPEAK_DATA, "--by", "r@example.com"])
    capsys.readouterr()
    edited = _json.loads(path.read_text(encoding="utf-8"))
    edited["asset"]["hostname"]["case"] = "lower"
    path.write_text(_json.dumps(edited, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    assert main(["adapt", "rereview", str(path), "--data", BLUEPEAK_DATA]) == 1
    out = capsys.readouterr().out
    assert "a MAPPING DECISION has changed" in out
    assert "NEEDS REVIEW asset.hostname" in out
    assert "23 unchanged, 1 changed" in out


def test_the_run_banner_notices_a_size_mismatch_against_what_was_signed(tmp_path, capsys):
    """Nothing else in the codebase reads `observed`, so without this a
    contract confirmed against a small sample and then run against a full
    export is undetectable."""
    from rhinosecure.adapters.config_io import confirm_contract, overwrite_contract
    from rhinosecure.adapters.config_model import Review

    path = _scratch_contract(tmp_path)
    main(["adapt", "confirm", str(path), "--data", BLUEPEAK_DATA, "--by", "r@example.com"])
    capsys.readouterr()

    edited = _json.loads(path.read_text(encoding="utf-8"))
    edited["observed"]["assets_loaded"] = 3  # as if signed against a trimmed sample
    path.write_text(_json.dumps(edited, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # That edit voids the signature, so re-sign the doctored content.
    doctored = read_contract(path).model_copy(update={"review": Review()})
    overwrite_contract(path, confirm_contract(doctored, at="2026-09-05T00:00:00Z", by="r@example.com"))

    assert main(["run", "--adapter-config", str(path), "--data", "bluepeak", "--seed", "42"]) == 0
    assert "was confirmed against 3 asset(s)" in capsys.readouterr().out


def test_a_malformed_slot_digest_key_does_not_crash_the_printer(tmp_path, capsys):
    """Found by review. `slot_digests` lives under `review`, which sits
    outside both digests -- so its keys are unsigned and a hand-edited file
    can carry a name with no `.` in it, which the node lookup split on."""
    path = _scratch_contract(tmp_path)
    main(["adapt", "confirm", str(path), "--data", BLUEPEAK_DATA, "--by", "r@example.com"])
    capsys.readouterr()
    edited = _json.loads(path.read_text(encoding="utf-8"))
    edited["review"]["slot_digests"]["bogus-no-dot"] = "sha256:" + "0" * 64
    path.write_text(_json.dumps(edited, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    assert main(["adapt", "rereview", str(path), "--data", BLUEPEAK_DATA]) == 1  # must not raise
    out = capsys.readouterr().out
    assert "bogus-no-dot" in out
    assert "(removed)" in out


def test_a_truncated_value_list_says_how_many_it_dropped(tmp_path, capsys):
    """Found by review. The distribution showed only the top 4 values with no
    ellipsis, so the counts silently failed to add up to assets_loaded."""
    main(["adapt", "rereview", "bluepeak-gen", "--data", "bluepeak"])
    out = capsys.readouterr().out
    role_line = next(line for line in out.splitlines() if line.startswith("role "))
    assert "more" in role_line  # bluepeak's fleet spans more than four roles


def test_the_banner_says_nothing_when_the_contract_has_no_measurement(capsys):
    """Both committed contracts predate `observed` being written at all --
    their output must not change."""
    assert main(["run", "--adapter-config", "bluepeak-gen", "--data", "bluepeak", "--seed", "42"]) == 0
    out = capsys.readouterr().out
    assert "Using adapter config" in out
    assert "was confirmed against" not in out
