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
