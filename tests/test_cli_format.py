"""`rhino run --format` -- the CLI's own concerns: flag wiring, the data-gap
summary and per-finding --explain note driven by not_collected, the
byte-identical native output, and the loud refusal of --agents with a
non-native format. The adapters themselves are covered in
test_adapters*.py; these run the committed data/defender-sample export
(synthetic, CVEs chosen from the committed snapshots so --offline works)."""

from __future__ import annotations

from pathlib import Path

import pytest

from rhinosecure.cli import main, run, run_with_report

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"
SAMPLE_DIR = Path(__file__).resolve().parents[1] / "data" / "defender-sample"


@pytest.fixture(autouse=True)
def _isolated_memory_db(tmp_path, monkeypatch):
    monkeypatch.setattr("rhinosecure.memory.DEFAULT_DB_PATH", tmp_path / "test-rhinosecure.db")


def test_format_defaults_to_native_and_changes_nothing_about_native_output(capsys):
    assert main(["run", "--data", "demo", "--seed", "42", "--offline"]) == 0
    implicit = capsys.readouterr().out
    assert main(["run", "--data", "demo", "--seed", "42", "--offline", "--format", "native"]) == 0
    explicit = capsys.readouterr().out

    assert implicit == explicit
    assert "Data gaps" not in implicit
    assert "not collected" not in implicit
    assert "Contested: 3/24 (12.5%) of scored findings" in implicit


def test_run_keeps_its_list_return_and_native_report_is_empty():
    scored = run(DEMO_DIR, seed=42, offline=True)
    result = run_with_report(DEMO_DIR, seed=42, offline=True)
    assert [(s.finding_id, s.risk_score, s.bucket) for s in scored] == [
        (s.finding_id, s.risk_score, s.bucket) for s in result.scored
    ]
    assert not result.report.has_anything_to_report
    assert result.not_collected_by_finding == {}


def test_format_defender_scores_the_sample_export_offline_and_prints_data_gaps(capsys):
    assert main(["run", "--format", "defender", "--data", "defender-sample", "--seed", "42", "--offline"]) == 0
    out = capsys.readouterr().out

    # the table: 9 distinct findings across 5 devices, hostnames as Defender's FQDNs
    assert "dc01.corp.example.com" in out and "sql02.corp.example.com" in out
    assert "MDVM-" in out
    assert "Contested:" in out
    # the gap summary
    assert "Data gaps (--format defender)" in out
    assert "assets   5/5" in out
    assert "patch_window" in out and "compensating_controls" in out and "role" in out
    assert "assets   1/5" in out and "criticality" in out  # wks-it05's blank AssetValue
    assert "findings 9/9" in out and "port" in out and "detected_date" in out
    assert "rhino constraint add" in out
    assert "Collapsed 1 duplicate finding row(s) and 1 repeated device row(s)" in out
    for line in out.splitlines():
        assert len(line) <= 100 or line.startswith("MDVM-") or line.startswith("finding_id"), line


def test_format_defender_explain_prints_a_per_finding_gap_note(capsys):
    assert main(["run", "--format", "defender", "--data", "defender-sample", "--offline", "--explain"]) == 0
    out = capsys.readouterr().out

    notes = [line for line in out.splitlines() if line.startswith("  ! not collected:")]
    assert len(notes) == 9  # one per finding, every Defender finding has gaps
    assert "environment=prod" in out and "data_sensitivity=internal" in out and "role=file" in out
    assert "role=workstation" in out
    # The scoring rationale itself says "not collected" for these assets, and
    # never the native "none declared" phrasing (scoring._rationale).
    assert "patch window not collected" in out
    assert "no patch_window declared" not in out
    for line in out.splitlines():
        if not line.startswith(("MDVM-", "finding_id")):  # table rows carry 40-hex-derived widths
            assert len(line) <= 100, line


def test_format_defender_sample_report_values():
    result = run_with_report(SAMPLE_DIR, seed=42, offline=True, fmt="defender")
    report = result.report

    assert report.assets_total == 5 and report.findings_total == 9
    assert report.duplicate_assets_collapsed == 1 and report.duplicate_findings_collapsed == 1
    assert report.asset_gaps["patch_window"] == 5 and report.asset_gaps["criticality"] == 1
    assert report.finding_gaps == {"detected_date": 9, "port": 9, "service": 9}
    assert result.assets["3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d"].os_build == "19045"  # latest Timestamp won
    assert len(result.scored) == 9 and len(result.not_collected_by_finding) == 9


def test_format_reaches_both_agent_entry_points(monkeypatch):
    """--format is threaded to run_agents and submit_constraint, not just
    the deterministic path -- the constraint path is the one a
    context-free export most needs."""
    class _Reached(Exception):
        """Carries the fmt that arrived, and stops main() right there --
        neither entry point has a cheap fake return value, and what is
        being checked is the argument, not what happens after it."""

    def _capture(*a, **k):
        raise _Reached(k.get("fmt"))

    monkeypatch.setattr("rhinosecure.cli.run_agents", _capture)
    monkeypatch.setattr("rhinosecure.cli.submit_constraint", _capture)

    with pytest.raises(_Reached) as run_call:
        main(["run", "--format", "defender", "--data", "defender-sample", "--agents"])
    assert run_call.value.args[0] == "defender"

    with pytest.raises(_Reached) as constraint_call:
        main(["constraint", "add", "x", "--format", "defender", "--data", "defender-sample"])
    assert constraint_call.value.args[0] == "defender"


def test_constraint_add_defaults_to_native_format():
    """--format is opt-in on constraint add too; omitting it must keep
    the native behavior every existing invocation relies on."""
    import argparse
    import inspect

    from rhinosecure.cli import submit_constraint as cli_submit

    assert inspect.signature(cli_submit).parameters["fmt"].default == "native"


def test_adapter_refusal_maps_to_ingest_error_and_exit_1(tmp_path, capsys):
    (tmp_path / "devices.csv").write_text("Device name,Device ID\ndc01,abc\n")
    (tmp_path / "vulnerabilities.csv").write_text("DeviceId,CveId\nabc,CVE-2020-1472\n")
    assert main(["run", "--format", "defender", "--data", str(tmp_path), "--offline"]) == 1
    err = capsys.readouterr().err
    assert "ingest error" in err
    assert "not a DeviceInfo export" in err


def test_unknown_format_is_rejected_by_argparse():
    with pytest.raises(SystemExit):
        main(["run", "--format", "qualys"])


def test_format_flag_lists_every_registered_adapter(capsys):
    with pytest.raises(SystemExit):
        main(["run", "--help"])
    out = capsys.readouterr().out
    assert "--format {bluepeak,defender,native}" in out


# --- reported bug: --format defender with --data left at its default ------
#
# `rhino constraint add --format defender` (no --data, so it defaults to
# "demo", the native fixture) crashed with an unhandled FileNotFoundError
# traceback -- devices.csv doesn't exist under data/demo. Same crash on
# `rhino run --format defender` with no --data. ingest.load_batch now
# raises a clear IngestError before either file is opened; cli.py already
# maps IngestError to "ingest error: ..." / exit 1 on every command, so
# no cli.py change was needed to fix this once the check moved down there.


def test_constraint_add_format_defender_without_data_fails_cleanly_not_a_traceback(capsys):
    """The exact bug report: --format defender, --data omitted (defaults
    to demo, the native fixture) -- must not raise past main()."""
    exit_code = main(["constraint", "add", "some constraint", "--format", "defender", "--offline"])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "ingest error" in err
    assert "devices.csv" in err and "vulnerabilities.csv" in err  # what defender needed
    assert "assets.csv" in err and "findings.csv" in err  # what demo actually has
    assert "--format/--data mismatch" in err
    assert "Traceback" not in err
    assert "FileNotFoundError" not in err


def test_run_format_defender_without_data_fails_cleanly_not_a_traceback(capsys):
    exit_code = main(["run", "--format", "defender", "--offline"])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "ingest error" in err
    assert "devices.csv" in err and "assets.csv" in err
    assert "Traceback" not in err


def test_run_agents_format_defender_without_data_fails_cleanly(capsys, monkeypatch):
    """Fails during ingest, before Coordinator is ever constructed --
    confirm run_agents is never reached to be extra sure this isn't
    accidentally caught somewhere deeper and re-raised differently."""
    monkeypatch.setattr(
        "rhinosecure.agents.coordinator.Coordinator",
        lambda *a, **k: pytest.fail("Coordinator must not be constructed -- ingest should fail first"),
    )
    exit_code = main(["run", "--agents", "--format", "defender", "--offline"])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "ingest error" in err


def test_run_format_native_default_against_defender_sample_fails_cleanly(capsys):
    """The reverse mismatch: --data points at a defender export but
    --format is left at its native default."""
    exit_code = main(["run", "--data", "defender-sample", "--offline"])
    err = capsys.readouterr().err

    assert exit_code == 1
    assert "devices.csv" in err and "assets.csv" in err
    assert "Traceback" not in err
