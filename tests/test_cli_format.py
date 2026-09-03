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
    # scoring.py's own rationale is untouched -- the note sits next to it, not inside it
    assert "no patch_window declared -> no scheduling restriction" in out
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


def test_format_defender_with_agents_is_refused_before_any_agent_is_built(capsys, monkeypatch):
    """The Coordinator reads <data>/assets.csv itself (native only); a
    non-native --agents run must stop with a clear message, not fail
    inside the Coordinator or read a stale native file."""
    monkeypatch.setattr(
        "rhinosecure.cli.run_agents", lambda *a, **k: pytest.fail("run_agents must not be called")
    )
    assert main(["run", "--format", "defender", "--data", "defender-sample", "--agents"]) == 2
    err = capsys.readouterr().err
    assert "--format defender is not supported with --agents" in err
    assert "assets.csv" in err


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
    assert "--format {defender,native}" in out
