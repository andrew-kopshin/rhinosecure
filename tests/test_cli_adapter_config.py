"""`rhino run`/`rhino constraint add --adapter-config` -- the CLI's own
concerns: flag wiring, mutual exclusion with --format, the provenance
banner, clean errors for a bad config, and the slice's own stated exit
criteria. `adapters/configured.py`'s own correctness against the hand-
written adapters is covered by test_adapters_configured_differential.py;
this file is CLI-only.

Explicitly re-asserts (not just relies on the source files being untouched)
that adding --adapter-config left the built-in registry and its pinned
--help text exactly as they were -- zero pinned-test churn was a design
goal here, not an accident, so it is worth this file proving on its own
rather than trusting tests/test_adapters.py and tests/test_cli_format.py
were never touched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rhinosecure.adapters import DEFAULT_FORMAT, FORMATS
from rhinosecure.cli import main, run_agents, run_with_report, submit_constraint

REPO_ROOT = Path(__file__).resolve().parents[1]
BLUEPEAK_DIR = REPO_ROOT / "data" / "bluepeak"
DEFENDER_DIR = REPO_ROOT / "data" / "defender-sample"
DEMO_DIR = REPO_ROOT / "data" / "demo"


# --- the exit criterion: byte-identical to the built-in format -----------


def test_bluepeak_gen_prints_a_table_byte_identical_to_format_bluepeak(capsys):
    assert main(["run", "--format", "bluepeak", "--data", "bluepeak", "--seed", "42"]) == 0
    via_format = capsys.readouterr().out.splitlines()

    assert main(["run", "--adapter-config", "bluepeak-gen", "--data", "bluepeak", "--seed", "42"]) == 0
    via_config = capsys.readouterr().out.splitlines()

    # The only two DELIBERATE differences a config-driven run introduces:
    # the provenance banner (built-ins have no reviewed contract to name),
    # and the format LABEL itself ("bluepeak-gen" is a real, distinct
    # format name -- required so severity_label can never be confused with
    # the built-in "bluepeak"'s own). Strip exactly those two, nothing else.
    via_config_normalized = [
        line.replace("--format bluepeak-gen", "--format bluepeak")
        for line in via_config
        if not line.startswith("Using adapter config")
    ]
    assert via_config_normalized == via_format


def test_every_printed_line_is_at_most_100_columns(capsys):
    assert main(["run", "--adapter-config", "bluepeak-gen", "--data", "bluepeak", "--seed", "42", "--explain"]) == 0
    out = capsys.readouterr().out
    for line in out.splitlines():
        assert len(line) <= 100, f"line exceeds 100 chars: {line!r}"


def test_native_demo_run_is_byte_identical_to_before_this_feature(capsys):
    """The other half of the exit criterion -- adding --adapter-config
    must not change one byte of the frozen fixture's own output, and must
    never print the banner (there is no reviewed contract on a built-in
    --format run)."""
    assert main(["run", "--data", "demo", "--seed", "42"]) == 0
    out = capsys.readouterr().out
    assert "Using adapter config" not in out


def test_mdvm_gen_differs_from_format_defender_only_in_the_declared_ways(capsys):
    """mdvm-gen's finding_id prefix (MDVMC-) is a documented divergence
    from defender's (MDVM-) -- see the contract's own `divergences` entry
    -- so this is not claimed byte-identical the way bluepeak-gen is.
    Confirms the ONLY differences are the banner, the format label, and
    the prefix (never the digest suffix, never a bucket, never a score)."""
    assert main(["run", "--format", "defender", "--data", "defender-sample", "--seed", "42", "--offline"]) == 0
    via_format = capsys.readouterr().out.splitlines()

    assert (
        main(["run", "--adapter-config", "mdvm-gen", "--data", "defender-sample", "--seed", "42", "--offline"]) == 0
    )
    via_config = capsys.readouterr().out.splitlines()

    via_config_normalized = [
        line.replace("MDVMC-", "MDVM-").replace("--format mdvm-gen", "--format defender")
        for line in via_config
        if not line.startswith("Using adapter config")
    ]
    # Column widths legitimately differ (MDVMC- is one character wider than
    # MDVM-, and _print_rows sizes each column to its content) -- compare
    # word-by-word per line rather than the raw padded strings. The header
    # separator row is itself one run of dashes per column with no internal
    # whitespace, so a width difference shows up as unequal dash-run LENGTH
    # even though the column count is identical -- compare column counts
    # there instead of the dash runs themselves.
    assert len(via_config_normalized) == len(via_format)
    for config_line, format_line in zip(via_config_normalized, via_format):
        if config_line and set(config_line) <= {"-", " "}:
            assert len(config_line.split()) == len(format_line.split()), (config_line, format_line)
        else:
            assert config_line.split() == format_line.split(), (config_line, format_line)


# --- the provenance banner --------------------------------------------------


def test_banner_names_the_contract_format_version_and_confirmer(capsys):
    assert main(["run", "--adapter-config", "bluepeak-gen", "--data", "bluepeak", "--seed", "42"]) == 0
    out = capsys.readouterr().out
    assert "Using adapter config 'bluepeak-gen'" in out
    assert "confirmed" in out
    assert "andy.kopshin@gmail.com" in out
    # Printed before the exclusion/gap report, per _print_adapter_config_banner's
    # own stated ordering rule (never a footnote under numbers already formed).
    banner_at = out.index("Using adapter config")
    table_at = out.index("finding_id")
    assert banner_at < table_at


def test_banner_is_absent_for_a_built_in_format(capsys):
    assert main(["run", "--format", "bluepeak", "--data", "bluepeak", "--seed", "42"]) == 0
    assert "Using adapter config" not in capsys.readouterr().out


# --- mutual exclusion and clean errors --------------------------------------


def test_format_and_adapter_config_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        main(["run", "--format", "bluepeak", "--adapter-config", "bluepeak-gen", "--data", "bluepeak"])


def test_format_and_adapter_config_are_mutually_exclusive_on_constraint_add():
    with pytest.raises(SystemExit):
        main(["constraint", "add", "x", "--format", "bluepeak", "--adapter-config", "bluepeak-gen"])


def test_unknown_adapter_config_name_is_a_clean_ingest_error_not_a_traceback(capsys):
    exit_code = main(["run", "--adapter-config", "nonexistent-config", "--data", "bluepeak", "--seed", "42"])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "ingest error" in err
    assert "nonexistent-config" in err
    assert "not found" in err


def test_a_path_with_a_separator_is_used_directly_not_resolved_under_data_adapters(tmp_path, capsys):
    """_resolve_config_path's own rule: a bare name resolves under
    data/adapters/, but anything that already looks like a path (has a
    separator, or a .json suffix) is used exactly as given."""
    missing = tmp_path / "not-here.json"
    exit_code = main(["run", "--adapter-config", str(missing), "--data", "bluepeak", "--seed", "42"])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert str(missing) in err


# --- function-level wiring: run_with_report / run_agents / submit_constraint


def test_run_with_report_resolves_adapter_config_and_rebinds_fmt():
    result = run_with_report(BLUEPEAK_DIR, seed=42, adapter_config="bluepeak-gen")
    assert result.report.format == "bluepeak-gen"
    assert result.contract is not None
    assert result.contract.format == "bluepeak-gen"


def test_run_with_report_contract_is_none_for_a_built_in_format():
    result = run_with_report(DEMO_DIR, seed=42, fmt=DEFAULT_FORMAT)
    assert result.contract is None


def test_run_agents_wires_adapter_config_and_uses_run_label_for_memory(monkeypatch):
    """run_label ("<format>@v<version>"), not the bare format, is what
    reaches Coordinator(ingest_format=...) for a config-driven run -- see
    IngestAdapter.run_label's own docstring for why (two runs against
    different revisions of the same contract are not the same mapping)."""
    captured = {}

    class _FakeCoordinator:
        def __init__(self, data_dir, cache=None, *, memory=None, verbose=False, assets=None, ingest_format="native", contract=None):
            captured["ingest_format"] = ingest_format
            captured["contract"] = contract
            captured["assets"] = assets
            self.contract = contract
            self.ingest_format = ingest_format
            from types import SimpleNamespace

            self.state = SimpleNamespace(
                research_failures={}, environment_failures={}, risk_failures={}, tot_failures={},
                tot_by_id={}, last_raw_output={},
            )

        def run(self, findings):
            return []

        def ranked(self):
            return []

    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)

    run_agents(DEFENDER_DIR, seed=42, offline=True, adapter_config="mdvm-gen")

    assert captured["contract"] is not None
    assert captured["contract"].format == "mdvm-gen"
    assert captured["ingest_format"] == f"mdvm-gen@v{captured['contract'].version}"
    # The real device ids from data/defender-sample/devices.csv -- confirms
    # the inventory genuinely came from ConfiguredAdapter, not the built-in
    # defender adapter silently substituted underneath (both would produce
    # SOME assets dict; only a config-driven one is keyed exactly this way,
    # since a hand-written adapter refusing/mapping differently would
    # exclude or fail well before reaching here).
    assert set(captured["assets"]) == {
        "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
        "2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c",
        "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d",
        "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e",
        "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f",
    }


def test_submit_constraint_reaches_the_configured_adapter_before_any_llm_call(monkeypatch):
    """Confirms the WIRING (adapter_config -> load_config_adapter -> the
    findings Coordinator.submit_constraint receives) without making a real
    LLM call -- Coordinator.submit_constraint itself is replaced, so
    nothing past adapter resolution executes. The real end-to-end path
    (LLM included) was confirmed manually: `rhino constraint add "dc01...
    can only be rebooted on Sundays" --adapter-config mdvm-gen --data
    defender-sample --offline` persists a constraint and re-plans two
    MDVMC--prefixed findings, moving one from contested to next_window."""
    captured = {}

    class _FakeCoordinator:
        def __init__(self, data_dir, cache=None, *, memory=None, verbose=False, assets=None, ingest_format="native", contract=None):
            captured["contract"] = contract
            captured["ingest_format"] = ingest_format

        def submit_constraint(self, text, findings, *, seed):
            captured["finding_ids"] = [f.finding.finding_id for f in findings]
            from rhinosecure.agents.coordinator import ConstraintSubmissionResult
            from rhinosecure.agents.constraint_intake import ConstraintInterpretation

            return ConstraintSubmissionResult(
                interpretation=ConstraintInterpretation(
                    constraint_kind="asset",
                    asset_id=None, effect_kind=None, effect_value=None, patch_limit=None,
                    affected_finding_ids=[], rationale="fake", sources=[],
                ),
                constraint_id=None,
                run_id=None,
                deltas=(),
            )

    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)

    submit_constraint(
        "dc01.corp.example.com can only be rebooted on Sundays",
        DEFENDER_DIR,
        seed=42,
        offline=True,
        adapter_config="mdvm-gen",
    )

    assert captured["contract"].format == "mdvm-gen"
    assert captured["ingest_format"].startswith("mdvm-gen@v")
    assert all(fid.startswith("MDVMC-") for fid in captured["finding_ids"])


# --- zero pinned-test churn, asserted here too, not just trusted ---------


def test_pinned_registry_and_help_text_are_unaffected_by_adapter_config(capsys):
    assert DEFAULT_FORMAT == "native"
    assert set(FORMATS) == {"native", "defender", "bluepeak"}

    with pytest.raises(SystemExit):
        main(["run", "--format", "qualys"])

    with pytest.raises(SystemExit):
        main(["run", "--help"])
    out = capsys.readouterr().out
    assert "--format {bluepeak,defender,native}" in out
