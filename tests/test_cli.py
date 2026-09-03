import ast
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from rhinosecure.enrich.cache import OfflineCacheMissError
from rhinosecure.cli import main, run, run_agents

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"


def test_offline_flag_is_accepted_and_does_not_error():
    assert main(["run", "--data", "demo", "--seed", "42", "--offline"]) == 0


def test_offline_flag_does_not_change_output_when_snapshots_already_cover_every_cve():
    """Every CVE in the demo fixture already has a committed KEV/EPSS
    snapshot, so both modes are pure cache hits and must agree exactly.
    --offline's real effect -- raising loudly on a genuine miss -- is
    covered separately below and in test_cache.py/test_kev.py/test_epss.py."""
    online = run(DEMO_DIR, seed=42, offline=False)
    offline = run(DEMO_DIR, seed=42, offline=True)
    assert [(s.finding_id, s.risk_score, s.bucket) for s in online] == [
        (s.finding_id, s.risk_score, s.bucket) for s in offline
    ]


def test_offline_flag_fails_loudly_on_a_genuinely_new_cve(tmp_path: Path):
    """A CVE with no committed snapshot anywhere must make --offline raise
    instead of silently reaching the network."""
    (tmp_path / "assets.csv").write_text(
        "asset_id,hostname,os,os_build,role,business_function,criticality,"
        "internet_exposed,environment,data_sensitivity,patch_window,"
        "patch_restrictions,compensating_controls,owner\n"
        "A01,HOST1,Windows Server 2019,17763,dc,DC,5,False,prod,regulated,,,,\n"
    )
    (tmp_path / "findings.csv").write_text(
        "finding_id,asset_id,cve_id,detected_date,scanner_severity,product,"
        "version,port,service,evidence\n"
        "F01,A01,CVE-1999-0001,2026-01-01,high,X,1.0,1,svc,ev\n"
    )

    with pytest.raises(OfflineCacheMissError):
        run(tmp_path, seed=42, offline=True)


def test_deterministic_path_prints_contested_rate_on_the_real_fixture(capsys):
    """F07, F11, F14 are the demo fixture's three contested findings
    (PROGRESS.md, test_scoring.py) -- 3/24."""
    assert main(["run", "--data", "demo", "--seed", "42", "--offline"]) == 0
    out = capsys.readouterr().out
    assert "Contested: 3/24 (12.5%) of scored findings" in out


def test_deterministic_explain_wraps_long_rationale_bullets_on_the_real_fixture(capsys):
    """F14 (CVE-2023-23397, contested) has a scoring_rationale bullet that
    runs to 319 characters unwrapped -- confirms the fix against real
    fixture data, not just a synthetic long string."""
    assert main(["run", "--data", "demo", "--seed", "42", "--offline", "--explain"]) == 0
    out = capsys.readouterr().out
    assert "F14" in out
    assert "bucket=contested" in out  # content survived the wrap, just reflowed
    for line in out.splitlines():
        assert len(line) <= 100, f"line exceeds 100 chars: {line!r}"


# --- --agents ------------------------------------------------------------
#
# Never dispatch a real Coordinator/Crew here -- that makes real LLM calls
# (see agents/coordinator.py's own tests, which fake crewai.Crew the same
# way). These tests fake Coordinator itself, one level up, to check cli.py's
# own wiring: argument threading, exit codes, and error-to-message mapping.


def test_cli_module_does_not_import_crewai_at_module_level():
    """`rhino run` (no --agents) must keep working on Python 3.14, where
    `import crewai` itself fails (CLAUDE.md Section 11) -- so nothing
    crewai-shaped may be imported at cli.py's module level, only inside
    run_agents()/main()'s --agents branch. Parses the source rather than
    trusting runtime sys.modules state, which other test files importing
    crewai would otherwise pollute for any check done that way."""
    import rhinosecure.cli as cli_module

    tree = ast.parse(Path(inspect.getfile(cli_module)).read_text(encoding="utf-8"))
    top_level_imports = []
    for node in tree.body:  # tree.body is module-level only, not nested in functions
        if isinstance(node, ast.Import):
            top_level_imports += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_level_imports.append(node.module)

    assert not any(name.startswith("crewai") for name in top_level_imports)
    assert not any(name.startswith("rhinosecure.agents") for name in top_level_imports)


class _FakeCoordinator:
    """Stands in for agents.coordinator.Coordinator so these tests never
    construct a real one (which would load KEV/ATT&CK snapshots) or call a
    real Crew (which would make real LLM calls). Mirrors the real
    Coordinator's public surface -- run(), ranked(), .state.*_failures,
    .state.tot_by_id -- since cli.py reads all of it (a failed finding is
    recorded and skipped inside Coordinator.run, never raised; see
    agents/coordinator.py)."""

    result: list = []
    failures: dict = {}
    tot_by_id: dict = {}
    last_init_args: tuple | None = None
    last_run_findings: list | None = None

    def __init__(self, data_dir, cache=None, *, verbose=False):
        _FakeCoordinator.last_init_args = (data_dir, cache)
        self.state = SimpleNamespace(
            research_failures=_FakeCoordinator.failures.get("research", {}),
            environment_failures=_FakeCoordinator.failures.get("environment", {}),
            risk_failures=_FakeCoordinator.failures.get("risk", {}),
            tot_failures=_FakeCoordinator.failures.get("tot", {}),
            tot_by_id=_FakeCoordinator.tot_by_id,
        )

    def run(self, findings):
        _FakeCoordinator.last_run_findings = findings
        return _FakeCoordinator.result

    def ranked(self):
        return _FakeCoordinator.result


@pytest.fixture(autouse=True)
def _reset_fake_coordinator():
    _FakeCoordinator.result = []
    _FakeCoordinator.failures = {}
    _FakeCoordinator.tot_by_id = {}
    _FakeCoordinator.last_init_args = None
    _FakeCoordinator.last_run_findings = None


def _fake_recommendation(finding_id="F01", risk_score=42.0, bucket="next_window"):
    from rhinosecure.agents.risk import RiskRecommendation

    return RiskRecommendation(
        finding_id=finding_id,
        cve_id="CVE-2021-26855",
        asset_id="A02",
        hostname="EXCH01",
        risk_score=risk_score,
        bucket=bucket,
        scoring_rationale=["fake rationale line"],
        verdict_summary="fake verdict summary.",
        narrative="fake narrative",
        sources=["fake"],
    )


def test_run_agents_wires_data_dir_seed_and_offline_to_coordinator(monkeypatch):
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation()]

    coordinator = run_agents(DEMO_DIR, seed=42, offline=True)

    assert isinstance(coordinator, _FakeCoordinator)
    assert coordinator.ranked() == [_fake_recommendation()]
    data_dir, cache = _FakeCoordinator.last_init_args
    assert data_dir == DEMO_DIR
    assert cache.offline is True
    assert len(_FakeCoordinator.last_run_findings) > 0


def test_main_with_agents_flag_dispatches_coordinator_and_returns_0(monkeypatch):
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation()]

    assert main(["run", "--data", "demo", "--agents"]) == 0


def test_main_with_agents_flag_and_explain_prints_narrative(monkeypatch, capsys):
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation()]

    assert main(["run", "--data", "demo", "--agents", "--explain"]) == 0
    out = capsys.readouterr().out
    assert "fake narrative" in out
    assert "fake rationale line" in out
    assert "fake verdict summary." in out
    # verdict_summary is skimmable up top: before the rationale bullets,
    # which come before the full narrative.
    assert out.index("fake verdict summary.") < out.index("- fake rationale line")
    assert out.index("- fake rationale line") < out.index("fake narrative")


def test_main_with_agents_flag_and_explain_wraps_long_narrative_and_bullet_text(monkeypatch, capsys):
    """verdict_summary/narrative/scoring_rationale bullets all currently
    ran off-screen unwrapped -- confirm every printed line stays within
    NARRATIVE_WRAP_WIDTH, on all three."""
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    long_text = " ".join(f"word{i}" for i in range(60))  # far longer than 100 chars unwrapped
    _FakeCoordinator.result = [
        _fake_recommendation().model_copy(
            update={
                "verdict_summary": long_text,
                "narrative": long_text,
                "scoring_rationale": ["fake rationale line", long_text],
            }
        )
    ]

    assert main(["run", "--data", "demo", "--agents", "--explain"]) == 0
    out = capsys.readouterr().out
    for line in out.splitlines():
        assert len(line) <= 100, f"line exceeds 100 chars: {line!r}"


def test_wrap_indents_every_line_and_respects_the_width():
    from rhinosecure.cli import _wrap

    text = " ".join(f"word{i}" for i in range(60))
    wrapped = _wrap(text)
    lines = wrapped.splitlines()
    assert len(lines) > 1  # actually wrapped, not left as one long line
    assert all(line.startswith("  ") for line in lines)
    assert all(len(line) <= 100 for line in lines)


def test_wrap_bullet_aligns_continuation_under_text_not_the_dash():
    from rhinosecure.cli import _wrap_bullet

    text = " ".join(f"word{i}" for i in range(60))
    wrapped = _wrap_bullet(text)
    lines = wrapped.splitlines()
    assert len(lines) > 1  # actually wrapped
    assert lines[0].startswith("  - ")
    assert all(line.startswith("    ") for line in lines[1:])  # aligned under the text, not "-"
    assert all(len(line) <= 100 for line in lines)


def test_main_with_agents_flag_prints_recorded_failures(monkeypatch, capsys):
    """A finding recorded and skipped (agents/coordinator.py) must still
    be surfaced to the user, not silently absent from the table."""
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation()]
    _FakeCoordinator.failures = {
        "research": {"F07": "gave up after 3 attempt(s): no valid JSON object found"},
    }

    assert main(["run", "--data", "demo", "--agents"]) == 0
    err = capsys.readouterr().err
    assert "F07" in err
    assert "research" in err


def test_main_with_agents_flag_prints_nothing_extra_when_no_failures(monkeypatch, capsys):
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation()]

    assert main(["run", "--data", "demo", "--agents"]) == 0
    assert capsys.readouterr().err == ""


def test_main_without_agents_flag_still_uses_the_deterministic_path(monkeypatch):
    """--agents defaults off -- plain `rhino run` must not touch Coordinator
    at all."""
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)

    assert main(["run", "--data", "demo", "--seed", "42"]) == 0
    assert _FakeCoordinator.last_init_args is None


# --- contested rate and Tree-of-Thought explain output -----------------------


def _fake_tot_result(finding_id="F01", *, near_tie=False):
    from crewai.types.usage_metrics import UsageMetrics

    from rhinosecure.tot import CriticScores, Strategy, Thought, ToTResult

    winner = Thought(
        strategy=Strategy.EMERGENCY_CHANGE,
        depth=1,
        proposal=f"Patch {finding_id} tonight via emergency change.",
        critic=CriticScores(
            risk_reduction=9, operational_cost=3, constraint_compliance=8,
            evidence_strength=8, contradicting_evidence=1, justification="fake",
        ),
    )
    if not near_tie:
        return ToTResult(
            finding_id=finding_id, winner=winner, near_tie=False, candidates=(winner,),
            termination_reason="clear_winner", depth_reached=1, usage=UsageMetrics(),
        )
    runner_up = Thought(
        strategy=Strategy.ESTABLISH_WINDOW,
        depth=3,
        proposal=f"Establish a Sunday window for {finding_id}.",
        critic=CriticScores(
            risk_reduction=7, operational_cost=3, constraint_compliance=9,
            evidence_strength=7, contradicting_evidence=2, justification="fake",
        ),
    )
    return ToTResult(
        finding_id=finding_id, winner=None, near_tie=True, candidates=(winner, runner_up),
        termination_reason="depth_limit", depth_reached=3, usage=UsageMetrics(),
    )


def test_agents_path_prints_contested_rate(monkeypatch, capsys):
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [
        _fake_recommendation(finding_id="F01", bucket="contested"),
        _fake_recommendation(finding_id="F02", bucket="next_window"),
    ]

    assert main(["run", "--data", "demo", "--agents"]) == 0
    out = capsys.readouterr().out
    assert "Contested: 1/2 (50.0%) of scored findings" in out


def test_agents_explain_prints_the_tot_winner_for_a_contested_finding(monkeypatch, capsys):
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation(finding_id="F01", bucket="contested")]
    _FakeCoordinator.tot_by_id = {"F01": _fake_tot_result("F01")}

    assert main(["run", "--data", "demo", "--agents", "--explain"]) == 0
    out = capsys.readouterr().out
    assert "Tree-of-Thought: winner = emergency_change" in out
    assert "Patch F01 tonight via emergency change." in out


def test_agents_explain_surfaces_both_candidates_on_a_near_tie_not_a_forced_winner(monkeypatch, capsys):
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation(finding_id="F01", bucket="contested")]
    _FakeCoordinator.tot_by_id = {"F01": _fake_tot_result("F01", near_tie=True)}

    assert main(["run", "--data", "demo", "--agents", "--explain"]) == 0
    out = capsys.readouterr().out
    assert "near-tie" in out
    assert "no single winner" in out
    assert "[emergency_change]" in out
    assert "[establish_window]" in out


def test_agents_explain_prints_a_tot_dispatch_failure_reason(monkeypatch, capsys):
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation(finding_id="F01", bucket="contested")]
    _FakeCoordinator.failures = {"tot": {"F01": "gave up after 3 attempt(s): no valid JSON object found"}}

    assert main(["run", "--data", "demo", "--agents", "--explain"]) == 0
    out = capsys.readouterr().out
    assert "Tree-of-Thought: failed" in out
    assert "gave up after 3 attempt(s)" in out


def test_agents_without_explain_prints_no_tot_detail(monkeypatch, capsys):
    """Only the contested-rate summary should show without --explain --
    per-finding ToT winner/near-tie detail is --explain-gated, the same
    as verdict_summary/narrative."""
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation(finding_id="F01", bucket="contested")]
    _FakeCoordinator.tot_by_id = {"F01": _fake_tot_result("F01")}

    assert main(["run", "--data", "demo", "--agents"]) == 0
    out = capsys.readouterr().out
    assert "Tree-of-Thought" not in out
    assert "Contested: 1/1 (100.0%) of scored findings" in out


# --- --quiet ---------------------------------------------------------------


def test_main_with_agents_and_quiet_suppresses_console_output(monkeypatch):
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation()]
    calls = []
    monkeypatch.setattr(
        "crewai.events.utils.console_formatter.set_suppress_console_output",
        lambda suppress: calls.append(suppress),
    )

    assert main(["run", "--data", "demo", "--agents", "--quiet"]) == 0
    assert calls == [True]


def test_main_with_agents_without_quiet_does_not_touch_console_suppression(monkeypatch):
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation()]
    calls = []
    monkeypatch.setattr(
        "crewai.events.utils.console_formatter.set_suppress_console_output",
        lambda suppress: calls.append(suppress),
    )

    assert main(["run", "--data", "demo", "--agents"]) == 0
    assert calls == []


def test_quiet_flag_without_agents_is_a_harmless_no_op():
    """--quiet only means something on the --agents path; alone it must not
    error or change the deterministic path's behavior."""
    assert main(["run", "--data", "demo", "--seed", "42", "--quiet"]) == 0


# --- _ensure_utf8_stdio ------------------------------------------------------


def test_ensure_utf8_stdio_does_not_raise_on_real_streams():
    from rhinosecure.cli import _ensure_utf8_stdio

    _ensure_utf8_stdio()  # must not raise, whatever pytest's own capture wraps stdout in


def test_ensure_utf8_stdio_tolerates_a_stream_without_reconfigure(monkeypatch):
    from rhinosecure.cli import _ensure_utf8_stdio

    class _NoReconfigure:
        pass

    monkeypatch.setattr("sys.stdout", _NoReconfigure())
    monkeypatch.setattr("sys.stderr", _NoReconfigure())

    _ensure_utf8_stdio()  # must not raise even when neither stream supports reconfigure()
