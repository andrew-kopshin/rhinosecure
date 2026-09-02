import ast
import inspect
from pathlib import Path

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
    real Crew (which would make real LLM calls)."""

    result: list = []
    raises: Exception | None = None
    last_init_args: tuple | None = None
    last_run_findings: list | None = None

    def __init__(self, data_dir, cache=None, *, verbose=False):
        _FakeCoordinator.last_init_args = (data_dir, cache)

    def run(self, findings):
        _FakeCoordinator.last_run_findings = findings
        if _FakeCoordinator.raises is not None:
            raise _FakeCoordinator.raises
        return _FakeCoordinator.result


@pytest.fixture(autouse=True)
def _reset_fake_coordinator():
    _FakeCoordinator.result = []
    _FakeCoordinator.raises = None
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
        narrative="fake narrative",
        sources=["fake"],
    )


def test_run_agents_wires_data_dir_seed_and_offline_to_coordinator(monkeypatch):
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.result = [_fake_recommendation()]

    result = run_agents(DEMO_DIR, seed=42, offline=True)

    assert result == [_fake_recommendation()]
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


def test_main_with_agents_flag_maps_coordinator_error_to_exit_1(monkeypatch):
    from rhinosecure.agents.coordinator import CoordinatorError

    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.raises = CoordinatorError("no upstream state")

    assert main(["run", "--data", "demo", "--agents"]) == 1


def test_main_with_agents_flag_maps_scoring_mismatch_to_exit_1(monkeypatch):
    from rhinosecure.agents.risk import ScoringMismatchError

    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)
    _FakeCoordinator.raises = ScoringMismatchError("F01: risk_score mismatch")

    assert main(["run", "--data", "demo", "--agents"]) == 1


def test_main_without_agents_flag_still_uses_the_deterministic_path(monkeypatch):
    """--agents defaults off -- plain `rhino run` must not touch Coordinator
    at all."""
    monkeypatch.setattr("rhinosecure.agents.coordinator.Coordinator", _FakeCoordinator)

    assert main(["run", "--data", "demo", "--seed", "42"]) == 0
    assert _FakeCoordinator.last_init_args is None
