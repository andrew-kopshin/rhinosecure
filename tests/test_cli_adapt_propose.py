"""`rhino adapt propose` -- cli.py's own concerns around Slice 8's phase-1
inference command: argument wiring, the confirmed-contract overwrite guard,
--report-out, --from-proposal, and exit codes. `agents/schema_inference.py`'s
own grounding/assembly correctness is covered by test_schema_inference.py;
this file only exercises the CLI layer, with the LLM call faked the same way
test_coordinator.py fakes it for every other agent-backed command."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from crewai.types.usage_metrics import UsageMetrics

import rhinosecure.agents.schema_inference as schema_inference_module
import rhinosecure.cli as cli_module
from rhinosecure.adapters.config_io import confirm_contract, overwrite_contract
from rhinosecure.agents.schema_inference import AdapterProposal, Generator, assemble_contract, check_grounding
from rhinosecure.cli import main

_HEADER = ["Asset_ID", "Hostname", "Finding_ID", "Cve", "Col"]


def _write_csv(directory: Path, header: list[str], rows: list[list[str]], name: str = "data.csv") -> Path:
    path = directory / name
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    return path


def _mapped(mapping: dict, columns_cited: list[str] | None = None) -> dict:
    return {
        "status": "mapped", "mapping": mapping, "confidence": 0.9,
        "evidence": {"columns_cited": columns_cited or [], "sample_values_cited": [], "note": "test"},
    }


def _unresolved(reason: str = "no corresponding column") -> dict:
    return {"status": "unresolved", "candidate_columns": [], "reason": reason}


def _full_proposal_dict(name: str = "my-test-format") -> dict:
    from rhinosecure.adapters.config_model import ASSET_SLOTS, FINDING_SLOTS

    asset: dict = {}
    for slot in ASSET_SLOTS:
        if slot == "asset_id":
            asset[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, ["Asset_ID"])
        elif slot == "hostname":
            asset[slot] = _mapped({"kind": "column", "column": "Hostname", "case": "exact", "blank": "fatal"}, ["Hostname"])
        elif slot == "role":
            asset[slot] = _mapped({"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc"}}, ["Col"])
        else:
            asset[slot] = _mapped({"kind": "not_collected"})
    finding: dict = {}
    for slot in FINDING_SLOTS:
        if slot == "finding_id":
            finding[slot] = _mapped({"kind": "column", "column": "Finding_ID", "case": "exact", "blank": "fatal"}, ["Finding_ID"])
        elif slot == "asset_id":
            finding[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, ["Asset_ID"])
        elif slot == "cve_id":
            finding[slot] = _mapped({"kind": "parsed", "column": "Cve", "case": "upper", "blank": "fatal", "parser": "cve_id"}, ["Cve"])
        elif slot == "scanner_severity":
            finding[slot] = _mapped({"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "low"}}, ["Col"])
        elif slot in ("product", "evidence"):
            finding[slot] = _mapped({"kind": "column", "column": "Col", "case": "exact", "blank": "absent_fact"}, ["Col"])
        else:
            finding[slot] = _mapped({"kind": "not_collected"})

    return {
        "meta": {
            "format": name, "description": "test fixture", "source_layout": "single_file",
            "assets_filename": "data.csv", "findings_filename": "data.csv", "reasoning_summary": "test",
        },
        "asset": asset, "finding": finding, "derived": {},
        "asset_grouping": {"key": "Asset_ID", "resolution": "agree_or_recency"},
        "finding_dedup": {"content_targets": ["scanner_severity"], "on_identical": "collapse_and_count", "on_conflict": "fatal"},
        "unmapped_columns": {}, "open_questions": [],
    }


class _QueuedFakeCrew:
    """`kickoff()` increments the real `agent.llm`'s own cumulative usage
    counter (crewai's `_track_token_usage_internal`) rather than only
    setting a per-instance `usage_metrics` -- production code reads
    per-attempt usage via `agent.llm.get_token_usage_summary().delta_since
    (baseline)` (schema_inference.py's own note on why `crew.usage_metrics`
    is documented as cumulative for the LLM's lifetime, not per-kickoff,
    and this suite's agent is reused across every retry attempt)."""

    queue: list = []
    instantiations: int = 0

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.agents = agents
        self.tasks = tasks
        self.usage_metrics = UsageMetrics(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        type(self).instantiations += 1

    def kickoff(self):
        for agent in self.agents:
            agent.llm._track_token_usage_internal({"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})
        for task in self.tasks:
            task.output = SimpleNamespace(raw=_QueuedFakeCrew.queue.pop(0))
        return None


@pytest.fixture(autouse=True)
def fake_crew(monkeypatch):
    _QueuedFakeCrew.queue = []
    _QueuedFakeCrew.instantiations = 0
    monkeypatch.setattr(schema_inference_module, "Crew", _QueuedFakeCrew)
    return _QueuedFakeCrew


@pytest.fixture(autouse=True)
def isolated_repo_root(tmp_path, monkeypatch):
    """Redirect both the proposal-save path (REPO_ROOT/out/...) and the
    contract output path (resolve_config_path) into tmp_path -- a bare
    format `name` must match a strict token pattern (_validate_format_name),
    so it can never itself be repointed at tmp_path the way confirm/rereview's
    free-form NAME_OR_PATH can; this must never write into the real repo's
    data/adapters/ or out/ during a test."""
    monkeypatch.setattr(cli_module, "REPO_ROOT", tmp_path)
    adapters_dir = tmp_path / "adapters"
    monkeypatch.setattr(cli_module, "resolve_config_path", lambda name: adapters_dir / f"{name}.json")
    return adapters_dir


@pytest.fixture
def data_dir(tmp_path) -> Path:
    d = tmp_path / "source"
    d.mkdir()
    _write_csv(d, _HEADER, [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks"],
    ])
    return d


def test_propose_writes_a_contract_when_the_proposal_is_complete(data_dir, isolated_repo_root, capsys):
    _QueuedFakeCrew.queue = [json.dumps(_full_proposal_dict())]
    code = main(["adapt", "propose", "my-test-format", "--data", str(data_dir)])
    assert code == 0
    out = capsys.readouterr().out
    assert "Wrote" in out
    assert "rhino adapt confirm my-test-format" in out
    written = json.loads((isolated_repo_root / "my-test-format.json").read_text(encoding="utf-8"))
    assert written["review"]["state"] == "proposed"
    assert written["format"] == "my-test-format"


def test_propose_reports_per_attempt_cost_on_total_failure(data_dir, isolated_repo_root, capsys):
    """The real gap found running this exact path live against a real
    source (PROGRESS.md 2026-09-06): giving up after every attempt used to
    print only the last attempt's parse error, discarding what every
    discarded attempt actually cost -- exactly the run a human is most
    likely to ask about, since nothing got written for it."""
    _QueuedFakeCrew.queue = ["not json", "still not json"]
    code = main(["adapt", "propose", "my-test-format", "--data", str(data_dir), "--max-attempts", "2"])
    assert code == 1
    err = capsys.readouterr().err
    assert "gave up after 2 attempt" in err
    assert "attempt 1:" in err and "attempt 2:" in err
    assert "parse_error" in err
    assert "spent before giving up" in err


def test_propose_does_not_write_when_the_proposal_is_incomplete(data_dir, isolated_repo_root, capsys):
    data = _full_proposal_dict()
    data["asset"]["owner"] = _unresolved()
    _QueuedFakeCrew.queue = [json.dumps(data)]
    code = main(["adapt", "propose", "my-test-format", "--data", str(data_dir)])
    assert code == 1
    assert not (isolated_repo_root / "my-test-format.json").exists()
    out = capsys.readouterr().out
    assert "NOT written" in out
    assert "asset.owner" in out


def test_propose_saves_the_raw_proposal_regardless_of_completeness(data_dir, isolated_repo_root, capsys, tmp_path):
    data = _full_proposal_dict()
    data["asset"]["owner"] = _unresolved()
    _QueuedFakeCrew.queue = [json.dumps(data)]
    main(["adapt", "propose", "my-test-format", "--data", str(data_dir)])
    saved_path = tmp_path / "out" / "propose_my-test-format.json"
    assert saved_path.exists()
    saved = json.loads(saved_path.read_text(encoding="utf-8"))
    assert saved["proposal"]["meta"]["format"] == "my-test-format"
    assert "generator" in saved


def test_propose_report_out_saves_the_same_report_shown_on_stdout(data_dir, isolated_repo_root, capsys, tmp_path):
    _QueuedFakeCrew.queue = [json.dumps(_full_proposal_dict())]
    report_path = tmp_path / "report.txt"
    main(["adapt", "propose", "my-test-format", "--data", str(data_dir), "--report-out", str(report_path)])
    out = capsys.readouterr().out
    assert report_path.read_text(encoding="utf-8") in out


def test_propose_grounding_caveat_is_prominent_in_the_report(data_dir, isolated_repo_root, capsys, tmp_path):
    from rhinosecure.adapters.probe import MAX_DISTINCT_TRACKED

    big_dir = tmp_path / "big"
    big_dir.mkdir()
    rows = [["A%03d" % i, f"HOST{i}", "F%03d" % i, "CVE-2021-0001", "srv" if i == 0 else f"role-{i}"] for i in range(MAX_DISTINCT_TRACKED + 5)]
    _write_csv(big_dir, _HEADER, rows)

    data = _full_proposal_dict()
    data["asset"]["role"] = _mapped(
        {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc", "a-token-never-seen": "sql"}},
        ["Col"],
    )
    _QueuedFakeCrew.queue = [json.dumps(data)]
    code = main(["adapt", "propose", "my-test-format", "--data", str(big_dir)])
    out = capsys.readouterr().out
    assert code == 0  # a caveat alone never blocks assembly
    grounding_section = out.split("Evidence grounding")[1].split("Columns this proposal")[0]
    assert "caveat" in grounding_section
    assert "INCOMPLETE" in grounding_section


def _confirmed_contract_at(path: Path, data_dir: Path) -> None:
    from rhinosecure.adapters.probe import profile_source

    profiles = {p.path.name: p for p in profile_source(data_dir)}
    proposal = AdapterProposal.model_validate(_full_proposal_dict())
    report = check_grounding(proposal, profiles)
    generator = Generator(
        tool="test", model="claude-sonnet-5", prompt_tokens=1, completion_tokens=1,
        estimated_cost_usd=0.0, attempts=1, call_log_digest="sha256:" + "a" * 64,
    )
    contract = assemble_contract(proposal, profiles, report, generator=generator, generated_at="2026-09-04T00:00:00Z")
    signed = confirm_contract(contract, at="2026-09-04T00:00:00Z", by="tester")
    path.parent.mkdir(parents=True, exist_ok=True)
    overwrite_contract(path, signed)


def test_propose_refuses_to_silently_overwrite_a_confirmed_contract(data_dir, isolated_repo_root, capsys):
    target = isolated_repo_root / "my-test-format.json"
    _confirmed_contract_at(target, data_dir)

    _QueuedFakeCrew.queue = [json.dumps(_full_proposal_dict())]
    code = main(["adapt", "propose", "my-test-format", "--data", str(data_dir)])
    assert code == 1
    err = capsys.readouterr().err
    assert "already holds a CONFIRMED contract" in err
    assert json.loads(target.read_text(encoding="utf-8"))["review"]["state"] == "confirmed"  # untouched


def test_propose_overwrite_confirmed_flag_allows_replacing_it(data_dir, isolated_repo_root, capsys):
    target = isolated_repo_root / "my-test-format.json"
    _confirmed_contract_at(target, data_dir)

    _QueuedFakeCrew.queue = [json.dumps(_full_proposal_dict())]
    code = main(["adapt", "propose", "my-test-format", "--data", str(data_dir), "--overwrite-confirmed"])
    assert code == 0
    assert json.loads(target.read_text(encoding="utf-8"))["review"]["state"] == "proposed"


def test_propose_from_proposal_skips_the_llm_entirely(data_dir, isolated_repo_root, tmp_path):
    saved = {
        "proposal": _full_proposal_dict(),
        "generator": {
            "tool": "test", "model": "claude-sonnet-5", "prompt_tokens": 1, "completion_tokens": 1,
            "estimated_cost_usd": 0.0, "attempts": 1, "call_log_digest": "sha256:" + "a" * 64,
        },
    }
    saved_path = tmp_path / "saved.json"
    saved_path.write_text(json.dumps(saved), encoding="utf-8")

    code = main(["adapt", "propose", "my-test-format", "--data", str(data_dir), "--from-proposal", str(saved_path)])
    assert code == 0
    assert _QueuedFakeCrew.instantiations == 0


def test_propose_two_file_source_without_disambiguating_flags_is_refused(tmp_path, isolated_repo_root, capsys):
    src = tmp_path / "two_file_source"
    src.mkdir()
    _write_csv(src, ["Asset_ID"], [["A01"]], name="assets.csv")
    _write_csv(src, ["Finding_ID"], [["F01"]], name="findings.csv")

    code = main(["adapt", "propose", "my-test-format", "--data", str(src)])
    assert code == 1
    assert "ambiguous" in capsys.readouterr().err
    assert _QueuedFakeCrew.instantiations == 0


def test_propose_rejects_a_bad_format_name_before_any_llm_call(data_dir, isolated_repo_root, capsys):
    code = main(["adapt", "propose", "native", "--data", str(data_dir)])  # collides with a built-in format
    assert code == 1
    assert "propose error" in capsys.readouterr().err
    assert _QueuedFakeCrew.instantiations == 0
