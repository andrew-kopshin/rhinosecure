"""Coverage for the `ingest_propose` job kind (`web/jobs.py`) -- phase 1 of
LLM-assisted adapter generation (docs/adapter-generation.md) dispatched
against an uploaded source (`web/uploads.py`) instead of a `--data`
directory named on argv, per CLAUDE.md's conversational-front-end design.

Only the LLM dispatch is faked (`_QueuedFakeCrew`, the same pattern
`test_schema_inference.py`/`test_cli_adapt_propose.py` already use for
`propose_contract` itself) -- these tests exercise the real
`propose_contract` -> `check_grounding` -> `assemble_contract` ->
`write_contract` pipeline through the real job substrate and real HTTP
routes, not a mocked-out approximation of it.
"""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from crewai.types.usage_metrics import UsageMetrics
from fastapi.testclient import TestClient

import rhinosecure.agents.schema_inference as schema_inference_module
from rhinosecure.adapters.config_model import ASSET_SLOTS, FINDING_SLOTS
from rhinosecure.web import jobs as jobs_module
from rhinosecure.web import uploads as uploads_module
from rhinosecure.web.jobs import JobConfig, _default_propose_name, known_format_match
from rhinosecure.web.server import create_app

_HEADER = ["Asset_ID", "Hostname", "Finding_ID", "Cve", "Col"]


def _mapped(mapping: dict, *, confidence: float = 0.9, columns_cited: list[str] | None = None) -> dict:
    return {
        "status": "mapped", "mapping": mapping, "confidence": confidence,
        "evidence": {"columns_cited": columns_cited or [], "sample_values_cited": [], "note": "test"},
    }


def _unresolved(reason: str = "no corresponding column", candidates: list[str] | None = None) -> dict:
    return {"status": "unresolved", "candidate_columns": candidates or [], "reason": reason}


def _full_proposal_dict(
    *,
    name: str = "upload-test",
    layout: str = "single_file",
    assets_filename: str = "inventory.csv",
    findings_filename: str = "inventory.csv",
    overrides_asset: dict | None = None,
    overrides_finding: dict | None = None,
) -> dict:
    """Mirrors test_schema_inference.py's own `_full_proposal_dict` --
    duplicated rather than imported, matching this suite's existing
    convention of each test file owning its own fixtures."""
    asset: dict = {}
    for slot in ASSET_SLOTS:
        if slot == "asset_id":
            asset[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Asset_ID"])
        elif slot == "hostname":
            asset[slot] = _mapped({"kind": "column", "column": "Hostname", "case": "exact", "blank": "fatal"}, columns_cited=["Hostname"])
        elif slot == "role":
            asset[slot] = _mapped(
                {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc"}},
                columns_cited=["Col"],
            )
        else:
            asset[slot] = _mapped({"kind": "not_collected"})
    finding: dict = {}
    for slot in FINDING_SLOTS:
        if slot == "finding_id":
            finding[slot] = _mapped({"kind": "column", "column": "Finding_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Finding_ID"])
        elif slot == "asset_id":
            finding[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Asset_ID"])
        elif slot == "cve_id":
            finding[slot] = _mapped({"kind": "parsed", "column": "Cve", "case": "upper", "blank": "fatal", "parser": "cve_id"}, columns_cited=["Cve"])
        elif slot == "scanner_severity":
            finding[slot] = _mapped(
                {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "low"}},
                columns_cited=["Col"],
            )
        elif slot in ("product", "evidence"):
            finding[slot] = _mapped({"kind": "column", "column": "Col", "case": "exact", "blank": "absent_fact"}, columns_cited=["Col"])
        else:
            finding[slot] = _mapped({"kind": "not_collected"})

    asset.update(overrides_asset or {})
    finding.update(overrides_finding or {})

    return {
        "meta": {
            "format": name, "description": "test fixture", "source_layout": layout,
            "assets_filename": assets_filename, "findings_filename": findings_filename,
            "reasoning_summary": "test",
        },
        "asset": asset, "finding": finding, "derived": {},
        "asset_grouping": {"key": "Asset_ID", "resolution": "agree_or_recency"},
        "finding_dedup": {"content_targets": ["scanner_severity"], "on_identical": "collapse_and_count", "on_conflict": "fatal"},
        "unmapped_columns": {},
        "open_questions": [],
    }


def _csv_bytes(rows: list[list[str]]) -> bytes:
    return _csv_bytes_with_header(_HEADER, rows)


def _csv_bytes_with_header(header: list[str], rows: list[list[str]]) -> bytes:
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8")


_ROWS = [
    ["A01", "HOST01", "F01", "CVE-2021-0001", "srv"],
    ["A02", "HOST02", "F02", "CVE-2021-0002", "wks"],
]


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
        self.usage_metrics = UsageMetrics(prompt_tokens=111, completion_tokens=22, total_tokens=133)
        type(self).instantiations += 1

    def kickoff(self):
        for agent in self.agents:
            agent.llm._track_token_usage_internal(
                {"prompt_tokens": 111, "completion_tokens": 22, "total_tokens": 133}
            )
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
def isolated_dirs(tmp_path: Path, monkeypatch):
    """Redirects every real-repo path this job kind can write to: uploads
    (`web/uploads.py`'s own default), the proposal save path
    (`REPO_ROOT/out/...`), and the contract output path
    (`resolve_config_path`) -- the exact `isolated_repo_root` pattern
    `tests/test_cli_adapt_propose.py` already established for the CLI
    path onto this job-substrate path."""
    monkeypatch.setattr(uploads_module, "DEFAULT_UPLOADS_DIR", tmp_path / "uploads")
    monkeypatch.setattr(jobs_module, "REPO_ROOT", tmp_path)
    adapters_dir = tmp_path / "adapters"
    monkeypatch.setattr(jobs_module, "resolve_config_path", lambda name: adapters_dir / f"{name}.json")
    return adapters_dir


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config = JobConfig(data_dir=data_dir, db_path=tmp_path / "mem.db")
    app = create_app(tmp_path / "export.json", jobs_enabled=True, job_config=config)
    return TestClient(app)


def _wait_for_terminal(client: TestClient, job_id: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    body = None
    while time.monotonic() < deadline:
        body = client.get(f"/api/jobs/{job_id}").json()
        if body["status"] in ("succeeded", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not reach a terminal state within {timeout}s: {body}")


def _upload(client: TestClient, filename: str, content: bytes, **extra) -> dict:
    return client.post("/api/uploads", files={"file": (filename, content, "text/csv")}, data=extra).json()


def _submit(client: TestClient, **input_fields) -> dict:
    resp = client.post("/api/jobs", json={"kind": "ingest_propose", "input": input_fields})
    assert resp.status_code == 202, resp.text
    return resp.json()


# ---------------- known_format_match / _default_propose_name (pure, no HTTP) ----------------


def test_known_format_match_recognizes_native_filenames_exactly():
    assert known_format_match(["assets.csv", "findings.csv"]) == "native"


def test_known_format_match_recognizes_defender_filenames_exactly():
    assert known_format_match(["devices.csv", "vulnerabilities.csv"]) == "defender"


def test_known_format_match_recognizes_a_single_bluepeak_shaped_file():
    assert known_format_match(["synthetic_cve_inventory_50.csv"]) == "bluepeak"


def test_known_format_match_is_none_for_a_partial_set():
    assert known_format_match(["assets.csv"]) is None  # missing findings.csv


def test_known_format_match_is_none_for_unrelated_filenames():
    assert known_format_match(["inventory.csv", "vulns.csv"]) is None


def test_default_propose_name_matches_the_format_pattern_and_length_cap():
    from rhinosecure.adapters.config_model import _FORMAT_PATTERN

    name = _default_propose_name("a" * 32)
    assert _FORMAT_PATTERN.match(name)
    assert len(name) <= 32


def test_default_propose_name_is_deterministic_for_the_same_upload_id():
    assert _default_propose_name("abc123") == _default_propose_name("abc123")


# ---------------- ingest_propose: route-level validation ----------------


def test_submitting_without_upload_id_is_refused_before_any_job_runs(client: TestClient):
    resp = client.post("/api/jobs", json={"kind": "ingest_propose", "input": {}})
    assert resp.status_code == 400
    assert "upload_id" in resp.json()["detail"]


def test_unknown_upload_id_fails_the_job_cleanly(client: TestClient):
    job = _submit(client, upload_id="does-not-exist")
    body = _wait_for_terminal(client, job["job_id"])
    assert body["status"] == "failed"
    assert body["error"]["stage"] == "proposing"
    assert body["error"]["type"] == "SchemaInferenceError"


def test_a_total_generation_failure_still_reports_per_attempt_cost(client: TestClient):
    """The real gap found running this exact job live against a real
    source (PROGRESS.md 2026-09-06): every OTHER failure/success path
    already reported token usage, but exhausting every attempt used to
    discard it entirely -- exactly the run a human is most likely to ask
    "where did my money go" about, since nothing got written for it."""
    upload_id = _upload(client, "inventory.csv", _csv_bytes(_ROWS))["upload_id"]
    _QueuedFakeCrew.queue = ["not json", "also not json"]

    job = _submit(client, upload_id=upload_id, name="upload-gives-up", max_attempts=2)
    body = _wait_for_terminal(client, job["job_id"])

    assert body["status"] == "failed"
    assert body["error"]["type"] == "ProposalGenerationError"
    assert [entry["attempt"] for entry in body["error"]["attempt_usage"]] == [1, 2]
    assert all(entry["outcome"] == "parse_error" for entry in body["error"]["attempt_usage"])
    assert body["error"]["estimated_cost_usd"] > 0


# ---------------- ingest_propose: happy path ----------------


def test_single_file_upload_proposes_and_writes_a_confirmable_contract(client: TestClient, isolated_dirs: Path):
    upload_id = _upload(client, "inventory.csv", _csv_bytes(_ROWS))["upload_id"]
    _QueuedFakeCrew.queue = [json.dumps(_full_proposal_dict(name="upload-abc"))]

    job = _submit(client, upload_id=upload_id, name="upload-abc")
    body = _wait_for_terminal(client, job["job_id"])

    assert body["status"] == "succeeded"
    result = body["result"]
    assert result["contract_written"] is True
    assert result["unresolved_slots"] == []
    assert result["grounding"]["failures"] == []
    assert f"uploads/{upload_id}" in result["next_step"]
    assert "rhino adapt confirm upload-abc" in result["next_step"]

    written = json.loads((isolated_dirs / "upload-abc.json").read_text(encoding="utf-8"))
    assert written["review"]["state"] == "proposed"
    assert written["format"] == "upload-abc"


def test_a_default_name_is_derived_from_the_upload_id_when_none_is_given(client: TestClient, isolated_dirs: Path):
    upload_id = _upload(client, "inventory.csv", _csv_bytes(_ROWS))["upload_id"]
    expected_name = _default_propose_name(upload_id)
    _QueuedFakeCrew.queue = [json.dumps(_full_proposal_dict(name=expected_name))]

    job = _submit(client, upload_id=upload_id)
    body = _wait_for_terminal(client, job["job_id"])

    assert body["status"] == "succeeded"
    assert body["result"]["name"] == expected_name
    assert (isolated_dirs / f"{expected_name}.json").exists()


def _two_file_proposal_dict(name: str) -> dict:
    """A genuinely two-file-shaped proposal: devices.csv carries only
    asset columns, vulns.csv only finding columns (plus the Asset_ID join
    key) -- unlike a single-file source, validate_contract requires every
    column in EACH file to be accounted for on that file specifically, so
    (unlike `_full_proposal_dict`) the two files must not share an
    unmapped column neither side actually reads."""
    asset: dict = {}
    for slot in ASSET_SLOTS:
        if slot == "asset_id":
            asset[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Asset_ID"])
        elif slot == "hostname":
            asset[slot] = _mapped({"kind": "column", "column": "Hostname", "case": "exact", "blank": "fatal"}, columns_cited=["Hostname"])
        elif slot == "role":
            # Not GAP_LEGAL_TARGETS-eligible for bare "not_collected" --
            # needs a real vocabulary (or default_by), matching
            # _full_proposal_dict's own handling of this slot.
            asset[slot] = _mapped(
                {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc"}},
                columns_cited=["Col"],
            )
        else:
            asset[slot] = _mapped({"kind": "not_collected"})
    finding: dict = {}
    for slot in FINDING_SLOTS:
        if slot == "finding_id":
            finding[slot] = _mapped({"kind": "column", "column": "Finding_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Finding_ID"])
        elif slot == "asset_id":
            finding[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Asset_ID"])
        elif slot == "cve_id":
            finding[slot] = _mapped({"kind": "parsed", "column": "Cve", "case": "upper", "blank": "fatal", "parser": "cve_id"}, columns_cited=["Cve"])
        elif slot == "scanner_severity":
            # Also not GAP_LEGAL_TARGETS-eligible -- same reason as role.
            finding[slot] = _mapped(
                {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "low"}},
                columns_cited=["Col"],
            )
        elif slot in ("product", "evidence"):
            # Neither has a NOT_COLLECTED_DEFAULTS entry -- "not_collected"
            # is illegal for them (config_model.ABSENT_FACT_LEGAL_TARGETS
            # is the legal escape hatch instead), so they need a real,
            # if empty-in-practice, column mapping.
            finding[slot] = _mapped({"kind": "column", "column": "Col", "case": "exact", "blank": "absent_fact"}, columns_cited=["Col"])
        else:
            finding[slot] = _mapped({"kind": "not_collected"})
    return {
        "meta": {
            "format": name, "description": "two-file test fixture", "source_layout": "two_file",
            "assets_filename": "devices.csv", "findings_filename": "vulns.csv", "reasoning_summary": "test",
        },
        "asset": asset, "finding": finding, "derived": {},
        "asset_grouping": {"key": "Asset_ID", "resolution": "agree_or_recency"},
        "finding_dedup": {"content_targets": ["cve_id"], "on_identical": "collapse_and_count", "on_conflict": "fatal"},
        "unmapped_columns": {},
        "open_questions": [],
    }


def test_two_file_upload_passes_labeled_filenames_through_to_propose_contract(client: TestClient, isolated_dirs: Path):
    """The two-file case: the caller (a human via the label endpoint, or
    later the Router) resolves which uploaded file is which role and
    passes BOTH explicitly -- propose_contract has no way to guess which
    of two files is the inventory and which is findings on its own
    (_resolve_layout raises SchemaInferenceError without them)."""
    devices_csv = "Asset_ID,Hostname,Col\nA01,HOST01,srv\nA02,HOST02,srv\n".encode("utf-8")
    vulns_csv = "Asset_ID,Finding_ID,Cve,Col\nA01,F01,CVE-2021-0001,srv\nA02,F02,CVE-2021-0002,srv\n".encode("utf-8")
    upload_id = _upload(client, "devices.csv", devices_csv)["upload_id"]
    _upload(client, "vulns.csv", vulns_csv, upload_id=upload_id)
    client.post(f"/api/uploads/{upload_id}/label", json={"filename": "devices.csv", "label": "inventory"})
    client.post(f"/api/uploads/{upload_id}/label", json={"filename": "vulns.csv", "label": "findings"})

    _QueuedFakeCrew.queue = [json.dumps(_two_file_proposal_dict("upload-two-file"))]
    job = _submit(
        client, upload_id=upload_id, name="upload-two-file",
        assets_filename="devices.csv", findings_filename="vulns.csv",
    )
    body = _wait_for_terminal(client, job["job_id"])

    assert body["status"] == "succeeded"
    assert body["result"]["layout"] == "two_file"
    assert body["result"]["grounding"]["failures"] == []
    assert body["result"]["incomplete_reason"] is None
    assert body["result"]["contract_written"] is True


def test_two_file_upload_without_explicit_filenames_fails_as_ambiguous(client: TestClient):
    upload_id = _upload(client, "devices.csv", _csv_bytes(_ROWS))["upload_id"]
    _upload(client, "vulns.csv", _csv_bytes(_ROWS), upload_id=upload_id)

    job = _submit(client, upload_id=upload_id, name="upload-ambiguous")
    body = _wait_for_terminal(client, job["job_id"])

    assert body["status"] == "failed"
    assert body["error"]["type"] == "SchemaInferenceError"
    assert "ambiguous" in body["error"]["message"]


def test_an_unresolved_non_scoring_gap_legal_field_now_writes_a_provisional_contract(
    client: TestClient, isolated_dirs: Path
):
    """owner is gap-legal and never feeds scoring.py -- CLAUDE.md's "drop a
    CSV, get a plan" fallback (assemble_provisional_contract, tried when
    assemble_contract itself refuses) auto-fills it via not_collected and
    writes a real, unconfirmed contract immediately, rather than leaving
    the proposal blocked the way this exact scenario used to."""
    upload_id = _upload(client, "inventory.csv", _csv_bytes(_ROWS))["upload_id"]
    data = _full_proposal_dict(name="upload-incomplete", overrides_asset={"owner": _unresolved()})
    _QueuedFakeCrew.queue = [json.dumps(data)]

    job = _submit(client, upload_id=upload_id, name="upload-incomplete")
    body = _wait_for_terminal(client, job["job_id"])

    assert body["status"] == "succeeded"
    result = body["result"]
    assert result["contract_written"] is True
    assert result["provisional"] is True
    assert result["neutralized_axes"] == []  # owner isn't a scoring input -- nothing to neutralize
    assert "asset.owner" in result["unresolved_slots"]  # still reported -- the model DID leave it unresolved
    assert result["next_step"] is not None
    written = json.loads((isolated_dirs / "upload-incomplete.json").read_text(encoding="utf-8"))
    assert written["asset"]["owner"]["kind"] == "not_collected"
    assert written["review"]["state"] == "proposed"


def test_a_genuinely_unrecoverable_gap_still_writes_nothing(client: TestClient, isolated_dirs: Path):
    """cve_id is a mandatory identity field -- no not_collected default, no
    neutralize path (there's no row to identify a finding by without it).
    The provisional fallback refuses too, exactly like assemble_contract
    always has for this case, and nothing is written."""
    upload_id = _upload(client, "inventory.csv", _csv_bytes(_ROWS))["upload_id"]
    data = _full_proposal_dict(name="upload-incomplete", overrides_finding={"cve_id": _unresolved()})
    _QueuedFakeCrew.queue = [json.dumps(data)]

    job = _submit(client, upload_id=upload_id, name="upload-incomplete")
    body = _wait_for_terminal(client, job["job_id"])

    assert body["status"] == "succeeded"  # an incomplete proposal is NOT a job failure
    result = body["result"]
    assert result["contract_written"] is False
    assert result["provisional"] is False
    assert "finding.cve_id" in result["unresolved_slots"]
    assert result["next_step"] is None
    assert not (isolated_dirs / "upload-incomplete.json").exists()


# ---------------- ingest_propose: not silently overwriting a signature ----------------


def _build_and_write_confirmed_contract(source_dir: Path, output_path: Path, name: str) -> None:
    """Builds a real, signed Contract the short way -- assemble, then
    config_io.confirm_contract (pure stamping, no re-measurement) -- so
    the refusal test below exercises the real read_contract/review.state
    check rather than a hand-typed JSON stand-in."""
    from rhinosecure.adapters.config_io import confirm_contract, write_contract
    from rhinosecure.adapters.probe import profile_source
    from rhinosecure.agents.schema_inference import AdapterProposal, Generator, assemble_contract, check_grounding

    proposal = AdapterProposal.model_validate(_full_proposal_dict(name=name))
    profiles = {p.path.name: p for p in profile_source(source_dir)}
    report = check_grounding(proposal, profiles)
    generator = Generator(
        tool="rhino-adapt-propose", model="claude-sonnet-5", prompt_tokens=1, completion_tokens=1,
        estimated_cost_usd=0.0, attempts=1, call_log_digest="sha256:" + "a" * 64,
    )
    contract = assemble_contract(proposal, profiles, report, generator=generator, generated_at="2026-09-06T00:00:00Z")
    assert contract is not None
    signed = confirm_contract(contract, at="2026-09-06T01:00:00Z", by="test-suite")
    write_contract(output_path, signed)


def test_refuses_to_overwrite_an_already_confirmed_contract(client: TestClient, isolated_dirs: Path):
    upload_id = _upload(client, "inventory.csv", _csv_bytes(_ROWS))["upload_id"]
    source_dir = isolated_dirs.parent / "uploads" / upload_id
    isolated_dirs.mkdir(parents=True, exist_ok=True)
    _build_and_write_confirmed_contract(source_dir, isolated_dirs / "upload-signed.json", "upload-signed")

    job = _submit(client, upload_id=upload_id, name="upload-signed")
    body = _wait_for_terminal(client, job["job_id"])
    assert body["status"] == "failed"
    assert body["error"]["type"] == "SchemaInferenceError"
    assert "CONFIRMED" in body["error"]["message"]


# ---------------- ingest_propose: browser-resolved slots (edited_saved_proposal) ----------------


def test_edited_saved_proposal_resolves_without_a_new_llm_call(client: TestClient, isolated_dirs: Path):
    """The slot-resolution UI slice's own contract: a human filling in an
    unresolved slot and resubmitting the WHOLE saved proposal must cost
    zero new LLM tokens -- the same guarantee `--from-proposal` already
    gives the CLI path."""
    upload_id = _upload(client, "inventory.csv", _csv_bytes(_ROWS))["upload_id"]
    # cve_id (a mandatory identity field, no not_collected/neutralize
    # escape) is a genuine, still-a-hard-stop unresolved slot -- unlike an
    # owner-shaped gap, which the provisional-run fallback now auto-fills
    # and writes immediately (see test_an_unresolved_non_scoring_gap_legal
    # _field_now_writes_a_provisional_contract), so this keeps exercising
    # the "still incomplete, resolve and resubmit" path this test is for.
    incomplete = _full_proposal_dict(name="upload-resolve", overrides_finding={"cve_id": _unresolved()})
    _QueuedFakeCrew.queue = [json.dumps(incomplete)]

    job = _submit(client, upload_id=upload_id, name="upload-resolve")
    body = _wait_for_terminal(client, job["job_id"])
    assert body["result"]["contract_written"] is False

    fixed = _full_proposal_dict(name="upload-resolve")  # cve_id resolved normally
    edited_saved_proposal = {
        "proposal": fixed,
        "generator": {
            "tool": "rhino-adapt-propose", "model": "claude-sonnet-5", "prompt_tokens": 100,
            "completion_tokens": 50, "estimated_cost_usd": 0.001, "attempts": 1,
            "call_log_digest": "sha256:" + "a" * 64,
        },
    }
    assert _QueuedFakeCrew.queue == []  # nothing queued -- proves no LLM call happens below

    job2 = _submit(client, upload_id=upload_id, name="upload-resolve", edited_saved_proposal=edited_saved_proposal)
    body2 = _wait_for_terminal(client, job2["job_id"])

    assert body2["status"] == "succeeded"
    assert body2["result"]["contract_written"] is True
    assert _QueuedFakeCrew.instantiations == 1  # only the FIRST (incomplete) submission ever called the LLM

    # `contract_written: True` in the JSON response is a CLAIM, not proof --
    # a real regression (this file's own module docstring at the top,
    # CLAUDE.md's "0 slot(s) remain unresolved" incident) had this claim
    # true while nothing was actually readable at `contract_path` for a
    # different (unresolved-slot-shaped) reason. Assert the file itself,
    # over the real path the response names, not just the flag.
    contract_path = Path(body2["result"]["contract_path"])
    assert contract_path.exists(), f"contract_written was True but {contract_path} does not exist"
    on_disk = json.loads(contract_path.read_text(encoding="utf-8"))
    assert on_disk["review"]["state"] == "proposed"
    assert on_disk["format"] == "upload-resolve"


def test_edited_saved_proposal_still_refuses_an_illegal_edit(client: TestClient, isolated_dirs: Path):
    """A human's edit is held to the identical grounding gate a model's
    output is -- inventing a table entry for a value never observed in the
    real file is refused exactly like it would be from the LLM path."""
    upload_id = _upload(client, "inventory.csv", _csv_bytes(_ROWS))["upload_id"]
    bad = _full_proposal_dict(
        name="upload-resolve-bad",
        overrides_asset={
            "owner": _mapped(
                {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"never-seen": "x"}},
                columns_cited=["Col"],
            )
        },
    )
    edited_saved_proposal = {
        "proposal": bad,
        "generator": {
            "tool": "rhino-adapt-propose", "model": "claude-sonnet-5", "prompt_tokens": 100,
            "completion_tokens": 50, "estimated_cost_usd": 0.001, "attempts": 1,
            "call_log_digest": "sha256:" + "a" * 64,
        },
    }
    job = _submit(
        client, upload_id=upload_id, name="upload-resolve-bad", edited_saved_proposal=edited_saved_proposal
    )
    body = _wait_for_terminal(client, job["job_id"])

    assert body["status"] == "succeeded"  # a refused mapping is an incomplete proposal, not a job failure
    assert body["result"]["contract_written"] is False
    assert _QueuedFakeCrew.instantiations == 0


def test_resolving_a_free_text_unresolved_slot_via_a_column_mapping_writes_a_confirmable_contract(
    client: TestClient, isolated_dirs: Path
):
    """Regression test for the reported propose->persist bug: `finding.
    product` (like `evidence`) has no `NOT_COLLECTED_DEFAULTS` entry
    (config_model.GAP_LEGAL_TARGETS), so "mark not collected" -- the ONLY
    correction the browser's slot-resolution widget offered before this
    fix -- is illegal for it and always failed `validate_contract`, with
    the real reason hidden behind a JSON response that reported "0 slot(s)
    remain unresolved" (unresolved_slots is empty once a slot IS mapped,
    even illegally). This exercises the fixed resolution path instead: a
    `column` mapping with `blank: "absent_fact"`
    (config_model.ABSENT_FACT_LEGAL_TARGETS' own legal escape hatch) on a
    candidate column DEDICATED to this one slot -- not shared with any
    other mapping, unlike this file's usual "Col" placeholder, so the
    unmapped_columns reconciliation this fix also added is exercised for
    real rather than accidentally masked by column reuse."""
    header = ["Asset_ID", "Hostname", "Finding_ID", "Cve", "Col", "ProductCol"]
    rows = [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv", "Windows Server"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks", "Office"],
    ]
    upload_id = _upload(client, "inventory.csv", _csv_bytes_with_header(header, rows))["upload_id"]

    incomplete = _full_proposal_dict(
        name="upload-product",
        overrides_finding={
            "product": _unresolved("model was not confident how to parse this field", candidates=["ProductCol"])
        },
    )
    incomplete["unmapped_columns"] = {
        "inventory.csv": {"ProductCol": {"disposition": "ignored", "reason": "not yet resolved", "profile_cited": "n/a"}}
    }
    _QueuedFakeCrew.queue = [json.dumps(incomplete)]

    job = _submit(client, upload_id=upload_id, name="upload-product")
    body = _wait_for_terminal(client, job["job_id"])
    # product has no not_collected default but IS absent-fact-legal, so the
    # provisional-run fallback (assemble_provisional_contract) now auto-
    # fills it via literal("") and writes immediately -- unresolved_slots
    # still names it (the MODEL genuinely left it unresolved), even though
    # a contract was written.
    assert body["result"]["contract_written"] is True
    assert body["result"]["provisional"] is True
    assert body["result"]["unresolved_slots"] == ["finding.product"]

    # Exactly what the fixed browser widget now submits for this case: a
    # `column` mapping with blank="absent_fact" (never bare not_collected),
    # with "ProductCol" no longer in unmapped_columns (it's genuinely
    # mapped now) -- the reconciliation applySlotEditToProposal performs.
    fixed = _full_proposal_dict(
        name="upload-product",
        overrides_finding={
            "product": _mapped(
                {"kind": "column", "column": "ProductCol", "case": "exact", "blank": "absent_fact"},
                confidence=1.0, columns_cited=["ProductCol"],
            )
        },
    )
    edited_saved_proposal = {
        "proposal": fixed,
        "generator": {
            "tool": "rhino-adapt-propose", "model": "claude-sonnet-5", "prompt_tokens": 100,
            "completion_tokens": 50, "estimated_cost_usd": 0.001, "attempts": 1,
            "call_log_digest": "sha256:" + "a" * 64,
        },
    }

    job2 = _submit(client, upload_id=upload_id, name="upload-product", edited_saved_proposal=edited_saved_proposal)
    body2 = _wait_for_terminal(client, job2["job_id"])

    assert body2["status"] == "succeeded"
    assert body2["result"]["contract_written"] is True, body2["result"].get("incomplete_reason")
    assert body2["result"]["provisional"] is False  # every slot is now genuinely resolved, not auto-filled

    contract_path = Path(body2["result"]["contract_path"])
    assert contract_path.exists(), f"contract_written was True but {contract_path} does not exist"
    on_disk = json.loads(contract_path.read_text(encoding="utf-8"))
    assert on_disk["review"]["state"] == "proposed"
    assert on_disk["finding"]["product"]["kind"] == "column"
    assert on_disk["finding"]["product"]["column"] == "ProductCol"
    assert on_disk["finding"]["product"]["blank"] == "absent_fact"


def test_malformed_edited_saved_proposal_fails_cleanly(client: TestClient):
    upload_id = _upload(client, "inventory.csv", _csv_bytes(_ROWS))["upload_id"]
    job = _submit(client, upload_id=upload_id, name="upload-bad-edit", edited_saved_proposal={"nope": True})
    body = _wait_for_terminal(client, job["job_id"])

    assert body["status"] == "failed"
    assert body["error"]["type"] == "SchemaInferenceError"
    assert "'proposal' and 'generator'" in body["error"]["message"]
    assert _QueuedFakeCrew.instantiations == 0


def test_overwrite_confirmed_flag_allows_replacing_a_signed_contract(client: TestClient, isolated_dirs: Path):
    upload_id = _upload(client, "inventory.csv", _csv_bytes(_ROWS))["upload_id"]
    source_dir = isolated_dirs.parent / "uploads" / upload_id
    isolated_dirs.mkdir(parents=True, exist_ok=True)
    _build_and_write_confirmed_contract(source_dir, isolated_dirs / "upload-signed.json", "upload-signed")

    _QueuedFakeCrew.queue = [json.dumps(_full_proposal_dict(name="upload-signed"))]
    job = _submit(client, upload_id=upload_id, name="upload-signed", overwrite_confirmed=True)
    body = _wait_for_terminal(client, job["job_id"])

    assert body["status"] == "succeeded"
    assert body["result"]["contract_written"] is True
    written = json.loads((isolated_dirs / "upload-signed.json").read_text(encoding="utf-8"))
    assert written["review"]["state"] == "proposed"  # the fresh propose overwrote the signed one
