"""Coverage for the dispatcher pieces added to `web/jobs.py`: source
resolution (`resolve_source_ref`), the three new job kinds
(`run_deterministic`, `run_agents`, `remediation_mark`), and `PlanState`'s
generalization from "one fixed source for the process's whole lifetime"
to "one CURRENT source, replaceable by a later run_agents/run_deterministic
job" -- the piece the conversational front end's empty-workspace design
(CLAUDE.md) depends on.

Only the LLM dispatch is faked for `run_agents` (`_QueuedFakeCrew`, the
same pattern `test_web_jobs.py`/`test_coordinator.py` already use).
`run_deterministic` makes no LLM call at all -- it is tested against the
real, frozen `data/demo` fixture with `offline=True`, using the repo's own
committed snapshots, exactly like `rhino run --data demo --offline` does.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from rhinosecure.agents import coordinator as coordinator_module
from rhinosecure.web import jobs as jobs_module
from rhinosecure.web import uploads as uploads_module
from rhinosecure.web.jobs import (
    FORMATS,
    IngestError,
    JobConfig,
    PlanNotSeededError,
    PlanState,
    ResolvedSource,
    resolve_source_ref,
)
from rhinosecure.web.server import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = REPO_ROOT / "data" / "demo"

ASSETS_CSV_A = """asset_id,hostname,os,os_build,role,business_function,criticality,internet_exposed,environment,data_sensitivity,patch_window,patch_restrictions,compensating_controls,owner
A01,EXCH01,Windows Server 2019,17763,exchange,Mail server,5,True,prod,confidential,Sun 02:00-06:00,,,messaging-team
"""

FINDINGS_CSV_A = """finding_id,asset_id,cve_id,detected_date,scanner_severity,product,version,port,service,evidence
F01,A01,CVE-2021-26855,2026-08-01,critical,Microsoft Exchange Server,2016 CU19,443,https,OWA SSRF chain
"""

# A second, distinct source -- different asset_id/finding_id/hostname --
# used to prove run_agents_pipeline REPLACES the plan, not merges it.
ASSETS_CSV_B = """asset_id,hostname,os,os_build,role,business_function,criticality,internet_exposed,environment,data_sensitivity,patch_window,patch_restrictions,compensating_controls,owner
B01,SQL01,Windows Server 2022,20348,sql,ERP backend,4,False,prod,confidential,,,,db-team
"""

FINDINGS_CSV_B = """finding_id,asset_id,cve_id,detected_date,scanner_severity,product,version,port,service,evidence
G01,B01,CVE-2020-1472,2026-08-01,critical,Windows Server,2022,445,smb,ZeroLogon
"""

UNPARSEABLE = "this is not json and will never parse, no matter how many times you ask"


class _QueuedFakeCrew:
    """Trimmed-down stand-in for crewai.Crew -- Research/Environment pop
    one raw JSON string per task; Risk (detected by the score_finding
    tool) pops a finding_id and calls the REAL score_finding tool."""

    queue: list = []

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.tasks = tasks
        self.agent = agents[0]
        self.usage_metrics = None

    def kickoff(self):
        is_risk_stage = any(t.name == "score_finding" for t in self.agent.tools)
        for task in self.tasks:
            if is_risk_stage:
                finding_id = _QueuedFakeCrew.queue.pop(0)
                tool_result = json.loads(self.agent.tools[0].run(finding_id=finding_id))
                raw = json.dumps(
                    {
                        "finding_id": tool_result["finding_id"],
                        "cve_id": tool_result["cve_id"],
                        "asset_id": tool_result["asset_id"],
                        "hostname": tool_result["hostname"],
                        "risk_score": tool_result["risk_score"],
                        "bucket": tool_result["bucket"],
                        "scoring_rationale": tool_result["rationale"],
                        "constraints_applied": tool_result["constraints_applied"],
                        "verdict_summary": "fake verdict summary.",
                        "narrative": "fake narrative",
                        "sources": ["fake"],
                    }
                )
            else:
                raw = _QueuedFakeCrew.queue.pop(0)
            task.output = SimpleNamespace(raw=raw)
        return None


def _research_json(fid: str, cve_id: str) -> str:
    return json.dumps(
        {
            "finding_id": fid, "cve_id": cve_id, "scanner_severity": "high", "is_kev": False,
            "exploitation_summary": "fake research summary", "sources": ["fake"],
        }
    )


def _environment_json(fid: str, cve_id: str, asset_id: str, hostname: str) -> str:
    return json.dumps(
        {
            "finding_id": fid, "cve_id": cve_id, "asset_id": asset_id, "hostname": hostname,
            "os": "Windows Server 2019", "os_build": "17763", "os_build_consistent": True,
            "os_build_consistent_provenance": "model_judgment", "role": "exchange", "environment": "prod",
            "internet_exposed": True, "compensating_controls": [], "has_patch_window": True,
            "patch_window": "Sun 02:00-06:00", "patch_restrictions": "",
            "applicability_summary": "fake environment summary", "sources": ["fake"],
        }
    )


def _queue_seed_run(fid: str, cve_id: str, asset_id: str, hostname: str) -> None:
    _QueuedFakeCrew.queue = [
        _research_json(fid, cve_id),
        _environment_json(fid, cve_id, asset_id, hostname),
        fid,
    ]


@pytest.fixture(autouse=True)
def fake_crew(monkeypatch):
    _QueuedFakeCrew.queue = []
    monkeypatch.setattr(coordinator_module, "Crew", _QueuedFakeCrew)


@pytest.fixture(autouse=True)
def isolated_uploads_dir(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(uploads_module, "DEFAULT_UPLOADS_DIR", tmp_path / "uploads")


@pytest.fixture
def data_dir_a(tmp_path: Path) -> Path:
    d = tmp_path / "source_a"
    d.mkdir()
    (d / "assets.csv").write_text(ASSETS_CSV_A, encoding="utf-8")
    (d / "findings.csv").write_text(FINDINGS_CSV_A, encoding="utf-8")
    return d


@pytest.fixture
def data_dir_b(tmp_path: Path) -> Path:
    d = tmp_path / "source_b"
    d.mkdir()
    (d / "assets.csv").write_text(ASSETS_CSV_B, encoding="utf-8")
    (d / "findings.csv").write_text(FINDINGS_CSV_B, encoding="utf-8")
    return d


def _wait_for_terminal(client: TestClient, job_id: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    body = None
    while time.monotonic() < deadline:
        body = client.get(f"/api/jobs/{job_id}").json()
        if body["status"] in ("succeeded", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not reach a terminal state within {timeout}s: {body}")


# ---------------- resolve_source_ref ----------------


def test_resolve_source_ref_recognizes_a_bare_data_directory_name(monkeypatch):
    monkeypatch.setattr(jobs_module, "REPO_ROOT", REPO_ROOT)
    resolved = resolve_source_ref("demo")
    assert resolved.data_dir == DEMO_DIR
    assert resolved.fmt == "native"
    assert resolved.adapter_config is None


def test_resolve_source_ref_rejects_an_unknown_bare_name():
    with pytest.raises(IngestError, match="no such data set"):
        resolve_source_ref("this-does-not-exist-anywhere")


def test_resolve_source_ref_rejects_an_unknown_upload_id():
    """An upload-id-SHAPED source_ref with no real upload falls through
    to the bare --data check too (a legitimate dataset directory can
    coincidentally be 32 hex characters) before finally refusing -- the
    error names both things it tried, not just the upload guess."""
    fake_upload_id = "a" * 32
    with pytest.raises(IngestError, match="no such source"):
        resolve_source_ref(fake_upload_id)


def test_resolve_source_ref_recognizes_an_upload_matching_a_known_format(tmp_path: Path):
    upload_id = "b" * 32
    upload_dir = uploads_module.DEFAULT_UPLOADS_DIR / upload_id
    upload_dir.mkdir(parents=True)
    (upload_dir / "assets.csv").write_text(ASSETS_CSV_A, encoding="utf-8")
    (upload_dir / "findings.csv").write_text(FINDINGS_CSV_A, encoding="utf-8")

    resolved = resolve_source_ref(upload_id)
    assert resolved.data_dir == upload_dir
    assert resolved.fmt == "native"
    assert resolved.adapter_config is None


def test_resolve_source_ref_refuses_an_upload_with_no_known_format_and_no_contract(tmp_path: Path, monkeypatch):
    upload_id = "c" * 32
    upload_dir = uploads_module.DEFAULT_UPLOADS_DIR / upload_id
    upload_dir.mkdir(parents=True)
    (upload_dir / "mystery.csv").write_text("col1,col2\n1,2\n", encoding="utf-8")
    monkeypatch.setattr(jobs_module, "resolve_config_path", lambda name: tmp_path / "adapters" / f"{name}.json")

    with pytest.raises(IngestError, match="ingest_propose"):
        resolve_source_ref(upload_id)


def test_resolve_source_ref_accepts_the_uploads_prefixed_shape_identically(tmp_path: Path):
    """web/uploads.py's own UploadSet.to_dict()["relative_data_dir"] (and
    the ingest_propose job's own "next_step" hint) both hand back
    f"uploads/{id}", not the bare id -- an adversarial review found this
    shape used to fall through to the bare --data branch entirely,
    silently scoring as native format with zero validation."""
    upload_id = "f" * 32
    upload_dir = uploads_module.DEFAULT_UPLOADS_DIR / upload_id
    upload_dir.mkdir(parents=True)
    (upload_dir / "assets.csv").write_text(ASSETS_CSV_A, encoding="utf-8")
    (upload_dir / "findings.csv").write_text(FINDINGS_CSV_A, encoding="utf-8")

    resolved = resolve_source_ref(f"uploads/{upload_id}")
    assert resolved.data_dir == upload_dir
    assert resolved.fmt == "native"


def test_resolve_source_ref_is_case_insensitive_on_the_upload_id(tmp_path: Path):
    upload_id = "1a2b3c4d5e6f17181920212223242526"
    upload_dir = uploads_module.DEFAULT_UPLOADS_DIR / upload_id
    upload_dir.mkdir(parents=True)
    (upload_dir / "assets.csv").write_text(ASSETS_CSV_A, encoding="utf-8")
    (upload_dir / "findings.csv").write_text(FINDINGS_CSV_A, encoding="utf-8")

    resolved = resolve_source_ref(upload_id.upper())
    assert resolved.data_dir == upload_dir


def test_resolve_source_ref_falls_back_to_a_real_dataset_directory_shaped_like_an_upload_id(tmp_path: Path, monkeypatch):
    """A legitimate --data directory can coincidentally be named with 32
    hex characters (a hash-named or generated dataset) -- an adversarial
    review found this used to always be misclassified as a missing
    upload and refused, never falling back to check data/<name> at all."""
    hex_name = "0123456789abcdef0123456789abcdef"
    data_root = tmp_path / "data"
    (data_root / hex_name).mkdir(parents=True)
    (data_root / hex_name / "assets.csv").write_text(ASSETS_CSV_A, encoding="utf-8")
    (data_root / hex_name / "findings.csv").write_text(FINDINGS_CSV_A, encoding="utf-8")
    monkeypatch.setattr(jobs_module, "REPO_ROOT", tmp_path)

    resolved = resolve_source_ref(hex_name)
    assert resolved.data_dir == data_root / hex_name
    assert resolved.fmt == "native"


def _mapped(mapping: dict, columns_cited: list[str] | None = None) -> dict:
    return {
        "status": "mapped", "mapping": mapping, "confidence": 0.9,
        "evidence": {"columns_cited": columns_cited or [], "sample_values_cited": [], "note": "test"},
    }


def _full_proposal_dict(name: str) -> dict:
    """The same minimal-but-complete single-file proposal shape
    `test_schema_inference.py`/`test_web_jobs_ingest_propose.py` already
    use -- duplicated per this suite's own established convention of each
    test file owning its fixtures, over the header
    Asset_ID/Hostname/Finding_ID/Cve/Col."""
    from rhinosecure.adapters.config_model import ASSET_SLOTS, FINDING_SLOTS

    asset = {s: _mapped({"kind": "not_collected"}) for s in ASSET_SLOTS}
    asset["asset_id"] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, ["Asset_ID"])
    asset["hostname"] = _mapped({"kind": "column", "column": "Hostname", "case": "exact", "blank": "fatal"}, ["Hostname"])
    asset["role"] = _mapped(
        {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc"}}, ["Col"]
    )
    finding = {s: _mapped({"kind": "not_collected"}) for s in FINDING_SLOTS}
    finding["finding_id"] = _mapped({"kind": "column", "column": "Finding_ID", "case": "exact", "blank": "fatal"}, ["Finding_ID"])
    finding["asset_id"] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, ["Asset_ID"])
    finding["cve_id"] = _mapped({"kind": "parsed", "column": "Cve", "case": "upper", "blank": "fatal", "parser": "cve_id"}, ["Cve"])
    finding["scanner_severity"] = _mapped(
        {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "low"}}, ["Col"]
    )
    finding["product"] = _mapped({"kind": "column", "column": "Col", "case": "exact", "blank": "absent_fact"}, ["Col"])
    finding["evidence"] = _mapped({"kind": "column", "column": "Col", "case": "exact", "blank": "absent_fact"}, ["Col"])
    return {
        "meta": {
            "format": name, "description": "test", "source_layout": "single_file",
            "assets_filename": "mystery.csv", "findings_filename": "mystery.csv", "reasoning_summary": "test",
        },
        "asset": asset, "finding": finding, "derived": {},
        "asset_grouping": {"key": "Asset_ID", "resolution": "agree_or_recency"},
        "finding_dedup": {"content_targets": ["scanner_severity"], "on_identical": "collapse_and_count", "on_conflict": "fatal"},
        "unmapped_columns": {}, "open_questions": [],
    }


def _build_contract_for_upload(upload_dir: Path, name: str, *, confirm: bool = False):
    """Builds a real Contract (via the real assemble_contract/check_
    grounding pipeline, never a hand-typed stand-in) for `upload_dir`'s
    own `mystery.csv`, optionally signed via the real config_io.confirm_
    contract. Does not write anything -- callers write_contract it
    themselves at whatever path they're testing."""
    from rhinosecure.adapters.probe import profile_source
    from rhinosecure.agents.schema_inference import AdapterProposal, Generator, assemble_contract, check_grounding

    proposal = AdapterProposal.model_validate(_full_proposal_dict(name))
    profiles = {p.path.name: p for p in profile_source(upload_dir)}
    report = check_grounding(proposal, profiles)
    generator = Generator(
        tool="x", model="y", prompt_tokens=1, completion_tokens=1, estimated_cost_usd=0.0,
        attempts=1, call_log_digest="sha256:" + "a" * 64,
    )
    contract = assemble_contract(proposal, profiles, report, generator=generator, generated_at="2026-01-01T00:00:00Z")
    assert contract is not None  # sanity: the fixture above must actually assemble
    if confirm:
        from rhinosecure.adapters.config_io import confirm_contract

        contract = confirm_contract(contract, at="2026-01-01T01:00:00Z", by="test-suite")
    return contract


def test_resolve_source_ref_refuses_an_upload_with_a_proposed_but_unconfirmed_contract(tmp_path: Path, monkeypatch):
    from rhinosecure.adapters.config_io import write_contract

    upload_id = "d" * 32
    upload_dir = uploads_module.DEFAULT_UPLOADS_DIR / upload_id
    upload_dir.mkdir(parents=True)
    (upload_dir / "mystery.csv").write_text(
        "Asset_ID,Hostname,Finding_ID,Cve,Col\nA01,HOST01,F01,CVE-2021-0001,srv\nA02,HOST02,F02,CVE-2021-0002,wks\n",
        encoding="utf-8",
    )
    adapters_dir = tmp_path / "adapters"
    monkeypatch.setattr(jobs_module, "resolve_config_path", lambda name: adapters_dir / f"{name}.json")

    name = jobs_module._default_propose_name(upload_id)
    contract = _build_contract_for_upload(upload_dir, name)  # review.state == "proposed", never confirmed
    write_contract(adapters_dir / f"{contract.format}.json", contract)

    with pytest.raises(IngestError, match="rhino adapt confirm"):
        resolve_source_ref(upload_id)


def test_resolve_source_ref_finds_a_confirmed_contract_under_a_custom_name(tmp_path: Path, monkeypatch):
    """ingest_propose's own `name` input lets a human/Router propose (and
    later confirm) a contract under ANY name, not just the auto-generated
    default -- an adversarial review found resolve_source_ref could only
    ever find the default-named one, silently ignoring a real, confirmed,
    custom-named contract and reporting "no confirmed contract yet" even
    though one genuinely exists. The fix: _run_ingest_propose records
    which name it used next to the upload; resolve_source_ref checks that
    marker before falling back to the default-name guess."""
    from rhinosecure.adapters.config_io import write_contract

    upload_id = "1" * 32
    upload_dir = uploads_module.DEFAULT_UPLOADS_DIR / upload_id
    upload_dir.mkdir(parents=True)
    (upload_dir / "mystery.csv").write_text(
        "Asset_ID,Hostname,Finding_ID,Cve,Col\nA01,HOST01,F01,CVE-2021-0001,srv\nA02,HOST02,F02,CVE-2021-0002,wks\n",
        encoding="utf-8",
    )
    adapters_dir = tmp_path / "adapters"
    monkeypatch.setattr(jobs_module, "resolve_config_path", lambda name: adapters_dir / f"{name}.json")

    custom_name = "acme-scanner"
    contract = _build_contract_for_upload(upload_dir, custom_name, confirm=True)
    write_contract(adapters_dir / f"{custom_name}.json", contract)
    jobs_module._record_upload_contract_name(upload_dir, custom_name)

    resolved = resolve_source_ref(upload_id)
    assert resolved.fmt == custom_name
    assert resolved.adapter_config == str(adapters_dir / f"{custom_name}.json")


def test_resolve_source_ref_ignores_a_stale_marker_naming_a_file_that_no_longer_exists(tmp_path: Path, monkeypatch):
    """A best-effort marker, never load-bearing: if it names a contract
    that isn't there (deleted, renamed), resolution still falls back to
    the default-name convention rather than failing outright."""
    from rhinosecure.adapters.config_io import write_contract

    upload_id = "2" * 32
    upload_dir = uploads_module.DEFAULT_UPLOADS_DIR / upload_id
    upload_dir.mkdir(parents=True)
    (upload_dir / "mystery.csv").write_text(
        "Asset_ID,Hostname,Finding_ID,Cve,Col\nA01,HOST01,F01,CVE-2021-0001,srv\nA02,HOST02,F02,CVE-2021-0002,wks\n",
        encoding="utf-8",
    )
    adapters_dir = tmp_path / "adapters"
    monkeypatch.setattr(jobs_module, "resolve_config_path", lambda name: adapters_dir / f"{name}.json")
    jobs_module._record_upload_contract_name(upload_dir, "a-name-nothing-was-ever-written-under")

    default_name = jobs_module._default_propose_name(upload_id)
    contract = _build_contract_for_upload(upload_dir, default_name, confirm=True)
    write_contract(adapters_dir / f"{default_name}.json", contract)

    resolved = resolve_source_ref(upload_id)
    assert resolved.fmt == default_name


# ---------------- run_deterministic ----------------


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    config = JobConfig(data_dir=None, db_path=tmp_path / "mem.db", offline=True)
    app = create_app(tmp_path / "export.json", jobs_enabled=True, job_config=config)
    return TestClient(app)


def test_run_deterministic_requires_source_ref(client: TestClient):
    resp = client.post("/api/jobs", json={"kind": "run_deterministic", "input": {}})
    assert resp.status_code == 400
    assert "source_ref" in resp.json()["detail"]


def test_run_deterministic_against_the_real_demo_fixture_offline(client: TestClient, tmp_path: Path, monkeypatch):
    monkeypatch.setattr(jobs_module, "REPO_ROOT", REPO_ROOT)
    resp = client.post("/api/jobs", json={"kind": "run_deterministic", "input": {"source_ref": "demo"}})
    assert resp.status_code == 202
    body = _wait_for_terminal(client, resp.json()["job_id"])

    assert body["status"] == "succeeded", body.get("error")
    assert body["export_written"] is True
    assert body["result"]["source_ref"] == "demo"
    assert body["result"]["format"] == "native"
    assert body["result"]["total_findings"] == sum(body["result"]["bucket_distribution"].values())
    assert body["result"]["total_findings"] > 0

    export_data = json.loads((tmp_path / "export.json").read_text(encoding="utf-8"))
    assert export_data["run"]["agents"] is False
    assert len(export_data["findings"]) == body["result"]["total_findings"]


def test_run_deterministic_never_touches_plan_state_coordinator(client: TestClient, monkeypatch):
    """run_deterministic is a throwaway, Coordinator-free view -- it must
    not become "the current plan" constraint_submit would replan against."""
    monkeypatch.setattr(jobs_module, "REPO_ROOT", REPO_ROOT)
    resp = client.post("/api/jobs", json={"kind": "run_deterministic", "input": {"source_ref": "demo"}})
    _wait_for_terminal(client, resp.json()["job_id"])

    plan_state = client.app.state.plan_state
    assert plan_state.coordinator is None
    assert plan_state.active_source is None


def test_run_deterministic_resolves_an_uploaded_known_format_source(client: TestClient, tmp_path: Path):
    """CVE-2021-26855 (ProxyLogon) is one of the demo fixture's own anchor
    CVEs, so its KEV/EPSS/NVD/ATT&CK data is already committed to
    data/snapshots/ -- offline=True succeeds here for the same reason
    `rhino run --data demo --offline` does, not because this test data_dir
    has its own snapshots (snapshots are keyed by CVE ID, not by source)."""
    upload_id = "e" * 32
    upload_dir = uploads_module.DEFAULT_UPLOADS_DIR / upload_id
    upload_dir.mkdir(parents=True)
    (upload_dir / "assets.csv").write_text(ASSETS_CSV_A, encoding="utf-8")
    (upload_dir / "findings.csv").write_text(FINDINGS_CSV_A, encoding="utf-8")

    resp = client.post("/api/jobs", json={"kind": "run_deterministic", "input": {"source_ref": upload_id}})
    body = _wait_for_terminal(client, resp.json()["job_id"])
    assert body["status"] == "succeeded", body.get("error")
    assert body["result"]["source_ref"] == upload_id
    assert body["result"]["format"] == "native"
    assert body["result"]["total_findings"] == 1


# ---------------- run_agents: PlanState really replaces the current plan ----------------


def test_run_agents_establishes_the_current_plan_from_an_empty_workspace(tmp_path: Path, data_dir_a: Path):
    config = JobConfig(data_dir=None, db_path=tmp_path / "mem.db")
    app = create_app(tmp_path / "export.json", jobs_enabled=True, job_config=config)
    client = TestClient(app)

    _queue_seed_run("F01", "CVE-2021-26855", "A01", "EXCH01")
    resp = client.post("/api/jobs", json={"kind": "run_agents", "input": {"source_ref": str(data_dir_a)}})
    body = _wait_for_terminal(client, resp.json()["job_id"])

    assert body["status"] == "succeeded", body.get("error")
    assert body["export_written"] is True
    plan_state = app.state.plan_state
    assert plan_state.coordinator is not None
    assert plan_state.active_source.data_dir == data_dir_a


def test_run_agents_replaces_a_previously_established_plan(tmp_path: Path, data_dir_a: Path, data_dir_b: Path):
    config = JobConfig(data_dir=None, db_path=tmp_path / "mem.db")
    app = create_app(tmp_path / "export.json", jobs_enabled=True, job_config=config)
    client = TestClient(app)

    _queue_seed_run("F01", "CVE-2021-26855", "A01", "EXCH01")
    first = client.post("/api/jobs", json={"kind": "run_agents", "input": {"source_ref": str(data_dir_a)}})
    _wait_for_terminal(client, first.json()["job_id"])
    plan_state = app.state.plan_state
    assert {e.finding.finding_id for e in plan_state.findings} == {"F01"}
    first_coordinator = plan_state.coordinator
    assert "A01" in first_coordinator._asset_index

    _queue_seed_run("G01", "CVE-2020-1472", "B01", "SQL01")
    second = client.post("/api/jobs", json={"kind": "run_agents", "input": {"source_ref": str(data_dir_b)}})
    body = _wait_for_terminal(client, second.json()["job_id"])

    assert body["status"] == "succeeded", body.get("error")
    assert plan_state.active_source.data_dir == data_dir_b
    assert {e.finding.finding_id for e in plan_state.findings} == {"G01"}  # replaced, not merged
    assert plan_state.memory is not None
    # An adversarial review found this test never actually proved the
    # Coordinator itself was replaced -- only .findings/.active_source,
    # which a hypothetical refactor could satisfy while secretly reusing
    # (or mutating) the OLD Coordinator, silently leaving stale A01/
    # EXCH01 asset context behind for a later constraint_submit call.
    assert plan_state.coordinator is not first_coordinator
    assert "B01" in plan_state.coordinator._asset_index
    assert "A01" not in plan_state.coordinator._asset_index


def test_plan_not_seeded_error_when_constraint_submit_runs_before_any_source_is_resolved(tmp_path: Path):
    config = JobConfig(data_dir=None, db_path=tmp_path / "mem.db")
    plan_state = PlanState(config, export_path=tmp_path / "export.json")
    with pytest.raises(PlanNotSeededError):
        plan_state.seed()


def test_constraint_submit_job_reports_plan_not_seeded_cleanly_via_http(tmp_path: Path):
    config = JobConfig(data_dir=None, db_path=tmp_path / "mem.db")
    app = create_app(tmp_path / "export.json", jobs_enabled=True, job_config=config)
    client = TestClient(app)

    resp = client.post("/api/jobs", json={"kind": "constraint_submit", "input": {"text": "anything"}})
    body = _wait_for_terminal(client, resp.json()["job_id"])
    assert body["status"] == "failed"
    assert body["error"]["type"] == "PlanNotSeededError"


def test_seed_still_works_from_a_startup_configured_data_dir(tmp_path: Path, data_dir_a: Path):
    """Backward compatibility: rhino web --enable-jobs --data <name> (the
    pre-front-end default) must keep seeding exactly as before."""
    config = JobConfig(data_dir=data_dir_a, db_path=tmp_path / "mem.db")
    plan_state = PlanState(config, export_path=tmp_path / "export.json")
    _queue_seed_run("F01", "CVE-2021-26855", "A01", "EXCH01")
    plan_state.seed()
    assert plan_state.coordinator is not None
    assert plan_state.active_source.data_dir == data_dir_a


# ---------------- remediation_mark ----------------


def test_remediation_mark_requires_finding_id_and_status(client: TestClient):
    resp = client.post("/api/jobs", json={"kind": "remediation_mark", "input": {"finding_id": "F01"}})
    assert resp.status_code == 400
    assert "status" in resp.json()["detail"]


def test_remediation_mark_rejects_an_unknown_status(client: TestClient):
    resp = client.post(
        "/api/jobs", json={"kind": "remediation_mark", "input": {"finding_id": "F01", "status": "bogus"}}
    )
    assert resp.status_code == 400
    assert "bogus" in resp.json()["detail"]


def test_remediation_mark_records_a_new_finding_with_no_prior_history(client: TestClient):
    resp = client.post(
        "/api/jobs",
        json={"kind": "remediation_mark", "input": {"finding_id": "F01", "status": "remediated"}},
    )
    body = _wait_for_terminal(client, resp.json()["job_id"])
    assert body["status"] == "succeeded"
    assert body["export_written"] is False
    assert body["result"]["previous_status"] is None
    assert body["result"]["transition"] == "(untracked) -> remediated"
    assert body["result"]["seen_before_in_a_scored_run"] is False


def test_remediation_mark_requires_a_note_to_reopen_from_remediated(client: TestClient):
    first = client.post(
        "/api/jobs", json={"kind": "remediation_mark", "input": {"finding_id": "F02", "status": "remediated"}}
    )
    _wait_for_terminal(client, first.json()["job_id"])

    second = client.post("/api/jobs", json={"kind": "remediation_mark", "input": {"finding_id": "F02", "status": "open"}})
    body = _wait_for_terminal(client, second.json()["job_id"])
    assert body["status"] == "failed"
    assert "note is required" in body["error"]["message"]

    third = client.post(
        "/api/jobs",
        json={"kind": "remediation_mark", "input": {"finding_id": "F02", "status": "open", "note": "patch failed"}},
    )
    body = _wait_for_terminal(client, third.json()["job_id"])
    assert body["status"] == "succeeded"
    assert body["result"]["transition"] == "remediated -> open"
