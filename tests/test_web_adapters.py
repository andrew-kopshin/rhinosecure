"""Coverage for `web/adapters.py` -- the browser-facing slot-inspection
and confirmation-gate routes that close the upload-flow dead end CLAUDE.md
names (PROGRESS.md 2026-09-06). Only the LLM dispatch is faked
(`_QueuedFakeCrew`, the same pattern every other propose-adjacent test file
uses); everything downstream (grounding, assembly, `review_contract`'s
real measurement pass) runs for real against a real tmp_path source."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from crewai.types.usage_metrics import UsageMetrics
from fastapi.testclient import TestClient

import rhinosecure.agents.schema_inference as schema_inference_module
from rhinosecure.adapters.config_model import ASSET_SLOTS, FINDING_SLOTS
from rhinosecure.web import jobs as jobs_module
from rhinosecure.web import uploads as uploads_module
from rhinosecure.web.jobs import JobConfig
from rhinosecure.web.server import create_app

_HEADER = ["Asset_ID", "Hostname", "Finding_ID", "Cve", "Col", "Env"]
_ROWS = [
    ["A01", "HOST01", "F01", "CVE-2021-0001", "srv", "Production"],
    ["A02", "HOST02", "F02", "CVE-2021-0002", "wks", "Corporate"],
]


def _mapped(mapping: dict, *, confidence: float = 0.9, columns_cited: list[str] | None = None) -> dict:
    return {
        "status": "mapped", "mapping": mapping, "confidence": confidence,
        "evidence": {"columns_cited": columns_cited or [], "sample_values_cited": [], "note": "test reasoning"},
    }


def _unresolved(reason: str = "no confirmed target vocabulary", candidates: list[str] | None = None) -> dict:
    return {"status": "unresolved", "candidate_columns": candidates or [], "reason": reason}


def _proposal_dict(
    *, name: str, environment_status: str = "mapped", content_address_finding_id: bool = False,
    role_confidence: float = 0.9,
) -> dict:
    asset: dict = {}
    for slot in ASSET_SLOTS:
        if slot == "asset_id":
            asset[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Asset_ID"])
        elif slot == "hostname":
            asset[slot] = _mapped({"kind": "column", "column": "Hostname", "case": "exact", "blank": "fatal"}, columns_cited=["Hostname"])
        elif slot == "role":
            asset[slot] = _mapped(
                {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "dc", "wks": "workstation"}},
                confidence=role_confidence, columns_cited=["Col"],
            )
        elif slot == "environment":
            if environment_status == "unresolved":
                asset[slot] = _unresolved("Corporate has no confirmed prod/staging/dev equivalent", ["Env"])
            else:
                asset[slot] = _mapped(
                    {
                        "kind": "vocabulary", "column": "Env", "case": "exact", "blank": "fatal",
                        "table": {"Production": "prod", "Corporate": "staging"},
                    },
                    columns_cited=["Env"],
                )
        else:
            asset[slot] = _mapped({"kind": "not_collected"})
    finding: dict = {}
    for slot in FINDING_SLOTS:
        if slot == "finding_id":
            if content_address_finding_id:
                finding[slot] = _mapped(
                    {
                        "kind": "content_address", "algorithm": "sha256", "columns": ["Asset_ID", "Cve"],
                        "join": "|", "prefix": "t-", "hex_len": 16, "case": "lower", "recipe_version": 1,
                    },
                    columns_cited=["Asset_ID", "Cve"],
                )
            else:
                finding[slot] = _mapped({"kind": "column", "column": "Finding_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Finding_ID"])
        elif slot == "asset_id":
            finding[slot] = _mapped({"kind": "column", "column": "Asset_ID", "case": "exact", "blank": "fatal"}, columns_cited=["Asset_ID"])
        elif slot == "cve_id":
            finding[slot] = _mapped({"kind": "parsed", "column": "Cve", "case": "upper", "blank": "fatal", "parser": "cve_id"}, columns_cited=["Cve"])
        elif slot == "scanner_severity":
            finding[slot] = _mapped(
                {"kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal", "table": {"srv": "low", "wks": "low"}},
                columns_cited=["Col"],
            )
        elif slot in ("product", "evidence"):
            finding[slot] = _mapped({"kind": "column", "column": "Col", "case": "exact", "blank": "absent_fact"}, columns_cited=["Col"])
        else:
            finding[slot] = _mapped({"kind": "not_collected"})

    unmapped: dict = {}
    if environment_status == "unresolved":
        unmapped["Env"] = {"disposition": "ignored", "reason": "test", "profile_cited": "test"}
    if content_address_finding_id:
        unmapped["Finding_ID"] = {"disposition": "ignored", "reason": "superseded by content_address", "profile_cited": "test"}

    return {
        "meta": {
            "format": name, "description": "test fixture", "source_layout": "single_file",
            "assets_filename": "inventory.csv", "findings_filename": "inventory.csv", "reasoning_summary": "test",
        },
        "asset": asset, "finding": finding, "derived": {},
        "asset_grouping": {"key": "Asset_ID", "resolution": "agree_or_recency"},
        "finding_dedup": {"content_targets": ["cve_id"], "on_identical": "collapse_and_count", "on_conflict": "fatal"},
        "unmapped_columns": {"inventory.csv": unmapped} if unmapped else {},
        "open_questions": [],
    }


def _csv_bytes(rows: list[list[str]]) -> bytes:
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_HEADER)
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8")


class _QueuedFakeCrew:
    queue: list = []
    instantiations: int = 0

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.tasks = tasks
        self.usage_metrics = UsageMetrics(prompt_tokens=111, completion_tokens=22, total_tokens=133)
        type(self).instantiations += 1

    def kickoff(self):
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
    monkeypatch.setattr(uploads_module, "DEFAULT_UPLOADS_DIR", tmp_path / "uploads")
    monkeypatch.setattr(jobs_module, "REPO_ROOT", tmp_path)
    adapters_dir = tmp_path / "adapters"
    monkeypatch.setattr(jobs_module, "resolve_config_path", lambda name: adapters_dir / f"{name}.json")
    import rhinosecure.web.adapters as adapters_module

    monkeypatch.setattr(adapters_module, "resolve_config_path", lambda name: adapters_dir / f"{name}.json")
    monkeypatch.setattr(adapters_module, "_REPO_ROOT", tmp_path)
    return adapters_dir


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config = JobConfig(data_dir=data_dir, db_path=tmp_path / "mem.db")
    app = create_app(tmp_path / "export.json", jobs_enabled=True, job_config=config)
    return TestClient(app)


def _upload(client: TestClient, filename: str = "inventory.csv", content: bytes | None = None) -> str:
    resp = client.post("/api/uploads", files={"file": (filename, content or _csv_bytes(_ROWS), "text/csv")})
    return resp.json()["upload_id"]


def _propose(client: TestClient, upload_id: str, name: str, proposal: dict) -> dict:
    _QueuedFakeCrew.queue = [json.dumps(proposal)]
    resp = client.post("/api/jobs", json={"kind": "ingest_propose", "input": {"upload_id": upload_id, "name": name}})
    job_id = resp.json()["job_id"]
    import time

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        body = client.get(f"/api/jobs/{job_id}").json()
        if body["status"] in ("succeeded", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError("job did not finish")


# ---------------- routes are absent without jobs_enabled ----------------


def test_adapter_routes_are_404_when_jobs_are_disabled(tmp_path: Path):
    app = create_app(tmp_path / "export.json")
    client = TestClient(app)
    assert client.get("/api/adapters/whatever/proposal", params={"upload_id": "x"}).status_code == 404
    assert client.get("/api/adapters/whatever/review", params={"upload_id": "x"}).status_code == 404
    assert client.post("/api/adapters/whatever/confirm", json={"upload_id": "x", "by": "me"}).status_code == 404


# ---------------- GET /api/adapters/{name}/proposal ----------------


def test_get_proposal_surfaces_unresolved_slot_detail(client: TestClient):
    upload_id = _upload(client)
    job = _propose(client, upload_id, "upload-detail", _proposal_dict(name="upload-detail", environment_status="unresolved"))
    assert job["result"]["contract_written"] is False

    resp = client.get(f"/api/adapters/upload-detail/proposal", params={"upload_id": upload_id})
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "upload-detail"
    slots = {u["slot"]: u for u in body["unresolved"]}
    assert "asset.environment" in slots
    detail = slots["asset.environment"]
    assert detail["candidate_columns"] == ["Env"]
    assert detail["target_vocabulary"] == {"kind": "enum", "values": ["dev", "prod", "staging"]}
    assert set(detail["column_profiles"]["Env"]["distinct_values"]) == {"Production", "Corporate"}


def test_get_proposal_404s_for_an_unknown_name(client: TestClient):
    upload_id = _upload(client)
    resp = client.get("/api/adapters/no-such-name/proposal", params={"upload_id": upload_id})
    assert resp.status_code == 404


def test_get_proposal_404s_for_an_unknown_upload_id(client: TestClient):
    _propose(client, _upload(client), "upload-x", _proposal_dict(name="upload-x"))
    resp = client.get("/api/adapters/upload-x/proposal", params={"upload_id": "does-not-exist"})
    assert resp.status_code == 404


def test_get_proposal_surfaces_a_low_confidence_mapped_slot(client: TestClient):
    """The real gap check_grounding can't close on its own: role's
    vocabulary table cites only real observed tokens (srv/wks), so
    grounding is clean, but confidence is deliberately low -- a human must
    see it before confirming, not just a clean grounding report."""
    upload_id = _upload(client)
    job = _propose(client, upload_id, "upload-low-conf", _proposal_dict(name="upload-low-conf", role_confidence=0.5))
    assert job["result"]["contract_written"] is True

    resp = client.get("/api/adapters/upload-low-conf/proposal", params={"upload_id": upload_id})
    assert resp.status_code == 200
    body = resp.json()
    low_conf = {entry["slot"]: entry for entry in body["low_confidence"]}
    assert "asset.role" in low_conf
    assert low_conf["asset.role"]["confidence"] == 0.5
    assert low_conf["asset.role"]["candidate_columns"] == ["Col"]
    assert set(low_conf["asset.role"]["column_profiles"]["Col"]["distinct_values"]) == {"srv", "wks"}
    assert low_conf["asset.role"]["target_vocabulary"]["kind"] == "enum"
    assert low_conf["asset.role"]["current_mapping"]["table"] == {"srv": "dc", "wks": "workstation"}
    # environment is mapped at the default 0.9 confidence -- must not appear.
    assert "asset.environment" not in low_conf


def test_get_proposal_low_confidence_is_empty_when_every_slot_is_confident(client: TestClient):
    upload_id = _upload(client)
    _propose(client, upload_id, "upload-confident", _proposal_dict(name="upload-confident"))
    resp = client.get("/api/adapters/upload-confident/proposal", params={"upload_id": upload_id})
    assert resp.json()["low_confidence"] == []


# ---------------- GET /api/adapters/{name}/review ----------------


def test_get_review_reports_a_clean_measurement_with_nothing_required(client: TestClient):
    upload_id = _upload(client)
    job = _propose(client, upload_id, "upload-clean", _proposal_dict(name="upload-clean"))
    assert job["result"]["contract_written"] is True

    resp = client.get("/api/adapters/upload-clean/review", params={"upload_id": upload_id})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["written"] is False  # review never writes
    assert body["required_attestations"] == {}
    assert body["still_missing"] == []
    assert body["measurement"]["assets_loaded"] == 2


def test_get_review_names_a_required_attestation(client: TestClient):
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-needs-attest", content_address_finding_id=True)
    job = _propose(client, upload_id, "upload-needs-attest", proposal)
    assert job["result"]["contract_written"] is True

    resp = client.get("/api/adapters/upload-needs-attest/review", params={"upload_id": upload_id})
    body = resp.json()
    assert "finding_id.synthesized" in body["required_attestations"]
    assert body["still_missing"] == ["finding_id.synthesized"]


def test_get_review_names_the_low_confidence_attestation_and_the_slot(client: TestClient):
    """This one is pure -- computable from Contract.mapping_confidence
    alone, unlike `exclusions` -- so it shows up at PREVIEW time, before
    any measurement runs, not only after a first failed confirm attempt."""
    upload_id = _upload(client)
    _propose(client, upload_id, "upload-low-conf2", _proposal_dict(name="upload-low-conf2", role_confidence=0.5))

    resp = client.get("/api/adapters/upload-low-conf2/review", params={"upload_id": upload_id})
    body = resp.json()
    assert "low_confidence_mappings" in body["required_attestations"]
    assert "asset.role" in body["required_attestations"]["low_confidence_mappings"]
    assert "low_confidence_mappings" in body["still_missing"]


def test_confirm_succeeds_once_the_low_confidence_attestation_is_supplied(client: TestClient, isolated_dirs: Path):
    upload_id = _upload(client)
    _propose(client, upload_id, "upload-low-conf3", _proposal_dict(name="upload-low-conf3", role_confidence=0.5))

    refused = client.post(
        "/api/adapters/upload-low-conf3/confirm", json={"upload_id": upload_id, "by": "andrew"}
    ).json()
    assert refused["written"] is False
    assert "low_confidence_mappings" in refused["still_missing"]

    confirmed = client.post(
        "/api/adapters/upload-low-conf3/confirm",
        json={
            "upload_id": upload_id, "by": "andrew",
            "attestations": {
                "low_confidence_mappings": "Reviewed the role vocabulary table by hand against the real "
                "Col values (srv/wks) -- srv -> dc and wks -> workstation are correct for this fleet."
            },
        },
    ).json()
    assert confirmed["written"] is True


# ---------------- POST /api/adapters/{name}/confirm ----------------


def test_confirm_signs_a_contract_that_needs_no_attestations(client: TestClient, isolated_dirs: Path):
    upload_id = _upload(client)
    _propose(client, upload_id, "upload-confirm-me", _proposal_dict(name="upload-confirm-me"))

    resp = client.post(
        "/api/adapters/upload-confirm-me/confirm", json={"upload_id": upload_id, "by": "andrew"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["written"] is True

    written = json.loads((isolated_dirs / "upload-confirm-me.json").read_text(encoding="utf-8"))
    assert written["review"]["state"] == "confirmed"
    assert written["review"]["confirmed_by"] == "andrew"


def test_confirm_refuses_without_a_required_attestation(client: TestClient, isolated_dirs: Path):
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-missing-attest", content_address_finding_id=True)
    _propose(client, upload_id, "upload-missing-attest", proposal)

    resp = client.post(
        "/api/adapters/upload-missing-attest/confirm", json={"upload_id": upload_id, "by": "andrew"}
    )
    assert resp.status_code == 200  # a refusal is a normal outcome, not an HTTP error
    body = resp.json()
    assert body["written"] is False
    assert "finding_id.synthesized" in body["still_missing"]
    assert body["refusals"]
    # ingest_propose already wrote the unconfirmed proposal to disk (as
    # designed -- that write happens at propose time, independent of
    # confirmation); a refused confirm must leave it exactly at "proposed",
    # never advance it to "confirmed".
    written = json.loads((isolated_dirs / "upload-missing-attest.json").read_text(encoding="utf-8"))
    assert written["review"]["state"] == "proposed"


def test_confirm_succeeds_once_the_required_attestation_is_supplied(client: TestClient, isolated_dirs: Path):
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-attest-supplied", content_address_finding_id=True)
    _propose(client, upload_id, "upload-attest-supplied", proposal)

    resp = client.post(
        "/api/adapters/upload-attest-supplied/confirm",
        json={
            "upload_id": upload_id, "by": "andrew",
            "attestations": {"finding_id.synthesized": "No natural unique id exists; content-addressed from Asset_ID+Cve."},
        },
    )
    body = resp.json()
    assert body["written"] is True


def test_confirm_rejects_an_empty_identity(client: TestClient):
    upload_id = _upload(client)
    _propose(client, upload_id, "upload-no-identity", _proposal_dict(name="upload-no-identity"))

    resp = client.post("/api/adapters/upload-no-identity/confirm", json={"upload_id": upload_id, "by": "  "})
    assert resp.status_code == 400


def test_confirming_an_already_confirmed_contract_is_a_refusal_not_a_crash(client: TestClient, isolated_dirs: Path):
    upload_id = _upload(client)
    _propose(client, upload_id, "upload-twice", _proposal_dict(name="upload-twice"))
    first = client.post("/api/adapters/upload-twice/confirm", json={"upload_id": upload_id, "by": "andrew"})
    assert first.json()["written"] is True

    second = client.post("/api/adapters/upload-twice/confirm", json={"upload_id": upload_id, "by": "andrew"})
    assert second.status_code == 200
    body = second.json()
    assert body["written"] is False
    assert body["refusals"]
