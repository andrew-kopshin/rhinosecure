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

import openpyxl
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


def _propose_edited(client: TestClient, upload_id: str, name: str, proposal: dict) -> dict:
    """Mirrors `_propose`, but submits `proposal` as a human's resubmitted
    edit (`edited_saved_proposal`) rather than a fresh LLM candidate --
    the resolve-slots form's own request shape. Never touches the fake-crew
    queue: `_run_ingest_propose`'s `from_proposal` branch never calls the
    LLM at all, exactly like the real `rhino adapt propose --from-proposal`
    it shares code with."""
    edited_saved_proposal = {
        "proposal": proposal,
        "generator": {
            "tool": "rhino-adapt-propose", "model": "claude-sonnet-5",
            "prompt_tokens": 10, "completion_tokens": 5, "estimated_cost_usd": 0.0,
            "attempts": 1, "call_log_digest": "sha256:" + "a" * 64,
        },
        "attempt_usage": [],
    }
    resp = client.post(
        "/api/jobs",
        json={
            "kind": "ingest_propose",
            "input": {"upload_id": upload_id, "name": name, "edited_saved_proposal": edited_saved_proposal},
        },
    )
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
    # environment is gap-legal AND scoring-relevant -- the provisional-run
    # fallback (assemble_provisional_contract) now auto-fills it via
    # not_collected (neutralized for scoring) and writes immediately,
    # rather than leaving the proposal blocked. `unresolved` below is still
    # populated from the SAVED PROPOSAL (out/propose_<name>.json, written
    # unconditionally), not the contract, so this endpoint's own behavior
    # -- the actual thing this test exercises -- is otherwise unaffected.
    assert job["result"]["contract_written"] is True
    assert job["result"]["provisional"] is True

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


def test_get_proposal_surfaces_an_illegal_mapped_slot_distinctly_from_unresolved(client: TestClient):
    """The gap this endpoint addition closes: `role` HAS a mapping here --
    it is not unresolved -- but `blank='gap'` is illegal for it
    (`role` has no `NOT_COLLECTED_DEFAULTS` entry). Before `illegal`
    existed, the only documented recourse was hand-editing the saved
    proposal JSON and re-running `rhino adapt propose --from-proposal` on
    the CLI -- this proves the same slot now round-trips through the web
    endpoint instead, worded as a rejection, not a generic message, and
    never double-counted as unresolved."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-illegal")
    proposal["asset"]["role"] = {
        "status": "mapped", "confidence": 0.9,
        "mapping": {
            "kind": "vocabulary", "column": "Col", "case": "lower", "blank": "gap",
            "table": {"srv": "dc", "wks": "workstation"},
        },
        "evidence": {"columns_cited": ["Col"], "sample_values_cited": [], "note": "test reasoning"},
    }
    job = _propose_edited(client, upload_id, "upload-illegal", proposal)
    assert job["status"] == "succeeded"
    # assemble_contract refuses role outright (blank='gap' is illegal for
    # it). UPDATED: the provisional fallback used to degrade it and write a
    # contract; arriving via edited_saved_proposal it is attributed to a
    # human author, and a human-authored invalid mapping is now refused
    # instead. Either way the scenario this test is actually about really
    # occurred -- role IS mapped and IS rejected -- which is what makes the
    # endpoint assertions below meaningful rather than incidental.
    assert job["result"]["contract_written"] is False
    assert "asset.role" in job["result"]["incomplete_reason"]
    assert job["result"]["invalid_mappings_dropped"] == []  # refused, not degraded
    # And the refusal is exactly the case that most needs a row back in the
    # form, which is what the rest of this test checks.

    resp = client.get("/api/adapters/upload-illegal/proposal", params={"upload_id": upload_id})
    assert resp.status_code == 200
    body = resp.json()
    illegal = {entry["slot"]: entry for entry in body["illegal"]}
    assert "asset.role" in illegal
    entry = illegal["asset.role"]
    assert entry["kind"] == "illegal"
    assert "blank='gap'" in entry["reason"]  # the validator's own text, not a generic message
    assert entry["candidate_columns"] == ["Col"]
    assert entry["current_mapping"]["table"] == {"srv": "dc", "wks": "workstation"}
    assert set(entry["column_profiles"]["Col"]["distinct_values"]) == {"srv", "wks"}
    # mapped-but-illegal is not unresolved -- must never appear in both lists.
    assert "asset.role" not in {u["slot"] for u in body["unresolved"]}


def test_get_proposal_surfaces_an_illegal_vocabulary_value_with_a_usable_picker(client: TestClient):
    """One of the two classes that used to be enforced only by
    validate_contract and gated only in the browser. 'srv' is a real
    observed token, so check_grounding passes it cleanly -- it says nothing
    about whether 'supervisor' is a legal AssetRole. The row must carry the
    validator's own text AND the column profile, since correcting this one
    means repicking each value against the real column."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-badvalue")
    proposal["asset"]["role"] = {
        "status": "mapped", "confidence": 0.9,
        "mapping": {
            "kind": "vocabulary", "column": "Col", "case": "lower", "blank": "fatal",
            "table": {"srv": "supervisor", "wks": "workstation"},
        },
        "evidence": {"columns_cited": ["Col"], "sample_values_cited": [], "note": "test reasoning"},
    }
    job = _propose_edited(client, upload_id, "upload-badvalue", proposal)
    assert job["status"] == "succeeded"
    assert job["result"]["grounding"]["failures"] == []  # grounding really is clean; only the value rule catches this

    resp = client.get("/api/adapters/upload-badvalue/proposal", params={"upload_id": upload_id})
    assert resp.status_code == 200
    entry = {e["slot"]: e for e in resp.json()["illegal"]}["asset.role"]
    assert entry["kind"] == "illegal"
    assert "'supervisor' is not one of" in entry["reason"]  # the validator's own text
    # The row has what the value-picker needs to actually be correctable.
    assert entry["candidate_columns"] == ["Col"]
    assert set(entry["column_profiles"]["Col"]["distinct_values"]) == {"srv", "wks"}
    assert entry["target_vocabulary"]["kind"] == "enum"


def test_get_proposal_surfaces_not_collected_on_a_target_with_no_defaults_entry(client: TestClient):
    """The other class. `role` falls back through default_by/
    ROLE_DEFAULT_BY_OS_CLASS, never a bare not_collected mapping, so it has
    no NOT_COLLECTED_DEFAULTS entry. The browser hides its not-collected
    checkbox for exactly this target, but that gate is client-side and
    /api/jobs is not bound to the browser.

    Pins the row's SHAPE as well as its presence, because the shape is the
    known limitation: a not_collected mapping cites no column, so
    candidate_columns is empty and gap_legal is false -- which between them
    leave resolveSlotRowHtml with no control to render. The row states the
    reason; it is not yet correctable in the form. Asserted so that stays a
    recorded fact rather than a surprise."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-badgap")
    proposal["asset"]["role"] = {
        "status": "mapped", "confidence": 0.9,
        "mapping": {"kind": "not_collected"},
        "evidence": {"columns_cited": [], "sample_values_cited": [], "note": "test reasoning"},
    }
    job = _propose_edited(client, upload_id, "upload-badgap", proposal)
    assert job["status"] == "succeeded"

    resp = client.get("/api/adapters/upload-badgap/proposal", params={"upload_id": upload_id})
    assert resp.status_code == 200
    body = resp.json()
    entry = {e["slot"]: e for e in body["illegal"]}["asset.role"]
    assert entry["kind"] == "illegal"
    assert "not_collected has no NOT_COLLECTED_DEFAULTS entry for 'role'" in entry["reason"]
    assert entry["current_mapping"] == {"kind": "not_collected"}
    assert entry["candidate_columns"] == []  # no column is cited, so none can be offered
    assert entry["gap_legal"] is False  # and "mark not collected" is the very thing being refused
    # Mapped-but-illegal is not unresolved -- never both lists.
    assert "asset.role" not in {u["slot"] for u in body["unresolved"]}
    # The form names this file as the recourse for a row it cannot correct.
    # Response-level, not per-row: it is a property of the proposal.
    assert body["saved_proposal_path"].endswith("propose_upload-badgap.json")
    assert Path(body["saved_proposal_path"]).is_file()
    # And deliberately NOT a server-side "correctable" flag -- which
    # controls this form can emit is app.js's fact, not the endpoint's
    # (resolveSlotControls' own comment argues it).
    assert "correctable" not in entry


def test_get_proposal_does_not_crash_on_a_misplaced_timestamp_parser(client: TestClient):
    """Regression test for docs/handoff.md 4.2.1's crash defect. `parser:
    "timestamp"` is legal only inside `asset_grouping.order_by`
    (`PARSER_POSITIONS`), never on a plain per-row mapping -- exactly the
    illegality `illegal_mapped_slots` exists to turn into a row (this
    function's own docstring names `finding.detected_date` with a
    misplaced `timestamp` parser as its worked example).

    Before the fix, `_predict_current_values` called `_parse_scalar`
    unconditionally for every `"parsed"` mapping, which raises a bare
    `AssertionError` for `"timestamp"` ("timestamp is order_by-only")
    with nothing catching it between there and the route handler --
    a 500 out of `GET /api/adapters/{name}/proposal`, not a row."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-badparser")
    proposal["finding"]["detected_date"] = {
        "status": "mapped", "confidence": 0.9,
        "mapping": {"kind": "parsed", "column": "Col", "case": "exact", "blank": "fatal", "parser": "timestamp"},
        "evidence": {"columns_cited": ["Col"], "sample_values_cited": [], "note": "test reasoning"},
    }
    job = _propose_edited(client, upload_id, "upload-badparser", proposal)
    assert job["status"] == "succeeded"  # a refused mapping is an incomplete proposal, not a job failure
    assert job["result"]["contract_written"] is False

    resp = client.get("/api/adapters/upload-badparser/proposal", params={"upload_id": upload_id})
    assert resp.status_code == 200  # not a 500
    entry = {e["slot"]: e for e in resp.json()["illegal"]}["finding.detected_date"]
    assert entry["kind"] == "illegal"
    assert "order_by" in entry["reason"]  # the validator's own text
    # No scalar resolver exists for "timestamp" outside order_by, so
    # nothing is predicted for it -- the same honest-blank behavior as any
    # other value a mapping doesn't resolve, never a guess.
    assert entry["current_values"] == {}


def test_get_proposal_illegal_is_empty_for_a_clean_proposal(client: TestClient):
    upload_id = _upload(client)
    job = _propose(client, upload_id, "upload-clean", _proposal_dict(name="upload-clean"))
    assert job["result"]["contract_written"] is True
    assert job["result"].get("provisional") is False

    resp = client.get("/api/adapters/upload-clean/proposal", params={"upload_id": upload_id})
    assert resp.json()["illegal"] == []


# ---------------- grounding_failed: the row source docs/handoff.md 4.2.1 found missing ----------------


def _grounding_rows(client: TestClient, name: str, upload_id: str) -> tuple[dict, dict]:
    resp = client.get(f"/api/adapters/{name}/proposal", params={"upload_id": upload_id})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return body, {row["slot"]: row for row in body["grounding_failed"]}


def test_get_proposal_grounding_failed_is_empty_for_a_clean_proposal(client: TestClient):
    upload_id = _upload(client)
    _propose(client, upload_id, "upload-gf-clean", _proposal_dict(name="upload-gf-clean"))
    body, rows = _grounding_rows(client, "upload-gf-clean", upload_id)
    assert body["grounding_failed"] == []


def test_grounding_failed_row_for_a_parser_that_rejects_the_source_ids(client: TestClient):
    """The itco case (docs/handoff.md section 4 item 1): a source whose IDs
    are `CVE-SYN-2026-1001`, mapped with the `cve_id` parser, which insists
    on `CVE-YYYY-NNNN+`. `Finding.cve_id` itself accepts these (its own
    pattern is the safe-identifier one), so the correction is a plain
    `column` mapping -- and the row must make that reachable: the real
    column as the only candidate, and `fatal_legal` true, because `fatal` is
    the ONLY blank policy `cve_id` has, which is what used to leave the form
    with no column picker to draw."""
    rows = [
        ["A01", "HOST01", "F01", "CVE-SYN-2026-1001", "srv", "Production"],
        ["A02", "HOST02", "F02", "CVE-SYN-2026-1002", "wks", "Corporate"],
    ]
    upload_id = _upload(client, content=_csv_bytes(rows))
    job = _propose_edited(client, upload_id, "upload-gf-syn", _proposal_dict(name="upload-gf-syn"))
    assert job["result"]["contract_written"] is False

    _, found = _grounding_rows(client, "upload-gf-syn", upload_id)
    assert set(found) == {"finding.cve_id"}
    row = found["finding.cve_id"]
    assert row["kind"] == "grounding"
    assert row["grounding_kinds"] == ["parser_no_resolve"]
    assert "does not resolve 2 of 2" in row["reason"]
    assert row["candidate_columns"] == ["Cve"]
    assert set(row["column_profiles"]["Cve"]["distinct_values"]) == {"CVE-SYN-2026-1001", "CVE-SYN-2026-1002"}
    assert row["current_values"] == {}  # the parser resolves nothing, so nothing is predicted
    assert row["target_vocabulary"] is None
    assert (row["gap_legal"], row["absent_fact_legal"], row["fatal_legal"]) == (False, False, True)
    assert "structural" not in row


def test_grounding_failed_row_for_a_registry_anchor_disagreement_offers_no_override(client: TestClient):
    """The reported incident: `{Critical: 4}` against a registry that
    anchors "Critical" to 5. The row shows the real reason and the value
    picker's ingredients; it does NOT change what is accepted -- the
    disputed table is still refused (contract_written False) by the same
    gate, so nothing here decides whether a human may overrule an anchor."""
    rows = [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "Critical", "Production"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "Low", "Corporate"],
    ]
    upload_id = _upload(client, content=_csv_bytes(rows))
    proposal = _proposal_dict(name="upload-gf-anchor")
    # Re-key every other Col-reading table onto the real values so that
    # criticality is the ONLY slot failing grounding.
    proposal["asset"]["role"]["mapping"]["table"] = {"Critical": "dc", "Low": "workstation"}
    proposal["asset"]["role"]["mapping"]["case"] = "exact"
    proposal["finding"]["scanner_severity"]["mapping"]["table"] = {"Critical": "critical", "Low": "low"}
    proposal["finding"]["scanner_severity"]["mapping"]["case"] = "exact"
    proposal["asset"]["criticality"] = _mapped(
        {"kind": "vocabulary", "column": "Col", "case": "exact", "blank": "fatal", "table": {"Critical": 4, "Low": 2}},
        columns_cited=["Col"],
    )
    job = _propose_edited(client, upload_id, "upload-gf-anchor", proposal)
    assert job["result"]["contract_written"] is False

    _, found = _grounding_rows(client, "upload-gf-anchor", upload_id)
    assert set(found) == {"asset.criticality"}
    row = found["asset.criticality"]
    assert row["grounding_kinds"] == ["registry_anchor"]
    assert "'Critical'" in row["reason"] and "5" in row["reason"] and "4" in row["reason"]
    assert row["candidate_columns"] == ["Col"]
    assert row["current_values"] == {"Critical": 4, "Low": 2}  # what the mapping says today, to correct in place
    assert row["target_vocabulary"] == {"kind": "range", "min": 1, "max": 5}

    # A resubmit that MATCHES the anchor is accepted -- the row is a way
    # to fix the table, not a way around the registry.
    proposal["asset"]["criticality"]["mapping"]["table"] = {"Critical": 5, "Low": 2}
    fixed = _propose_edited(client, upload_id, "upload-gf-anchor", proposal)
    assert fixed["result"]["grounding"]["failures"] == []


def test_grounding_failed_row_for_an_invented_table_key_on_a_closed_vocabulary(client: TestClient):
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-gf-key")
    proposal["asset"]["role"]["mapping"]["table"] = {"srv": "dc", "never-seen": "file"}
    _propose_edited(client, upload_id, "upload-gf-key", proposal)

    _, found = _grounding_rows(client, "upload-gf-key", upload_id)
    assert set(found) == {"asset.role"}
    row = found["asset.role"]
    assert row["grounding_kinds"] == ["invented_table_key"]
    assert "never-seen" in row["reason"]
    assert row["candidate_columns"] == ["Col"]  # the real column the value picker reads
    assert set(row["column_profiles"]["Col"]["distinct_values"]) == {"srv", "wks"}
    assert row["current_values"] == {"srv": "dc"}  # only what the mapping actually resolves
    assert row["target_vocabulary"]["kind"] == "enum"


def test_grounding_failed_row_for_a_missing_column_on_a_free_text_target_offers_the_real_header(client: TestClient):
    """Picking a real column IS the correction for a hallucinated one, so a
    free-text target is offered the whole header of its file -- never the
    column that failed."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-gf-col")
    proposal["finding"]["product"] = _mapped(
        {"kind": "column", "column": "Nope", "case": "exact", "blank": "absent_fact"}, columns_cited=["Nope"]
    )
    _propose_edited(client, upload_id, "upload-gf-col", proposal)

    _, found = _grounding_rows(client, "upload-gf-col", upload_id)
    assert set(found) == {"finding.product"}
    row = found["finding.product"]
    assert row["grounding_kinds"] == ["missing_column"]
    assert row["candidate_columns"] == _HEADER
    assert "Nope" not in row["candidate_columns"]
    # No profiles for a widened whole-header list: the free-text picker needs
    # names, not profiles, and a real source can have hundreds of columns
    # each carrying a distinct-value table. This mapping reads no real column.
    assert row["column_profiles"] == {}
    assert row["current_values"] == {}
    assert row["absent_fact_legal"] is True


def test_grounding_failed_row_for_a_missing_column_on_a_closed_vocabulary_is_left_uncorrectable(client: TestClient):
    """The per-value picker needs ONE specific column and its profile, and
    a missing column supplies neither -- so the row carries the reason and
    no candidates, and the form names the recourse instead of drawing a
    picker over an arbitrary column."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-gf-vocab")
    proposal["asset"]["role"]["mapping"]["column"] = "Nope"
    _propose_edited(client, upload_id, "upload-gf-vocab", proposal)

    _, found = _grounding_rows(client, "upload-gf-vocab", upload_id)
    row = found["asset.role"]
    assert row["grounding_kinds"] == ["missing_column"]
    assert row["candidate_columns"] == []
    assert row["column_profiles"] == {}
    assert row["target_vocabulary"]["kind"] == "enum"


def test_grounding_failed_reports_a_structural_reference_as_a_row_with_no_target(client: TestClient):
    """`asset_grouping.key` is not a slot, so no mapping can be built for
    it -- but a failure must not be invisible, or the panel is back to zero
    rows and a Resubmit that reproduces the refusal."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-gf-struct")
    proposal["asset_grouping"]["key"] = "Nope"
    _propose_edited(client, upload_id, "upload-gf-struct", proposal)

    _, found = _grounding_rows(client, "upload-gf-struct", upload_id)
    row = found["asset_grouping.key"]
    assert row["structural"] is True
    assert row["grounding_kinds"] == ["missing_column"]
    assert row["candidate_columns"] == [] and row["current_mapping"] is None
    assert (row["gap_legal"], row["absent_fact_legal"], row["fatal_legal"]) == (False, False, False)


def test_a_slot_that_is_both_illegal_and_ungrounded_is_one_row_not_two(client: TestClient):
    """The JS looks a row up by `data-slot`, so a slot listed twice would
    render two forms and edit only the first. The grounding text is merged
    into the `illegal` row instead of hidden."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-gf-both")
    # blank='gap' is illegal for cve_id (fatal is its only policy), and the
    # cited column does not exist.
    proposal["finding"]["cve_id"] = _mapped(
        {"kind": "parsed", "column": "Nope", "case": "upper", "blank": "gap", "parser": "cve_id"}, columns_cited=["Nope"]
    )
    _propose_edited(client, upload_id, "upload-gf-both", proposal)

    body, found = _grounding_rows(client, "upload-gf-both", upload_id)
    assert "finding.cve_id" not in found
    entry = {e["slot"]: e for e in body["illegal"]}["finding.cve_id"]
    assert "blank='gap'" in entry["reason"]
    assert "also fails grounding" in entry["reason"] and "Nope" in entry["reason"]
    assert entry["grounding_kinds"] == ["missing_column"]


def test_an_unresolved_slot_with_a_hallucinated_candidate_is_not_also_a_grounding_row(client: TestClient):
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-gf-unres", environment_status="unresolved")
    proposal["asset"]["environment"]["candidate_columns"] = ["Nope"]
    _propose_edited(client, upload_id, "upload-gf-unres", proposal)

    body, found = _grounding_rows(client, "upload-gf-unres", upload_id)
    assert "asset.environment" in {u["slot"] for u in body["unresolved"]}
    assert "asset.environment" not in found


def test_an_unresolved_identity_slot_carries_fatal_legal_so_the_form_can_offer_its_column(client: TestClient):
    """`hostname` has `fatal` as its only blank policy. Before `fatal_legal`
    the form's column picker required `gap` or `absent_fact`, so an
    unresolved `hostname` with an obvious candidate column rendered as
    "cannot be corrected from this form"."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-gf-host")
    proposal["asset"]["hostname"] = _unresolved("the source has no machine name", ["Hostname"])
    proposal["unmapped_columns"] = {}
    _propose_edited(client, upload_id, "upload-gf-host", proposal)

    resp = client.get("/api/adapters/upload-gf-host/proposal", params={"upload_id": upload_id})
    row = {u["slot"]: u for u in resp.json()["unresolved"]}["asset.hostname"]
    assert row["candidate_columns"] == ["Hostname"]
    assert (row["gap_legal"], row["absent_fact_legal"], row["fatal_legal"]) == (False, False, True)


def test_get_proposal_409s_when_the_saved_proposal_names_files_the_upload_does_not_have(client: TestClient):
    """A proposal generated for one source, read against another. Refusing
    is right: an empty grounding list would present a proposal nobody has
    checked against THIS upload as though it were clean."""
    first = _upload(client)
    _propose(client, first, "upload-gf-mismatch", _proposal_dict(name="upload-gf-mismatch"))
    other = _upload(client, filename="other.csv")
    resp = client.get("/api/adapters/upload-gf-mismatch/proposal", params={"upload_id": other})
    assert resp.status_code == 409
    assert "does not match this upload" in resp.json()["detail"]


# ---------------- adversarial-review fixes (2026-09-21) ----------------


def test_get_proposal_404s_for_a_saved_proposal_that_is_not_utf8(client: TestClient, tmp_path: Path):
    """A hand-edit saved as UTF-16 (Windows PowerShell 5.1's `>`), which the
    UI's own recourse text recommends. `UnicodeDecodeError` escaped
    `load_saved_proposal` and 500ed the endpoint instead of being the clean
    "cannot read this proposal" it is for every other unreadable file."""
    upload_id = _upload(client)
    _propose(client, upload_id, "upload-badenc", _proposal_dict(name="upload-badenc"))
    saved_path = tmp_path / "out" / "propose_upload-badenc.json"
    saved_path.write_bytes(saved_path.read_text(encoding="utf-8").encode("utf-16"))

    resp = client.get("/api/adapters/upload-badenc/proposal", params={"upload_id": upload_id})
    assert resp.status_code == 404
    assert "could not be decoded" in resp.json()["detail"]


def test_unresolved_row_drops_a_hallucinated_candidate_and_shows_why(client: TestClient):
    """The model's candidate list is unverified. A hallucinated FIRST
    candidate hid the value picker (the browser reads candidate_columns[0]
    and needs its profile), and the failure itself was skipped, so the panel
    was silent about the only thing blocking the contract."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-gf-ghost", environment_status="unresolved")
    proposal["asset"]["environment"]["candidate_columns"] = ["Ghost", "Env"]
    _propose_edited(client, upload_id, "upload-gf-ghost", proposal)

    body, found = _grounding_rows(client, "upload-gf-ghost", upload_id)
    row = {u["slot"]: u for u in body["unresolved"]}["asset.environment"]
    assert row["candidate_columns"] == ["Env"]
    assert row["settle_columns"] == ["Env"]
    assert set(row["column_profiles"]) == {"Env"}
    assert "also fails grounding" in row["reason"] and "Ghost" in row["reason"]
    assert row["grounding_kinds"] == ["missing_column"]
    assert "asset.environment" not in found  # merged, never a second row


def test_settle_columns_are_the_slots_own_columns_not_the_pickers_whole_header(client: TestClient):
    """`candidate_columns` is what the picker may offer; `settle_columns` is
    what an edit is responsible for accounting for. Conflating them made a
    one-slot fix declare every unaccounted column 'ignored'."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-gf-settle")
    proposal["finding"]["product"] = _mapped(
        {"kind": "column", "column": "Nope", "case": "exact", "blank": "absent_fact"}, columns_cited=["Nope"]
    )
    proposal["asset"]["role"]["mapping"]["table"] = {"srv": "dc", "never-seen": "file"}
    proposal["asset_grouping"]["key"] = "Nope"
    _propose_edited(client, upload_id, "upload-gf-settle", proposal)

    _, found = _grounding_rows(client, "upload-gf-settle", upload_id)
    missing = found["finding.product"]
    assert missing["candidate_columns"] == _HEADER  # the picker may offer any real column
    assert missing["settle_columns"] == []  # but the hallucinated column being replaced is not a real one
    invented = found["asset.role"]
    assert invented["settle_columns"] == ["Col"]  # the real column the replaced table read
    assert found["asset_grouping.key"]["settle_columns"] == []  # structural: nothing to settle


def _upload_two_file_set(client: TestClient) -> str:
    assets = b"Asset_ID,Hostname,Col,Env\nA01,HOST01,srv,Production\nA02,HOST02,wks,Corporate\n"
    findings = b"Finding_ID,Asset_ID,Cve,Col\nF01,A01,CVE-2021-0001,alpha\nF02,A02,CVE-2021-0002,beta\n"
    upload_id = client.post("/api/uploads", files={"file": ("assets.csv", assets, "text/csv")}).json()["upload_id"]
    client.post("/api/uploads", files={"file": ("findings.csv", findings, "text/csv")}, data={"upload_id": upload_id})
    client.post(f"/api/uploads/{upload_id}/label", json={"filename": "assets.csv", "label": "inventory"})
    client.post(f"/api/uploads/{upload_id}/label", json={"filename": "findings.csv", "label": "findings"})
    return upload_id


def _two_file_proposal(name: str) -> dict:
    proposal = _proposal_dict(name=name)
    proposal["meta"].update(source_layout="two_file", assets_filename="assets.csv", findings_filename="findings.csv")
    return proposal


def test_two_file_rows_are_built_from_the_slots_own_file(client: TestClient):
    """`Col` exists in BOTH files with different values. Looking it up in
    whichever profile came first showed a findings slot the ASSETS file's
    values."""
    upload_id = _upload_two_file_set(client)
    # finding.scanner_severity reads findings.csv's Col (alpha/beta), but the
    # default table is keyed on assets.csv's values (srv/wks): an invented key.
    _propose_edited(client, upload_id, "upload-two-scope", _two_file_proposal("upload-two-scope"))

    _, found = _grounding_rows(client, "upload-two-scope", upload_id)
    row = found["finding.scanner_severity"]
    assert row["grounding_kinds"] == ["invented_table_key"]
    assert set(row["column_profiles"]["Col"]["distinct_values"]) == {"alpha", "beta"}


def test_a_column_only_the_other_file_has_is_not_offered_as_a_candidate(client: TestClient):
    """asset.role cites a column that exists only in findings.csv. It is a
    missing column for an ASSETS slot, and offering it as the candidate is
    offering the very column that failed."""
    assets = b"Asset_ID,Hostname,Env\nA01,HOST01,Production\n"
    findings = b"Finding_ID,Asset_ID,Cve,Col\nF01,A01,CVE-2021-0001,srv\n"
    upload_id = client.post("/api/uploads", files={"file": ("assets.csv", assets, "text/csv")}).json()["upload_id"]
    client.post("/api/uploads", files={"file": ("findings.csv", findings, "text/csv")}, data={"upload_id": upload_id})
    client.post(f"/api/uploads/{upload_id}/label", json={"filename": "assets.csv", "label": "inventory"})
    client.post(f"/api/uploads/{upload_id}/label", json={"filename": "findings.csv", "label": "findings"})
    _propose_edited(client, upload_id, "upload-two-cross", _two_file_proposal("upload-two-cross"))

    _, found = _grounding_rows(client, "upload-two-cross", upload_id)
    row = found["asset.role"]  # vocabulary over Col, which assets.csv lacks
    assert row["grounding_kinds"] == ["missing_column"]
    assert row["candidate_columns"] == []  # findings.csv's Col is not this slot's
    assert row["column_profiles"] == {}


def test_a_two_file_resolve_form_resubmit_succeeds(client: TestClient):
    """Every resubmit for a two-file source failed with CLI wording ("Pass
    --assets-file NAME --findings-file NAME") because the edit path never
    passed the filenames the saved proposal already carries -- so no row of
    any kind could be submitted from the browser for one."""
    upload_id = _upload_two_file_set(client)
    proposal = _two_file_proposal("upload-two-resubmit")
    proposal["finding"]["scanner_severity"]["mapping"]["table"] = {"alpha": "low", "beta": "low"}
    job = _propose_edited(client, upload_id, "upload-two-resubmit", proposal)
    assert job["status"] == "succeeded", job.get("error")
    assert job["result"]["grounding"]["failures"] == []
    assert job["result"]["contract_written"] is True


def test_the_form_style_exact_case_rebuild_cannot_walk_around_a_registry_anchor(client: TestClient):
    """The model's `case: lower` mapping of {critical: 4} was refused, and the
    form rebuilds every vocabulary as `case: exact`: it must be refused too,
    or an untouched Resubmit overrides the registry and stamps it human."""
    rows = [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "critical", "Production"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "low", "Corporate"],
    ]
    upload_id = _upload(client, content=_csv_bytes(rows))

    def proposal_with(case: str, table: dict) -> dict:
        p = _proposal_dict(name="upload-anchor-case")
        p["asset"]["role"]["mapping"].update(table={"critical": "dc", "low": "workstation"}, case="exact")
        p["finding"]["scanner_severity"]["mapping"].update(table={"critical": "critical", "low": "low"}, case="exact")
        p["asset"]["criticality"] = _mapped(
            {"kind": "vocabulary", "column": "Col", "case": case, "blank": "fatal", "table": table},
            columns_cited=["Col"],
        )
        return p

    for case in ("lower", "exact"):
        job = _propose_edited(client, upload_id, "upload-anchor-case", proposal_with(case, {"critical": 4, "low": 2}))
        assert job["result"]["contract_written"] is False, case
        assert [f["kind"] for f in job["result"]["grounding"]["failures"]] == ["registry_anchor"], case

    ok = _propose_edited(client, upload_id, "upload-anchor-case", proposal_with("exact", {"critical": 5, "low": 2}))
    assert ok["result"]["grounding"]["failures"] == []


# ---------------- second review round (2026-09-21) ----------------


def test_settle_columns_cover_every_column_a_content_address_mapping_reads(client: TestClient):
    """`_mapping_source_columns` returns [] for the multi-column kinds (it
    answers "which one column can a picker point at"), so settling from it
    left a replaced content_address's columns in neither `mapped` nor
    `unmapped_columns`: the contract was refused and no row was left."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-settle-ca")
    proposal["finding"]["finding_id"] = _mapped(
        {"kind": "content_address", "algorithm": "sha256", "columns": ["Env", "Ghost"], "join": "|",
         "prefix": "t-", "hex_len": 16, "case": "lower", "recipe_version": 1},
        columns_cited=["Env", "Ghost"],
    )
    _propose_edited(client, upload_id, "upload-settle-ca", proposal)

    _, found = _grounding_rows(client, "upload-settle-ca", upload_id)
    row = found["finding.finding_id"]
    assert row["grounding_kinds"] == ["missing_column"]
    assert row["candidate_columns"] == _HEADER  # free text: any real column may replace it
    assert row["settle_columns"] == ["Env"]  # the real column the replaced mapping read; Ghost is not one


def test_settle_columns_cover_a_composed_mapping(client: TestClient):
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-settle-comp")
    # composed is legal only finding-side; on an asset slot it is a grounding failure
    proposal["asset"]["owner"] = _mapped(
        {"kind": "composed", "join": "; ", "max_chars": 4096, "parts": [{"prefix": None, "join_nonblank": ["Col"], "join": " "}]}
    )
    _propose_edited(client, upload_id, "upload-settle-comp", proposal)

    _, found = _grounding_rows(client, "upload-settle-comp", upload_id)
    assert found["asset.owner"]["grounding_kinds"] == ["misplaced_kind"]
    assert found["asset.owner"]["settle_columns"] == ["Col"]


def test_a_free_text_unresolved_slot_with_only_hallucinated_candidates_is_offered_the_real_header(client: TestClient):
    """After hallucinated candidates are filtered nothing is left to choose
    from, and for `hostname` "not collected" is illegal too, so the row was a
    dead end."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-widen-unres")
    proposal["asset"]["hostname"] = _unresolved("the source has no machine name", ["fqdn"])
    _propose_edited(client, upload_id, "upload-widen-unres", proposal)

    body, found = _grounding_rows(client, "upload-widen-unres", upload_id)
    row = {u["slot"]: u for u in body["unresolved"]}["asset.hostname"]
    assert row["candidate_columns"] == _HEADER
    assert row["settle_columns"] == []  # nothing real was ever read
    assert row["column_profiles"] == {}
    assert row["fatal_legal"] is True
    assert "asset.hostname" not in found  # merged, not a second row


def test_a_free_text_illegal_slot_with_a_missing_column_is_offered_the_real_header(client: TestClient):
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-widen-illegal")
    # blank='gap' is illegal for product (absent_fact/fatal only) AND the column is not there
    proposal["finding"]["product"] = _mapped(
        {"kind": "column", "column": "Ghost", "case": "exact", "blank": "gap"}, columns_cited=["Ghost"]
    )
    _propose_edited(client, upload_id, "upload-widen-illegal", proposal)

    body, found = _grounding_rows(client, "upload-widen-illegal", upload_id)
    row = {e["slot"]: e for e in body["illegal"]}["finding.product"]
    assert row["candidate_columns"] == _HEADER
    assert "finding.product" not in found


def test_a_real_candidate_the_model_named_stays_the_suggestion(client: TestClient):
    """Only widen when NOTHING real is left."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-widen-keep")
    proposal["finding"]["product"] = _unresolved("no product column", ["Ghost", "Col"])
    _propose_edited(client, upload_id, "upload-widen-keep", proposal)

    body, _ = _grounding_rows(client, "upload-widen-keep", upload_id)
    assert {u["slot"]: u for u in body["unresolved"]}["finding.product"]["candidate_columns"] == ["Col"]


def test_a_closed_vocabulary_slot_with_only_hallucinated_candidates_stays_uncorrectable(client: TestClient):
    """The per-value picker needs ONE column and that column's profile, which
    the whole header cannot supply."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-widen-vocab", environment_status="unresolved")
    proposal["asset"]["environment"]["candidate_columns"] = ["Ghost"]
    _propose_edited(client, upload_id, "upload-widen-vocab", proposal)

    body, _ = _grounding_rows(client, "upload-widen-vocab", upload_id)
    row = {u["slot"]: u for u in body["unresolved"]}["asset.environment"]
    assert row["candidate_columns"] == []
    assert row["target_vocabulary"]["kind"] == "enum"


# ---------------- the zero-row panel: incomplete_reason ----------------


def _orphaned_column_proposal(name: str) -> dict:
    """Fully mapped, every slot individually legal, every citation real -- and
    yet the ASSEMBLED contract is refused: `Env` is read by nothing and is not
    declared in unmapped_columns."""
    proposal = _proposal_dict(name=name)
    proposal["asset"]["environment"] = _mapped({"kind": "not_collected"})
    return proposal


def test_a_whole_contract_refusal_with_no_row_is_reported_on_the_endpoint(client: TestClient):
    """The zero-row panel (CLAUDE.md "Still open" (2)): nothing is unresolved,
    illegal, ungrounded or low-confidence, so the panel had no row and a
    Resubmit that reproduced the identical refusal. The reason lived only in
    the job result."""
    upload_id = _upload(client)
    job = _propose_edited(client, upload_id, "upload-zero-row", _orphaned_column_proposal("upload-zero-row"))
    assert job["result"]["contract_written"] is False

    resp = client.get("/api/adapters/upload-zero-row/proposal", params={"upload_id": upload_id})
    body = resp.json()
    assert body["unresolved"] == [] and body["illegal"] == []
    assert body["grounding_failed"] == [] and body["low_confidence"] == []  # really the zero-row shape
    assert "neither mapped nor in unmapped_columns" in body["incomplete_reason"]
    # It is what a resubmit reports, not a paraphrase of it.
    assert body["incomplete_reason"] == job["result"]["incomplete_reason"]


def test_incomplete_reason_is_none_when_a_contract_would_be_written(client: TestClient):
    """A reason with nothing blocking would be a false alarm, and the panel
    hides its Resubmit only when a reason is present."""
    upload_id = _upload(client)
    _propose(client, upload_id, "upload-reason-clean", _proposal_dict(name="upload-reason-clean"))
    clean = client.get("/api/adapters/upload-reason-clean/proposal", params={"upload_id": upload_id}).json()
    assert clean["incomplete_reason"] is None

    # A slot the provisional path degrades and writes: also not blocked.
    job = _propose(
        client, upload_id, "upload-reason-prov", _proposal_dict(name="upload-reason-prov", environment_status="unresolved")
    )
    assert job["result"]["contract_written"] is True and job["result"]["provisional"] is True
    prov = client.get("/api/adapters/upload-reason-prov/proposal", params={"upload_id": upload_id}).json()
    assert prov["incomplete_reason"] is None


def test_working_out_the_reason_does_not_change_the_proposal_the_panel_edits(client: TestClient, tmp_path: Path):
    """`assemble_provisional_contract` DEGRADES unresolved slots into
    placeholders. The panel edits and resubmits `saved_proposal` from this same
    response, so a reason computed by mutating the proposal in place would
    quietly turn every unresolved slot into a model-authored placeholder."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-reason-pure", environment_status="unresolved")
    proposal["asset"]["environment"]["candidate_columns"] = ["Env"]
    _propose(client, upload_id, "upload-reason-pure", proposal)  # provisional: environment degraded in the CONTRACT
    on_disk = json.loads((tmp_path / "out" / "propose_upload-reason-pure.json").read_text(encoding="utf-8"))

    body = client.get("/api/adapters/upload-reason-pure/proposal", params={"upload_id": upload_id}).json()
    assert body["saved_proposal"]["proposal"] == on_disk["proposal"]
    assert body["saved_proposal"]["proposal"]["asset"]["environment"]["status"] == "unresolved"  # still unresolved
    assert body["incomplete_reason"] is None  # a provisional write would succeed


def test_incomplete_reason_never_takes_the_panel_down(client: TestClient, monkeypatch):
    """Display-only: an unexpected failure while working out the reason is
    shown AS the reason, not a 500 out of the endpoint the panel needs."""
    import rhinosecure.web.adapters as adapters_module

    upload_id = _upload(client)
    _propose(client, upload_id, "upload-reason-boom", _proposal_dict(name="upload-reason-boom"))

    def boom(*args, **kwargs):
        raise RuntimeError("assembly exploded")

    monkeypatch.setattr(adapters_module, "assemble_contract", boom)
    resp = client.get("/api/adapters/upload-reason-boom/proposal", params={"upload_id": upload_id})
    assert resp.status_code == 200
    assert "could not be determined" in resp.json()["incomplete_reason"]
    assert "assembly exploded" in resp.json()["incomplete_reason"]


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


def test_get_proposal_low_confidence_surfaces_affected_row_counts(client: TestClient):
    """`ColumnProfile.distinct_values` is `value -> occurrence count`
    (probe.py) -- the confirm form's per-mapping correction UI needs the
    count, not just the value, to show "affected row count"."""
    rows = [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "srv", "Production"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "wks", "Corporate"],
        ["A03", "HOST03", "F03", "CVE-2021-0003", "srv", "Production"],
    ]
    upload_id = _upload(client, content=_csv_bytes(rows))
    job = _propose(client, upload_id, "upload-row-counts", _proposal_dict(name="upload-row-counts", role_confidence=0.5))
    assert job["result"]["contract_written"] is True

    resp = client.get("/api/adapters/upload-row-counts/proposal", params={"upload_id": upload_id})
    body = resp.json()
    low_conf = {entry["slot"]: entry for entry in body["low_confidence"]}
    assert low_conf["asset.role"]["column_profiles"]["Col"]["distinct_values"] == {"srv": 2, "wks": 1}


def test_get_proposal_low_confidence_predicts_values_for_a_mixed_case_vocabulary(client: TestClient):
    """The engine applies a `vocabulary` mapping's declared `case`
    transform BEFORE the table lookup (`configured._apply_case`,
    `_resolve_target`) -- the corrector's "proposed:" hint must use the
    identical transform, not compare the table's (already-lowercase) keys
    against the raw, un-cased observed value."""
    rows = [
        ["A01", "HOST01", "F01", "CVE-2021-0001", "SRV", "Production"],
        ["A02", "HOST02", "F02", "CVE-2021-0002", "WKS", "Corporate"],
    ]
    upload_id = _upload(client, content=_csv_bytes(rows))
    job = _propose(client, upload_id, "upload-mixed-case", _proposal_dict(name="upload-mixed-case", role_confidence=0.5))
    assert job["result"]["contract_written"] is True

    resp = client.get("/api/adapters/upload-mixed-case/proposal", params={"upload_id": upload_id})
    low_conf = {entry["slot"]: entry for entry in resp.json()["low_confidence"]}
    # role's mapping is `case: "lower"`, table keys "srv"/"wks" -- the raw
    # observed values are upper-case, so a naive uncased lookup would find
    # nothing at all.
    assert low_conf["asset.role"]["current_values"] == {"SRV": "dc", "WKS": "workstation"}


def test_get_proposal_low_confidence_predicts_values_for_a_default_by_mapping(client: TestClient):
    """The flagship real-world case (data/adapters/defender-propose-check
    .json's own `asset.role`): a `default_by` mapping has no per-value
    `table` of its own at all -- its "proposed" value for an observed raw
    value comes from resolving a `derived` block first, then looking that
    key up in the named `REGISTERED_DEFAULT_TABLES` entry. Not a
    `vocabulary` mapping, so the corrector must not fall back to showing
    nothing just because `current_mapping.kind != "vocabulary"`."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-default-by", role_confidence=0.5)
    proposal["asset"]["role"] = _mapped(
        {
            "kind": "default_by",
            "table": "ROLE_DEFAULT_BY_OS_CLASS",
            "keyed_by": {"from": "os_class_from_env", "output": "os_class"},
        },
        confidence=0.5,
        columns_cited=["Env"],
    )
    proposal["derived"] = {
        "os_class_from_env": {
            "column": "Env",
            "case": "exact",
            "blank": "fatal",
            "outputs": ["os_class"],
            "table": {"Production": ["server"], "Corporate": ["client"]},
        }
    }
    job = _propose(client, upload_id, "upload-default-by", proposal)
    assert job["result"]["contract_written"] is True

    resp = client.get("/api/adapters/upload-default-by/proposal", params={"upload_id": upload_id})
    low_conf = {entry["slot"]: entry for entry in resp.json()["low_confidence"]}
    assert low_conf["asset.role"]["candidate_columns"] == ["Env"]
    # Production -> derived os_class "server" -> ROLE_DEFAULT_BY_OS_CLASS["server"] == "file"
    # Corporate  -> derived os_class "client" -> ROLE_DEFAULT_BY_OS_CLASS["client"] == "workstation"
    assert low_conf["asset.role"]["current_values"] == {"Production": "file", "Corporate": "workstation"}


def test_get_proposal_low_confidence_predicts_values_for_a_parsed_bool_mapping(client: TestClient):
    """`internet_exposed` (a `SCORING_ENUM_TARGETS` member) is legally
    mapped via `parsed`/`parser="bool"`, never `vocabulary` -- the
    corrector must predict per-value using the SAME parser the engine
    calls (`configured._parse_scalar`), not only understand a raw
    dict-lookup table."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-parsed-bool", role_confidence=0.5)
    proposal["asset"]["internet_exposed"] = _mapped(
        {
            "kind": "parsed",
            "column": "Col",
            "case": "lower",
            "blank": "fatal",
            "parser": "bool",
            "params": {"true": ["srv"], "false": ["wks"]},
        },
        confidence=0.4,
        columns_cited=["Col"],
    )
    job = _propose(client, upload_id, "upload-parsed-bool", proposal)
    assert job["result"]["contract_written"] is True

    resp = client.get("/api/adapters/upload-parsed-bool/proposal", params={"upload_id": upload_id})
    low_conf = {entry["slot"]: entry for entry in resp.json()["low_confidence"]}
    assert low_conf["asset.internet_exposed"]["current_values"] == {"srv": True, "wks": False}


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


def test_get_review_reports_the_measured_dialect(client: TestClient):
    """The confirm form's own surface (app.js's renderConfirmPanel reads
    this) -- encoding/delimiter are measured, not asserted, and a signer
    must see them before signing, the same reason cli.py's `_print_review_
    header` shows a `dialect:` line first."""
    upload_id = _upload(client)
    _propose(client, upload_id, "upload-dialect", _proposal_dict(name="upload-dialect"))
    resp = client.get("/api/adapters/upload-dialect/review", params={"upload_id": upload_id})
    assert resp.json()["source"] == {"encoding": "utf-8", "delimiter": ","}


def test_get_review_reports_a_detected_non_comma_delimiter(client: TestClient):
    semicolon_csv = (
        "Asset_ID;Hostname;Finding_ID;Cve;Col;Env\n"
        "A01;HOST01;F01;CVE-2021-0001;srv;Production\n"
        "A02;HOST02;F02;CVE-2021-0002;wks;Corporate\n"
    ).encode("utf-8")
    upload_id = _upload(client, content=semicolon_csv)
    job = _propose(client, upload_id, "upload-semicolon", _proposal_dict(name="upload-semicolon"))
    assert job["result"]["contract_written"] is True

    resp = client.get("/api/adapters/upload-semicolon/review", params={"upload_id": upload_id})
    assert resp.json()["source"] == {"encoding": "utf-8", "delimiter": ";"}


def test_get_review_reports_the_dialect_even_before_attestations_are_supplied(client: TestClient):
    """The early-return path (still_missing non-empty, no real measurement
    run yet) must carry `source` too -- a signer filling in attestation
    text shouldn't have to submit first just to see what dialect they're
    about to sign off on."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-dialect-pre-attest", content_address_finding_id=True)
    _propose(client, upload_id, "upload-dialect-pre-attest", proposal)
    resp = client.get("/api/adapters/upload-dialect-pre-attest/review", params={"upload_id": upload_id})
    body = resp.json()
    assert body["still_missing"] == ["finding_id.synthesized"]
    assert body["source"] == {"encoding": "utf-8", "delimiter": ","}


def test_get_review_names_a_required_attestation(client: TestClient):
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-needs-attest", content_address_finding_id=True)
    job = _propose(client, upload_id, "upload-needs-attest", proposal)
    assert job["result"]["contract_written"] is True

    resp = client.get("/api/adapters/upload-needs-attest/review", params={"upload_id": upload_id})
    body = resp.json()
    assert "finding_id.synthesized" in body["required_attestations"]
    assert body["still_missing"] == ["finding_id.synthesized"]


# ---------------- open_questions: what the model asked and nothing answered ----------------

_QUESTIONS = [
    "How many total tiers does the source's own scale have? Needed to place 'Low'.",
    "Is <b>Corporate</b> prod, or a distinct tier?",  # markup must survive the server untouched; the browser escapes
]


def test_get_proposal_carries_the_models_open_questions(client: TestClient):
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-oq-prop")
    proposal["open_questions"] = list(_QUESTIONS)
    _propose(client, upload_id, "upload-oq-prop", proposal)

    resp = client.get("/api/adapters/upload-oq-prop/proposal", params={"upload_id": upload_id})
    assert resp.json()["open_questions"] == _QUESTIONS


def test_get_proposal_open_questions_is_empty_when_the_model_asked_nothing(client: TestClient):
    upload_id = _upload(client)
    _propose(client, upload_id, "upload-oq-none", _proposal_dict(name="upload-oq-none"))
    resp = client.get("/api/adapters/upload-oq-none/proposal", params={"upload_id": upload_id})
    assert resp.json()["open_questions"] == []


def test_get_review_carries_open_questions_on_the_measured_path(client: TestClient):
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-oq-clean")
    proposal["open_questions"] = list(_QUESTIONS)
    job = _propose(client, upload_id, "upload-oq-clean", proposal)
    assert job["result"]["contract_written"] is True

    body = client.get("/api/adapters/upload-oq-clean/review", params={"upload_id": upload_id}).json()
    assert body["measurement"] is not None  # really the measured branch
    assert body["open_questions"] == _QUESTIONS


def test_get_review_carries_open_questions_on_the_attestation_needed_path(client: TestClient):
    """The other return path: a contract that still needs an attestation
    returns before any measurement. The signer needs the questions most
    here, so it must not be the branch that forgets them."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-oq-attest", content_address_finding_id=True)
    proposal["open_questions"] = list(_QUESTIONS)
    _propose(client, upload_id, "upload-oq-attest", proposal)

    body = client.get("/api/adapters/upload-oq-attest/review", params={"upload_id": upload_id}).json()
    assert body["measurement"] is None and body["still_missing"]  # really the early-return branch
    assert body["open_questions"] == _QUESTIONS


def test_get_review_keeps_open_questions_after_a_human_edit(client: TestClient):
    """A resubmit through the form carries the saved proposal's generator
    along unchanged, so contract and proposal still pair up."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-oq-edited")
    proposal["open_questions"] = list(_QUESTIONS)
    job = _propose_edited(client, upload_id, "upload-oq-edited", proposal)
    assert job["result"]["contract_written"] is True

    body = client.get("/api/adapters/upload-oq-edited/review", params={"upload_id": upload_id}).json()
    assert body["open_questions"] == _QUESTIONS


def test_get_review_omits_open_questions_when_the_proposal_did_not_produce_the_contract(
    client: TestClient, tmp_path: Path
):
    """`rhino adapt propose` under an existing name writes its new proposal
    even when assembly is refused, so an old contract can sit beside a newer
    proposal. The signer must not read questions about a mapping they are not
    signing -- but the proposal endpoint, which is about the proposal, still
    shows them."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-oq-stale")
    proposal["open_questions"] = list(_QUESTIONS)
    _propose(client, upload_id, "upload-oq-stale", proposal)

    saved_path = tmp_path / "out" / "propose_upload-oq-stale.json"
    saved = json.loads(saved_path.read_text(encoding="utf-8"))
    saved["generator"]["call_log_digest"] = "sha256:" + "f" * 64  # a different LLM call
    saved_path.write_text(json.dumps(saved), encoding="utf-8")

    review = client.get("/api/adapters/upload-oq-stale/review", params={"upload_id": upload_id}).json()
    assert review["open_questions"] == []
    proposal_body = client.get("/api/adapters/upload-oq-stale/proposal", params={"upload_id": upload_id}).json()
    assert proposal_body["open_questions"] == _QUESTIONS


def test_get_review_omits_open_questions_when_there_is_no_saved_proposal(client: TestClient, tmp_path: Path):
    """A hand-authored contract never went through propose."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-oq-nosaved")
    proposal["open_questions"] = list(_QUESTIONS)
    _propose(client, upload_id, "upload-oq-nosaved", proposal)
    (tmp_path / "out" / "propose_upload-oq-nosaved.json").unlink()

    resp = client.get("/api/adapters/upload-oq-nosaved/review", params={"upload_id": upload_id})
    assert resp.status_code == 200
    assert resp.json()["open_questions"] == []


def test_get_review_survives_a_saved_proposal_that_is_not_utf8(client: TestClient, tmp_path: Path):
    """The signing form must not depend on a display-only lookup: a saved
    proposal that cannot be decoded shows no questions instead of a 500."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-badenc-review")
    proposal["open_questions"] = list(_QUESTIONS)
    _propose(client, upload_id, "upload-badenc-review", proposal)
    saved_path = tmp_path / "out" / "propose_upload-badenc-review.json"
    saved_path.write_bytes(saved_path.read_text(encoding="utf-8").encode("utf-16"))

    review = client.get("/api/adapters/upload-badenc-review/review", params={"upload_id": upload_id})
    assert review.status_code == 200
    assert review.json()["open_questions"] == []


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


def test_confirm_against_a_source_that_became_undecodable_since_propose_does_not_500(
    client: TestClient, isolated_dirs: Path
):
    """`_unmapped_profiles`' own crash bug, reproduced through the web
    endpoint: `content_address_finding_id=True`'s proposal (reused as-is,
    unmodified) declares `unmapped_columns` for its own source file
    (`get_proposal`'s own code comment already names this exact scenario --
    "a source that changed shape since it was proposed" -- as recognized,
    not hypothetical). Overwriting the uploaded file with real `.xlsx`
    bytes after propose reproduces it directly: `measure()`'s `load_batch`
    call hits the decode failure and records it in `halted_by`; before this
    fix, `_unmapped_profiles`' own separate, unguarded `profile_csv` call
    hit the SAME failure a moment later and raised `ProbeError` uncaught --
    not a `ReviewError`, so `post_confirm`'s own `except ReviewError` never
    caught it, and the request failed as an unhandled 500 rather than the
    normal "refused, here is why" JSON response every other refusal in this
    file gets."""
    upload_id = _upload(client)
    proposal = _proposal_dict(name="upload-goes-undecodable", content_address_finding_id=True)
    job = _propose(client, upload_id, "upload-goes-undecodable", proposal)
    assert job["result"]["contract_written"] is True

    upload_dir = client.app.state.upload_registry.get(upload_id).dir_path
    wb = openpyxl.Workbook()
    wb.active.append(["Record_ID"])
    wb.save(upload_dir / "inventory.csv")

    resp = client.post(
        "/api/adapters/upload-goes-undecodable/confirm", json={"upload_id": upload_id, "by": "andrew"}
    )
    assert resp.status_code == 200  # not an unhandled 500
    body = resp.json()
    assert body["written"] is False
    assert body["measurement"]["halted_by"] is not None
    assert "is not a text file" in body["measurement"]["halted_by"]
    assert "ZIP archive" in body["measurement"]["halted_by"]


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
