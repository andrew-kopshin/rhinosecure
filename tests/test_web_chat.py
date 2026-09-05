"""HTTP-level coverage for the chat route (`web/chat.py`), mounted via
`create_app(chat_enabled=True)`. Only the LLM dispatch is faked -- same
`_FakeCrew` pattern as test_agents_chat.py/test_web_jobs.py -- so these
tests exercise the real route, request validation, and
agents.chat.answer_question wiring end to end.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from rhinosecure.agents import chat as chat_module
from rhinosecure.web.server import create_app

EXPORT_PAYLOAD = {
    "export_schema_version": "1.0.0",
    "findings": [
        {
            "finding_id": "F01",
            "cve_id": "CVE-2021-26855",
            "asset_id": "A01",
            "hostname": "EXCH01",
            "bucket": "patch_now",
            "risk_score": 88.5,
            "rationale": ["bucket=patch_now: risk_score=88.5/100 >= 70"],
        }
    ],
    "contested": [],
    "constraints": {"asset_scoped": [], "capacity": []},
}


class _FakeCrew:
    queue: list = []

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.tasks = tasks

    def kickoff(self):
        for task in self.tasks:
            task.output = SimpleNamespace(raw=_FakeCrew.queue.pop(0))
        return None


@pytest.fixture(autouse=True)
def fake_crew(monkeypatch):
    _FakeCrew.queue = []
    monkeypatch.setattr(chat_module, "Crew", _FakeCrew)
    return _FakeCrew


@pytest.fixture
def export_file(tmp_path: Path) -> Path:
    path = tmp_path / "export.json"
    path.write_text(json.dumps(EXPORT_PAYLOAD), encoding="utf-8")
    return path


def _answer_json(**overrides) -> str:
    base = {
        "answer": "F01 landed in patch_now because its risk score is 88.5.",
        "citations": [{"finding_id": "F01", "fields_used": ["risk_score"]}],
        "insufficient_data": False,
        "insufficient_reason": None,
    }
    base.update(overrides)
    return json.dumps(base)


def test_default_app_has_no_chat_route(export_file):
    client = TestClient(create_app(export_file))
    resp = client.post("/api/chat", json={"message": "anything"})
    assert resp.status_code == 404


def test_chat_enabled_false_explicitly_also_has_no_chat_route(export_file):
    client = TestClient(create_app(export_file, chat_enabled=False))
    resp = client.post("/api/chat", json={"message": "anything"})
    assert resp.status_code == 404


def test_health_reports_chat_enabled(export_file):
    client = TestClient(create_app(export_file, chat_enabled=True))
    resp = client.get("/api/health")
    assert resp.json()["chat_enabled"] is True

    client2 = TestClient(create_app(export_file))
    assert client2.get("/api/health").json()["chat_enabled"] is False


def test_post_chat_returns_a_score_and_bucket_enriched_citation(export_file):
    _FakeCrew.queue = [_answer_json()]
    client = TestClient(create_app(export_file, chat_enabled=True))

    resp = client.post("/api/chat", json={"message": "why did F01 land in patch_now?"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["insufficient_data"] is False
    assert body["citations"] == [
        {
            "finding_id": "F01",
            "fields_used": ["risk_score"],
            "risk_score": 88.5,
            "bucket": "patch_now",
            "cve_id": "CVE-2021-26855",
            "hostname": "EXCH01",
        }
    ]


def test_post_chat_reads_the_export_file_currently_on_disk(export_file):
    """Confirms web/chat.py reads through the same load_export() path
    GET /api/export uses -- not a second, independently-loaded copy."""
    _FakeCrew.queue = [_answer_json()]
    client = TestClient(create_app(export_file, chat_enabled=True))

    export_file.write_text(
        json.dumps(
            {
                **EXPORT_PAYLOAD,
                "findings": [{**EXPORT_PAYLOAD["findings"][0], "risk_score": 12.0, "bucket": "accept"}],
            }
        ),
        encoding="utf-8",
    )
    resp = client.post("/api/chat", json={"message": "why did F01 land in patch_now?"})
    assert resp.json()["citations"][0]["risk_score"] == 12.0
    assert resp.json()["citations"][0]["bucket"] == "accept"


def test_post_chat_rejects_empty_message(export_file):
    client = TestClient(create_app(export_file, chat_enabled=True))
    resp = client.post("/api/chat", json={"message": ""})
    assert resp.status_code == 422


def test_post_chat_rejects_overlong_message(export_file):
    client = TestClient(create_app(export_file, chat_enabled=True))
    resp = client.post("/api/chat", json={"message": "x" * 3000})
    assert resp.status_code == 422


def test_post_chat_returns_502_when_no_attempt_grounds(export_file):
    ungrounded = _answer_json(citations=[{"finding_id": "F99-does-not-exist", "fields_used": []}])
    _FakeCrew.queue = [ungrounded, ungrounded, ungrounded]
    client = TestClient(create_app(export_file, chat_enabled=True))

    resp = client.post("/api/chat", json={"message": "anything"})
    assert resp.status_code == 502
