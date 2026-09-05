"""Coverage for agents/chat.py -- the read-only chat layer over one run's
export file. Only the LLM dispatch is faked (the same `_FakeCrew` pattern
test_coordinator.py/test_web_jobs.py use for the same reason): these tests
exercise the real parsing, grounding, retry, and citation-enrichment code,
not a mocked-out approximation of it.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from rhinosecure.agents import chat as chat_module
from rhinosecure.agents.chat import ChatAnswerError, answer_question
from rhinosecure.agents.parsing import AgentOutputParseError

EXPORT_DATA = {
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
        },
        {
            "finding_id": "F02",
            "cve_id": "CVE-2018-8410",
            "asset_id": "A02",
            "hostname": "WKS01",
            "bucket": "accept",
            "risk_score": 9.5,
            "rationale": ["bucket=accept: risk_score=9.5/100 < 18"],
        },
    ],
    "contested": [],
    "constraints": {"asset_scoped": [], "capacity": []},
}


class _FakeCrew:
    queue: list = []
    instantiations = 0

    def __init__(self, agents, tasks, process=None, verbose=False):
        self.tasks = tasks
        _FakeCrew.instantiations += 1

    def kickoff(self):
        for task in self.tasks:
            raw = _FakeCrew.queue.pop(0)
            task.output = SimpleNamespace(raw=raw)
        return None


@pytest.fixture(autouse=True)
def fake_crew(monkeypatch):
    """Only Crew.kickoff is faked -- get_llm() still builds a real
    crewai.LLM from the real .env ANTHROPIC_API_KEY (test_web_jobs.py's
    same convention), since Crew being faked means that object is
    constructed but never actually dispatched against."""
    _FakeCrew.queue = []
    _FakeCrew.instantiations = 0
    monkeypatch.setattr(chat_module, "Crew", _FakeCrew)
    return _FakeCrew


def _answer_json(**overrides) -> str:
    base = {
        "answer": "F01 landed in patch_now because its risk score is 88.5.",
        "citations": [{"finding_id": "F01", "fields_used": ["risk_score", "bucket"]}],
        "insufficient_data": False,
        "insufficient_reason": None,
    }
    base.update(overrides)
    return json.dumps(base)


def test_answer_question_enriches_citation_from_export_not_from_model():
    """The model's own JSON never carries risk_score/bucket for a
    citation -- ChatCitation has no such fields. This confirms the
    returned citation's score/bucket come from the export, matching what
    findings[] actually says for F01."""
    _FakeCrew.queue = [_answer_json()]

    result = answer_question(EXPORT_DATA, "why did F01 land in patch_now?")

    assert result["citations"] == [
        {
            "finding_id": "F01",
            "fields_used": ["risk_score", "bucket"],
            "risk_score": 88.5,
            "bucket": "patch_now",
            "cve_id": "CVE-2021-26855",
            "hostname": "EXCH01",
        }
    ]
    assert result["insufficient_data"] is False
    assert _FakeCrew.instantiations == 1


def test_answer_question_retries_once_on_ungrounded_citation_then_succeeds():
    _FakeCrew.queue = [
        _answer_json(citations=[{"finding_id": "F99-does-not-exist", "fields_used": []}]),
        _answer_json(),
    ]

    result = answer_question(EXPORT_DATA, "why did F01 land in patch_now?")

    assert result["citations"][0]["finding_id"] == "F01"
    assert _FakeCrew.instantiations == 2


def test_answer_question_raises_after_max_attempts_of_ungrounded_citations():
    bad = _answer_json(citations=[{"finding_id": "F99-does-not-exist", "fields_used": []}])
    _FakeCrew.queue = [bad, bad, bad]

    with pytest.raises(ChatAnswerError, match="could not produce a grounded answer"):
        answer_question(EXPORT_DATA, "anything", max_attempts=3)
    assert _FakeCrew.instantiations == 3


def test_answer_question_raises_after_max_attempts_of_unparseable_output():
    unparseable = "not json at all, no matter how many times you ask"
    _FakeCrew.queue = [unparseable, unparseable]

    with pytest.raises(ChatAnswerError) as excinfo:
        answer_question(EXPORT_DATA, "anything", max_attempts=2)
    assert isinstance(excinfo.value.__cause__, AgentOutputParseError)
    assert _FakeCrew.instantiations == 2


def test_insufficient_data_true_requires_a_non_empty_reason():
    """ChatAnswer's own validator rejects insufficient_data=true with no
    reason -- this becomes a parse failure (AgentOutputParseError), which
    retries and eventually raises, same as any other malformed shape."""
    missing_reason = _answer_json(insufficient_data=True, insufficient_reason=None, citations=[])
    valid = _answer_json(
        insufficient_data=True,
        insufficient_reason="No finding in this export concerns CVE-9999-00000.",
        citations=[],
        answer="This plan contains no finding for that CVE.",
    )
    _FakeCrew.queue = [missing_reason, valid]

    result = answer_question(EXPORT_DATA, "what about CVE-9999-00000?")

    assert result["insufficient_data"] is True
    assert result["insufficient_reason"].startswith("No finding")
    assert result["citations"] == []
    assert _FakeCrew.instantiations == 2


def test_insufficient_data_answer_needs_no_citations():
    _FakeCrew.queue = [
        _answer_json(
            insufficient_data=True,
            insufficient_reason="This export has no CVE-9999-00000.",
            citations=[],
            answer="Not in this plan.",
        )
    ]

    result = answer_question(EXPORT_DATA, "what about CVE-9999-00000?")

    assert result["insufficient_data"] is True
    assert result["citations"] == []


def test_history_is_threaded_into_the_prompt():
    """Not a behavioral assertion about the model (there is none here) --
    confirms build_chat_task actually includes prior turns, so a
    regression that silently drops history would be caught."""
    from rhinosecure.agents.chat import build_chat_agent, build_chat_task

    agent = build_chat_agent()
    task = build_chat_task(
        EXPORT_DATA,
        "and the other one?",
        [{"role": "user", "content": "why did F01 land in patch_now?"}, {"role": "assistant", "content": "..."}],
        agent,
    )
    assert "why did F01 land in patch_now?" in task.description
    assert "and the other one?" in task.description
