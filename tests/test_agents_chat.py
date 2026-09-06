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
from rhinosecure.agents.chat import (
    COMPACT_FINDING_FIELDS,
    ChatAnswerError,
    answer_question,
    build_scoped_export,
    is_plan_unrelated,
)
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

# A second fixture for the pre-filter tests: F07/F14 share a hostname
# (WKS-FIN12), mirroring the real demo fixture's own F07/F14 shape, and
# F14 is contested with a full ToT branch -- exercises both the
# multiple-findings-per-hostname match and contested-entry compaction.
SCOPING_EXPORT_DATA = {
    "export_schema_version": "1.0.0",
    "findings": [
        {
            "finding_id": "F07",
            "cve_id": "CVE-2022-30190",
            "asset_id": "A09",
            "hostname": "WKS-FIN12",
            "bucket": "contested",
            "risk_score": 18.7,
            "has_tot": False,
            "rationale": ["F07's own real rationale text -- contested, KEV, no control, no window"],
        },
        {
            "finding_id": "F14",
            "cve_id": "CVE-2023-23397",
            "asset_id": "A09",
            "hostname": "WKS-FIN12",
            "bucket": "contested",
            "risk_score": 25.5,
            "has_tot": False,
            "rationale": ["F14's own real rationale text -- contested, KEV, no control, no window"],
        },
        {
            "finding_id": "F01",
            "cve_id": "CVE-2021-26855",
            "asset_id": "A01",
            "hostname": "EXCH01",
            "bucket": "patch_now",
            "risk_score": 88.5,
            "has_tot": False,
            "rationale": ["F01's own real rationale text -- unrelated to F07/F14"],
        },
    ],
    "contested": [
        {
            "finding_id": "F14",
            "cve_id": "CVE-2023-23397",
            "hostname": "WKS-FIN12",
            "status": "resolved",
            "termination_reason": "clear_winner",
            "near_tie": False,
            "winner_strategy": "emergency_change",
            "failure_reason": None,
            "branches": [{"strategy": "emergency_change", "proposal": "F14's full ToT proposal text"}],
        }
    ],
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


def test_build_chat_agent_has_a_max_execution_time():
    from rhinosecure.agents.chat import build_chat_agent
    from rhinosecure.agents.limits import MAX_AGENT_EXECUTION_SECONDS

    agent = build_chat_agent()
    assert agent.max_execution_time == MAX_AGENT_EXECUTION_SECONDS


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


# ---------------- build_scoped_export (the deterministic pre-filter) ----------------


def test_build_scoped_export_returns_the_same_object_when_nothing_named():
    scoped_data, was_scoped = build_scoped_export(SCOPING_EXPORT_DATA, "what's the overall bucket distribution?")
    assert was_scoped is False
    assert scoped_data is SCOPING_EXPORT_DATA  # identity, not just equality -- no copy made


def test_build_scoped_export_narrows_to_a_named_finding_id():
    scoped_data, was_scoped = build_scoped_export(SCOPING_EXPORT_DATA, "why is F14 contested?")
    assert was_scoped is True

    by_id = {f["finding_id"]: f for f in scoped_data["findings"]}
    assert "rationale" in by_id["F14"]  # matched -- kept full
    assert "rationale" not in by_id["F01"]  # not matched -- compacted
    assert "rationale" not in by_id["F07"]  # shares nothing with the question -- compacted
    assert set(by_id["F01"].keys()) == set(COMPACT_FINDING_FIELDS)


def test_build_scoped_export_narrows_to_a_named_cve_case_insensitively():
    scoped_data, was_scoped = build_scoped_export(SCOPING_EXPORT_DATA, "tell me about cve-2023-23397")
    assert was_scoped is True
    by_id = {f["finding_id"]: f for f in scoped_data["findings"]}
    assert "rationale" in by_id["F14"]
    assert "rationale" not in by_id["F01"]


def test_build_scoped_export_narrows_to_a_named_hostname_matches_every_finding_on_it():
    """WKS-FIN12 hosts both F07 and F14 -- naming the host should keep
    BOTH full, not just one, matching the literal instruction to narrow
    to everything the question named."""
    scoped_data, was_scoped = build_scoped_export(SCOPING_EXPORT_DATA, "what's going on with WKS-FIN12?")
    assert was_scoped is True
    by_id = {f["finding_id"]: f for f in scoped_data["findings"]}
    assert "rationale" in by_id["F07"]
    assert "rationale" in by_id["F14"]
    assert "rationale" not in by_id["F01"]


def test_build_scoped_export_compacts_non_matching_contested_entries():
    scoped_data, was_scoped = build_scoped_export(SCOPING_EXPORT_DATA, "what about F01?")
    assert was_scoped is True
    # F01 isn't contested, so the one contested entry (F14) isn't named --
    # it should be compacted, dropping its full ToT branch detail.
    assert scoped_data["contested"][0]["finding_id"] == "F14"
    assert "branches" not in scoped_data["contested"][0]
    assert scoped_data["contested"][0]["winner_strategy"] == "emergency_change"


def test_build_scoped_export_keeps_contested_full_when_its_own_finding_is_named():
    scoped_data, was_scoped = build_scoped_export(SCOPING_EXPORT_DATA, "why is F14 contested?")
    assert was_scoped is True
    assert "branches" in scoped_data["contested"][0]


def test_build_scoped_export_named_cve_not_in_export_still_scopes_to_all_compact():
    """A CVE mentioned in the question that this export doesn't contain is
    still 'named' -- scoping to zero full findings plus the compact
    summary is the honest minimum context for a question about something
    this plan doesn't have, not a reason to fall back to full context."""
    scoped_data, was_scoped = build_scoped_export(SCOPING_EXPORT_DATA, "what about CVE-9999-00000?")
    assert was_scoped is True
    assert all("rationale" not in f for f in scoped_data["findings"])


def test_answer_question_prompt_reflects_scoping_and_hides_unrelated_rationale():
    """End-to-end wiring check: a question naming F14 builds a task whose
    prompt contains F14's real rationale text but not F01's, and states
    the scoping note -- not just that build_scoped_export works in
    isolation."""
    _FakeCrew.queue = [
        json.dumps(
            {
                "answer": "F14 is contested because it's KEV-listed with no control and no window.",
                "citations": [{"finding_id": "F14", "fields_used": ["rationale"]}],
                "insufficient_data": False,
                "insufficient_reason": None,
            }
        )
    ]

    result = answer_question(SCOPING_EXPORT_DATA, "why is F14 contested?")

    assert result["citations"][0]["finding_id"] == "F14"
    assert result["citations"][0]["risk_score"] == 25.5  # still enriched correctly


def test_answer_question_citation_to_a_compacted_finding_still_enriches_correctly():
    """A citation naming F01 -- compacted because the question was about
    F14 -- must still enrich with F01's real score/bucket. known is built
    from the ORIGINAL export_data, precisely so this can't regress."""
    _FakeCrew.queue = [
        json.dumps(
            {
                "answer": "By contrast, F01 (unrelated) is patch_now.",
                "citations": [{"finding_id": "F01", "fields_used": ["bucket"]}],
                "insufficient_data": False,
                "insufficient_reason": None,
            }
        )
    ]

    result = answer_question(SCOPING_EXPORT_DATA, "why is F14 contested, compared to F01?")

    assert result["citations"] == [
        {
            "finding_id": "F01",
            "fields_used": ["bucket"],
            "risk_score": 88.5,
            "bucket": "patch_now",
            "cve_id": "CVE-2021-26855",
            "hostname": "EXCH01",
        }
    ]


def test_build_chat_task_scoped_prompt_names_compact_vs_full():
    from rhinosecure.agents.chat import build_chat_agent, build_chat_task

    scoped_data, was_scoped = build_scoped_export(SCOPING_EXPORT_DATA, "why is F14 contested?")
    assert was_scoped is True
    agent = build_chat_agent()

    task = build_chat_task(scoped_data, "why is F14 contested?", [], agent, scoped=was_scoped)

    assert "F14's own real rationale text" in task.description
    assert "F01's own real rationale text" not in task.description
    assert "COMPACT form" in task.description


def test_build_chat_task_unscoped_prompt_has_no_scoping_note():
    from rhinosecure.agents.chat import build_chat_agent, build_chat_task

    agent = build_chat_agent()
    task = build_chat_task(SCOPING_EXPORT_DATA, "what's the bucket distribution?", [], agent, scoped=False)

    assert "COMPACT form" not in task.description
    assert "F01's own real rationale text" in task.description  # full context, unscoped


# ---------------- is_plan_unrelated (the export-skip pre-filter) ----------------


@pytest.mark.parametrize(
    "message",
    ["hi", "Hi", "HELLO", "hey", "thanks", "Thank you", "thanks!", "thanks!!", "  bye  ", "Good morning."],
)
def test_is_plan_unrelated_matches_known_greetings_case_and_punctuation_insensitively(message):
    assert is_plan_unrelated(message) is True


@pytest.mark.parametrize(
    "message",
    [
        "why is F14 contested?",
        "hi, why is F14 contested?",  # starts with a greeting but is a real question -- must NOT match
        "yes",
        "no",
        "ok",
        "what's the bucket distribution?",
        "",
        "thanks for nothing, that's not what I asked",
    ],
)
def test_is_plan_unrelated_does_not_match_real_questions_or_bare_acknowledgments(message):
    assert is_plan_unrelated(message) is False


def test_answer_question_dispatches_the_greeting_path_with_no_export_attached():
    _FakeCrew.queue = ["Hi there! Ask me anything about this remediation plan."]

    result = answer_question(EXPORT_DATA, "hello")

    assert result == {
        "answer": "Hi there! Ask me anything about this remediation plan.",
        "citations": [],
        "insufficient_data": False,
        "insufficient_reason": None,
    }
    assert _FakeCrew.instantiations == 1


def test_greeting_path_prompt_carries_no_export_data():
    from rhinosecure.agents.chat import build_chat_agent, build_greeting_task

    agent = build_chat_agent()
    task = build_greeting_task("hi", [], agent)

    assert "F01" not in task.description
    assert "EXPORT JSON" not in task.description


def test_greeting_path_threads_history():
    from rhinosecure.agents.chat import build_chat_agent, build_greeting_task

    agent = build_chat_agent()
    task = build_greeting_task(
        "thanks",
        [{"role": "user", "content": "why did F01 land in patch_now?"}],
        agent,
    )
    assert "why did F01 land in patch_now?" in task.description
