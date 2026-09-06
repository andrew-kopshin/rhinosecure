"""Read-only chat over one run's export file (export.py's
EXPORT_SCHEMA_VERSION contract) -- the implementation of the "chat layer"
design proposed and approved in conversation, not a CLAUDE.md-numbered
slice. Answers a human's question about the CURRENT plan using ONLY the
export JSON already being served; changes nothing, persists nothing, and
is deliberately decoupled from agents/coordinator.py and memory.py -- a
chat answer is a pure function of (export_data, message, history).

**Full-context-stuffing by default, narrowed by a deterministic pre-filter
when the question names something specific.** The whole export still goes
into the prompt every turn -- no vector search, no embeddings, no
tool-calling that would let the model retrieve on its own (that would be
exactly the escape hatch grounding is supposed to close, see "No tools"
below). What changed: `build_scoped_export` checks the question's own text
-- deterministically, with substring/regex matching, never a model call --
for a real finding_id, cve_id, or hostname already present in this export.
When it finds one, every OTHER finding is projected down to
`COMPACT_FINDING_FIELDS` (id/cve/asset/host/bucket/risk_score/has_tot,
identical field names to the full entry -- nothing is dropped from the
`findings[]` array, only detail past those fields), while every finding
that matched keeps its full rationale/sources/etc. When nothing is named,
`build_scoped_export` returns `export_data` completely unchanged -- full
context stays the default, not a fallback.

**Why this exists: a real, reproduced failure mode, not the token-budget
concern the previous version of this docstring anticipated.** A
`qwen2.5:14b` local-model test asked about `F14` returned a schema-valid,
citation-grounded answer whose PROSE was fabricated (see PROGRESS.md
2026-09-05). A follow-up test with a larger 32B local model was worse in a
specific way: it invented a CVE ID, asset ID, and hostname for `F14` and
then claimed `F14`'s real rationale -- present verbatim in
the very JSON blob it was given -- wasn't in the export at all. That
reads as a long-context retrieval failure (losing track of one record
inside a large single JSON blob), not a capability ceiling -- a bigger
model failing a way a smaller one didn't is the signature of "lost in the
middle," not "too dumb." Narrowing the context so a named finding is one
of very few full-detail entries, surrounded only by compact rows with
nothing to confuse it with, is a direct, deterministic countermeasure for
exactly that failure shape. It does not, and cannot, fix the *other*
failure mode PROGRESS.md 2026-09-05 recorded (fabricated prose anchored to
a real, correctly-cited finding) -- that one is a truthfulness problem
`_validate_citations` was never built to catch (see "What this checks, and
what it can't" below); this pre-filter is a countermeasure for a different
problem that happens to have shown up in the same round of local-model
testing.

This also, incidentally, is the CLAUDE.md Section 1 "nothing may assume
the dataset is small enough to fetch in one pass" concern's actual fix,
should a real fleet's export ever grow past a single context window --
the same mechanism, triggered by the same condition, addresses both.

**No tools.** Every other agent in this codebase (research.py,
environment.py, risk.py, constraint_intake.py) gets tools because its job
is to gather or act on evidence beyond what one prompt can hold. This
agent gets none -- deliberately. The whole point of "no enrichment
lookups, no answering from model knowledge" is that the export is the
model's entire universe of facts; a tool that could fetch anything else
(even something else already in this codebase, like lookup_nvd) would be
exactly the escape hatch grounding is supposed to close.

**Citations are code-verified, never model-trusted.** `ChatCitation`
carries only `finding_id`/`fields_used` -- the model is never asked for,
and never supplies, a cited finding's risk_score or bucket.
`enrich_citations` looks those up from the export itself, after
`_validate_citations` confirms the finding_id is real, and attaches them
server-side. This is the same "the model never computes the number"
discipline `scoring.risk_score` and `tot.CriticScores.aggregate` already
enforce elsewhere in this codebase, applied here so a UI citation chip
can show a score/bucket the model was never in a position to misreport.

**What this checks, and what it can't.** `_validate_citations` is a real,
mechanical check -- same shape as `agents/risk.py`'s
`verify_scoring_matches_tool` and `agents/schema_inference.py`'s
`check_grounding`: it fails a response if any cited finding_id doesn't
exist in the export. It does NOT verify that every sentence of prose is
true -- there is no ground-truth log to check free text against, unlike
`score_finding`'s tool-call log. This is the same limitation CLAUDE.md's
Safety and guardrails section names as an open, unbuilt general mechanism
("Grounding validation") -- chat inherits it, doesn't solve it.

**Prompt-injection surface, named rather than ignored.** The export's
`rationale`/`narrative`/evidence-derived text ultimately traces back to
scanner output and asset inventory fields -- untrusted free text, per
CLAUDE.md Safety and guardrails' open item on prompt-injection resistance
(NOT NVD descriptions -- `enrich/nvd.py` never fetches that field; see
`agents/prompt_safety.py`'s module docstring for what's actually live).
Chat was the first place that text reached an LLM prompt a human is
actively reading answers from, and is still the one place a human directly
converses with a model over this text. The task prompt uses
`agents/prompt_safety.py`'s shared fence/notice convention -- the same one
now applied at research.py/environment.py/risk.py/constraint_intake.py,
where the text actually first enters a prompt -- rather than its own
inline copy of the same idea. A mitigation, not a solved problem, at every
one of those sites.

All LLM calls route through `rhinosecure.llm.get_llm`, the trust-boundary
seam. `build_chat_task` does not set `output_pydantic`, for the same
reason every other agent in this codebase doesn't (`agents/parsing.py`'s
module docstring) -- the raw final-answer text is parsed by
`parse_structured_output`, bounded-retried on either a parse failure or a
grounding failure, then raises `ChatAnswerError` rather than ever
returning an ungrounded answer to a caller.

**`is_plan_unrelated`: a message that isn't a plan question at all skips
attaching the export entirely, not just narrowing it.** The conversational
front end design (CLAUDE.md, "Future direction: a conversational front
end") named this as a gap worth closing on its own, ahead of everything
else that design describes: `build_scoped_export` only narrows the export
down to compact rows when the message names something specific, and
returns the WHOLE export unchanged otherwise -- so a bare "hi" or "thanks"
paid the same full-export prompt cost as a real fleet-wide question, for
zero benefit. Checked BEFORE `build_scoped_export` is ever called, via a
small, closed, exact-match list of greetings/courtesies (case-folded,
trailing punctuation stripped) -- deliberately not a substring or
keyword-vs-plan-vocabulary classifier, and deliberately not a model call
either (asking a model "should I even see the export" is circular). A
false negative (an unrecognized greeting falls through to the normal
path) costs nothing beyond today's existing behavior; a false positive
would silently withhold context from a real question, which the
exact-match rule exists to prevent. Bare acknowledgments ("yes", "no",
"ok") are deliberately excluded from the list -- those can legitimately
be a contextual reply to a real prior question, where full export access
may still matter.
"""

from __future__ import annotations

import json
import re
import string
from typing import Any

from crewai import Agent, Crew, Process, Task
from crewai.llms.base_llm import BaseLLM
from pydantic import BaseModel, model_validator

from rhinosecure.agents.limits import MAX_AGENT_EXECUTION_SECONDS
from rhinosecure.agents.parsing import AgentOutputParseError, parse_structured_output
from rhinosecure.agents.prompt_safety import UNTRUSTED_TEXT_NOTICE, fence
from rhinosecure.llm import get_llm

ROLE = "Plan Analyst"

DEFAULT_MAX_ATTEMPTS = 3

# Same pattern configured.py's own _CVE_ID_PATTERN checks a CSV cell
# against (a real external identifier format, MITRE's -- not a
# RhinoSecure- or fixture-specific pattern), unanchored here to find a
# mention anywhere inside free-form question text instead of validating
# one whole field.
_CVE_MENTION_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# What a COMPACT (non-matched) finding keeps -- identical field names to a
# full finding entry, so _known_findings()/enrich_citations() need no
# awareness that compaction happened at all: every finding, full or
# compact, still carries these five real facts.
COMPACT_FINDING_FIELDS = ("finding_id", "cve_id", "asset_id", "hostname", "bucket", "risk_score", "has_tot")

COMPACT_CONTESTED_FIELDS = (
    "finding_id",
    "cve_id",
    "hostname",
    "status",
    "termination_reason",
    "near_tie",
    "winner_strategy",
    "failure_reason",
)

# Closed, exact-match set -- see module docstring's is_plan_unrelated entry
# for why this is exact match rather than substring/keyword matching.
# Bare acknowledgments ("yes"/"no"/"ok") are deliberately absent: those can
# legitimately be a contextual reply to a real prior question.
_PLAN_UNRELATED_MESSAGES = frozenset(
    {
        "hi",
        "hello",
        "hey",
        "hiya",
        "yo",
        "howdy",
        "good morning",
        "good afternoon",
        "good evening",
        "thanks",
        "thank you",
        "thanks a lot",
        "thank you very much",
        "much appreciated",
        "appreciate it",
        "bye",
        "goodbye",
        "see you",
        "later",
        "cheers",
    }
)


def is_plan_unrelated(message: str) -> bool:
    """True only for an exact (post-normalization) match against a small,
    closed list of greetings and courtesies -- never a substring match,
    never a keyword classifier. Normalization is deliberately minimal:
    case-fold, strip surrounding whitespace, strip trailing punctuation
    (so "Thanks!!" and "hello." still match) -- nothing fancier, since a
    false negative here is harmless (see module docstring) and a broader
    match would risk a false positive on a real question that merely
    starts with a greeting ("hi, why is F14 contested?" is NOT plan-
    unrelated and must not match)."""
    normalized = message.strip().casefold().rstrip(string.punctuation + " ")
    return normalized in _PLAN_UNRELATED_MESSAGES


class ChatCitation(BaseModel):
    """What the MODEL supplies for one citation -- deliberately just an
    identity and which parts of that finding it used. No score, no
    bucket: see module docstring on why those are injected server-side,
    never taken from the model."""

    finding_id: str
    fields_used: list[str] = []


class ChatAnswer(BaseModel):
    """This agent's raw structured output, before citation enrichment.
    `insufficient_data` and `citations` are independent fields rather than
    a discriminated union (unlike ConstraintInterpretation's constraint_kind)
    -- an insufficient-data answer can still legitimately cite the
    finding(s) that came closest, so the two aren't mutually exclusive the
    way asset-vs-capacity-vs-refusal are."""

    answer: str
    citations: list[ChatCitation] = []
    insufficient_data: bool = False
    insufficient_reason: str | None = None

    @model_validator(mode="after")
    def _reason_required_when_insufficient(self) -> "ChatAnswer":
        if self.insufficient_data and not (self.insufficient_reason or "").strip():
            raise ValueError("insufficient_data is true but insufficient_reason is empty")
        return self


class ChatAnswerError(RuntimeError):
    """Raised when the model's response never parses, or every attempt's
    citations fail grounding, within max_attempts. Mirrors
    ConstraintInterpretationError's role for the Constraint Interpreter --
    a chat turn that can't be grounded has nothing sensible to fall back
    to, so the caller (web/chat.py) turns this into a real HTTP error
    rather than showing an unverified answer."""


def _known_findings(export_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """finding_id -> the real risk_score/bucket/cve_id/hostname this
    export records for it. Built from `findings[]` alone: every
    `contested[]` entry and every constraint delta's finding_id already
    names a finding_id that also appears in `findings[]` (export.py never
    introduces one that doesn't), so this one pass is authoritative for
    "does this citation refer to something real"."""
    return {
        f["finding_id"]: {
            "risk_score": f["risk_score"],
            "bucket": f["bucket"],
            "cve_id": f["cve_id"],
            "hostname": f["hostname"],
        }
        for f in export_data.get("findings", [])
    }


def _mentioned_known_values(message: str, values: set[str]) -> set[str]:
    """Case-insensitive substring match -- the same convention
    `agents/constraint_intake.py`'s own `_matches()` already uses for
    resolving a human's free text against real identifiers. Imprecise for
    a very short id (a two-character finding_id could false-positive
    against unrelated text, and a short id can itself substring-match
    inside a longer one that happens to share a prefix) -- a bounded,
    deterministic decision instead of guessing which mentions are "close
    enough", the same tradeoff `_matches()` already accepts."""
    lowered = message.lower()
    return {v for v in values if v and v.lower() in lowered}


def _matched_finding_ids(message: str, findings: list[dict[str, Any]]) -> tuple[set[str], bool]:
    """Returns (finding_ids whose finding_id/cve_id/hostname was named in
    `message`, whether ANYTHING was named at all). The second value can be
    True with an empty first value -- e.g. a CVE mentioned in the question
    that isn't in this export at all -- and that's still "named": scoping
    to zero full findings plus the compact summary is the honest minimum
    context for a question about something this plan doesn't contain,
    exactly the shape an insufficient_data answer needs."""
    cve_mentions = {m.group(0).upper() for m in _CVE_MENTION_PATTERN.finditer(message)}
    known_hostnames = {f["hostname"] for f in findings if f.get("hostname")}
    known_finding_ids = {f["finding_id"] for f in findings if f.get("finding_id")}
    mentioned_hostnames = _mentioned_known_values(message, known_hostnames)
    mentioned_finding_ids = _mentioned_known_values(message, known_finding_ids)

    named = bool(cve_mentions or mentioned_hostnames or mentioned_finding_ids)
    matched = {
        f["finding_id"]
        for f in findings
        if f.get("finding_id") in mentioned_finding_ids
        or (f.get("cve_id") or "").upper() in cve_mentions
        or f.get("hostname") in mentioned_hostnames
    }
    return matched, named


def _compact(record: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {k: record.get(k) for k in fields}


def build_scoped_export(export_data: dict[str, Any], message: str) -> tuple[dict[str, Any], bool]:
    """The deterministic pre-filter: when `message` names a real
    finding_id, cve_id, or hostname already in this export, every OTHER
    finding (and OTHER contested entry) is projected down to
    COMPACT_FINDING_FIELDS/COMPACT_CONTESTED_FIELDS -- full detail stays
    only for what was actually named. Nothing is removed from `findings`/
    `contested`, so `_known_findings` sees the identical set of
    finding_id/cve_id/hostname/bucket/risk_score whether or not scoping
    happened; every other export section (run/pipeline/summary/
    constraints/usage) is untouched.

    Returns `(export_data, False)` UNCHANGED -- same object, not a copy --
    when nothing was named: full-context-stuffing is the default, not a
    fallback path. See the module docstring for why this exists (a
    reproduced long-context retrieval failure on a 32B local model, not a
    token-budget worry) and what it cannot fix (fabricated prose anchored
    to a correctly-cited finding -- a different, truthfulness problem).
    """
    findings = export_data.get("findings", [])
    matched_ids, named = _matched_finding_ids(message, findings)
    if not named:
        return export_data, False

    scoped_findings = [
        f if f.get("finding_id") in matched_ids else _compact(f, COMPACT_FINDING_FIELDS) for f in findings
    ]
    scoped_contested = [
        c if c.get("finding_id") in matched_ids else _compact(c, COMPACT_CONTESTED_FIELDS)
        for c in export_data.get("contested", [])
    ]
    return {**export_data, "findings": scoped_findings, "contested": scoped_contested}, True


def build_chat_agent(llm: BaseLLM | None = None) -> Agent:
    """`llm` defaults to the trust-boundary seam's `get_llm()` -- pass one
    explicitly (as tests do) to avoid depending on real `.env` state."""
    return Agent(
        role=ROLE,
        goal=(
            "Answer a question about this one remediation plan using ONLY the export JSON "
            "supplied in the task -- never outside knowledge about any CVE, never a live "
            "lookup, never a tool. Say plainly, via insufficient_data, when the export "
            "doesn't contain the answer rather than filling the gap with a guess."
        ),
        backstory=(
            "An analyst who has read this run's export and nothing else -- no memory of "
            "any CVE from training, no access to NVD/KEV/EPSS/ATT&CK, no ability to look "
            "anything up. Every claim traces to a specific finding in the file; a question "
            "the file can't answer gets an honest 'not in this plan', not a best guess."
        ),
        tools=[],
        llm=llm or get_llm(),
        verbose=False,
        max_execution_time=MAX_AGENT_EXECUTION_SECONDS,
    )


def build_chat_task(
    export_data: dict[str, Any],
    message: str,
    history: list[dict[str, str]],
    agent: Agent,
    *,
    scoped: bool = False,
) -> Task:
    """`scoped=True` means `export_data` already went through
    `build_scoped_export` and some finding/contested entries are compact
    projections, not full detail -- the prompt says so explicitly so the
    model is told, not left to infer, which entries it has full evidence
    for. Never pass `scoped=True` for an unscoped `export_data`, or vice
    versa -- `answer_question` is the only caller and always passes the
    real value `build_scoped_export` returned."""
    history_block = (
        "\n".join(f"{h['role']}: {h['content']}" for h in history) if history else "(none)"
    )
    export_json = json.dumps(export_data, separators=(",", ":"))

    scoping_note = (
        "\n\nYour question named a specific finding, CVE, or host, so the export below has "
        "been narrowed: any finding or contested entry that matches what you asked about "
        "keeps its FULL detail (rationale, sources, narrative, ToT branches, everything). "
        "Every OTHER finding/contested entry -- because it wasn't what the question was "
        "about -- is shown only in COMPACT form: finding_id, cve_id, asset_id, hostname, "
        "bucket, risk_score, has_tot, and (for a contested entry) status/near_tie/"
        "winner_strategy/termination_reason. A compact entry has NO rationale, sources, "
        "narrative, or ToT branch detail available to you at all -- if the question needs "
        "that level of detail about a compact entry, set insufficient_data to true and say "
        "so, rather than inventing what a full entry would have said."
        if scoped
        else ""
    )

    return Task(
        description=(
            "You are answering questions about ONE remediation plan, given below as the "
            "export JSON for this run. This is the entire universe of facts you have -- "
            "findings, risk scores, buckets, rationale, cited sources with retrieval "
            "timestamps, Tree-of-Thought branches and critic scores for contested findings, "
            "constraints on file, and data-gap notes. You have no tools and no other source "
            f"of truth.{scoping_note}\n\n"
            "Do NOT use outside knowledge about any CVE, vendor, or vulnerability -- even if "
            "you recognize a CVE ID, answer only from what THIS export says about it, which "
            "may differ from what you recall (a scanner's own severity call, why it landed "
            "in a particular bucket, an asset-specific compensating control). If the export "
            "does not contain enough to answer the question, set insufficient_data to true "
            "and explain what's missing in insufficient_reason -- do not fill the gap with "
            "outside knowledge or a plausible-sounding guess.\n\n"
            f"{UNTRUSTED_TEXT_NOTICE}\n\n"
            f"{fence('EXPORT JSON', export_json)}\n\n"
            f"=== CONVERSATION SO FAR ===\n{history_block}\n=== END CONVERSATION ===\n\n"
            f"The human's new question: {message!r}\n\n"
            "Every factual claim in your answer should be traceable to at least one finding "
            "in the export -- name it in citations. A citation's finding_id MUST be a real "
            "finding_id that appears in the export's findings list (the same id also used in "
            "contested entries and constraint deltas, when relevant). fields_used should name "
            "which parts of that finding you relied on (e.g. \"risk_score\", \"rationale\", "
            "\"sources\", \"contested.branches\", \"asset_not_collected\"). Never invent a "
            "finding_id that isn't in the export."
        ),
        expected_output=(
            "Return ONLY a single JSON object, keys directly at the top level -- not wrapped "
            "in any container key, no markdown code fences or prose before or after it: "
            "answer (string -- your full prose answer, or an explanation of what's missing if "
            "insufficient_data is true), citations (a list of objects, each with finding_id "
            "(string, must be a real finding_id from the export's findings list) and "
            "fields_used (a list of strings)), insufficient_data (boolean -- true if the "
            "export cannot answer the question), insufficient_reason (a non-empty string "
            "explaining what's missing whenever insufficient_data is true, otherwise null)."
        ),
        agent=agent,
    )


def build_greeting_task(message: str, history: list[dict[str, str]], agent: Agent) -> Task:
    """The export-free counterpart to build_chat_task, dispatched only when
    is_plan_unrelated(message) is True. No export JSON, no citation
    schema, no grounding to verify -- there is no plan data in this
    prompt for a reply to misrepresent. Plain text out, not JSON: unlike
    build_chat_task's answer, this text is never parsed, cited, or
    grounding-checked, so asking for structured output here would only
    add a way for this path to fail that carries no benefit."""
    history_block = "\n".join(f"{h['role']}: {h['content']}" for h in history) if history else "(none)"
    return Task(
        description=(
            "The human's message is a greeting or courtesy, not a question about a "
            "remediation plan -- reply naturally and briefly, and invite them to ask a "
            "real question about the plan (findings, risk scores, buckets, rationale, "
            "contested findings, constraints, and so on). You have not been given any "
            "plan data this turn -- do not reference or guess at specific findings, "
            "scores, or CVEs.\n\n"
            f"=== CONVERSATION SO FAR ===\n{history_block}\n=== END CONVERSATION ===\n\n"
            f"The human's message: {message!r}"
        ),
        expected_output="A brief, natural, plain-text reply -- no JSON, no citations.",
        agent=agent,
    )


def _validate_citations(parsed: ChatAnswer, known: dict[str, dict[str, Any]]) -> list[str]:
    """Returns problems found, empty if every citation is grounded. Only
    checks finding_id membership -- see module docstring on what this
    can't check (the truth of the prose itself)."""
    return [
        f"cited finding_id {c.finding_id!r} does not appear in this export's findings"
        for c in parsed.citations
        if c.finding_id not in known
    ]


def enrich_citations(parsed: ChatAnswer, known: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Attaches the REAL risk_score/bucket/cve_id/hostname for each cited
    finding, read from the export -- never from the model, which supplies
    no such fields to begin with (see ChatCitation). This is what lets a
    UI citation chip show a score/bucket the model could never misreport,
    per the chat-layer design conversation's citation requirement."""
    return [
        {"finding_id": c.finding_id, "fields_used": c.fields_used, **known[c.finding_id]}
        for c in parsed.citations
        if c.finding_id in known
    ]


def answer_question(
    export_data: dict[str, Any],
    message: str,
    history: list[dict[str, str]] | None = None,
    *,
    llm: BaseLLM | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    verbose: bool = False,
) -> dict[str, Any]:
    """Runs the chat agent, bounded-retrying on a parse failure or a
    grounding failure (a cited finding_id that doesn't exist), up to
    `max_attempts` fresh dispatches -- CLAUDE.md's open "tool-call retry
    cap" item, honored here from the start rather than added later.
    Returns a plain dict: {answer, citations (score/bucket-enriched),
    insufficient_data, insufficient_reason}. Raises ChatAnswerError if no
    attempt produces a grounded response.

    `build_scoped_export` runs once here, before the retry loop -- it
    depends only on (export_data, message), never on anything the model
    returns, so there's nothing to recompute between attempts. `known` is
    built from the ORIGINAL `export_data`, not the scoped one, on purpose:
    a compact finding still carries the exact same finding_id/cve_id/
    hostname/bucket/risk_score fields a full one does (see
    COMPACT_FINDING_FIELDS), so the two are equivalent for grounding --
    but reading from the original keeps that guarantee true even if a
    future change to compaction ever drops one of those fields, rather
    than depending on it silently.

    `is_plan_unrelated(message)` is checked first, before anything
    export-related runs at all: a matched greeting/courtesy dispatches
    build_greeting_task instead, with no export attached and no retry
    loop (there is nothing to parse or ground), and returns immediately.
    """
    history = history or []
    if is_plan_unrelated(message):
        agent = build_chat_agent(llm)
        task = build_greeting_task(message, history, agent)
        Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=verbose).kickoff()
        return {
            "answer": task.output.raw.strip(),
            "citations": [],
            "insufficient_data": False,
            "insufficient_reason": None,
        }

    known = _known_findings(export_data)
    scoped_export, scoped = build_scoped_export(export_data, message)
    agent = build_chat_agent(llm)

    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        task = build_chat_task(scoped_export, message, history, agent, scoped=scoped)
        Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=verbose).kickoff()

        try:
            parsed = parse_structured_output(task.output.raw, ChatAnswer)
        except AgentOutputParseError as exc:
            last_error = exc
            continue

        problems = _validate_citations(parsed, known)
        if problems:
            last_error = ChatAnswerError(
                f"ungrounded response on attempt {attempt}: {'; '.join(problems)}"
            )
            continue

        return {
            "answer": parsed.answer,
            "citations": enrich_citations(parsed, known),
            "insufficient_data": parsed.insufficient_data,
            "insufficient_reason": parsed.insufficient_reason,
        }

    raise ChatAnswerError(
        f"could not produce a grounded answer after {max_attempts} attempt(s)"
    ) from last_error
