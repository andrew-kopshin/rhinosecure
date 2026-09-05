"""Read-only, LLM-backed chat over the export file -- the second module
`web/server.py` is allowed to reach for beyond serving a static file
(alongside `web/jobs.py`), and only when an operator explicitly starts
`rhino web --enable-chat`. `create_app()` imports this module only inside
its own body, only when `chat_enabled=True`, never at `web/server.py`'s
module level -- the same import-boundary discipline `web/jobs.py` already
established, applied here for a second, independent opt-in flag.

**Why this is not the job substrate.** `web/jobs.py`'s `JobRegistry`/
`PlanState`/single-job-at-a-time lock exist to serialize access to shared
mutable state (`Coordinator.state`, `memory.py`'s SQLite) that a
constraint submission actually writes to. Chat writes to neither -- every
request is a pure function of (the export file's current contents, the
question) -- via `agents/chat.answer_question`, which never imports
`agents.coordinator` or `memory` at all. So `--enable-chat` needs no
`--data`/`--format`/`--seed`/`--db` the way `--enable-jobs` does, and
concurrent chat requests need no lock: nothing here can race with itself.

**Cost control, not access control.** Confirmed nowhere else in this
codebase: no auth, no rate limiting, no request-size limit exists on any
existing route either (`web/jobs.py`'s own docstring doesn't claim any).
`--enable-chat` is the only gate on this route ever existing at all;
`ChatRequest.message`'s `max_length` is the only per-request cost control,
since -- unlike every other LLM-backed path in this codebase -- there is
no `--offline` equivalent for chat: every request calls the seam for real.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from rhinosecure.agents.chat import ChatAnswerError, answer_question
from rhinosecure.agents.parsing import AgentOutputParseError
from rhinosecure.llm import LLMConfigError
from rhinosecure.web.server import load_export

MAX_MESSAGE_LENGTH = 2000
MAX_HISTORY_TURNS = 20


class ChatTurn(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_LENGTH)
    history: list[ChatTurn] = []


def mount_chat_routes(app: FastAPI) -> None:
    """Called by `create_app()` only when `chat_enabled=True`. Registers
    the one write-nothing route -- `write` here meaning "mutates plan
    state"; the route itself only ever reads `app.state.export_path`,
    same file `GET /api/export` serves, via the shared `load_export`."""

    @app.post("/api/chat")
    def post_chat(body: ChatRequest) -> dict[str, Any]:
        export_data = load_export(app.state.export_path)
        # Only the most recent turns -- an unbounded client-supplied
        # history would otherwise be an unbounded per-request cost lever,
        # the same concern MAX_MESSAGE_LENGTH addresses for the new turn.
        history = [h.model_dump() for h in body.history[-MAX_HISTORY_TURNS:]]
        try:
            return answer_question(export_data, body.message, history)
        except (ChatAnswerError, AgentOutputParseError) as exc:
            raise HTTPException(502, f"could not produce a grounded answer: {exc}")
        except LLMConfigError as exc:
            raise HTTPException(500, str(exc))
