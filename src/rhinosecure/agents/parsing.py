"""Lenient parsing of an agent's raw final-answer text into a locked
pydantic schema -- deliberately independent of CrewAI's own
`output_pydantic` structured-output conversion.

**Why this exists.** A 24-finding agent run hung on the first finding,
retrying an identical failure indefinitely (PROGRESS.md, this date). Root
cause, traced in the installed `crewai` package: the model's final answer
was syntactically valid JSON but shaped as `{"finding": {...fields...}}`
instead of `{...fields...}` directly. `Task._export_output` routes that
through `crewai.utilities.converter.convert_to_model`, which catches the
resulting `pydantic.ValidationError` and retries once via
`handle_partial_json` -- but that function's own retry
(`model.model_validate(parsed)`) fails the same way and **re-raises the
`ValidationError` uncaught** (`except ValidationError: raise`), with no
enclosing handler anywhere in that call chain. That exception then
propagates out of `crew.kickoff()` into whatever retry logic sits above
it in CrewAI's own execution loop -- which kept reproducing the same
malformed shape rather than converging, since nothing in that path can
recover data CrewAI's own converter discards on failure.

No Task built by this project's agents sets `output_pydantic` any more,
specifically to avoid depending on that conversion path at all --
`expected_output` still tells the model the required JSON shape, but the
model's raw final answer (`TaskOutput.raw`, always populated regardless of
whether any conversion succeeds) is what gets parsed, here, by code this
project owns, tests, and can retry or give up on deliberately. See
`agents/coordinator.py` for the retry-cap-then-skip logic built on top of
this.
"""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel, ValidationError

ModelT = TypeVar("ModelT", bound=BaseModel)

_JSON_BLOB = re.compile(r"\{.*\}", re.DOTALL)


class AgentOutputParseError(RuntimeError):
    """Raised when an agent's raw final-answer text can't be coerced into
    the expected schema, even after tolerating a single-key wrapper.

    `str(self)` is a short, terminal-safe summary -- it never embeds the
    agent's raw output, which can be arbitrarily long and, worse, is
    untrusted model-generated text (CLAUDE.md's Safety and guardrails
    section names prompt-injection resistance in agent-reachable text as
    an open item; printing it unbounded to every terminal that sees a
    failure message is the opposite of containing it). The raw text is
    still available, deliberately separated out, as `.raw` -- a caller
    decides whether and how to show it (e.g. only under --verbose)."""

    def __init__(self, message: str, *, raw: str):
        super().__init__(message)
        self.raw = raw


def parse_structured_output(raw: str, model: type[ModelT]) -> ModelT:
    """Parse `raw` into `model`.

    Tolerates exactly one shape beyond a direct match: a single top-level
    key wrapping the real fields as a nested object (e.g. `{"finding":
    {...}}`, `{"result": {...}}`) -- the concrete failure mode that caused
    the incident above. Any other mismatch (missing fields, wrong types,
    a wrapper with more than one key, non-JSON text) raises
    `AgentOutputParseError` rather than guessing further; the caller
    decides whether that's worth a retry.
    """
    match = _JSON_BLOB.search(raw)
    text = match.group() if match else raw
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AgentOutputParseError("no valid JSON object found in agent output", raw=raw) from exc

    try:
        return model.model_validate(parsed)
    except ValidationError as direct_error:
        if isinstance(parsed, dict) and len(parsed) == 1:
            (inner,) = parsed.values()
            if isinstance(inner, dict):
                try:
                    return model.model_validate(inner)
                except ValidationError:
                    pass  # fall through to the error below -- unwrapping didn't fix it either
        raise AgentOutputParseError(
            f"agent output did not match {model.__name__}, even after tolerating a "
            f"single-key wrapper: {direct_error}",
            raw=raw,
        ) from direct_error
