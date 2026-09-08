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

**A second, real incident, found the same way as the first: live testing
against a real, previously-untested source shape.** A source whose own
`finding_id` is naturally numeric (a scanner's numeric "Plugin ID", e.g.
`148676`) produces a model response that emits it as a bare JSON *number*
(`"finding_id": 148676`) rather than a JSON *string* (`"finding_id":
"148676"`) -- both encode the identical value, but pydantic v2's default
(non-strict) mode, unlike v1, does NOT coerce an int/float into a
`str`-typed field, so validation fails every time. This is not
occasional model flakiness: `agents/coordinator.py`'s own retry loop
(`_resolve_output`) rebuilds the IDENTICAL task with no error-specific
correction on each attempt (unlike `schema_inference.py`'s own retry
loop, which embeds the previous failure's exact message) -- so a model
that made this exact type choice once reliably makes it again on every
retry, exhausting `max_parse_attempts` deterministically and taking every
finding on that source down with it. `_coerce_str_fields` (below) closes
this the same way `adapters/configured.py`'s own str-typed-target
coercion already does for a different parsing seam (CSV cell values):
accept the same value in the other JSON-legal encoding of it, never
invent one. Scoped narrowly on purpose -- top-level fields only (every
schema this module parses is flat), and only when the model's OWN field
is genuinely typed `str`, never a guess at what the value should be.
"""

from __future__ import annotations

import json
import re
from typing import Any, TypeVar, get_args, get_origin

from pydantic import BaseModel, ValidationError

ModelT = TypeVar("ModelT", bound=BaseModel)

_JSON_BLOB = re.compile(r"\{.*\}", re.DOTALL)


def _is_str_typed(annotation: Any) -> bool:
    """True for `str` itself, or a `Union` (`str | None`, `Optional[str]`)
    that includes `str` as one of its members -- every shape a top-level
    field on the models this module parses can legally have. Never
    matches a field typed anything else (a `Literal[...]` of strings,
    say), which is a deliberate, narrower target this coercion has no
    reason to touch."""
    if annotation is str:
        return True
    return get_origin(annotation) is not None and str in get_args(annotation)


def _coerce_str_fields(data: dict[str, Any], model: type[BaseModel]) -> dict[str, Any]:
    """Returns a shallow copy of `data` with every top-level value that is
    a bare `int`/`float` (never `bool` -- `bool` is an `int` subclass in
    Python, and stringifying a genuine boolean mistake would hide a real
    type error rather than tolerate a harmless encoding choice) coerced
    to its `str()` form, but ONLY for a key `model` itself declares as
    str-typed (`_is_str_typed`). See module docstring for the concrete
    incident this exists to close (a numeric `finding_id`/`Plugin ID`
    emitted as a JSON number)."""
    fields = model.model_fields
    coerced = dict(data)
    for name, value in data.items():
        if (
            name in fields
            and _is_str_typed(fields[name].annotation)
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
        ):
            coerced[name] = str(value)
    return coerced


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

    if isinstance(parsed, dict):
        parsed = _coerce_str_fields(parsed, model)

    try:
        return model.model_validate(parsed)
    except ValidationError as direct_error:
        if isinstance(parsed, dict) and len(parsed) == 1:
            (inner,) = parsed.values()
            if isinstance(inner, dict):
                try:
                    return model.model_validate(_coerce_str_fields(inner, model))
                except ValidationError:
                    pass  # fall through to the error below -- unwrapping didn't fix it either
        raise AgentOutputParseError(
            f"agent output did not match {model.__name__}, even after tolerating a "
            f"single-key wrapper: {direct_error}",
            raw=raw,
        ) from direct_error
