"""Shared, code-owned execution ceiling for every CrewAI `Agent` this
project constructs -- CLAUDE.md's Safety and guardrails "tool-call retry
cap" open item. Every `build_*_agent` function in this package previously
left `max_iter`/`max_execution_time`/`max_retry_limit` at CrewAI's own raw
defaults (`max_iter=25`, `max_execution_time=None` -- no wall-clock cap at
all, `max_retry_limit=2`). None of those defaults were ever examined or
chosen for this project; they were simply whatever CrewAI ships with.

**Why `max_execution_time` is the actual fix here, not `max_iter`.** A
"tool-call retry cap" sounds like it should bound a COUNT -- but the real
compounding risk this item names is invisible to any count this project
controls. CrewAI's own tool-execution layer (`ToolUsage._use`, entirely
external to this project) already retries a raising tool call up to 3
times with no delay of its own before giving up; `research.py`'s network-
calling tools used to compound with THEIR target's own real retry/backoff
on top of that (`enrich/nvd.py`'s 5-attempt exponential backoff), invisible
to `max_iter`. `research.py`'s four tools now catch their own exceptions
and never raise into CrewAI's retry layer at all (see that module's own
docstring) -- closing the worst of the compounding at its source, inside
this project's own code, not by tuning a CrewAI knob. `MAX_AGENT_EXECUTION_
SECONDS` is the backstop for everything that fix doesn't anticipate: a
slow or confused model spinning through many legitimate-looking tool
calls, a slow LLM response, or a future tool that doesn't yet follow the
catch-your-own-exceptions convention. A wall-clock ceiling bounds all of
those uniformly, regardless of how many internal retries or iterations
contribute to it -- a count-based cap does not, since a single "iteration"
can itself take minutes.

**This is a backstop, not a tuned performance number.** 300 seconds is
deliberately generous: a real dispatch (several network lookups plus
reasoning) rarely approaches even a fraction of this under normal
conditions. The value only matters once something has already gone wrong.

**Hitting this raises `TimeoutError`, which CrewAI's own `Agent.execute_
task` explicitly never retries** (its error handler re-raises a
`TimeoutError` immediately rather than treating it like any other
exception) -- and which, before `agents/coordinator.py`'s `_kickoff_batch`
existed, was not caught anywhere in this project either: an exception
escaping `crew.kickoff()` used to abort every OTHER finding batched into
the same stage dispatch, contradicting this project's own documented "a
failed finding is recorded and skipped" guarantee. Setting this constant
without also fixing that gap would trade "hangs forever" for "silently
drops the rest of the batch" -- not progress. See `Coordinator
._kickoff_batch`'s own docstring for the other half of this fix.

No I/O, no LLM call, no CrewAI import -- a plain constant, the same
"one shared value, not seven independent guesses" discipline `agents/
prompt_safety.py` already applies to its own convention.
"""

from __future__ import annotations

MAX_AGENT_EXECUTION_SECONDS = 300
