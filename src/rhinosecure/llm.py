"""Single seam for LLM client construction and dispatch.

CLAUDE.md's trust boundary section: one module owns provider client
construction; agent code (`agents/`, `crew.py`, once they exist) calls
`get_llm()` and never imports `crewai.LLM`, `anthropic`, or any other
provider SDK directly. That keeps a self-hosted or on-premises model a
substitution -- change `LLMConfig`'s inputs, or the environment variables
`_config_from_env` reads -- rather than a rewrite of every agent.

Pinned model is `claude-sonnet-5` (CLAUDE.md Section 11). `get_llm` returns a
`BaseLLM` instance, not a plain model string -- confirmed in practice
(PROGRESS.md 2026-09-02) that `crewai.Agent.llm` accepts either shape, but
only a `BaseLLM` instance carries `api_key`/`base_url` on the object itself
rather than leaking them into ambient environment lookups scattered across
every call site. `crewai.LLM(...)` is itself a dispatcher: constructing it
with an Anthropic-shaped model string returns a provider-specific `BaseLLM`
subclass (`AnthropicCompletion`), not a generic wrapper.

This module only runs under a Python interpreter where `import crewai`
itself succeeds -- `.venv312`, not `.venv` (see CLAUDE.md Section 11 and
PROGRESS.md 2026-09-02 for why CrewAI's own import chain fails on 3.14).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from crewai import LLM
from crewai.llms.base_llm import BaseLLM
from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODEL = "claude-sonnet-5"


class LLMConfigError(RuntimeError):
    """Raised when there is no way to reach any model -- no API key for the
    default hosted provider, and no base_url pointing at a self-hosted one."""


@dataclass(frozen=True)
class LLMConfig:
    """The seam's swap point. Construct one directly to override the
    environment (e.g. in a test, or to point at a local model), or leave
    callers to `_config_from_env`'s defaults for the hosted Anthropic model
    CLAUDE.md pins."""

    model: str = DEFAULT_MODEL
    api_key: str | None = None
    base_url: str | None = None


def _config_from_env() -> LLMConfig:
    return LLMConfig(
        model=os.environ.get("RHINO_LLM_MODEL", DEFAULT_MODEL),
        api_key=os.environ.get("RHINO_LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"),
        base_url=os.environ.get("RHINO_LLM_BASE_URL"),
    )


def get_llm(config: LLMConfig | None = None, *, max_tokens: int | None = None) -> BaseLLM:
    """Construct the object every CrewAI `Agent`'s `llm=` field receives.

    No request is made here -- this only builds the client. A missing
    `api_key` is only an error when there is also no `base_url`: a
    self-hosted swap may need no real key at all, so the hosted-Anthropic
    default is the one path this refuses to construct silently broken.

    `max_tokens` is left unset by every caller except `agents/schema_inference
    .py`'s propose agent. Left unset, `crewai`'s Anthropic provider defaults
    to the model's full Messages API ceiling (128,000 tokens for
    `claude-sonnet-5`) -- the right choice for an agent whose output shape is
    open-ended. A caller whose task has a small, well-understood output size
    can pass a tight cap instead, so a wayward call fails fast and cheap
    (a truncated response, a quick parse error) rather than silently
    generating tens of thousands of unneeded completion tokens before an
    unrelated failure discards all of it (PROGRESS.md 2026-09-06: a 5-row,
    20-column ingest_propose job spent ~50k completion tokens on at least one
    of its three attempts when the accepted proposal needed ~8k).
    """
    cfg = config or _config_from_env()
    if not cfg.api_key and not cfg.base_url:
        raise LLMConfigError(
            "No API key available (set ANTHROPIC_API_KEY or RHINO_LLM_API_KEY in "
            ".env) and no RHINO_LLM_BASE_URL configured for a self-hosted model."
        )

    kwargs: dict[str, str | int] = {"model": cfg.model}
    if cfg.api_key:
        kwargs["api_key"] = cfg.api_key
    if cfg.base_url:
        kwargs["base_url"] = cfg.base_url
    if max_tokens is not None:
        kwargs["max_tokens"] = max_tokens
    return LLM(**kwargs)
