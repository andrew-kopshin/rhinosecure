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
from crewai.types.usage_metrics import UsageMetrics
from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODEL = "claude-sonnet-5"

#: Claude Sonnet 5's first-party API rate (DEFAULT_MODEL above, CLAUDE.md
#: Section 11 pins this model for every agent call). Sourced from Anthropic's
#: published pricing, not recalled -- re-check before changing either
#: number. Originally defined in `agents/schema_inference.py` (the first
#: place in the codebase that needed a cost estimate) and moved here so
#: `cli.py` -- which has no reason to import an agents/ module just for a
#: pricing constant -- can reuse the SAME rate for `rhino run --agents`'s own
#: usage/cost summary (CLAUDE.md Safety and guardrails, "Open" item 2)
#: instead of a second, driftable copy of these two numbers.
INPUT_USD_PER_MILLION_TOKENS = 2.00
OUTPUT_USD_PER_MILLION_TOKENS = 10.00


def estimate_cost_usd(usage: UsageMetrics | None) -> float:
    """A plain, undiscounted estimate: prompt tokens at the input rate plus
    completion tokens at the output rate. Deliberately ignores
    `cached_prompt_tokens`/`cache_creation_tokens` -- prompt caching changes
    the real per-token rate (a cache write costs more than a plain input
    token, a cache read much less), and this function has no way to tell
    which of `usage`'s plain `prompt_tokens` were actually cache hits versus
    misses without a per-call breakdown no caller here currently threads
    through. Folding in a wrong multiplier would be a confident-looking but
    fabricated number -- the same "wrong-but-plausible" failure this
    project's own not-collected/refuse-rather-than-guess discipline exists
    to prevent elsewhere. Documented as a known simplification rather than
    silently treated as exact; revisit if a caller ever needs the tighter
    number badly enough to thread per-call cache stats through."""
    if usage is None:
        return 0.0
    return (usage.prompt_tokens / 1_000_000) * INPUT_USD_PER_MILLION_TOKENS + (
        usage.completion_tokens / 1_000_000
    ) * OUTPUT_USD_PER_MILLION_TOKENS


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


def _is_hosted_anthropic(cfg: LLMConfig) -> bool:
    """`thinking` is an Anthropic Messages API parameter. A self-hosted
    endpoint (`RHINO_LLM_BASE_URL`, a first-class deployment target) or a
    non-Claude model has no such parameter to receive it, so it is simply not
    sent -- the caller asked for a cap on reasoning, and a model with no
    reasoning mode already satisfies it."""
    return not cfg.base_url and "claude" in cfg.model.lower()


def _thinking_config(thinking: dict[str, str | int]) -> object:
    """crewai's `AnthropicThinkingConfig` serializes `{"type": "disabled"}` as
    `{"type": "disabled", "budget_tokens": null}`, and the API rejects it
    (`thinking.disabled.budget_tokens: Extra inputs are not permitted`) --
    three attempts, each failing before a token was spent. The provider calls
    `model_dump()` on this object, so a subclass that drops unset fields fixes
    the wire format without patching the library."""
    from crewai.llms.providers.anthropic.completion import AnthropicThinkingConfig

    class _WireThinkingConfig(AnthropicThinkingConfig):
        def model_dump(self, **kwargs):  # type: ignore[override]
            kwargs.setdefault("exclude_none", True)
            return super().model_dump(**kwargs)

    return _WireThinkingConfig(**thinking)


def get_llm(
    config: LLMConfig | None = None,
    *,
    max_tokens: int | None = None,
    thinking: dict[str, str | int] | None = None,
) -> BaseLLM:
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

    `thinking` is left unset by every caller except the propose agent, for
    the same reason. Left unset, `claude-sonnet-5` thinks adaptively, and
    thinking tokens count against `max_tokens`: a 27-column source spent all
    24,000 of them on a thinking block and returned no answer at all
    (`stop_reason: max_tokens`, content `['thinking']`), which CrewAI reports
    as "None or empty" -- on every retry, identically. `{"type": "disabled"}`
    is the only setting crewai's Anthropic provider can pass for this model
    (`enabled` is rejected by the API, and the provider has no way to send
    `output_config.effort`).
    """
    cfg = config or _config_from_env()
    if not cfg.api_key and not cfg.base_url:
        raise LLMConfigError(
            "No API key available (set ANTHROPIC_API_KEY or RHINO_LLM_API_KEY in "
            ".env) and no RHINO_LLM_BASE_URL configured for a self-hosted model."
        )

    kwargs: dict[str, object] = {"model": cfg.model}
    if cfg.api_key:
        kwargs["api_key"] = cfg.api_key
    if cfg.base_url:
        kwargs["base_url"] = cfg.base_url
    if max_tokens is not None:
        kwargs["max_tokens"] = max_tokens
    if thinking is not None and _is_hosted_anthropic(cfg):
        kwargs["thinking"] = _thinking_config(thinking)
    return LLM(**kwargs)
