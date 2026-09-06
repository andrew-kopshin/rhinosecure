import pytest

from crewai import Agent
from crewai.llms.base_llm import BaseLLM

from rhinosecure.llm import DEFAULT_MODEL, LLMConfig, LLMConfigError, get_llm


def test_default_model_is_the_claude_sonnet_5_pin():
    assert DEFAULT_MODEL == "claude-sonnet-5"


def test_explicit_config_returns_a_base_llm_instance():
    llm = get_llm(LLMConfig(model="claude-sonnet-5", api_key="sk-test-key"))
    assert isinstance(llm, BaseLLM)
    assert llm.model == "claude-sonnet-5"


def test_no_api_key_and_no_base_url_raises():
    with pytest.raises(LLMConfigError):
        get_llm(LLMConfig(model="claude-sonnet-5", api_key=None, base_url=None))


def test_base_url_alone_is_sufficient_for_a_self_hosted_swap():
    """A local/on-prem model may need no real API key at all -- only the
    hosted-Anthropic default path requires one."""
    llm = get_llm(
        LLMConfig(model="local-model", api_key=None, base_url="http://localhost:11434/v1")
    )
    assert isinstance(llm, BaseLLM)
    assert llm.base_url == "http://localhost:11434/v1"


def test_max_tokens_is_unset_by_default():
    """Every agent except schema_inference's propose agent leaves this
    unset, so `crewai`'s Anthropic provider falls back to claude-sonnet-5's
    own documented 128,000-token ceiling rather than a value this seam
    invented."""
    llm = get_llm(LLMConfig(model="claude-sonnet-5", api_key="sk-test-key"))
    assert llm.max_tokens == 128_000


def test_max_tokens_override_reaches_the_constructed_llm():
    llm = get_llm(LLMConfig(model="claude-sonnet-5", api_key="sk-test-key"), max_tokens=24_000)
    assert llm.max_tokens == 24_000


def test_returned_object_is_accepted_by_crewai_agent_llm():
    """Locks in the finding from PROGRESS.md 2026-09-02: Agent.llm accepts a
    BaseLLM instance, not a raw langchain client."""
    llm = get_llm(LLMConfig(model="claude-sonnet-5", api_key="sk-test-key"))
    agent = Agent(
        role="Test Agent",
        goal="Confirm the seam's return value satisfies Agent.llm",
        backstory="Exercises get_llm() without making any API call.",
        llm=llm,
    )
    assert agent.llm is llm


# --- environment-driven config -----------------------------------------------


def test_env_defaults_to_the_pinned_model_and_anthropic_key(monkeypatch):
    monkeypatch.delenv("RHINO_LLM_MODEL", raising=False)
    monkeypatch.delenv("RHINO_LLM_API_KEY", raising=False)
    monkeypatch.delenv("RHINO_LLM_BASE_URL", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-anthropic-env")

    llm = get_llm()

    assert llm.model == DEFAULT_MODEL
    assert llm.api_key == "sk-from-anthropic-env"


def test_rhino_llm_api_key_overrides_anthropic_api_key(monkeypatch):
    monkeypatch.delenv("RHINO_LLM_MODEL", raising=False)
    monkeypatch.delenv("RHINO_LLM_BASE_URL", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-anthropic-env")
    monkeypatch.setenv("RHINO_LLM_API_KEY", "sk-from-rhino-override")

    llm = get_llm()

    assert llm.api_key == "sk-from-rhino-override"


def test_rhino_llm_model_swaps_the_model_without_touching_code(monkeypatch):
    monkeypatch.setenv("RHINO_LLM_MODEL", "claude-sonnet-5")
    monkeypatch.delenv("RHINO_LLM_BASE_URL", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-anthropic-env")

    llm = get_llm()

    assert llm.model == "claude-sonnet-5"


def test_rhino_llm_base_url_swaps_in_a_self_hosted_endpoint(monkeypatch):
    monkeypatch.setenv("RHINO_LLM_MODEL", "local-model")
    monkeypatch.setenv("RHINO_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.delenv("RHINO_LLM_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    llm = get_llm()

    assert llm.base_url == "http://localhost:11434/v1"
    assert llm.model == "local-model"


def test_env_with_no_key_and_no_base_url_raises(monkeypatch):
    monkeypatch.delenv("RHINO_LLM_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("RHINO_LLM_BASE_URL", raising=False)

    with pytest.raises(LLMConfigError):
        get_llm()
