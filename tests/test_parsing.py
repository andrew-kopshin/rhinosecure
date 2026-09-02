import pytest
from pydantic import BaseModel

from rhinosecure.agents.parsing import AgentOutputParseError, parse_structured_output


class Widget(BaseModel):
    name: str
    count: int


def test_direct_match_parses_cleanly():
    result = parse_structured_output('{"name": "bolt", "count": 3}', Widget)
    assert result == Widget(name="bolt", count=3)


def test_single_key_wrapper_is_unwrapped():
    """The exact shape that caused the incident: {"finding": {...}} instead
    of the fields directly at the top level."""
    result = parse_structured_output('{"finding": {"name": "bolt", "count": 3}}', Widget)
    assert result == Widget(name="bolt", count=3)


def test_wrapper_key_name_is_irrelevant():
    """Tolerance is structural (exactly one key, nested object) -- not tied
    to the specific key name "finding" from the incident."""
    result = parse_structured_output('{"result": {"name": "bolt", "count": 3}}', Widget)
    assert result == Widget(name="bolt", count=3)


def test_surrounding_prose_is_stripped_before_parsing():
    raw = 'Here is my answer:\n{"name": "bolt", "count": 3}\nHope that helps!'
    result = parse_structured_output(raw, Widget)
    assert result == Widget(name="bolt", count=3)


def test_two_key_wrapper_is_not_unwrapped():
    """Tolerance is narrowly scoped to exactly one wrapping key -- two keys
    is a genuinely different (and more ambiguous) shape, not covered."""
    with pytest.raises(AgentOutputParseError):
        parse_structured_output('{"a": {"name": "bolt", "count": 3}, "b": 1}', Widget)


def test_wrapper_whose_inner_value_also_fails_validation_raises():
    with pytest.raises(AgentOutputParseError):
        parse_structured_output('{"finding": {"name": "bolt"}}', Widget)  # missing count


def test_non_json_text_raises():
    with pytest.raises(AgentOutputParseError):
        parse_structured_output("not json at all", Widget)


def test_wrapper_around_a_scalar_is_not_unwrapped():
    with pytest.raises(AgentOutputParseError):
        parse_structured_output('{"finding": "not an object"}', Widget)
