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


# --- raw output is carried separately from the short message -----------------


def test_non_json_text_carries_raw_but_not_in_the_short_message():
    """The failure text itself must stay short and terminal-safe -- the
    agent's full, untrusted raw output belongs on .raw, not baked into
    str(exc), so a caller can withhold it unless --verbose is passed."""
    raw = "not json at all, and quite a bit longer than a summary should ever be"
    with pytest.raises(AgentOutputParseError) as exc_info:
        parse_structured_output(raw, Widget)
    assert exc_info.value.raw == raw
    assert raw not in str(exc_info.value)


def test_schema_violation_also_carries_raw():
    raw = '{"finding": {"name": "bolt"}}'  # missing count
    with pytest.raises(AgentOutputParseError) as exc_info:
        parse_structured_output(raw, Widget)
    assert exc_info.value.raw == raw
    assert "count" in str(exc_info.value)  # the short message still names what's wrong


# --- str-typed field coercion: a real incident from live verification -------
#
# A source whose finding_id is naturally numeric (a scanner's "Plugin ID")
# produced a model response with `"finding_id": 148676` (a JSON number)
# instead of `"finding_id": "148676"` (a JSON string) -- pydantic v2's
# default mode does not coerce int->str, so this failed validation
# identically on every one of coordinator.py's 3 retry attempts (that loop
# rebuilds the SAME task with no error-specific correction), taking every
# finding on that source down with it. Regression-tested here directly
# against parse_structured_output, the shared seam every agent routes
# through.


class IdLike(BaseModel):
    finding_id: str
    count: int


def test_numeric_json_value_is_coerced_for_a_str_typed_field():
    result = parse_structured_output('{"finding_id": 148676, "count": 3}', IdLike)
    assert result == IdLike(finding_id="148676", count=3)


def test_float_json_value_is_also_coerced_for_a_str_typed_field():
    result = parse_structured_output('{"finding_id": 148676.0, "count": 3}', IdLike)
    assert result.finding_id == "148676.0"


def test_numeric_coercion_also_applies_inside_a_single_key_wrapper():
    result = parse_structured_output('{"finding": {"finding_id": 148676, "count": 3}}', IdLike)
    assert result == IdLike(finding_id="148676", count=3)


def test_coercion_never_touches_a_genuinely_int_typed_field():
    """count is legitimately typed int -- a wrong type there must still
    raise, not be silently coerced into something else."""
    with pytest.raises(AgentOutputParseError):
        parse_structured_output('{"finding_id": "F01", "count": "not a number"}', IdLike)


def test_coercion_never_stringifies_a_bool_for_a_str_typed_field():
    """bool is an int subclass in Python -- must not be swept up by the
    int/float coercion, since that would hide a real type mistake
    (a bool value can never be a legitimate encoding of a str field)."""
    with pytest.raises(AgentOutputParseError):
        parse_structured_output('{"finding_id": true, "count": 3}', IdLike)


def test_a_correctly_str_typed_value_is_unaffected():
    result = parse_structured_output('{"finding_id": "F01", "count": 3}', IdLike)
    assert result.finding_id == "F01"


class OptionalIdLike(BaseModel):
    finding_id: str | None = None
    count: int


def test_coercion_applies_to_an_optional_str_typed_field_too():
    result = parse_structured_output('{"finding_id": 148676, "count": 3}', OptionalIdLike)
    assert result.finding_id == "148676"
