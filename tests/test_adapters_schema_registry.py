"""`adapters/schema_registry.py`: the published target-schema knowledge base
(meaning + real-world aliases for role/environment/data_sensitivity, and the
criticality scale's anchor-only alias resolution), plus the two relocated
name sets (`ASSET_SLOTS`/`FINDING_SLOTS`) and `PARSER_POSITIONS`. No LLM, no
I/O -- every test here is a pure function call."""

from __future__ import annotations

import pytest

from rhinosecure.adapters.schema_registry import (
    ASSET_SLOTS,
    FINDING_SLOTS,
    PARSER_POSITIONS,
    TARGET_REGISTRY,
    AliasedValue,
    CriticalityAnchor,
    CriticalityScale,
    EnumTargetSpec,
    TargetSpec,
    alias_table_for_column,
    full_alias_coverage,
    resolve_criticality_anchor,
    resolve_enum_alias,
)

# --- TARGET_REGISTRY completeness -------------------------------------------


def test_every_asset_slot_is_in_the_registry():
    for target in ASSET_SLOTS:
        assert target in TARGET_REGISTRY, target


def test_every_finding_slot_is_in_the_registry():
    for target in FINDING_SLOTS:
        assert target in TARGET_REGISTRY, target


def test_registry_entries_are_target_spec_instances():
    for target, spec in TARGET_REGISTRY.items():
        assert isinstance(spec, TargetSpec)
        assert spec.target == target
        assert isinstance(spec.legal_blank_policies, frozenset)
        assert "fatal" in spec.legal_blank_policies  # always legal, every column-reading target


def test_exactly_one_of_enum_or_criticality_for_the_registry_backed_targets():
    for target in ("role", "environment", "data_sensitivity", "scanner_severity"):
        spec = TARGET_REGISTRY[target]
        assert spec.enum is not None
        assert spec.criticality is None
    spec = TARGET_REGISTRY["criticality"]
    assert spec.enum is None
    assert spec.criticality is not None


def test_free_text_and_bool_targets_have_neither_enum_nor_criticality():
    for target in ("hostname", "business_function", "owner", "internet_exposed", "os", "os_build"):
        spec = TARGET_REGISTRY[target]
        assert spec.enum is None
        assert spec.criticality is None


# --- blank-policy legality: role has no gap fallback, matching EXCLUDING_TARGETS ---


def test_role_is_not_gap_or_absent_fact_legal():
    assert TARGET_REGISTRY["role"].legal_blank_policies == frozenset({"fatal"})


def test_criticality_is_gap_legal_but_not_absent_fact_legal():
    assert TARGET_REGISTRY["criticality"].legal_blank_policies == frozenset({"fatal", "gap"})


def test_product_is_absent_fact_legal_but_not_gap_legal():
    # product has a "" default but no NOT_COLLECTED_DEFAULTS entry.
    assert TARGET_REGISTRY["product"].legal_blank_policies == frozenset({"fatal", "absent_fact"})


# --- role alias resolution ---------------------------------------------------


def test_role_resolves_a_known_real_world_alias():
    assert resolve_enum_alias("role", "Domain Controller", "exact") == "dc"


def test_role_resolves_its_own_legal_spelling_too():
    assert resolve_enum_alias("role", "workstation", "exact") == "workstation"


def test_role_alias_resolution_is_case_normalized():
    assert resolve_enum_alias("role", "domain controller", "lower") == "dc"
    assert resolve_enum_alias("role", "DOMAIN CONTROLLER", "upper") == "dc"


def test_role_alias_resolution_returns_none_for_an_unknown_token():
    assert resolve_enum_alias("role", "Some Unknown Device Type", "exact") is None


def test_role_development_server_resolves_to_file_not_dev():
    # bluepeak-gen.json's own table_notes: "Development Server: file, not dev".
    assert resolve_enum_alias("role", "Development Server", "exact") == "file"


# --- environment / data_sensitivity alias resolution ------------------------


def test_environment_resolves_known_aliases():
    assert resolve_enum_alias("environment", "Production", "exact") == "prod"
    assert resolve_enum_alias("environment", "Development", "exact") == "dev"


def test_data_sensitivity_resolves_known_aliases():
    assert resolve_enum_alias("data_sensitivity", "Confidential", "exact") == "confidential"
    assert resolve_enum_alias("data_sensitivity", "PII", "exact") == "regulated"


def test_resolve_enum_alias_returns_none_for_a_target_with_no_enum_spec():
    assert resolve_enum_alias("hostname", "anything", "exact") is None
    assert resolve_enum_alias("not-a-real-target", "anything", "exact") is None


# --- criticality: the anchor-only safety boundary ---------------------------


def test_criticality_resolves_the_ceiling_anchor():
    assert resolve_criticality_anchor("Critical", "exact") == 5


def test_criticality_resolves_the_floor_anchor():
    assert resolve_criticality_anchor("Informational", "exact") == 1
    assert resolve_criticality_anchor("Minimal", "exact") == 1
    assert resolve_criticality_anchor("Negligible", "exact") == 1


def test_criticality_anchor_resolution_is_case_normalized():
    assert resolve_criticality_anchor("critical", "lower") == 5
    assert resolve_criticality_anchor("CRITICAL", "upper") == 5


@pytest.mark.parametrize("middle_word", ["High", "Medium", "Normal", "Low", "Moderate"])
def test_criticality_middle_words_are_never_resolvable(middle_word):
    """Safety property, not an implementation detail: the correct number
    for a middle tier depends on how many tiers the SOURCE's own scale has
    (CLAUDE.md/this module's own docstring cites bluepeak-gen.json mapping
    low->2 against mdvm-gen.json mapping low->1 -- both correct, for
    different scales). A deterministic alias table must never resolve one
    of these, in any case fold, ever."""
    assert resolve_criticality_anchor(middle_word, "exact") is None
    assert resolve_criticality_anchor(middle_word.lower(), "lower") is None
    assert resolve_criticality_anchor(middle_word.upper(), "upper") is None


def test_resolve_criticality_anchor_returns_none_for_unknown_token():
    assert resolve_criticality_anchor("Whatever", "exact") is None


# --- full_alias_coverage / alias_table_for_column ---------------------------


def test_full_alias_coverage_is_none_when_any_value_is_unresolvable():
    # "Low" is deliberately not an anchor -- see the criticality tests above.
    assert full_alias_coverage("criticality", ["Critical", "Low"], "exact") is None


def test_full_alias_coverage_returns_a_complete_table_when_every_value_resolves():
    table = full_alias_coverage("role", ["Workstation", "Domain Controller"], "exact")
    assert table == {"Workstation": "workstation", "Domain Controller": "dc"}


def test_full_alias_coverage_is_none_for_an_empty_input():
    assert full_alias_coverage("role", [], "exact") is None


def test_full_alias_coverage_ignores_blank_values():
    table = full_alias_coverage("role", ["Domain Controller", ""], "exact")
    assert table == {"Domain Controller": "dc"}


def test_alias_table_for_column_returns_partial_coverage():
    # "Low" never resolves -- alias_table_for_column returns whatever DOES,
    # unlike full_alias_coverage which would refuse the whole thing.
    table = alias_table_for_column("criticality", ["Critical", "Low"], "exact")
    assert table == {"Critical": 5}


def test_alias_table_for_column_returns_empty_dict_not_none_when_nothing_resolves():
    assert alias_table_for_column("role", ["Some Unknown Device"], "exact") == {}


# --- PARSER_POSITIONS --------------------------------------------------------


def test_parser_positions_has_exactly_the_five_parser_names():
    assert set(PARSER_POSITIONS) == {"bool", "float", "date", "timestamp", "cve_id"}


def test_timestamp_is_legal_only_at_order_by():
    assert PARSER_POSITIONS["timestamp"] == frozenset({"order_by"})


def test_date_is_legal_at_both_positions():
    assert PARSER_POSITIONS["date"] == frozenset({"row", "order_by"})


@pytest.mark.parametrize("parser", ["bool", "float", "cve_id"])
def test_row_only_parsers_are_not_legal_at_order_by(parser):
    assert PARSER_POSITIONS[parser] == frozenset({"row"})


# --- dataclass shapes (a later agent adds data, never restructures these) ---


def test_aliased_value_shape():
    av = AliasedValue(value="dc", meaning="test", aliases=frozenset({"DC"}))
    assert av.value == "dc"
    assert av.meaning == "test"
    assert av.aliases == frozenset({"DC"})


def test_enum_target_spec_shape():
    spec = EnumTargetSpec(target="role", values=(AliasedValue(value="dc", meaning="", aliases=frozenset()),))
    assert spec.target == "role"
    assert len(spec.values) == 1


def test_criticality_anchor_shape():
    anchor = CriticalityAnchor(level=5, meaning="test", aliases=frozenset({"Critical"}))
    assert anchor.level == 5


def test_criticality_scale_defaults_to_a_one_to_five_range():
    scale = CriticalityScale()
    assert scale.low == 1
    assert scale.high == 5


def test_registry_criticality_scale_has_five_tier_meanings_and_two_anchors():
    scale = TARGET_REGISTRY["criticality"].criticality
    assert scale is not None
    assert len(scale.tier_meanings) == 5
    assert {a.level for a in scale.anchors} == {1, 5}
