from rhinosecure.agents.entity_consistency import (
    find_neutralized_axis_assertions,
    find_wrong_cve_mentions,
)


def test_no_mention_at_all_is_not_a_mismatch():
    assert find_wrong_cve_mentions("some plain prose with no identifiers", "CVE-2021-26855") == set()


def test_mentioning_only_the_real_cve_is_not_a_mismatch():
    text = "This CVE-2021-26855 (ProxyLogon) issue is critical and KEV-listed."
    assert find_wrong_cve_mentions(text, "CVE-2021-26855") == set()


def test_case_insensitive_on_both_sides():
    assert find_wrong_cve_mentions("see cve-2021-26855 for details", "CVE-2021-26855") == set()
    assert find_wrong_cve_mentions("see CVE-2021-26855 for details", "cve-2021-26855") == set()


def test_mentioning_a_different_cve_is_a_mismatch():
    text = "This looks similar to CVE-2020-1472 (Zerologon)."
    assert find_wrong_cve_mentions(text, "CVE-2021-26855") == {"CVE-2020-1472"}


def test_mentioning_multiple_wrong_cves_returns_all_of_them():
    text = "Related to CVE-2020-1472 and also CVE-2019-1068, unlike CVE-2021-26855 itself."
    assert find_wrong_cve_mentions(text, "CVE-2021-26855") == {"CVE-2020-1472", "CVE-2019-1068"}


def test_real_and_wrong_mentions_together_reports_only_the_wrong_one():
    text = "CVE-2021-26855 is the real issue here, not CVE-2020-1472."
    assert find_wrong_cve_mentions(text, "CVE-2021-26855") == {"CVE-2020-1472"}


# --- Track C: find_neutralized_axis_assertions ------------------------------
#
# Collision-string regression cases FIRST, per CLAUDE.md's own build-order
# convention for this task: the placeholder values below (workstation,
# file, internal, prod, 3) are ordinary English words/digits that collide
# constantly with legitimate prose -- these lock in that the proximity gate
# actually prevents that, before any real-violation case is added.

ALL_AXES = frozenset({"role", "environment", "data_sensitivity", "criticality", "internet_exposed"})

DEFAULT_AXIS_VALUES = {
    "role": "workstation",
    "environment": "prod",
    "data_sensitivity": "internal",
    "criticality": 3,
    "internet_exposed": False,
}


def test_dev_workstation_does_not_trigger_role_when_role_is_not_discussed():
    text = "This is a dev workstation used for internal testing purposes."
    result = find_neutralized_axis_assertions(text, {"role"}, DEFAULT_AXIS_VALUES)
    assert result == set()


def test_file_server_does_not_trigger_role_when_role_is_not_discussed():
    text = "The file server hosts several shared drives for the finance team."
    result = find_neutralized_axis_assertions(text, {"role"}, DEFAULT_AXIS_VALUES)
    assert result == set()


def test_internal_network_does_not_trigger_data_sensitivity_when_not_discussed():
    text = "Traffic from this host stays on the internal network at all times."
    result = find_neutralized_axis_assertions(text, {"data_sensitivity"}, DEFAULT_AXIS_VALUES)
    assert result == set()


def test_neutralized_axis_not_mentioned_at_all_never_fires():
    text = "This finding concerns a remote code execution vulnerability with a public exploit."
    result = find_neutralized_axis_assertions(text, ALL_AXES, DEFAULT_AXIS_VALUES)
    assert result == set()


def test_anchor_present_without_its_own_value_nearby_does_not_fire():
    # "environment" appears, but the placeholder value ("prod"/"production")
    # is nowhere near it -- discussing the axis in the abstract, without
    # restating its value, must not trip the check.
    text = "We assessed the environment broadly but have no specific data on file for it."
    result = find_neutralized_axis_assertions(text, {"environment"}, DEFAULT_AXIS_VALUES)
    assert result == set()


def test_critical_severity_language_never_triggers_criticality_check():
    # "critical" (CVSS/NVD severity language) must never be confused with
    # the literal word "criticality".
    text = "NVD rates CVE-2023-23397 as Critical severity, with a base score of 9.8."
    result = find_neutralized_axis_assertions(text, {"criticality"}, DEFAULT_AXIS_VALUES)
    assert result == set()


def test_role_value_stated_near_role_anchor_is_a_real_violation():
    text = "This asset's role is workstation, a standard corporate device."
    result = find_neutralized_axis_assertions(text, {"role"}, DEFAULT_AXIS_VALUES)
    assert result == {"role"}


def test_data_sensitivity_value_stated_near_anchor_is_a_real_violation():
    text = "Data sensitivity: internal, per the company's classification policy."
    result = find_neutralized_axis_assertions(text, {"data_sensitivity"}, DEFAULT_AXIS_VALUES)
    assert result == {"data_sensitivity"}


def test_environment_value_stated_near_anchor_is_a_real_violation():
    text = "This host runs in the prod environment alongside other production services."
    result = find_neutralized_axis_assertions(text, {"environment"}, DEFAULT_AXIS_VALUES)
    assert result == {"environment"}


def test_environment_aliased_production_form_is_also_caught():
    text = "The environment is production, so any change here needs extra caution."
    result = find_neutralized_axis_assertions(text, {"environment"}, DEFAULT_AXIS_VALUES)
    assert result == {"environment"}


def test_criticality_value_stated_near_anchor_is_a_real_violation():
    text = "With an asset criticality of 3, this is a mid-tier system."
    result = find_neutralized_axis_assertions(text, {"criticality"}, DEFAULT_AXIS_VALUES)
    assert result == {"criticality"}


def test_criticality_anchor_far_from_its_value_does_not_fire():
    text = (
        "Asset criticality is discussed elsewhere in this report. "
        "Meanwhile, note that exactly 3 separate mitigations were proposed for this finding."
    )
    result = find_neutralized_axis_assertions(text, {"criticality"}, DEFAULT_AXIS_VALUES)
    assert result == set()


def test_internet_exposed_false_claim_phrase_is_a_real_violation():
    text = "This asset is internal-only and not internet-facing."
    result = find_neutralized_axis_assertions(text, {"internet_exposed"}, DEFAULT_AXIS_VALUES)
    assert result == {"internet_exposed"}


def test_internet_exposed_true_claim_phrase_is_a_real_violation_when_placeholder_is_true():
    text = "This host is internet-facing and reachable from the internet."
    values = {**DEFAULT_AXIS_VALUES, "internet_exposed": True}
    result = find_neutralized_axis_assertions(text, {"internet_exposed"}, values)
    assert result == {"internet_exposed"}


def test_internet_exposed_not_mentioned_does_not_fire():
    text = "This finding was detected via an authenticated scan of the host."
    result = find_neutralized_axis_assertions(text, {"internet_exposed"}, DEFAULT_AXIS_VALUES)
    assert result == set()


def test_only_neutralized_axes_are_checked_even_if_others_would_match():
    # role's placeholder value ("workstation") is stated near "role", but
    # role is NOT in neutralized_axes here -- a confirmed run's honest
    # restatement of a REAL role must never be flagged.
    text = "This asset's role is workstation, a standard corporate device."
    result = find_neutralized_axis_assertions(text, {"environment"}, DEFAULT_AXIS_VALUES)
    assert result == set()


def test_missing_axis_value_is_skipped_not_a_false_positive():
    text = "This asset's role is workstation."
    result = find_neutralized_axis_assertions(text, {"role"}, {})
    assert result == set()


def test_plural_anchor_form_is_also_caught():
    """Adversarial-review finding: the singular-only anchor originally
    missed a real, plausible bypass -- "Roles: workstation" (plural,
    parenthesis-free) matched neither the old literal "role" anchor nor
    any value token, so it passed clean despite confidently restating the
    placeholder. Locks in the fix (plain-plural anchor patterns) for all
    four value-token axes."""
    assert find_neutralized_axis_assertions(
        "Roles: workstation, standard configuration.", {"role"}, DEFAULT_AXIS_VALUES
    ) == {"role"}
    assert find_neutralized_axis_assertions(
        "Environments: prod, standard tier.", {"environment"}, DEFAULT_AXIS_VALUES
    ) == {"environment"}
    assert find_neutralized_axis_assertions(
        "Sensitivities: internal, per policy.", {"data_sensitivity"}, DEFAULT_AXIS_VALUES
    ) == {"data_sensitivity"}
    assert find_neutralized_axis_assertions(
        "Criticalities observed: 3 across the fleet.", {"criticality"}, DEFAULT_AXIS_VALUES
    ) == {"criticality"}


def test_plural_anchor_broadening_does_not_reintroduce_the_collision_cases():
    """The plural broadening above must not weaken the original
    collision-safety guarantees -- re-checked explicitly."""
    assert find_neutralized_axis_assertions(
        "This is a dev workstation used for internal testing purposes.", {"role"}, DEFAULT_AXIS_VALUES
    ) == set()
    assert find_neutralized_axis_assertions(
        "The file server hosts several shared drives for the finance team.", {"role"}, DEFAULT_AXIS_VALUES
    ) == set()


def test_multiple_violations_in_one_text_are_all_reported():
    text = (
        "This asset's role is workstation, running in the prod environment "
        "with an asset criticality of 3."
    )
    result = find_neutralized_axis_assertions(text, ALL_AXES, DEFAULT_AXIS_VALUES)
    assert result == {"role", "environment", "criticality"}


# --- Adversarial-review hardening pass -------------------------------------
#
# 4 independent reviewers, each finding re-verified by an independent
# skeptic, found six real defects in the checks above. Each is locked in
# here with the reviewer's own repro text, per the module docstring's own
# numbered account of the hardening pass.


def test_internet_exposed_confident_true_claim_is_caught_when_placeholder_is_false():
    """Hardening-pass item 1 (critical): the old code only ever consulted
    the phrase list matching the CURRENT placeholder direction (always
    False), so a model confidently asserting the OPPOSITE direction --
    the one that inflates apparent risk -- was undetectable by
    construction. Both directions are now checked regardless of which way
    the placeholder points."""
    text = (
        "Firewall rule review confirms this asset is internet-facing and "
        "directly reachable from the public internet on port 443, making "
        "this an urgent patch-now candidate."
    )
    result = find_neutralized_axis_assertions(text, {"internet_exposed"}, {"internet_exposed": False})
    assert result == {"internet_exposed"}

    text2 = "This host is publicly accessible from the internet, which significantly raises the risk here."
    result2 = find_neutralized_axis_assertions(text2, {"internet_exposed"}, {"internet_exposed": False})
    assert result2 == {"internet_exposed"}


def test_internet_exposed_claim_about_a_different_named_asset_does_not_fire():
    """Hardening-pass item 2 (medium): the old code was a flat whole-text
    substring scan with no subject scoping at all, so a claim clearly
    attributed to a DIFFERENT, named asset tripped a violation on this
    finding's own asset. A self-referential subject anchor ("this
    host"/"this asset"/...) now gates the check the way an axis-name
    anchor already gates the other four axes."""
    text = (
        "Our other file servers in the DMZ are not reachable from the "
        "internet; that hardening effort is ongoing fleet-wide."
    )
    result = find_neutralized_axis_assertions(text, {"internet_exposed"}, {"internet_exposed": False})
    assert result == set()


def test_internet_exposed_still_fires_for_the_own_asset_even_alongside_another_asset_claim():
    """Companion to the case above: a message that discusses another
    asset's exposure AND makes a real claim about THIS finding's own
    asset must still catch the real claim."""
    text = (
        "Unlike the payroll server (which is not exposed to the internet), "
        "this specific host sits behind a WAF but is still internet-facing "
        "to partner traffic."
    )
    result = find_neutralized_axis_assertions(text, {"internet_exposed"}, {"internet_exposed": False})
    assert result == {"internet_exposed"}


def test_role_paraphrase_with_no_literal_value_token_is_now_caught():
    """Hardening-pass item 5 (high, tempered): a model paraphrase that
    never uses the schema's own value word at all -- but does discuss the
    axis by name -- previously evaded detection completely. A curated,
    axis-scoped alias table now covers the specific paraphrases an
    adversarial review round demonstrated a model actually producing."""
    text = (
        "Based on the asset naming convention and the fact that this "
        "device checks in as a managed corporate laptop, we treat its "
        "role as a standard employee endpoint used for day-to-day office "
        "work, not a server."
    )
    assert find_neutralized_axis_assertions(text, {"role"}, {"role": "workstation"}) == {"role"}

    assert find_neutralized_axis_assertions(
        "In terms of its role within the fleet, this is simply an end-user endpoint device, not a server.",
        {"role"}, {"role": "workstation"},
    ) == {"role"}

    assert find_neutralized_axis_assertions(
        "The asset's role in this environment is that of a network-attached storage node used for shared document archives.",
        {"role"}, {"role": "file"},
    ) == {"role"}

    assert find_neutralized_axis_assertions(
        "Given its role, this machine is a domain controller for the corporate Active Directory forest.",
        {"role"}, {"role": "dc"},
    ) == {"role"}


def test_environment_paraphrase_customer_facing_is_now_caught():
    text = "Regarding the environment, this is essentially a live, customer-facing tier, not a lab or test box."
    result = find_neutralized_axis_assertions(text, {"environment"}, {"environment": "prod"})
    assert result == {"environment"}


def test_ordinary_two_sentence_restatement_of_role_is_now_caught():
    """Hardening-pass item 4 (high, tempered to medium): the old 60-char
    window was narrower than an entirely ordinary two-sentence
    restatement (measured gap 64), not adversarial phrasing."""
    text = (
        "This host's role has already been confirmed by the infrastructure "
        "team. It is a workstation used daily by finance staff."
    )
    result = find_neutralized_axis_assertions(text, {"role"}, {"role": "workstation"})
    assert result == {"role"}


def test_ordinary_one_sentence_restatement_of_criticality_is_now_caught():
    """Companion to the case above, for criticality's own tighter window
    (measured gap 49 against the old 20-char window)."""
    text = "The criticality assigned during intake review here comes out to 3."
    result = find_neutralized_axis_assertions(text, {"criticality"}, {"criticality": 3})
    assert result == {"criticality"}


def test_widened_criticality_window_still_excludes_a_genuinely_distant_mention():
    """The widened window (item 4) must not swallow the pre-existing
    `test_criticality_anchor_far_from_its_value_does_not_fire` case above
    -- its measured gap (69) stays outside the widened window (55),
    calibrated against this exact test rather than picked by feel."""
    text = (
        "Asset criticality is discussed elsewhere in this report. "
        "Meanwhile, note that exactly 3 separate mitigations were proposed for this finding."
    )
    result = find_neutralized_axis_assertions(text, {"criticality"}, {"criticality": 3})
    assert result == set()


def test_value_straddling_the_old_window_boundary_is_no_longer_truncated():
    """Hardening-pass item 3 (medium): the old slice-then-search
    implementation could bisect the value token itself mid-word when its
    span straddled the window boundary ("internal" truncated to "intern"),
    silently missing a value whose START was well within the nominal
    window. Comparing match spans directly (rather than slicing text)
    fixes this regardless of incidental word length or offset."""
    text = (
        "From a data sensitivity standpoint, this system only handles "
        "routine company-internal business records, nothing regulated."
    )
    result = find_neutralized_axis_assertions(text, {"data_sensitivity"}, {"data_sensitivity": "internal"})
    assert result == {"data_sensitivity"}


def test_explicit_negation_of_a_different_asset_does_not_fire():
    """Hardening-pass item 6 (medium): a sentence that explicitly DENIES
    the placeholder value about a different, named subject -- not restate
    it as fact about this finding's own asset -- must not be flagged."""
    text = "Unlike the file share host discussed earlier, this asset's role is unrelated to storage."
    result = find_neutralized_axis_assertions(text, {"role"}, {"role": "file"})
    assert result == set()


def test_contrast_marker_guard_does_not_suppress_a_hedged_but_still_asserted_value():
    """The contrast-marker guard added for the case above is deliberately
    narrow: it must never suppress a HEDGED restatement, which the
    module's own design intentionally keeps flagging (a hedge still
    states the value as fact, only qualifying confidence in it)."""
    text = "role: workstation, though this was never actually collected for this asset"
    result = find_neutralized_axis_assertions(text, {"role"}, {"role": "workstation"})
    assert result == {"role"}


def test_decimal_criticality_score_no_longer_collides_with_the_bare_digit():
    """Hardening-pass item 5's sibling decimal-collision bug: plain
    `\\b3\\b` matched inside "3.5" too, because "." is a non-word
    character and `\\b` only checks the word/non-word boundary -- a real
    false positive against CVSS-style decimal scores near the word
    "criticality" in the same prose."""
    text = "Estimated criticality: 3.5 (composite of multiple factors)."
    result = find_neutralized_axis_assertions(text, {"criticality"}, {"criticality": 3})
    assert result == set()


def test_decimal_criticality_fix_does_not_break_a_genuine_bare_digit_match():
    text = "With an asset criticality of 3, this is a mid-tier system."
    result = find_neutralized_axis_assertions(text, {"criticality"}, {"criticality": 3})
    assert result == {"criticality"}
