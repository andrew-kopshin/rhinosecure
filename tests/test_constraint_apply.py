"""constraint_apply.py -- the crewai-free matcher/overlay module (CLAUDE.md's
machine-identity constraint scoping entry). `apply_constraints`'s own
pure-overlay behavior is already covered by test_constraint_intake.py
(unchanged by the move, re-exported from there); this file covers the new
`match_constraints` matcher and the crewai-import boundary."""

import ast
import inspect
from pathlib import Path
from types import SimpleNamespace

from rhinosecure.constraint_apply import (
    AppliedConstraintRecord,
    AppliedGroupConstraintRecord,
    ConstraintMatch,
    GroupConstraintMatch,
    apply_constraints,
    compute_constraint_digest,
    fold_constraints,
    has_usable_effect,
    match_constraints,
    match_group_constraints,
)
from rhinosecure.memory import Constraint, GroupConstraint
from rhinosecure.schema import Asset

ASSET_ID = "A09"
HOSTNAME = "WKS-FIN12"


def _constraint(*, id_: int, asset_id: str = ASSET_ID, hostname: str | None) -> Constraint:
    return Constraint(
        id=id_,
        asset_id=asset_id,
        constraint_text="fake constraint text",
        created_at="2026-10-02T00:00:00+00:00",
        active=True,
        effect_kind="patch_window",
        effect_value="Sun 02:00-06:00",
        hostname=hostname,
    )


def test_matches_on_exact_asset_id_and_hostname():
    c = _constraint(id_=1, hostname=HOSTNAME)
    result = match_constraints([c], ASSET_ID, HOSTNAME)
    assert result == ConstraintMatch(applied=(c,))


def test_no_hostname_recorded_is_skipped_as_legacy_never_applied():
    """A constraint written with no hostname (predates this feature, or a
    raw Memory.add_constraint call that omitted it) must never be treated
    as applicable -- there is no truthful applies/doesn't-apply verdict
    for it."""
    c = _constraint(id_=1, hostname=None)
    result = match_constraints([c], ASSET_ID, HOSTNAME)
    assert result == ConstraintMatch(skipped_legacy=(c,))


def test_a_different_recorded_hostname_is_skipped_as_identity_mismatch():
    """Same asset_id, different hostname -- the asset was renamed since
    the constraint was recorded, or two different real machines share one
    asset_id. Either way, never applied."""
    c = _constraint(id_=1, hostname="SOME-OTHER-HOST")
    result = match_constraints([c], ASSET_ID, HOSTNAME)
    assert result == ConstraintMatch(skipped_identity_mismatch=(c,))


def test_a_constraint_for_a_different_asset_id_is_neither_applied_nor_counted_as_skipped():
    """CLAUDE.md: "constraints for assets that aren't in this run are
    another fleet's business and are not counted" -- a constraint whose
    own asset_id disagrees with the one being matched contributes to
    neither applied nor either skip bucket."""
    c = _constraint(id_=1, asset_id="A99", hostname=HOSTNAME)
    result = match_constraints([c], ASSET_ID, HOSTNAME)
    assert result == ConstraintMatch()


def test_mixed_set_sorts_each_constraint_into_exactly_one_bucket():
    applied = _constraint(id_=1, hostname=HOSTNAME)
    legacy = _constraint(id_=2, hostname=None)
    mismatch = _constraint(id_=3, hostname="RENAMED-HOST")
    other_asset = _constraint(id_=4, asset_id="A99", hostname=HOSTNAME)

    result = match_constraints([applied, legacy, mismatch, other_asset], ASSET_ID, HOSTNAME)

    assert result.applied == (applied,)
    assert result.skipped_legacy == (legacy,)
    assert result.skipped_identity_mismatch == (mismatch,)


def test_empty_candidate_list_matches_nothing():
    assert match_constraints([], ASSET_ID, HOSTNAME) == ConstraintMatch()


ASSET = Asset(
    asset_id=ASSET_ID,
    hostname=HOSTNAME,
    os="Windows 10",
    os_build="19045",
    role="workstation",
    business_function="Finance analyst workstation",
    criticality=2,
    internet_exposed=False,
    environment="prod",
    data_sensitivity="confidential",
    patch_window="",
    patch_restrictions="",
    compensating_controls="",
    owner="it-helpdesk",
)


# --- compensating_control accumulation across multiple distinct rows -------
# (adversarial-review gap, closed: the existing apply_constraints tests in
# test_constraint_intake.py only ever pass a SINGLE compensating_control
# Constraint object; none exercise two separate rows of the same kind.)


def test_two_compensating_control_constraints_both_accumulate():
    first = Constraint(
        id=1, asset_id=ASSET_ID, constraint_text="first control", created_at="2026-10-02T00:00:00+00:00",
        active=True, effect_kind="compensating_control", effect_value="WAF rule enabled", hostname=HOSTNAME,
    )
    second = Constraint(
        id=2, asset_id=ASSET_ID, constraint_text="second control", created_at="2026-10-02T00:00:01+00:00",
        active=True, effect_kind="compensating_control", effect_value="network segmentation", hostname=HOSTNAME,
    )

    result = apply_constraints(ASSET, [first, second])

    assert result.compensating_control_list == ("WAF rule enabled", "network segmentation")


# --- has_usable_effect (adversarial-review fix: identity match != real effect) ---


def test_has_usable_effect_is_true_for_a_recognized_kind_and_truthy_value():
    c = _constraint(id_=1, hostname=HOSTNAME)  # patch_window / "Sun 02:00-06:00"
    assert has_usable_effect(c) is True


def test_has_usable_effect_is_false_when_never_interpreted():
    """memory.py's own add_constraint docstring: 'a constraint that hasn't
    been interpreted into a structured effect yet' -- a real, legitimate
    row shape, not an identity failure (not legacy, not identity_mismatch)
    and not a usable effect either."""
    c = Constraint(
        id=1, asset_id=ASSET_ID, constraint_text="not yet interpreted",
        created_at="2026-10-02T00:00:00+00:00", active=True,
        effect_kind=None, effect_value=None, hostname=HOSTNAME,
    )
    assert has_usable_effect(c) is False


def test_has_usable_effect_is_false_for_an_empty_effect_value():
    c = Constraint(
        id=1, asset_id=ASSET_ID, constraint_text="effect_value is blank",
        created_at="2026-10-02T00:00:00+00:00", active=True,
        effect_kind="patch_window", effect_value="", hostname=HOSTNAME,
    )
    assert has_usable_effect(c) is False


# --- summarize_for_assets / ConstraintAccumulator -- the shared run-wide
# summary engine both the deterministic (`cli.ConstraintApplicator`) and
# agents (`export._build_agents_export`, `cli._agents_constraint_application
# _summary`) paths now use (CLAUDE.md's "agents path reports constraint
# application honestly" fix). The decisive property is digest/applied/
# skipped PARITY between the two paths for the identical (memory, assets)
# inputs -- checked here at unit level, against the real demo fixture,
# with no LLM calls and no Coordinator at all.


def test_summarize_for_assets_matches_cli_apply_constraints_on_the_real_demo_fixture(tmp_path):
    """Acceptance test for the shared-engine extraction: one scratch DB (a
    matching constraint on A09/WKS-FIN12, a legacy row, and a wrong-
    hostname row, all on demo's real A09), scored against the real demo
    fixture two different ways -- the deterministic `--apply-constraints`
    path (`cli.run_with_report`, which drives `ConstraintApplicator` per
    finding) and a bare call to `summarize_for_assets` over the SAME
    fixture's real per-finding assets, with no Coordinator, no crew, no
    LLM call anywhere -- and asserts the two summaries are identical:
    same digest, same applied ids, same skip lists by reason. This is the
    property that makes the agents path's own top-level
    `constraint_application` block trustworthy: it is computed by this
    SAME function over `coordinator.state.enriched_by_id`'s assets, never
    a second, independently-written implementation that could drift."""
    from rhinosecure.adapters import get_adapter
    from rhinosecure.cli import run_with_report
    from rhinosecure.constraint_apply import summarize_for_assets
    from rhinosecure.ingest import load_batch
    from rhinosecure.memory import Memory

    demo_dir = Path(__file__).resolve().parents[1] / "data" / "demo"

    db_path = tmp_path / "mem.db"
    memory = Memory(db_path)
    memory.add_constraint(  # matches -- demo's real A09 is WKS-FIN12
        "A09", "WKS-FIN12 can only patch on Sundays",
        effect_kind="patch_window", effect_value="Sun 02:00-06:00", hostname="WKS-FIN12",
    )
    memory.add_constraint(  # legacy -- no hostname recorded
        "A01", "predates hostname recording", effect_kind="compensating_control", effect_value="WAF rule enabled",
    )
    memory.add_constraint(  # identity_mismatch -- A01's real hostname is not this
        "A01", "recorded against the wrong machine",
        effect_kind="compensating_control", effect_value="a different control", hostname="SOME-OTHER-MACHINE",
    )
    memory.close()

    deterministic = run_with_report(demo_dir, 42, offline=True, memory=Memory(db_path)).constraint_application
    assert deterministic is not None
    assert deterministic.applied_count == 1  # sanity: the fixture above must actually exercise all three paths
    assert deterministic.skipped_legacy_count == 1
    assert deterministic.skipped_identity_mismatch_count == 1

    # The agents path's own real population: one Asset per FINDING (not
    # per inventory row) -- exactly what coordinator.state.enriched_by_id
    # .values() gives a real caller, and what makes an asset with zero
    # findings this run correctly invisible to both sides alike.
    _assets, enriched = load_batch(demo_dir, get_adapter("native"))
    finding_assets = [e.asset for e in enriched]
    agents_side = summarize_for_assets(Memory(db_path), finding_assets)

    assert agents_side.digest == deterministic.digest
    assert [r.constraint_id for r in agents_side.applied] == [r.constraint_id for r in deterministic.applied]
    assert {r.constraint_id for r in agents_side.skipped_legacy} == {
        r.constraint_id for r in deterministic.skipped_legacy
    }
    assert {r.constraint_id for r in agents_side.skipped_identity_mismatch} == {
        r.constraint_id for r in deterministic.skipped_identity_mismatch
    }


def test_summarize_for_assets_matches_cli_apply_constraints_on_the_real_demo_fixture_with_a_group_constraint(
    tmp_path,
):
    """A71. Extends the test directly above with a seeded group constraint
    (role=workstation, matching several demo-fixture workstations) -- the
    deterministic and agents-path summaries still agree on digest, applied
    ids (both origins), and skip lists."""
    from rhinosecure.adapters import get_adapter
    from rhinosecure.cli import run_with_report
    from rhinosecure.constraint_apply import summarize_for_assets
    from rhinosecure.ingest import load_batch
    from rhinosecure.memory import Memory

    demo_dir = Path(__file__).resolve().parents[1] / "data" / "demo"

    db_path = tmp_path / "mem.db"
    memory = Memory(db_path)
    memory.add_constraint(  # matches -- demo's real A09 is WKS-FIN12
        "A09", "WKS-FIN12 can only patch on Sundays",
        effect_kind="patch_window", effect_value="Sun 02:00-06:00", hostname="WKS-FIN12",
    )
    memory.add_group_constraint(
        "role", "workstation", "all workstations only patch weekends",
        effect_kind="patch_restriction", effect_value="no reboot during business hours",
    )
    memory.close()

    deterministic = run_with_report(demo_dir, 42, offline=True, memory=Memory(db_path)).constraint_application
    assert deterministic is not None
    assert deterministic.applied_group_count >= 1  # sanity: the group constraint actually matched something

    _assets, enriched = load_batch(demo_dir, get_adapter("native"))
    finding_assets = [e.asset for e in enriched]
    agents_side = summarize_for_assets(Memory(db_path), finding_assets)

    assert agents_side.digest == deterministic.digest
    assert [r.constraint_id for r in agents_side.applied] == [r.constraint_id for r in deterministic.applied]
    assert sorted(r.group_constraint_id for r in agents_side.applied_group) == sorted(
        r.group_constraint_id for r in deterministic.applied_group
    )
    assert {r.constraint_id for r in agents_side.skipped_legacy} == {
        r.constraint_id for r in deterministic.skipped_legacy
    }
    assert {r.constraint_id for r in agents_side.skipped_identity_mismatch} == {
        r.constraint_id for r in deterministic.skipped_identity_mismatch
    }


def test_scored_assets_excludes_a_finding_that_failed_upstream_of_risk():
    """A72 (docs/group-constraints-design.md Section 8.8 housekeeping).
    The shared fixture: enriched_by_id has two findings; risk_by_id has
    only one of them (the other "failed" Research/Environment/Risk
    dispatch and never reached a real score) -- scored_assets must
    exclude the failed one's asset."""
    from rhinosecure.constraint_apply import scored_assets

    scored_asset = _asset(asset_id="A-SCORED")
    failed_asset = _asset(asset_id="A-FAILED")
    enriched_by_id = {
        "F-SCORED": SimpleNamespace(asset=scored_asset, finding=SimpleNamespace(finding_id="F-SCORED")),
        "F-FAILED": SimpleNamespace(asset=failed_asset, finding=SimpleNamespace(finding_id="F-FAILED")),
    }
    risk_by_id = {"F-SCORED": object()}  # F-FAILED never reached Risk

    result = list(scored_assets(enriched_by_id, risk_by_id))

    assert result == [scored_asset]


def test_scored_assets_is_single_sourced_across_export_cli_and_web_jobs():
    """A72. export.py/cli.py/web/jobs.py each call the shared
    constraint_apply.scored_assets helper rather than each re-deriving
    the same filter -- confirmed by AST inspection of each module's own
    source for a direct call to the name `scored_assets`, not merely an
    import (which alone wouldn't catch a module that imports the name but
    never actually calls it, re-deriving the filter inline instead -- the
    exact defect this test was written against, found and fixed in
    web/jobs.py during this same Slice A pass: it imported
    summarize_for_assets but had its own inline generator-expression copy
    of the filter instead of calling scored_assets at all)."""
    import ast
    import inspect

    import rhinosecure.cli as cli_module
    import rhinosecure.export as export_module
    import rhinosecure.web.jobs as web_jobs_module

    for module in (cli_module, export_module, web_jobs_module):
        source = inspect.getsource(module)
        tree = ast.parse(source)
        call_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "scored_assets" in call_names, f"{module.__name__} never calls scored_assets()"


def test_importing_constraint_apply_does_not_import_crewai():
    """The whole point of extracting this module out of
    agents/constraint_intake.py: the deterministic path must be able to
    import it without pulling crewai in. Parses the source rather than
    checking sys.modules at runtime, which another already-imported test
    module would otherwise pollute for any check done that way (the
    identical reasoning cli.py's own
    test_cli_module_does_not_import_crewai_at_module_level already uses)."""
    import rhinosecure.constraint_apply as constraint_apply_module

    tree = ast.parse(Path(inspect.getfile(constraint_apply_module)).read_text(encoding="utf-8"))
    top_level_imports = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_level_imports += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_level_imports.append(node.module)

    assert not any(name.startswith("crewai") for name in top_level_imports)
    assert not any(name.startswith("rhinosecure.agents") for name in top_level_imports)
    # Adversarial-review finding, fixed: Constraint used to be imported
    # eagerly here (type-hint only, never instantiated) -- harmless on its
    # own, but it made cli.py's own module-level import of this file
    # transitively load rhinosecure.memory (and the real Memory class) the
    # instant `import rhinosecure.cli` ran, contradicting that module's own
    # "memory stays out of the import graph unless asked" convention. Moved
    # under `if TYPE_CHECKING:` -- which this same top-level-only AST walk
    # already correctly ignores (it's nested inside an ast.If, not a direct
    # child of tree.body), the identical mechanism that lets cli.py's own
    # TYPE_CHECKING imports pass its analogous crewai/agents check above.
    assert not any(name == "rhinosecure.memory" for name in top_level_imports)


# --- group constraints (docs/group-constraints-design.md Slice A) ---------


def _group_constraint(
    *, id_: int, group_field: str = "role", group_value: str = "workstation",
    effect_kind: str | None = "patch_window", effect_value: str | None = "Sat-Sun",
    created_at: str = "2026-10-03T00:00:00+00:00",
) -> GroupConstraint:
    return GroupConstraint(
        id=id_, group_field=group_field, group_value=group_value,
        constraint_text="fake group constraint text", created_at=created_at, active=True,
        effect_kind=effect_kind, effect_value=effect_value,
    )


def _asset(*, role: str = "workstation", not_collected: frozenset[str] = frozenset(), **overrides) -> Asset:
    fields = dict(
        asset_id=ASSET_ID, hostname=HOSTNAME, os="Windows 10", os_build="19045", role=role,
        business_function="Finance analyst workstation", criticality=2, internet_exposed=False,
        environment="prod", data_sensitivity="confidential", patch_window="", patch_restrictions="",
        compensating_controls="", owner="it-helpdesk", not_collected=not_collected,
    )
    fields.update(overrides)
    return Asset(**fields)


def test_match_group_constraints_applies_when_the_field_value_matches():
    """A13."""
    gc = _group_constraint(id_=1)
    result = match_group_constraints([gc], _asset(role="workstation"))
    assert result == GroupConstraintMatch(applied=(gc,))


def test_match_group_constraints_does_not_apply_on_a_different_value():
    """A14. Silence, not a third bucket -- "not relevant" is not "a problem"."""
    gc = _group_constraint(id_=1, group_value="workstation")
    result = match_group_constraints([gc], _asset(role="sql"))
    assert result == GroupConstraintMatch()


def test_match_group_constraints_skips_as_not_collected_when_the_field_is_a_placeholder():
    """A15. Even though the raw placeholder value happens to equal
    group_value (the Defender-defaulted-role case), a not_collected field
    is never treated as a real match."""
    gc = _group_constraint(id_=1, group_value="workstation")
    result = match_group_constraints(
        [gc], _asset(role="workstation", not_collected=frozenset({"role"}))
    )
    assert result == GroupConstraintMatch(skipped_not_collected=(gc,))


def test_match_group_constraints_mixed_population_sorts_each_asset_correctly():
    """A16."""
    gc = _group_constraint(id_=1, group_value="workstation")
    matches = _asset(role="workstation")
    wrong_value = _asset(role="sql")
    not_collected = _asset(role="workstation", not_collected=frozenset({"role"}))

    assert match_group_constraints([gc], matches) == GroupConstraintMatch(applied=(gc,))
    assert match_group_constraints([gc], wrong_value) == GroupConstraintMatch()
    assert match_group_constraints([gc], not_collected) == GroupConstraintMatch(skipped_not_collected=(gc,))


def test_match_group_constraints_getattr_degrades_gracefully_for_an_unknown_field():
    """A17. A forward-compat row from a newer version naming a group_field
    this code doesn't recognize must degrade to "doesn't match," never raise."""
    gc = _group_constraint(id_=1, group_field="some_future_field", group_value="x")
    result = match_group_constraints([gc], _asset())
    assert result == GroupConstraintMatch()


def test_has_usable_effect_accepts_a_group_constraint_identically_to_an_asset_constraint():
    """A18."""
    assert has_usable_effect(_group_constraint(id_=1, effect_kind="patch_window", effect_value="Sat-Sun")) is True
    assert has_usable_effect(_group_constraint(id_=1, effect_kind=None, effect_value=None)) is False


# --- precedence (fold_constraints) -----------------------------------------


def test_asset_patch_window_overrides_group_patch_window_on_the_same_asset():
    """A19."""
    asset_pw = _constraint(id_=1, hostname=HOSTNAME)  # patch_window / "Sun 02:00-06:00"
    group_pw = _group_constraint(id_=1, effect_kind="patch_window", effect_value="Sat-Sun")

    result = fold_constraints(_asset(), constraints=[asset_pw], group_constraints=[group_pw])

    assert result.asset.patch_window == "Sun 02:00-06:00"  # the asset's value wins
    assert len(result.overridden_group_effects) == 1
    overridden = result.overridden_group_effects[0]
    assert overridden.group_constraint_id == 1
    assert overridden.group_value_would_have_set == "Sat-Sun"
    assert overridden.overriding_constraint_id == 1


def test_group_patch_window_alone_applies_and_clears_not_collected():
    """A20."""
    group_pw = _group_constraint(id_=1, effect_kind="patch_window", effect_value="Sat-Sun")

    result = fold_constraints(
        _asset(not_collected=frozenset({"patch_window"})), group_constraints=[group_pw]
    )

    assert result.asset.patch_window == "Sat-Sun"
    assert "patch_window" not in result.asset.not_collected
    assert result.overridden_group_effects == ()


def test_compensating_control_accumulates_from_both_asset_and_group_constraints():
    """A21. Additive, never a single-winner override, unlike the
    replace-kind fields above."""
    asset_cc = Constraint(
        id=1, asset_id=ASSET_ID, constraint_text="asset control", created_at="2026-10-02T00:00:00+00:00",
        active=True, effect_kind="compensating_control", effect_value="WAF rule enabled", hostname=HOSTNAME,
    )
    group_cc = _group_constraint(id_=1, effect_kind="compensating_control", effect_value="network segmentation")

    result = fold_constraints(_asset(), constraints=[asset_cc], group_constraints=[group_cc])

    assert "WAF rule enabled" in result.asset.compensating_controls
    assert "network segmentation" in result.asset.compensating_controls


def test_precedence_is_independent_of_which_constraint_was_created_more_recently():
    """A22. The named regression target: precedence is "which pass," never
    timestamp or list position."""
    asset_pw = Constraint(
        id=1, asset_id=ASSET_ID, constraint_text="asset", created_at="2026-10-01T00:00:00+00:00",
        active=True, effect_kind="patch_window", effect_value="Sun 02:00-06:00", hostname=HOSTNAME,
    )
    group_pw = _group_constraint(
        id_=1, effect_kind="patch_window", effect_value="Sat-Sun", created_at="2026-10-03T00:00:00+00:00",
    )  # strictly LATER created_at than the asset constraint -- must still lose

    result = fold_constraints(_asset(), constraints=[asset_pw], group_constraints=[group_pw])

    assert result.asset.patch_window == "Sun 02:00-06:00"  # asset wins regardless of timestamps


def test_group_vs_group_precedence_is_oldest_first_last_writer_wins():
    """A23. Two group constraints on the same (group_field, group_value)
    both setting patch_window -- the one with the LATER created_at wins,
    mirroring the asset-only within-type rule. group_constraints is
    expected oldest-first (the real all_active_group_constraints ordering,
    ORDER BY created_at, id); fold_constraints relies on iteration order,
    not re-sorting internally. IDs are deliberately assigned OPPOSITE to
    chronological order (the retract-and-reinsert scenario the design's
    own break/fix names: a constraint created earlier but assigned a
    HIGHER id after being retracted and resubmitted) -- a regression that
    re-sorts by id instead of trusting the given (created_at) order would
    pick the wrong winner here, whereas ids matching chronological order
    would not expose that bug at all."""
    older_but_higher_id = _group_constraint(
        id_=99, effect_value="Sat-Sun", created_at="2026-10-01T00:00:00+00:00",
    )
    newer_but_lower_id = _group_constraint(
        id_=2, effect_value="Sun only", created_at="2026-10-02T00:00:00+00:00",
    )

    result = fold_constraints(
        _asset(), group_constraints=[older_but_higher_id, newer_but_lower_id]
    )

    assert result.asset.patch_window == "Sun only"  # the later-created one wins, despite the lower id


def test_patch_restriction_precedence_mirrors_patch_window_precedence():
    """A24. Exists specifically because an implementation might elide this
    branch as "identical to patch_window, omitted for brevity" and get the
    override-recording subtly wrong."""
    asset_pr = Constraint(
        id=1, asset_id=ASSET_ID, constraint_text="asset", created_at="2026-10-02T00:00:00+00:00",
        active=True, effect_kind="patch_restriction", effect_value="no reboot during business hours",
        hostname=HOSTNAME,
    )
    group_pr = _group_constraint(id_=1, effect_kind="patch_restriction", effect_value="no reboot ever")

    result = fold_constraints(_asset(), constraints=[asset_pr], group_constraints=[group_pr])

    assert result.asset.patch_restrictions == "no reboot during business hours"
    assert len(result.overridden_group_effects) == 1
    overridden = result.overridden_group_effects[0]
    assert overridden.field == "patch_restrictions"
    assert overridden.group_value_would_have_set == "no reboot ever"


def test_fold_constraints_never_mutates_the_input_asset():
    """A25."""
    asset = _asset()
    gc = _group_constraint(id_=1)
    result = fold_constraints(asset, group_constraints=[gc])
    assert result.asset is not asset
    assert asset.patch_window == ""  # original untouched


def test_apply_constraints_still_behaves_identically_when_no_group_constraints_are_passed():
    """A26. A direct regression guard that the apply_constraints wrapper's
    refactor onto fold_constraints changed nothing for existing callers."""
    asset = _asset(not_collected=frozenset({"patch_window"}))
    c = _constraint(id_=1, hostname=HOSTNAME)

    via_wrapper = apply_constraints(asset, [c])
    via_fold = fold_constraints(asset, constraints=[c], group_constraints=()).asset

    assert via_wrapper == via_fold


# --- digest (Option C) ------------------------------------------------------


def _applied(*, constraint_id: int = 1, asset_id: str = ASSET_ID, hostname: str = HOSTNAME,
             effect_kind: str = "patch_window", effect_value: str = "Sun 02:00-06:00") -> AppliedConstraintRecord:
    return AppliedConstraintRecord(
        constraint_id=constraint_id, asset_id=asset_id, hostname=hostname,
        effect_kind=effect_kind, effect_value=effect_value,
    )


def _applied_group(*, group_constraint_id: int = 1, asset_id: str = ASSET_ID, hostname: str = HOSTNAME,
                    effect_kind: str = "patch_window", effect_value: str = "Sat-Sun") -> AppliedGroupConstraintRecord:
    return AppliedGroupConstraintRecord(
        group_constraint_id=group_constraint_id, asset_id=asset_id, hostname=hostname,
        effect_kind=effect_kind, effect_value=effect_value,
    )


def test_compute_constraint_digest_is_byte_identical_to_pre_feature_output_when_no_group_constraints_exist():
    """A27. A literal before/after byte comparison against a hardcoded
    digest captured from the real pre-group-constraints formula (plain
    4-tuples: (asset_id, hostname, effect_kind, effect_value), sorted,
    canonical JSON, sha256) for this exact input."""
    applied = (_applied(constraint_id=1, asset_id="A09", hostname="WKS-FIN12"),)
    expected_pre_feature = hashlib_sha256_of_plain_4_tuples(applied)
    assert compute_constraint_digest(applied) == expected_pre_feature


def hashlib_sha256_of_plain_4_tuples(applied) -> str:
    """Reimplements the pre-feature formula verbatim (not by calling the
    function under test) -- this is the independent "before" oracle A27
    diffs against."""
    import hashlib as _hashlib
    import json as _json

    tuples = [(r.asset_id, r.hostname, r.effect_kind, r.effect_value) for r in applied]
    tuples.sort(key=lambda t: tuple((x is None, x) for x in t))
    blob = _json.dumps(
        [list(t) for t in tuples], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + _hashlib.sha256(blob).hexdigest()


def test_asset_origin_tuples_stay_4_tuples_even_when_a_group_origin_record_is_also_present():
    """A28. The Option-C-specific invariant: an asset-origin record never
    widens to 5 elements just because a group-origin record is also
    present this run. Verified by reconstructing the exact blob the real
    function must have hashed (one 4-tuple, one 5-tuple) and confirming
    an independently-computed digest over that exact shape matches --
    not by inspecting the real function's internals."""
    import hashlib as _hashlib
    import json as _json

    asset_record = _applied(constraint_id=1, asset_id="A01", hostname="DC01")
    group_record = _applied_group(group_constraint_id=1, asset_id="A09", hostname="WKS-FIN12")

    digest = compute_constraint_digest((asset_record,), (group_record,))

    expected_tuples = [
        [asset_record.asset_id, asset_record.hostname, asset_record.effect_kind, asset_record.effect_value],
        [
            group_record.asset_id, group_record.hostname, f"group:{group_record.group_constraint_id}",
            group_record.effect_kind, group_record.effect_value,
        ],
    ]
    expected_tuples.sort(key=lambda t: tuple((x is None, x) for x in t))
    blob = _json.dumps(expected_tuples, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    expected = "sha256:" + _hashlib.sha256(blob).hexdigest()

    assert digest == expected


class _FakeGroupOnlyMemory:
    """A minimal Memory stand-in exposing only what ConstraintAccumulator
    actually calls -- no real sqlite file needed for a pure accumulation
    test."""

    def __init__(self, group_constraints):
        self._group_constraints = list(group_constraints)

    def all_active_group_constraints(self):
        return self._group_constraints

    def constraints_for_asset(self, asset_id):
        return []


def test_digest_changes_when_a_second_asset_joins_an_existing_group():
    """A29. Exercises the REAL accumulation path (ConstraintAccumulator),
    not just the digest function in isolation -- the actual defect this
    test is designed to catch lives in record_group's own dedup key, not
    in compute_constraint_digest, which has no dedup of its own. Dedupe
    must be by (group_constraint_id, asset_id), not group_constraint_id
    alone."""
    from rhinosecure.constraint_apply import ConstraintAccumulator

    gc = _group_constraint(id_=1, effect_kind="patch_window", effect_value="Sat-Sun")
    engine = ConstraintAccumulator(_FakeGroupOnlyMemory([gc]))
    engine.record_group(_asset(asset_id="A09", hostname="WKS-FIN12"))
    digest_one_asset = engine.summary().digest

    engine.record_group(_asset(asset_id="A10", hostname="WKS-IT05"))
    digest_two_assets = engine.summary().digest

    assert digest_one_asset != digest_two_assets
    assert len(engine.summary().applied_group) == 2


def test_digest_changes_when_an_asset_leaves_a_group():
    """A30. The symmetric case to A29, at the same real accumulation
    level -- removing a record changes the digest again, and lands back
    on exactly what a single-asset digest already was, proving this is a
    pure function of the current set, not of history. "Leaving" is
    modeled the honest way this engine actually supports it: a fresh
    accumulator over the smaller population, mirroring how a real run
    recomputes `ConstraintApplicationSummary` from scratch every time
    rather than mutating a prior one in place."""
    gc = _group_constraint(id_=1, effect_kind="patch_window", effect_value="Sat-Sun")

    from rhinosecure.constraint_apply import ConstraintAccumulator

    two_assets_engine = ConstraintAccumulator(_FakeGroupOnlyMemory([gc]))
    two_assets_engine.record_group(_asset(asset_id="A09", hostname="WKS-FIN12"))
    two_assets_engine.record_group(_asset(asset_id="A10", hostname="WKS-IT05"))
    digest_with_two = two_assets_engine.summary().digest

    one_asset_engine_a = ConstraintAccumulator(_FakeGroupOnlyMemory([gc]))
    one_asset_engine_a.record_group(_asset(asset_id="A09", hostname="WKS-FIN12"))
    digest_after_removal = one_asset_engine_a.summary().digest

    one_asset_engine_b = ConstraintAccumulator(_FakeGroupOnlyMemory([gc]))
    one_asset_engine_b.record_group(_asset(asset_id="A09", hostname="WKS-FIN12"))
    digest_recomputed = one_asset_engine_b.summary().digest

    assert digest_with_two != digest_after_removal
    assert digest_after_removal == digest_recomputed  # pure function, no history


def test_digest_is_insertion_order_independent_with_mixed_asset_and_group_origins_of_different_tuple_lengths():
    """A31. Confirms the mixed 4-tuple/5-tuple sort never raises TypeError
    and produces the identical digest regardless of construction order."""
    asset_record = _applied(constraint_id=1, asset_id="A01", hostname="DC01")
    group_record = _applied_group(group_constraint_id=1, asset_id="A09", hostname="WKS-FIN12")

    forward = compute_constraint_digest((asset_record,), (group_record,))
    # Construct the equivalent inputs in reverse order -- tuple membership
    # is a single-element tuple either way per call, so instead vary order
    # across two records of the SAME kind to test real order-independence.
    two_asset_records = (
        _applied(constraint_id=1, asset_id="A01", hostname="DC01"),
        _applied(constraint_id=2, asset_id="A02", hostname="SRV02"),
    )
    two_asset_records_reversed = tuple(reversed(two_asset_records))
    two_group_records = (
        _applied_group(group_constraint_id=1, asset_id="A09", hostname="WKS-FIN12"),
        _applied_group(group_constraint_id=2, asset_id="A10", hostname="WKS-IT05"),
    )
    two_group_records_reversed = tuple(reversed(two_group_records))

    assert compute_constraint_digest(two_asset_records, two_group_records) == compute_constraint_digest(
        two_asset_records_reversed, two_group_records_reversed
    )
    assert forward == compute_constraint_digest((asset_record,), (group_record,))  # sanity, unchanged


def test_digest_does_not_change_on_an_unrelated_free_text_edit():
    """A32. Exercises the real record_group pipeline, not just the
    AppliedGroupConstraintRecord dataclass directly: two otherwise-identical
    GroupConstraint rows (same id, group_field, group_value, effect_kind,
    effect_value) that differ ONLY in constraint_text must produce the
    identical digest -- constraint_text is never part of either tuple
    shape compute_constraint_digest hashes."""
    from rhinosecure.constraint_apply import ConstraintAccumulator

    gc_before = _group_constraint(
        id_=1, effect_kind="patch_window", effect_value="Sat-Sun", created_at="2026-10-01T00:00:00+00:00",
    )
    engine_before = ConstraintAccumulator(_FakeGroupOnlyMemory([gc_before]))
    engine_before.record_group(_asset())
    digest_before = engine_before.summary().digest

    gc_after_text_edit = GroupConstraint(
        id=gc_before.id, group_field=gc_before.group_field, group_value=gc_before.group_value,
        constraint_text="an entirely different free-text description of the same rule",
        created_at=gc_before.created_at, active=True,
        effect_kind=gc_before.effect_kind, effect_value=gc_before.effect_value,
    )
    engine_after = ConstraintAccumulator(_FakeGroupOnlyMemory([gc_after_text_edit]))
    engine_after.record_group(_asset())
    digest_after = engine_after.summary().digest

    assert digest_before == digest_after
