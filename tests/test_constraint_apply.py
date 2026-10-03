"""constraint_apply.py -- the crewai-free matcher/overlay module (CLAUDE.md's
machine-identity constraint scoping entry). `apply_constraints`'s own
pure-overlay behavior is already covered by test_constraint_intake.py
(unchanged by the move, re-exported from there); this file covers the new
`match_constraints` matcher and the crewai-import boundary."""

import ast
import inspect
from pathlib import Path

from rhinosecure.constraint_apply import ConstraintMatch, apply_constraints, has_usable_effect, match_constraints
from rhinosecure.memory import Constraint
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
