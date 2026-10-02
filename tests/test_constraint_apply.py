"""constraint_apply.py -- the crewai-free matcher/overlay module (CLAUDE.md's
machine-identity constraint scoping entry). `apply_constraints`'s own
pure-overlay behavior is already covered by test_constraint_intake.py
(unchanged by the move, re-exported from there); this file covers the new
`match_constraints` matcher and the crewai-import boundary."""

import ast
import inspect
from pathlib import Path

from rhinosecure.constraint_apply import ConstraintMatch, match_constraints
from rhinosecure.memory import Constraint

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
