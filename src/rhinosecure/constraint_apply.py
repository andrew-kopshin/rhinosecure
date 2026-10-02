"""Crewai-free constraint application: the asset-identity matcher and the
LLM-free overlay (`apply_constraints`) that folds a matched constraint's
effect onto an `Asset`. Extracted out of `agents/constraint_intake.py`
(which imports `crewai` at module level) so the deterministic path
(`cli.py`'s `--apply-constraints`) can reuse the identical fold the agents
path already uses, without pulling crewai into a path that must keep
running on core dependencies alone. `agents/constraint_intake.py`
re-exports both `ConstraintEffectKind` and `apply_constraints` from here
for backward compatibility; neither's behavior changed in the move.

**Why machine identity (asset_id + hostname), not "source."** An earlier
design (see `out/constraint-source-scoping-survey.md`) explored scoping a
constraint to the run/upload/contract it was submitted against. Measuring
that design against real data showed every version of it fails one of its
own cases: scoping by directory silently drops a constraint across a
byte-identical re-upload of the same fleet (a fresh `upload_id` every
time); scoping by format collides two unrelated assets that happen to
share one adapter's bare name (confirmed: `demo`'s `A01`, a domain
controller, and `cp1252-sample`'s `A01`, a workstation, share nothing but
a coincidental id string).

A constraint is a fact about a MACHINE -- "the payroll server only
reboots on Sundays" -- not about which file or run that machine happened
to appear in. `Asset.hostname` is required on every `Asset` regardless of
source (`schema.py`), so it is always available to compare, unlike any
notion of a run's "source." Keying on the resolved asset's own
`(asset_id, hostname)` pair at submission time, and matching on both at
application time, sidesteps both measured failures: a re-upload of the
same machine still carries the same asset_id/hostname pair, so it
matches regardless of path; two different real machines that happen to
share one asset_id are told apart because their hostnames differ.

`match_constraints` is the ONE matcher (CLAUDE.md's "no second rule"),
used identically by the deterministic path (`cli.run_with_report`'s own
`ConstraintApplicator`) and every agents-path read site
(`agents/risk.py`'s `score_finding_tool`, `agents/environment.py`'s
`lookup_asset_context`, `agents/coordinator.py`'s
`_submit_capacity_constraint`, and `export.py`'s `_agents_decomposition`).
A `Constraint` recorded before the `hostname` column existed, or whose
resolved asset somehow had none recorded, has `hostname=None` -- `legacy`
below: never applied, always reported, never silently dropped. An
asset_id match with a DIFFERENT hostname -- `identity_mismatch` below --
is the live case this exists to catch: the machine was renamed since the
constraint was recorded, or two different real assets in two different
ingests happen to share one id.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from rhinosecure.schema import Asset

if TYPE_CHECKING:
    # Type-hint only: constraint_apply.py must stay crewai-free, but it must
    # also not pull rhinosecure.memory into sys.modules just by being
    # imported -- an adversarial review of this feature's first version
    # caught that cli.py's own module-level import of this file was
    # transitively loading memory.py (and the real Memory class) the
    # instant `import rhinosecure.cli` ran, contradicting this module's own
    # "memory requires a Coordinator... stays out of that path's import
    # graph" convention even though no Memory instance was ever actually
    # CONSTRUCTED. `Constraint` is never instantiated or isinstance-checked
    # here, only used in type hints, so TYPE_CHECKING-only is correct and
    # `from __future__ import annotations` (above) makes every annotation
    # in this file a lazily-evaluated string regardless.
    from rhinosecure.memory import Constraint


class ConstraintEffectKind(str, Enum):
    PATCH_WINDOW = "patch_window"
    COMPENSATING_CONTROL = "compensating_control"
    PATCH_RESTRICTION = "patch_restriction"


@dataclass(frozen=True)
class ConstraintMatch:
    """The result of matching one asset's stored constraints against its
    own current identity. `applied` is what `apply_constraints` should
    actually fold in; `skipped_legacy`/`skipped_identity_mismatch` are for
    reporting only (CLAUDE.md's skip-count-by-reason requirement) -- never
    folded into scoring themselves."""

    applied: tuple[Constraint, ...] = ()
    skipped_legacy: tuple[Constraint, ...] = ()
    skipped_identity_mismatch: tuple[Constraint, ...] = ()


def match_constraints(constraints: list[Constraint], asset_id: str, hostname: str) -> ConstraintMatch:
    """The one matcher. `constraints` should already be scoped to
    `asset_id` (`Memory.constraints_for_asset`'s own contract) -- a
    constraint whose own `asset_id` disagrees with the one passed in is
    neither applied nor counted as skipped ("constraints for assets that
    aren't in this run are another fleet's business and are not
    counted"); callers only ever reach this with one asset's own
    constraints, but the check is defensive here too in case a caller
    ever passes an unfiltered list.

    A constraint with no recorded hostname (`hostname is None`) is
    `legacy` -- it predates this feature's hostname column, or something
    went wrong recording it, and there is no truthful applies/doesn't-
    apply verdict for it, so it is never applied. A constraint whose
    asset_id matches but whose hostname does not is `identity_mismatch`
    -- the asset behind this asset_id was renamed since the constraint
    was recorded, or two different real machines in two different
    ingests happen to share one id. Only an asset_id+hostname match is
    `applied`.
    """
    applied: list[Constraint] = []
    skipped_legacy: list[Constraint] = []
    skipped_identity_mismatch: list[Constraint] = []
    for c in constraints:
        if c.asset_id != asset_id:
            continue
        if c.hostname is None:
            skipped_legacy.append(c)
        elif c.hostname != hostname:
            skipped_identity_mismatch.append(c)
        else:
            applied.append(c)
    return ConstraintMatch(
        applied=tuple(applied),
        skipped_legacy=tuple(skipped_legacy),
        skipped_identity_mismatch=tuple(skipped_identity_mismatch),
    )


_RECOGNIZED_EFFECT_KINDS = {k.value for k in ConstraintEffectKind}


def has_usable_effect(c: Constraint) -> bool:
    """Whether `c` would actually change anything if folded into an asset
    by `apply_constraints` -- a recognized `effect_kind` AND a truthy
    `effect_value`, the identical condition `apply_constraints`'s own loop
    checks internally (`if not c.effect_value: continue`, then an `elif`
    chain over the three recognized kinds). `Memory.add_constraint`'s own
    docstring explicitly allows recording "a constraint that hasn't been
    interpreted into a structured effect yet" -- a real, legitimate row
    shape, reachable in practice whenever `agents/coordinator.py`'s
    `submit_constraint` resolves an asset but the Interpreter returned no
    `effect_kind`/`effect_value` (it is not asked to enforce that as a
    refusal condition; only `verify_constraint_matches_tool` checks
    `asset_id`/`affected_finding_ids`, never effect completeness).

    An adversarial review of this feature's first version caught that
    `match_constraints` alone could not distinguish this case from a real,
    effect-bearing match: identity alone put a constraint into `.applied`,
    so a caller that counted/digested/reported `.applied` directly (as
    `cli.ConstraintApplicator` now does) would count, hash, and print a
    constraint that changes nothing about the scored plan -- contradicting
    this project's own stated digest-stability contract ("only a change to
    what scoring actually reads [churns it]"). This function is the filter
    a caller applies to `ConstraintMatch.applied` AFTER identity matching,
    to get the subset that is both identity-matched AND would actually do
    something -- it is deliberately NOT folded into `match_constraints`
    itself, because "no usable effect yet" is not an identity failure (not
    `legacy`, not `identity_mismatch` -- CLAUDE.md's decision 7 names only
    those two skip reasons) and must not be reported as either; it is
    simply invisible to both the overlay and this feature's own counting,
    the same way it is already invisible to `apply_constraints` itself."""
    return c.effect_kind in _RECOGNIZED_EFFECT_KINDS and bool(c.effect_value)


def apply_constraints(asset: Asset, constraints: list[Constraint]) -> Asset:
    """Overlay `constraints`' effects onto a COPY of `asset` -- `asset`
    itself is never modified, and nothing this returns is written back
    anywhere. `constraints` should already be filtered to active,
    identity-matched ones for this asset (`match_constraints(...).applied`
    on the new paths; `Memory.constraints_for_asset`'s own default on the
    code that predates identity matching). Later constraints in the list
    win over earlier ones of the same effect_kind -- `constraints_for_asset`
    returns oldest-first, so the most recently stated version of a fact
    supersedes an older one, same as a human correcting an earlier
    statement. compensating_control is the one additive kind: multiple
    controls accumulate rather than replacing each other, matching how
    `Asset.compensating_control_list` already treats its own comma/
    semicolon-separated field as a set, not a single value.

    **A supplied field stops being not-collected.** Any field a
    constraint actually writes is removed from `Asset.not_collected`
    (adapters/base.py) on the returned copy. This is the whole point of
    the constraint path for a record ingested from a source that exports
    no operational context: before, a Defender asset's blank
    `patch_window` meant "unknown" and everything downstream said so;
    after a human states the window, it is known, and continuing to flag
    it as a data gap would be false. Fields no constraint touched keep
    their marker, so one constraint never launders an asset's other gaps.
    """
    patch_window = asset.patch_window
    patch_restrictions = asset.patch_restrictions
    added_controls: list[str] = []
    supplied: set[str] = set()
    for c in constraints:
        if not c.effect_value:
            continue
        if c.effect_kind == ConstraintEffectKind.PATCH_WINDOW.value:
            patch_window = c.effect_value
            supplied.add("patch_window")
        elif c.effect_kind == ConstraintEffectKind.PATCH_RESTRICTION.value:
            patch_restrictions = c.effect_value
            supplied.add("patch_restrictions")
        elif c.effect_kind == ConstraintEffectKind.COMPENSATING_CONTROL.value:
            added_controls.append(c.effect_value)
            supplied.add("compensating_controls")

    if added_controls:
        compensating_controls = (
            f"{asset.compensating_controls}, {', '.join(added_controls)}"
            if asset.compensating_controls
            else ", ".join(added_controls)
        )
    else:
        compensating_controls = asset.compensating_controls

    return asset.model_copy(
        update={
            "patch_window": patch_window,
            "patch_restrictions": patch_restrictions,
            "compensating_controls": compensating_controls,
            "not_collected": asset.not_collected - supplied,
        }
    )
