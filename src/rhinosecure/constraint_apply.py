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

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Iterable, Iterator, Mapping, Protocol

from rhinosecure.schema import Asset, EnrichedFinding

if TYPE_CHECKING:
    # Type-hint only: constraint_apply.py must stay crewai-free, but it must
    # also not pull rhinosecure.memory into sys.modules just by being
    # imported -- an adversarial review of this feature's first version
    # caught that cli.py's own module-level import of this file was
    # transitively loading memory.py (and the real Memory class) the
    # instant `import rhinosecure.cli` ran, contradicting this module's own
    # "memory requires a Coordinator... stays out of that path's import
    # graph" convention even though no Memory instance was ever actually
    # CONSTRUCTED. `Constraint`/`GroupConstraint` are never instantiated or
    # isinstance-checked here, only used in type hints, so TYPE_CHECKING-only
    # is correct and `from __future__ import annotations` (above) makes
    # every annotation in this file a lazily-evaluated string regardless.
    from rhinosecure.memory import Constraint, GroupConstraint, Memory


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


GROUP_FIELD_CHOICES: frozenset[str] = frozenset({"role"})
"""v1 field scope (docs/group-constraints-design.md Section 4): `role` alone,
measured to cover 77 of 96 contested findings on a realistic-KEV-share,
5,000-finding fleet -- the only candidate field with a measured case behind
it. The single source of truth for which `Asset` fields a group constraint
may target; `agents/constraint_intake.py`'s `ConstraintInterpretation
.group_field` is a `Literal` built to match this set."""


@dataclass(frozen=True)
class GroupConstraintMatch:
    """The result of matching one asset against the fleet's stored group
    constraints. `applied` is what `fold_constraints` should fold in;
    `skipped_not_collected` is for reporting only -- never folded into
    scoring. A group constraint whose field is real on this asset but
    simply doesn't equal `group_value` is neither `applied` nor
    `skipped_not_collected` -- not reported at all, the same way
    `match_constraints` never reports "this constraint's asset_id is a
    different asset": a non-match carries no honesty concern the way a
    placeholder match does."""

    applied: tuple[GroupConstraint, ...] = ()
    skipped_not_collected: tuple[GroupConstraint, ...] = ()


def match_group_constraints(
    group_constraints: list[GroupConstraint], asset: Asset
) -> GroupConstraintMatch:
    """The group-constraint sibling of `match_constraints`. A group
    constraint's `group_field` is checked against `asset.not_collected`
    FIRST, always -- the live, read-time analogue of
    `agents/constraint_intake.py`'s `_matches` skip ("the file server"
    must not match every Defender-sourced server sharing one defaulted
    `role`), moved from a human's own asset *resolution* to a stored
    rule's *membership* test. Only once the field is confirmed real on
    this asset does its value get compared to `group_value`.

    `getattr(asset, gc.group_field, None)` is deliberately defensive, not
    merely convenient: `group_field` is restricted to a closed `Literal`
    at every writer, so a genuinely illegal value should never reach a
    stored row -- but a row written by a future version of this code with
    a wider `GROUP_FIELD_CHOICES` than an older reader knows about must
    not crash matching; it degrades to "doesn't match" instead, the same
    forward-compatible posture `Asset.not_collected`'s own "absence means
    no signal" convention already takes elsewhere."""
    applied: list[GroupConstraint] = []
    skipped: list[GroupConstraint] = []
    for gc in group_constraints:
        if gc.group_field in asset.not_collected:
            skipped.append(gc)
        elif str(getattr(asset, gc.group_field, None)) == gc.group_value:
            applied.append(gc)
        # else: this asset's real value for group_field simply isn't
        # gc.group_value -- not a skip, not reported.
    return GroupConstraintMatch(applied=tuple(applied), skipped_not_collected=tuple(skipped))


_RECOGNIZED_EFFECT_KINDS = {k.value for k in ConstraintEffectKind}


class _EffectBearing(Protocol):
    effect_kind: str | None
    effect_value: str | None


def has_usable_effect(c: _EffectBearing) -> bool:
    """Whether `c` would actually change anything if folded into an asset
    by `fold_constraints` -- a recognized `effect_kind` AND a truthy
    `effect_value`, the identical condition `fold_constraints`'s own loop
    checks internally (`if not c.effect_value: continue`, then an `elif`
    chain over the three recognized kinds). `Memory.add_constraint`'s own
    docstring explicitly allows recording "a constraint that hasn't been
    interpreted into a structured effect yet" -- a real, legitimate row
    shape, reachable in practice whenever `agents/coordinator.py`'s
    `submit_constraint` resolves an asset but the Interpreter returned no
    `effect_kind`/`effect_value` (it is not asked to enforce that as a
    refusal condition; only `verify_constraint_matches_tool` checks
    `asset_id`/`affected_finding_ids`, never effect completeness). The
    identical allowance applies to a `GroupConstraint` resolved by
    `preview_group_constraint` with no usable effect.

    An adversarial review of this feature's first version caught that
    `match_constraints` alone could not distinguish this case from a real,
    effect-bearing match: identity alone put a constraint into `.applied`,
    so a caller that counted/digested/reported `.applied` directly (as
    `cli.ConstraintApplicator` now does) would count, hash, and print a
    constraint that changes nothing about the scored plan -- contradicting
    this project's own stated digest-stability contract ("only a change to
    what scoring actually reads [churns it]"). This function is the filter
    a caller applies to `ConstraintMatch.applied`/`GroupConstraintMatch
    .applied` AFTER identity/membership matching, to get the subset that
    is both matched AND would actually do something -- it is deliberately
    NOT folded into `match_constraints`/`match_group_constraints`
    themselves, because "no usable effect yet" is not a match failure (not
    `legacy`, not `identity_mismatch`, not `not_collected`) and must not be
    reported as any of them; it is simply invisible to both the overlay
    and this feature's own counting, the same way it is already invisible
    to `fold_constraints` itself.

    Typed against the `_EffectBearing` `Protocol` (structural typing) so a
    `Constraint` and a `GroupConstraint` -- two unrelated dataclasses, each
    with no knowledge of the other -- satisfy this check identically, with
    no import of one module's row type into the other's."""
    return c.effect_kind in _RECOGNIZED_EFFECT_KINDS and bool(c.effect_value)


@dataclass(frozen=True)
class OverriddenGroupEffect:
    """One replace-kind field a group constraint would have set, on one
    asset, that an active asset-level constraint overrode instead
    (docs/group-constraints-design.md Section 5, decision 2: "the
    overridden group value is reported in the run summary and the
    export"). Produced only when a real conflict existed -- a group
    constraint whose field an asset constraint never touches never
    appears here."""

    asset_id: str
    field: str
    overriding_constraint_id: int
    group_constraint_id: int
    group_value_would_have_set: str


@dataclass(frozen=True)
class FoldResult:
    asset: Asset
    overridden_group_effects: tuple[OverriddenGroupEffect, ...] = ()


def fold_constraints(
    asset: Asset,
    *,
    constraints: Iterable[Constraint] = (),
    group_constraints: Iterable[GroupConstraint] = (),
) -> FoldResult:
    """Overlay `constraints`'/`group_constraints`' effects onto a COPY of
    `asset` -- `asset` itself is never modified, and nothing this returns
    is written back anywhere. Both arguments should already be filtered
    to matched, active constraints for this asset (`match_constraints`/
    `match_group_constraints`' own `.applied`).

    **Precedence is explicit and type-based, never positional
    (docs/group-constraints-design.md Section 5, decision 2).** Two
    passes over two SEPARATE lists, joined only by an explicit `if`:

    Pass 1 -- GROUP constraints establish a baseline for each replace-kind
    field (`patch_window`, `patch_restrictions`). Among themselves, the
    identical "oldest-first, later supersedes earlier" rule the asset pass
    already uses applies within the group pass only (`group_constraints`
    is expected oldest-first, the same `ORDER BY created_at, id`
    convention `all_active_group_constraints`/`constraints_for_asset`
    already use) -- a plain last-one-wins overwrite in iteration order
    gives exactly that.

    Pass 2 -- ASSET constraints. For a replace-kind field, this
    UNCONDITIONALLY overwrites whatever pass 1 set, regardless of either
    side's `created_at` -- precedence is which PASS you're in, never a
    timestamp or a list position. If pass 1 already set the field from a
    group constraint, the override is recorded in the returned
    `FoldResult.overridden_group_effects` before being overwritten.

    `compensating_control` stays the one additive kind, from BOTH
    sources: every matching constraint's value survives into the joined
    string (`Asset.compensating_control_list`'s own existing "a set, not
    a single value" treatment), with no override concept at all -- there
    is nothing to "win" when nothing replaces anything.

    **A supplied field stops being not-collected.** Any field a
    constraint actually writes (from either source) is removed from
    `Asset.not_collected` (adapters/base.py) on the returned copy -- the
    whole point of the constraint path for a record ingested from a
    source that exports no operational context. Fields no constraint
    touched keep their marker, so one constraint never launders an
    asset's other gaps.
    """
    constraints = list(constraints)
    group_constraints = list(group_constraints)

    patch_window = asset.patch_window
    patch_restrictions = asset.patch_restrictions
    added_controls: list[str] = []
    supplied: set[str] = set()
    overridden: list[OverriddenGroupEffect] = []

    # Pass 1 -- group baseline. Tracks which group constraint (if any) won
    # each replace-kind field within the group pass, so pass 2 can report
    # an override precisely (which group constraint, what value) rather
    # than merely "something changed."
    group_patch_window: tuple[str, int] | None = None  # (effect_value, group_constraint_id)
    group_patch_restriction: tuple[str, int] | None = None
    for g in group_constraints:
        if not g.effect_value:
            continue
        if g.effect_kind == ConstraintEffectKind.PATCH_WINDOW.value:
            group_patch_window = (g.effect_value, g.id)
        elif g.effect_kind == ConstraintEffectKind.PATCH_RESTRICTION.value:
            group_patch_restriction = (g.effect_value, g.id)
        elif g.effect_kind == ConstraintEffectKind.COMPENSATING_CONTROL.value:
            added_controls.append(g.effect_value)
            supplied.add("compensating_controls")

    if group_patch_window is not None:
        patch_window = group_patch_window[0]
        supplied.add("patch_window")
    if group_patch_restriction is not None:
        patch_restrictions = group_patch_restriction[0]
        supplied.add("patch_restrictions")

    # Pass 2 -- asset constraints unconditionally win a replace-kind field.
    asset_patch_window_winner: Constraint | None = None
    asset_patch_restriction_winner: Constraint | None = None
    for c in constraints:
        if not c.effect_value:
            continue
        if c.effect_kind == ConstraintEffectKind.PATCH_WINDOW.value:
            asset_patch_window_winner = c
        elif c.effect_kind == ConstraintEffectKind.PATCH_RESTRICTION.value:
            asset_patch_restriction_winner = c
        elif c.effect_kind == ConstraintEffectKind.COMPENSATING_CONTROL.value:
            added_controls.append(c.effect_value)
            supplied.add("compensating_controls")

    if asset_patch_window_winner is not None:
        if group_patch_window is not None:
            overridden.append(
                OverriddenGroupEffect(
                    asset_id=asset.asset_id,
                    field="patch_window",
                    overriding_constraint_id=asset_patch_window_winner.id,
                    group_constraint_id=group_patch_window[1],
                    group_value_would_have_set=group_patch_window[0],
                )
            )
        patch_window = asset_patch_window_winner.effect_value
        supplied.add("patch_window")

    if asset_patch_restriction_winner is not None:
        if group_patch_restriction is not None:
            overridden.append(
                OverriddenGroupEffect(
                    asset_id=asset.asset_id,
                    field="patch_restrictions",
                    overriding_constraint_id=asset_patch_restriction_winner.id,
                    group_constraint_id=group_patch_restriction[1],
                    group_value_would_have_set=group_patch_restriction[0],
                )
            )
        patch_restrictions = asset_patch_restriction_winner.effect_value
        supplied.add("patch_restrictions")

    if added_controls:
        compensating_controls = (
            f"{asset.compensating_controls}, {', '.join(added_controls)}"
            if asset.compensating_controls
            else ", ".join(added_controls)
        )
    else:
        compensating_controls = asset.compensating_controls

    new_asset = asset.model_copy(
        update={
            "patch_window": patch_window,
            "patch_restrictions": patch_restrictions,
            "compensating_controls": compensating_controls,
            "not_collected": asset.not_collected - supplied,
        }
    )
    return FoldResult(asset=new_asset, overridden_group_effects=tuple(overridden))


def apply_constraints(asset: Asset, constraints: list[Constraint]) -> Asset:
    """Thin wrapper kept for every existing caller -- identical behavior,
    now implemented by `fold_constraints` with an empty `group_constraints`
    list, so the asset-only case is byte-for-byte what it has always been."""
    return fold_constraints(asset, constraints=constraints).asset


# --- run-wide summary: shared by the deterministic (`cli.ConstraintApplicator`)
# and agents (`summarize_for_assets`) paths -- CLAUDE.md's "agents path reports
# constraint application honestly" fix. Moved here (out of cli.py, where it was
# deterministic-path-only) so BOTH paths compute the same digest/applied/
# skipped accounting through the identical code, rather than the agents path
# reimplementing it or going without one entirely.


@dataclass(frozen=True)
class AppliedConstraintRecord:
    """One constraint that was actually identity-matched (asset_id AND
    hostname) and folded into scoring this run -- the facts a human or
    the export needs to know WHAT applied, joinable back to the existing
    `constraints.asset_scoped[]` export section by `constraint_id` for
    everything else about the row (created_at, active, free-text
    constraint_text already live there)."""

    constraint_id: int
    asset_id: str
    hostname: str
    effect_kind: str | None
    effect_value: str | None


@dataclass(frozen=True)
class SkippedConstraintRecord:
    """One constraint that matched by asset_id but was never applied this
    run, and why -- `reason` is exactly `"legacy"` (no hostname was ever
    recorded for it) or `"identity_mismatch"` (a hostname was recorded,
    but it disagrees with this asset's current hostname -- a rename, or
    two different real machines sharing one asset_id). `current_hostname`
    is this run's own, real answer for what the asset is actually called
    now -- not derivable from the old constraints section, which has no
    notion of "the asset's current hostname" at all."""

    constraint_id: int
    asset_id: str
    current_hostname: str
    reason: str


@dataclass(frozen=True)
class AppliedGroupConstraintRecord:
    """The group-constraint sibling of `AppliedConstraintRecord` -- one
    group constraint that matched one asset and was actually folded into
    scoring this run. A deliberately SEPARATE dataclass, not a reuse of
    `AppliedConstraintRecord` with an overloaded `constraint_id`: the two
    tables' integer id spaces are independent and will collide, so
    `group_constraint_id` keeps a reader from ever having to guess which
    table an id in a combined list came from."""

    group_constraint_id: int
    asset_id: str
    hostname: str
    effect_kind: str | None
    effect_value: str | None


DISPLAY_CAP = 50
"""Fleet-scale-safe reporting limit (docs/group-constraints-design.md
Section 7.2), matching `SCENARIO_PAGE_SIZE`'s own existing precedent: a
real total count is always shown honestly alongside a truncated sample,
never a silent truncation with no count."""


@dataclass(frozen=True)
class SkippedGroupConstraintSummary:
    """One group constraint's not_collected skips, SUMMARIZED rather than
    enumerated per-asset: unlike `legacy`/`identity_mismatch` (which can
    only ever name exactly one asset, since an asset constraint belongs
    to exactly one asset by construction), one group constraint can be
    skipped against an unbounded number of assets -- enumerating every
    one in a CLI/digest-adjacent summary line would repeat the exact
    unpaginated-dump defect the Fleet-scale audit already found and fixed
    elsewhere. The FULL list remains available on request (the export's
    `group_scoped[].excluded_not_collected_asset_ids`, capped the same
    way but with its own honest total count) -- this shape is for the
    one-line summary only."""

    group_constraint_id: int
    group_field: str
    group_value: str
    skipped_asset_count: int
    sample_asset_ids: tuple[str, ...]


@dataclass(frozen=True)
class ConstraintApplicationSummary:
    """What a run actually did with stored constraints this run --
    CLAUDE.md's machine-identity constraint scoping entry, extended so
    the agents path (not just `--apply-constraints`/the web job's
    always-on equivalent) can report the same shape, and extended again
    (docs/group-constraints-design.md, Slice A) for group constraints.
    `digest` is computed by `compute_constraint_digest` over both
    `applied` and `applied_group` -- see that function's own docstring
    for the exact per-origin tuple-shape rule. `deltas` is a before/after
    comparison per finding whose asset had at least one applied
    constraint (asset- or group-origin) -- populated by the deterministic
    path (`cli.ConstraintApplicator`, which already scores a finding with
    and without the overlay) and left empty (`()`) by `summarize_for_assets`
    below, which has no per-finding rescoring step of its own to compare
    against: the agents path's equivalent before/after view already lives
    in `export.py`'s `constraints.asset_scoped[]`/`group_scoped[].deltas`,
    a live recompute against the same `coordinator`, so this field is not
    duplicated here."""

    digest: str
    applied: tuple[AppliedConstraintRecord, ...] = ()
    skipped_legacy: tuple[SkippedConstraintRecord, ...] = ()
    skipped_identity_mismatch: tuple[SkippedConstraintRecord, ...] = ()
    applied_group: tuple[AppliedGroupConstraintRecord, ...] = ()
    skipped_not_collected: tuple[SkippedGroupConstraintSummary, ...] = ()
    overridden_group_effects: tuple[OverriddenGroupEffect, ...] = ()
    deltas: tuple[dict, ...] = ()

    @property
    def applied_count(self) -> int:
        return len(self.applied)

    @property
    def skipped_legacy_count(self) -> int:
        return len(self.skipped_legacy)

    @property
    def skipped_identity_mismatch_count(self) -> int:
        return len(self.skipped_identity_mismatch)

    @property
    def applied_group_count(self) -> int:
        return len(self.applied_group)


def compute_constraint_digest(
    applied: tuple[AppliedConstraintRecord, ...],
    group_applied: tuple[AppliedGroupConstraintRecord, ...] = (),
) -> str:
    """sha256 of one sorted list of tuples, as canonical JSON -- reuses the
    identical sha256-over-canonical-JSON convention
    `adapters/config_model.py`'s `compute_content_digest` already
    established in this codebase (`json.dumps(..., sort_keys=True,
    separators=(",", ":"), ensure_ascii=True)`).

    **Neither of two previously-weighed designs** (a single formula that
    switches shape run-wide the instant any group-origin record exists
    anywhere; two permanently-separate `digest`/`group_digest` fields).
    Instead: **each record's own tuple shape depends only on that
    record's own origin, never on what else applied this run.** An
    asset-origin record is always the plain 4-tuple `(asset_id, hostname,
    effect_kind, effect_value)` -- the literal, unmodified shape this
    function has always used -- regardless of whether any group-origin
    record is also present. A group-origin record is always the 5-tuple
    `(asset_id, hostname, "group:<id>", effect_kind, effect_value)`, with
    the literal string `"group:<id>"` injected as the third element so a
    reader can tell which table an id in the hashed data came from. There
    is no run-wide conditional to get right: with `group_applied=()` (the
    default, and the only possible value whenever `group_constraints`
    holds no rows), the function builds nothing but 4-tuples from
    `applied` -- byte-identical to the pre-group-constraints formula, by
    construction, not by a branch that happens to degenerate correctly.

    Python's tuple comparison handles the resulting mixed-length sort
    safely: each position is first wrapped `(x is None, x)` before
    comparison (so two positions are never compared one `None` against
    one real value directly), and a 4-element and a 5-element tuple that
    agree on their first four wrapped positions compare by length alone
    for the fifth -- the ordinary, safe Python rule for comparing a
    prefix against a longer sequence, never a `TypeError`.

    Row ids and timestamps are deliberately excluded from both tuple
    shapes, so an unrelated edit to a constraint's free text, or a
    retract-then-identical-resubmit, does not churn the digest; only a
    change to what scoring actually reads does.

    One correction to this function's own history, recorded here rather
    than silently: an earlier version of this docstring claimed the sort
    key treats `None` as sorting *before* any string. Mechanically it
    sorts `None` *after* every string (the key is `(x is None, x)`, and
    `False < True`), which is harmless -- the real purpose, never
    comparing `None` to `str` directly, holds regardless of direction --
    and in practice unreachable: no field of a genuine
    `AppliedConstraintRecord`/`AppliedGroupConstraintRecord` is ever
    `None`."""
    tuples: list[tuple[Any, ...]] = [
        (r.asset_id, r.hostname, r.effect_kind, r.effect_value) for r in applied
    ]
    tuples += [
        (g.asset_id, g.hostname, f"group:{g.group_constraint_id}", g.effect_kind, g.effect_value)
        for g in group_applied
    ]
    tuples.sort(key=lambda t: tuple((x is None, x) for x in t))
    blob = json.dumps(
        [list(t) for t in tuples], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


class ConstraintAccumulator:
    """The shared matching/accounting engine behind `ConstraintApplicationSummary`:
    looks up and caches each distinct asset's stored constraints (one DB
    read per asset actually touched, not per finding), matches by
    `(asset_id, hostname)` via `match_constraints` -- CLAUDE.md's "no
    second rule" -- filters to usable-effect ones via `has_usable_effect`,
    and accumulates the distinct applied/skipped-by-reason records a
    run-wide summary needs. Deliberately knows nothing about `Finding`,
    `EnrichedFinding`, or scoring -- `cli.ConstraintApplicator` wraps one
    of these to additionally fold a usable effect into each finding's
    `Asset` and record a before/after delta (concepts specific to the
    deterministic path's own per-finding rescoring loop); the agents path
    (`summarize_for_assets`, below) uses one directly, with no fold step
    of its own, since `agents/risk.py`'s `score_finding_tool` already
    folds a constraint's effect into scoring per finding through this same
    `match_constraints`/`has_usable_effect`/`apply_constraints` chain --
    this class exists for the run-wide ACCOUNTING only.

    Safe to call `record` more than once for the same `asset_id` (e.g.
    once per finding on a multi-finding asset): the DB read and the
    match/filter are memoized by `asset_id`, so repeating it costs a dict
    lookup, not a second query."""

    def __init__(self, memory: Memory):
        self._memory = memory
        self._cache: dict[str, list[Constraint]] = {}
        self._applied: dict[int, AppliedConstraintRecord] = {}
        self._skipped_legacy: dict[int, SkippedConstraintRecord] = {}
        self._skipped_mismatch: dict[int, SkippedConstraintRecord] = {}
        # Group-constraint state (Slice A). `_group_cache` is the WHOLE
        # table, fetched once on first use, never per-asset -- there is no
        # asset_id to key a per-asset cache on (Section 3: "fetch the group
        # table once, not per asset or per finding").
        self._group_cache: list[GroupConstraint] | None = None
        # Keyed (group_constraint_id, asset_id), never group_constraint_id
        # alone -- one group constraint applying to N assets is N distinct
        # applications (AppliedGroupConstraintRecord's own docstring: "one
        # group constraint that matched ONE asset"), and the digest must
        # change when the Nth asset joins or leaves (test A29/A30). Keying
        # by group_constraint_id alone and relying on setdefault would
        # silently keep only the FIRST asset ever seen for a given rule --
        # a real defect caught while writing this slice's own test suite.
        self._applied_group: dict[tuple[int, str], AppliedGroupConstraintRecord] = {}
        self._skipped_not_collected_meta: dict[int, GroupConstraint] = {}
        # Both dicts double as ordered sets (value always None / the asset_id
        # itself) -- same dedup discipline as `_applied_group`'s own
        # `(group_constraint_id, asset_id)` key, needed for the identical
        # reason: every real caller invokes `record_group`/
        # `record_fold_result` once per FINDING, not once per asset, so a
        # multi-finding asset would otherwise inflate a skipped count or
        # duplicate an override fact once per finding on it (an adversarial
        # review of this feature's first version caught both).
        self._skipped_not_collected_assets: dict[int, dict[str, None]] = {}
        self._overridden: dict[OverriddenGroupEffect, None] = {}

    def record(self, asset_id: str, hostname: str) -> tuple[Constraint, ...]:
        """Matches `asset_id`'s stored constraints against `hostname`,
        records the run-wide bookkeeping (applied/skipped-by-reason), and
        returns the usable-effect constraints a caller should fold into
        scoring -- empty if none."""
        candidates = self._cache.get(asset_id)
        if candidates is None:
            candidates = self._memory.constraints_for_asset(asset_id)
            self._cache[asset_id] = candidates
        match = match_constraints(candidates, asset_id, hostname)
        for c in match.skipped_legacy:
            self._skipped_legacy.setdefault(
                c.id,
                SkippedConstraintRecord(
                    constraint_id=c.id, asset_id=c.asset_id, current_hostname=hostname, reason="legacy"
                ),
            )
        for c in match.skipped_identity_mismatch:
            self._skipped_mismatch.setdefault(
                c.id,
                SkippedConstraintRecord(
                    constraint_id=c.id,
                    asset_id=c.asset_id,
                    current_hostname=hostname,
                    reason="identity_mismatch",
                ),
            )
        # Identity-matched is not the same claim as "changed something" --
        # an adversarial review caught that counting/digesting match.applied
        # directly would report, hash, and print a constraint that resolved
        # an asset but was never interpreted into a structured effect (a
        # real, legitimate row shape -- memory.py's own add_constraint
        # docstring anticipates it), contradicting this feature's own
        # digest-stability contract. has_usable_effect is the same
        # recognized-kind-and-truthy-value check apply_constraints' own
        # loop already applies internally -- filtering here means an
        # effect-less constraint is simply invisible to the overlay AND to
        # this reporting, never counted as applied, legacy, or mismatch.
        effective = tuple(c for c in match.applied if has_usable_effect(c))
        for c in effective:
            self._applied.setdefault(
                c.id,
                AppliedConstraintRecord(
                    constraint_id=c.id,
                    asset_id=c.asset_id,
                    hostname=c.hostname,
                    effect_kind=c.effect_kind,
                    effect_value=c.effect_value,
                ),
            )
        return effective

    def record_group(self, asset: Asset) -> tuple[GroupConstraint, ...]:
        """The group-constraint sibling of `record`. Fetches the WHOLE
        `group_constraints` table once (never per-asset), matches `asset`
        against it via `match_group_constraints`, records the run-wide
        not_collected-skip and applied bookkeeping, and returns the
        usable-effect group constraints a caller should fold in via
        `fold_constraints` -- empty if none."""
        if self._group_cache is None:
            self._group_cache = self._memory.all_active_group_constraints()
        match = match_group_constraints(self._group_cache, asset)
        for gc in match.skipped_not_collected:
            self._skipped_not_collected_meta.setdefault(gc.id, gc)
            self._skipped_not_collected_assets.setdefault(gc.id, {})[asset.asset_id] = None
        effective = tuple(gc for gc in match.applied if has_usable_effect(gc))
        for gc in effective:
            self._applied_group.setdefault(
                (gc.id, asset.asset_id),
                AppliedGroupConstraintRecord(
                    group_constraint_id=gc.id,
                    asset_id=asset.asset_id,
                    hostname=asset.hostname,
                    effect_kind=gc.effect_kind,
                    effect_value=gc.effect_value,
                ),
            )
        return effective

    def record_fold_result(self, result: FoldResult) -> None:
        """Accumulates one `fold_constraints` call's own
        `overridden_group_effects` into this run's running total -- called
        by whichever caller actually invoked `fold_constraints` (`cli
        .ConstraintApplicator`, `agents/risk.py`'s `score_finding_tool`,
        `_submit_capacity_constraint`'s fold, `export.py`'s
        `_agents_decomposition`, or `summarize_for_assets` below, for a
        caller with no fold step of its own)."""
        for effect in result.overridden_group_effects:
            self._overridden.setdefault(effect, None)

    def summary(self, deltas: tuple[dict, ...] = ()) -> ConstraintApplicationSummary:
        applied = tuple(sorted(self._applied.values(), key=lambda r: r.constraint_id))
        applied_group = tuple(
            sorted(self._applied_group.values(), key=lambda r: (r.group_constraint_id, r.asset_id))
        )
        skipped_not_collected = tuple(
            SkippedGroupConstraintSummary(
                group_constraint_id=gid,
                group_field=self._skipped_not_collected_meta[gid].group_field,
                group_value=self._skipped_not_collected_meta[gid].group_value,
                skipped_asset_count=len(asset_ids),
                sample_asset_ids=tuple(sorted(asset_ids)[:DISPLAY_CAP]),
            )
            for gid, asset_ids in sorted(self._skipped_not_collected_assets.items())
        )
        return ConstraintApplicationSummary(
            digest=compute_constraint_digest(applied, applied_group),
            applied=applied,
            skipped_legacy=tuple(sorted(self._skipped_legacy.values(), key=lambda r: r.constraint_id)),
            skipped_identity_mismatch=tuple(
                sorted(self._skipped_mismatch.values(), key=lambda r: r.constraint_id)
            ),
            applied_group=applied_group,
            skipped_not_collected=skipped_not_collected,
            overridden_group_effects=tuple(self._overridden),
            deltas=deltas,
        )


def summarize_for_assets(memory: Memory, assets: Iterable[Asset]) -> ConstraintApplicationSummary:
    """A run-wide `ConstraintApplicationSummary` for every asset actually
    present in this run, with no per-finding rescoring step -- the agents
    path's own analog of `cli.ConstraintApplicator`, used because the
    agents path already folds a constraint's effect into scoring per
    finding via `agents/risk.py`'s `score_finding_tool` (through this SAME
    `match_constraints`/`match_group_constraints`/`has_usable_effect`/
    `fold_constraints` chain) and only needs the run-wide accounting here,
    not a second application of the fold itself.

    **Deliberately does NOT call `fold_constraints` here** (unlike
    `cli.ConstraintApplicator`, which does and therefore has real
    `overridden_group_effects` to report): this function's own `assets`
    parameter is typed `Asset` but real callers may pass a lighter,
    duck-typed stand-in exposing only `asset_id`/`hostname` (confirmed
    live by an existing `cli.py` test using a bare `SimpleNamespace` for
    exactly this reason) -- `fold_constraints` needs a genuine `Asset`
    with every operational field, and calling it here would silently
    require every caller's stand-in to grow into a full fixture. The
    agents path's own `overridden_group_effects` reporting gap (the
    run-wide summary never aggregates what `score_finding_tool` already
    computed per finding) is accepted and named, not silently patched
    around -- `export.py`'s live per-finding decomposition still shows an
    override where it actually happened; only the run-wide AGGREGATE list
    is not populated by this function.

    **`assets` must already be scoped to findings that actually reached
    SCORING this run -- never a raw, pre-dispatch population.** An
    adversarial review of this function's first caller found a real bug
    exactly here: passing `coordinator.state.enriched_by_id.values()`
    unfiltered (every ingested finding, including ones whose Research/
    Environment/Risk dispatch failed and was recorded-and-skipped --
    `agents/coordinator.py`'s own documented "Tool-call retry cap"
    behavior) made an asset whose only finding(s) all failed upstream
    still count as `applied`, with a real digest, even though
    `score_finding_tool` was never called for it and nothing in the
    actual scored/exported plan reflects it -- the exact "plausible but
    false" claim this whole feature exists to prevent, just one level
    deeper. The correct population is every finding that reached
    `state.risk_by_id` (equivalently, every finding in
    `coordinator.ranked()`) -- see `scored_assets`, below, for the single
    source of this filter, and `export._asset_constraint_deltas` for the
    identical, older guard this one now mirrors.

    `assets` need not be de-duplicated by the caller -- one `Asset` per
    finding (several entries for the same asset) is exactly what a real
    caller has on hand, and `ConstraintAccumulator` caches per `asset_id`
    internally, so passing duplicates costs nothing beyond a dict lookup."""
    engine = ConstraintAccumulator(memory)
    for asset in assets:
        engine.record(asset.asset_id, asset.hostname)
        engine.record_group(asset)
    return engine.summary()


def scored_assets(
    enriched_by_id: Mapping[str, EnrichedFinding], risk_by_id: Mapping[str, Any]
) -> Iterator[Asset]:
    """Single-sourced (docs/group-constraints-design.md Section 8.8,
    housekeeping done during Slice A): the identical generator-expression
    filter that used to be written out independently in `export.py`,
    `cli.py`, and `web/jobs.py` -- `(e.asset for e in enriched_by_id
    .values() if e.finding.finding_id in risk_by_id)`. `enriched_by_id` is
    the raw, pre-dispatch ingest population; `risk_by_id` membership is
    "actually reached Risk this run" -- the same honest population
    `summarize_for_assets` above requires, and the identical guard
    `export._asset_constraint_deltas` already uses for the per-constraint
    delta view, now shared by every caller instead of re-derived three
    times. `risk_by_id`'s value type is intentionally untyped (`Any`) --
    only membership is checked, and typing it as `RiskRecommendation`
    would pull `agents.risk` (crewai-coupled) into this module's import
    graph for no reason."""
    return (e.asset for e in enriched_by_id.values() if e.finding.finding_id in risk_by_id)
