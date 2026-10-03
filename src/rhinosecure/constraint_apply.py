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
from typing import TYPE_CHECKING, Iterable

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
    from rhinosecure.memory import Constraint, Memory


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
class ConstraintApplicationSummary:
    """What a run actually did with stored constraints this run --
    CLAUDE.md's machine-identity constraint scoping entry, extended so
    the agents path (not just `--apply-constraints`/the web job's
    always-on equivalent) can report the same shape. `digest` is a sha256
    over the sorted, canonical-JSON `(asset_id, hostname, effect_kind,
    effect_value)` tuples of every entry in `applied` -- row ids and
    timestamps deliberately excluded, so an unrelated edit to a
    constraint's free text, or a retract-then-identical-resubmit, does
    not churn it; only a change to what scoring actually reads does.
    `deltas` is a before/after comparison per finding whose asset had at
    least one applied constraint -- populated by the deterministic path
    (`cli.ConstraintApplicator`, which already scores a finding with and
    without the overlay) and left empty (`()`) by `summarize_for_assets`
    below, which has no per-finding rescoring step of its own to compare
    against: the agents path's equivalent before/after view already lives
    in `export.py`'s `constraints.asset_scoped[].deltas`, a live recompute
    against the same `coordinator`, so this field is not duplicated here."""

    digest: str
    applied: tuple[AppliedConstraintRecord, ...] = ()
    skipped_legacy: tuple[SkippedConstraintRecord, ...] = ()
    skipped_identity_mismatch: tuple[SkippedConstraintRecord, ...] = ()
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


def compute_constraint_digest(applied: tuple[AppliedConstraintRecord, ...]) -> str:
    """sha256 of the sorted (asset_id, hostname, effect_kind, effect_value)
    tuples actually applied, as canonical JSON -- reuses the identical
    sha256-over-canonical-JSON convention `adapters/config_model.py`'s
    `compute_content_digest` already established in this codebase
    (`json.dumps(..., sort_keys=True, separators=(",", ":"),
    ensure_ascii=True)`), extended with an explicit list-order rule that
    module never needed (it hashes dicts, never an independently-orderable
    list of records): sorted here by the tuple itself, with None treated
    as sorting before any string so a legacy/incomplete record (should one
    ever reach this function -- in practice every genuinely `applied`
    record has both fields) never raises comparing None to str."""
    tuples = [(r.asset_id, r.hostname, r.effect_kind, r.effect_value) for r in applied]
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

    def summary(self, deltas: tuple[dict, ...] = ()) -> ConstraintApplicationSummary:
        applied = tuple(sorted(self._applied.values(), key=lambda r: r.constraint_id))
        return ConstraintApplicationSummary(
            digest=compute_constraint_digest(applied),
            applied=applied,
            skipped_legacy=tuple(sorted(self._skipped_legacy.values(), key=lambda r: r.constraint_id)),
            skipped_identity_mismatch=tuple(
                sorted(self._skipped_mismatch.values(), key=lambda r: r.constraint_id)
            ),
            deltas=deltas,
        )


def summarize_for_assets(memory: Memory, assets: Iterable[Asset]) -> ConstraintApplicationSummary:
    """A run-wide `ConstraintApplicationSummary` for every asset actually
    present in this run, with no per-finding rescoring step -- the agents
    path's own analog of `cli.ConstraintApplicator`, used because the
    agents path already folds a constraint's effect into scoring per
    finding via `agents/risk.py`'s `score_finding_tool` (through this
    SAME `match_constraints`/`has_usable_effect`/`apply_constraints`
    chain) and only needs the run-wide accounting here, not a second
    application of the fold itself.

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
    `coordinator.ranked()`) -- see `cli._agents_constraint_application_
    summary`/`export._build_agents_export` for the actual filter, and
    `export._asset_constraint_deltas` for the identical, older guard this
    one now mirrors.

    `assets` need not be de-duplicated by the caller -- one `Asset` per
    finding (several entries for the same asset) is exactly what a real
    caller has on hand, and `ConstraintAccumulator` caches per `asset_id`
    internally, so passing duplicates costs nothing beyond a dict lookup."""
    engine = ConstraintAccumulator(memory)
    for asset in assets:
        engine.record(asset.asset_id, asset.hostname)
    return engine.summary()
