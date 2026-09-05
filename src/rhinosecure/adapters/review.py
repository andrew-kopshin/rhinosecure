"""Slice 7 of docs/adapter-generation.md: what `rhino adapt confirm` and
`rhino adapt rereview` compute. This module measures, diffs, and decides;
it prints nothing (cli.py owns every `_print_*`) and it writes in exactly
one place, at the end of one function. Same split Slice 6 established --
`probe.profile_source` computes `FileProfile`s, `cli._print_probe_report`
prints them.

The property this whole feature exists for, from the design's own text:
**the review artifact must be produced by the same code that executes it**,
so a human never confirms a claim about a mapping, only a measurement of
what it does. Everything below follows from taking that literally -- the
measurement is a real `ingest.load_batch` through a real `ConfiguredAdapter`
over the real `--data` directory, not a second, review-only walker that
could disagree with the engine.

Measuring a contract the engine refuses to construct
------------------------------------------------------
`ConfiguredAdapter.__init__` calls `assert_confirmed` before it sets a
single attribute -- so the object that must measure an UNCONFIRMED contract
is the one object that refuses to exist for it. Resolved by SATISFYING the
gate rather than routing around it: `_provisional` returns an in-memory copy
stamped by the ordinary `config_io.confirm_contract`, with a sentinel
identity that says what it is. That copy is function-local -- it is never
returned by any public name here, never written, and never handed to
scoring; the public results are counts, gap maps and problem strings.

Rejected, deliberately: extracting the engine's constructor body so a
review could call it on an `__new__`'d instance. That adds a second,
supported construction path around a gate whose whole value is being the
only one, and then guards it with naming discipline -- the same class of
protection `config_model.py`'s own docstring refuses to rely on when it
argues against an `on_unmapped` key. Also rejected: a `review_only=` flag on
`ConfiguredAdapter.__init__`, which would put the bypass on the exact
constructor the ingest path calls, one keyword away from disabling the gate.
The provisional stamp leaves `configured.py`'s gate a single unconditional
statement with no parameter and no branch.

Two details of `_provisional` are load-bearing, not cosmetic:

- **`review` is cleared first**, so `confirm_contract` recomputes digests
  over the contract's CURRENT content. A contract that has drifted since it
  was confirmed is refused by `rhino run --adapter-config` (correctly), which
  leaves `rereview` as the only command that can still inspect it -- exactly
  the case a human needs most.
- **`observed` is cleared**, because `ConfiguredAdapter.load_assets` runs
  `validate_contract` on every load and V18 reads the STORED `observed`'s
  exclusion counts. A stale measurement would make the fresh measurement
  refuse itself.

Getting every problem instead of the first
--------------------------------------------
`_RecordingCollectors` is a callable factory that keeps every collector the
engine builds, because the engine keeps none: `load_assets` and
`_validate_findings` each build one locally and copy only `.excluded` onto
`self.stats`, and `load_findings` builds a throwaway per row (52 instances
on one 50-row file). Its `NonRaisingProblemCollector` (adapters/probe.py)
turns `raise_if_fatal` into a no-op so one pass sees everything, and the
messages are de-duplicated -- `load_findings`' per-row collector re-records
what `_validate_findings` already saw, so raw counts overstate.

Problems arrive two ways and mean different things, so they are reported
separately. *Accumulated* are what the collectors hold. *Halting* is the one
exception that stopped the pass -- four refusals never reach a collector at
all (`Asset(**fields)` failing pydantic, `_check_header_mode`/
`validate_contract`, `iter_csv_rows`' structural refusals, and `ingest.join`
on an orphan). All are `IngestError` subclasses, so one `except` covers them.

`ingest.load_batch` is used rather than re-implemented, including for the
orphan case, and that is a measured decision: `join` does abort on the first
orphan, but `_validate_findings` has already aggregated EVERY orphan into
one message on the collector by then (verified: two orphans, one message
naming both, before `join` ever ran). So catching the halt loses no
diagnostic information, and the alternative -- hand-rolling
`require_adapter_files` + `load_assets` + `load_findings` + a tolerant join --
would be a second implementation of the exact function whose sameness is the
design's decisive property.

Order of operations, which is not negotiable
----------------------------------------------
    measure -> build observed -> merge attestations -> confirm_contract
    (STAMP) -> validate_contract (LAST) -> round-trip verify -> write

Validating before stamping reports a spurious `review.content_digest`
mismatch on every already-confirmed contract, because `observed` has moved
while `review` still carries the old digest. And the validation must use
`adapter.headers` -- the engine's own post-`_filtered_for_validation` view --
not a freshly read raw header, or a vendor's new column that
`header.mode="declared"` deliberately tolerates as a notice comes back as a
V08 refusal at the very last step, in precisely the drift case a re-review
exists to report.

Everything else is a gate that runs strictly BEFORE the single
`overwrite_contract` call, so "it refused" always means "nothing was
written". That matters more than it sounds: a contract whose `observed` was
refreshed without re-stamping fails `assert_confirmed` afterwards
(`content_digest` covers everything except `review`), so a half-write would
turn a review-time refusal into an ingest-time outage.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from rhinosecure import ingest
from rhinosecure.adapters.base import ProblemCollector
from rhinosecure.adapters.config_io import confirm_contract, dump_for_disk, overwrite_contract
from rhinosecure.adapters.config_model import (
    ATTESTATION_ITEMS,
    Attestation,
    Contract,
    ContractError,
    Review,
    assert_confirmed,
    compute_slot_digests,
    missing_attestations,
    required_attestations,
    validate_contract,
)
from rhinosecure.adapters.configured import ConfiguredAdapter
from rhinosecure.adapters.probe import NonRaisingProblemCollector, profile_csv

#: What the in-memory provisional stamp records as its signer. It exists so
#: that if such an object ever did escape into a log or a debugger, it says
#: what it is rather than impersonating a reviewer. It is never written.
PROVISIONAL_AT = "0000-00-00T00:00:00Z"
PROVISIONAL_BY = "rhino adapt (provisional, in memory, never written)"


class ReviewError(ContractError):
    """The review itself cannot proceed -- an already-confirmed contract
    without `--reconfirm`, a bad `--attest` argument, a frozen identity
    recipe that moved. Distinct from the measurement finding fatal problems
    in the source, which is reported as data, not raised."""


class _RecordingCollectors:
    """See the module docstring. A callable, not a class, because the engine
    calls `self._collector_factory(path)` and we need every instance back."""

    def __init__(self) -> None:
        self.collectors: list[NonRaisingProblemCollector] = []

    def __call__(self, path: Path) -> ProblemCollector:
        collector = NonRaisingProblemCollector(path)
        self.collectors.append(collector)
        return collector

    def fatal_messages(self) -> list[str]:
        """Every problem recorded, de-duplicated, first-seen order."""
        return list(dict.fromkeys(m for c in self.collectors for m in c.fatal))


@dataclass(frozen=True)
class Measurement:
    """What the mapping actually did to the real files. `halted_by` is the
    exception that stopped the pass, if one did -- when it is set, every
    count below describes only what was read before that point."""

    data_dir: Path
    assets_loaded: int
    findings_loaded: int
    duplicate_assets_collapsed: int
    duplicate_findings_collapsed: int
    excluded_assets: dict[str, str]
    excluded_findings: dict[str, str]
    asset_gaps: dict[str, int]
    finding_gaps: dict[str, int]
    header_notices: list[str]
    headers: dict[str, list[str]]
    fatal_problems: list[str]
    halted_by: str | None
    #: target field -> {value: count}, for enumerated targets only (see
    #: `_value_distribution`). Printed, never persisted.
    value_distribution: dict[str, dict[str, int]] = field(default_factory=dict)
    #: source column -> its measured profile, for columns the contract
    #: declares it deliberately does not read. Printed, never persisted.
    unmapped_profiles: dict[str, dict[str, object]] = field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        return not self.fatal_problems and self.halted_by is None


@dataclass(frozen=True)
class SlotPartition:
    """`compute_slot_digests` recomputed and compared against what the
    contract recorded at confirmation time. `available` is False when the
    contract recorded none (legal, and the state both committed contracts
    are in) -- then nothing can be partitioned and the whole contract is in
    scope."""

    available: bool
    unchanged: list[str]
    changed: list[str]
    new: list[str]
    orphaned: list[str]

    @property
    def moved(self) -> list[str]:
        return sorted(self.changed + self.new + self.orphaned)


@dataclass(frozen=True)
class Drift:
    """How the contract on disk compares to what its own `review` block
    says was signed.

    `was_confirmed` is False for a contract that has never been signed at
    all, where the digest comparisons are vacuous rather than failing: there
    is no prior signature for the content to have drifted FROM. Keeping that
    distinct matters -- without it a never-confirmed contract looks maximally
    drifted, and every attestation its author wrote gets discarded as "no
    longer carries forward" from a signature that never existed."""

    state: str
    was_confirmed: bool
    content_matches: bool
    decision_matches: bool
    slots: SlotPartition

    @property
    def decisions_moved(self) -> bool:
        return self.was_confirmed and not self.decision_matches


@dataclass(frozen=True)
class ReviewOutcome:
    """Everything both verbs compute. `written` is only ever True for
    `confirm`, and only after every gate passed."""

    path: Path
    contract: Contract
    measurement: Measurement
    drift: Drift
    required: dict[str, str]
    still_missing: list[str]
    attestations_added: list[Attestation]
    attestations_replaced: list[tuple[Attestation, Attestation]]
    #: Prior attestations the drift invalidated, with why. Context for the
    #: reader, NOT a refusal on its own: an item that was dropped and not
    #: re-supplied already shows up in `still_missing`, which is the gate.
    #: Refusing on the drop itself would refuse even when the reviewer had
    #: just supplied a fresh sentence for that exact item.
    attestations_dropped: list[str]
    refusals: list[str]
    signed: Contract | None = None
    written: bool = False

    @property
    def ok(self) -> bool:
        return not self.refusals and self.measurement.is_clean

    @property
    def rereview_clean(self) -> bool:
        """Whether `rhino adapt rereview` should report nothing to do, and
        exit 0. Deliberately includes `still_missing`, which is NOT part of
        `ok`: an attestation requirement can appear without the contract
        changing at all -- the source starts excluding records, so V18 now
        demands `exclusions` where it did not before. That leaves every
        digest matching and the measurement clean while `confirm` refuses,
        which is exactly the drift a re-review exists to surface. Reporting
        it clean would send a CI drift check green on a contract that can no
        longer be signed. One property so the printed line and the exit code
        cannot disagree."""
        return (
            self.measurement.is_clean
            and self.drift.content_matches
            and self.drift.decision_matches
            and not self.drift.slots.moved
            and not self.still_missing
            and not self.refusals
        )


def _provisional(contract: Contract) -> Contract:
    """See the module docstring's "Measuring a contract the engine refuses
    to construct". Deliberately private and function-local at every call
    site: never returned by a public name here, never written."""
    return confirm_contract(
        contract.model_copy(update={"review": Review(), "observed": None}),
        at=PROVISIONAL_AT,
        by=PROVISIONAL_BY,
    )


#: Targets whose value space is closed and code-owned, so showing the values
#: a mapping actually produced is schema information rather than fleet data.
#: Free text (`hostname`, `owner`, `business_function`, `product`, `evidence`)
#: is never tallied and never leaves the terminal -- CLAUDE.md's trust
#: boundary calls real vulnerability data a map of where an organization is
#: weak, and a contract is committed to git.
_DISTRIBUTION_TARGETS = ("role", "environment", "data_sensitivity", "criticality", "internet_exposed")


def _value_distribution(assets: dict) -> dict[str, dict[str, int]]:
    distribution: dict[str, dict[str, int]] = {}
    for target in _DISTRIBUTION_TARGETS:
        counter: Counter[str] = Counter()
        for asset in assets.values():
            counter[str(getattr(asset, target))] += 1
        distribution[target] = dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))
    return distribution


def _unmapped_profiles(contract: Contract, data_dir: Path) -> dict[str, dict[str, object]]:
    """The measured shape of every column the contract says it deliberately
    does not read.

    `unmapped_columns` carries a human- or model-authored prose REASON per
    column and sits inside a decision subtree, so it is a signed claim -- and
    nothing checks whether it is true. This is where a mapping hides the
    patch-window column somebody dismissed as "operational metadata": a
    column that is 0% blank with a handful of distinct values reading like a
    maintenance window, printed next to the sentence waving it away, is the
    most useful thing this command can put in front of a reviewer. Reuses
    Slice 6's profiler rather than counting again."""
    profiles: dict[str, dict[str, object]] = {}
    # dict.fromkeys: single_file layout means both names are the same file
    # (ingest._require_adapter_files does the same de-dup for the same reason).
    for filename in dict.fromkeys((contract.source.assets_filename, contract.source.findings_filename)):
        declared = contract.unmapped_columns.get(filename) or {}
        if not declared:
            continue
        path = data_dir / filename
        if not path.is_file():
            continue
        # The contract's OWN dialect, not the profiler's defaults. A
        # semicolon-delimited or banner-prefixed source otherwise parses as
        # one giant column, every declared name misses, and this whole
        # section disappears from the review without saying so.
        source = contract.source
        file_profile = profile_csv(
            path,
            delimiter=source.delimiter,
            quotechar=source.quotechar,
            encoding=None if source.encoding == "auto" else source.encoding,
            skip_lines=source.first_data_row - 2,
        )
        for column, entry in declared.items():
            column_profile = file_profile.columns.get(column)
            if column_profile is None:
                continue
            profiles[f"{filename}:{column}"] = {
                "disposition": entry.disposition,
                "reason": entry.reason,
                "blank": column_profile.blank,
                "rows": file_profile.row_count,
                "distinct": column_profile.distinct_count,
                "looks_like": list(column_profile.looks_like),
                "samples": list(column_profile.sample_values[:3]),
            }
    return profiles


def measure(contract: Contract, data_dir: Path) -> Measurement:
    """Run the real mapping over the real files and report what happened.
    Never raises for a source problem -- that is the return value."""
    recording = _RecordingCollectors()
    adapter = ConfiguredAdapter(_provisional(contract), collector_factory=recording)

    tally = ingest.GapTally()
    assets: dict = {}
    halted_by: str | None = None
    try:
        assets, enriched = ingest.load_batch(data_dir, adapter)
        for item in enriched:
            tally.observe(item.finding)
    except ingest.IngestError as exc:
        halted_by = str(exc)

    report = tally.report(contract.format, assets, adapter.stats)
    return Measurement(
        data_dir=data_dir,
        assets_loaded=report.assets_total,
        findings_loaded=report.findings_total,
        duplicate_assets_collapsed=report.duplicate_assets_collapsed,
        duplicate_findings_collapsed=report.duplicate_findings_collapsed,
        excluded_assets=dict(report.excluded_assets),
        excluded_findings=dict(report.excluded_findings),
        asset_gaps=dict(report.asset_gaps),
        finding_gaps=dict(report.finding_gaps),
        header_notices=list(adapter.header_notices),
        headers=dict(adapter.headers),
        fatal_problems=recording.fatal_messages(),
        halted_by=halted_by,
        value_distribution=_value_distribution(assets),
        unmapped_profiles=_unmapped_profiles(contract, data_dir),
    )


def build_observed(measurement: Measurement, contract: Contract, *, at: str, by: str, command: str) -> dict:
    """The measurement, projected into `Contract.observed`.

    Flat on purpose: V18 reads `excluded_assets`/`excluded_findings` at the
    TOP level and adds them, so both must be plain ints there -- nesting
    them, or storing the `id -> reason` maps that `IngestStats` carries under
    those identical names, defeats the only validator that reads this block.

    What is deliberately NOT recorded: any cell value, any record id, and the
    per-finding exclusion reasons (a cascaded reason embeds its asset's id,
    which on a real export is a device identifier). Asset-side reasons ARE
    kept -- they contain the source's own vocabulary token and the known
    vocabulary, i.e. schema information -- but keyed by reason text with a
    count, never by record. A contract is committed to git; the terminal
    report, which prints all of it, is not."""
    reason_counts: Counter[str] = Counter(measurement.excluded_assets.values())
    return {
        "measured_at": at,
        "measured_by": by,
        "measured_by_command": command,
        "contract_version": contract.version,
        "assets_loaded": measurement.assets_loaded,
        "findings_loaded": measurement.findings_loaded,
        "duplicate_assets_collapsed": measurement.duplicate_assets_collapsed,
        "duplicate_findings_collapsed": measurement.duplicate_findings_collapsed,
        "excluded_assets": len(measurement.excluded_assets),
        "excluded_findings": len(measurement.excluded_findings),
        "excluded_asset_reasons": dict(sorted(reason_counts.items())),
        "not_collected_assets": dict(measurement.asset_gaps),
        "not_collected_findings": dict(measurement.finding_gaps),
        "header_notices": list(measurement.header_notices),
    }


def partition_slots(contract: Contract) -> SlotPartition:
    """Merge-by-slot-digest: which mapping decisions have moved since the
    contract was signed.

    This is what `compute_slot_digests`' own docstring exists for -- a vendor
    renaming one column changes `decision_digest` (the whole mapping moved)
    but leaves every other slot's digest untouched, so a reviewer re-reads
    one line instead of the whole contract. A digest cannot reconstruct what
    it hashed, so this names WHICH slot moved and the caller prints its
    current node; the previous one is in git."""
    stored = contract.review.slot_digests
    if not stored:
        return SlotPartition(available=False, unchanged=[], changed=[], new=[], orphaned=[])
    current = compute_slot_digests(contract)
    unchanged = sorted(k for k, v in current.items() if stored.get(k) == v)
    changed = sorted(k for k, v in current.items() if k in stored and stored[k] != v)
    new = sorted(k for k in current if k not in stored)
    orphaned = sorted(k for k in stored if k not in current)
    return SlotPartition(available=True, unchanged=unchanged, changed=changed, new=new, orphaned=orphaned)


def compute_drift(contract: Contract) -> Drift:
    from rhinosecure.adapters.config_model import compute_content_digest, compute_decision_digest

    return Drift(
        state=contract.review.state,
        was_confirmed=contract.review.decision_digest is not None,
        content_matches=contract.review.content_digest == compute_content_digest(contract),
        decision_matches=contract.review.decision_digest == compute_decision_digest(contract),
        slots=partition_slots(contract),
    )


def carried_attestations(contract: Contract, drift: Drift) -> tuple[list[Attestation], list[str]]:
    """Which of the reviewer's PRIOR claims survive the drift, and why the
    others do not.

    Carrying an unchanged slot's digest forward is arithmetically a no-op --
    a merged re-confirm and a full one produce the same file. The merge has
    teeth here instead: an attestation is a sentence a human wrote about a
    specific region of the mapping, and it survives only while that region is
    provably unmoved.

    - Nothing moved (`decision_digest` matches): everything carries.
    - Moved, with slot digests: `finding_id.synthesized` carries iff
      `finding.finding_id`'s own slot is unchanged. `enrichment` and `union`
      do NOT -- no stored digest covers the `enrichment` or `asset_grouping`
      subtrees individually, so there is no evidence they held still.

      This is conservative rather than provable, and it has a real cost: a
      one-word edit to an unrelated slot makes a reviewer retype two
      paragraphs about enrichment semantics, and prose retyped under duress
      reads like a fresh judgment without being one. The fix is to measure
      what is currently unmeasured -- have `compute_slot_digests` also emit
      an entry for the `enrichment` and `asset_grouping` subtrees, so the
      carry-forward can prove they held still instead of assuming they did
      not. Deliberately NOT done here: that changes what `confirm_contract`
      stamps and what `assert_confirmed` compares (Slice 3 machinery, and one
      of its pinned tests), which is a digest-format decision rather than a
      CLI one. Flagged, not silently fixed.
    - Moved, without slot digests: nothing carries; there is no evidence
      about any region.

    `exclusions` never carries on digest grounds at all -- it describes a
    measurement, not a mapping, and is re-checked against the fresh one.

    A contract that was never confirmed has nothing to carry FROM: its
    attestations are its author's original ones, not survivors of a prior
    signature, so they all simply stand."""
    if not drift.was_confirmed:
        return list(contract.attestations), []
    kept: list[Attestation] = []
    dropped: list[str] = []
    for attestation in contract.attestations:
        if attestation.item == "exclusions":
            kept.append(attestation)  # governed by the fresh measurement, not by drift
            continue
        if not drift.decisions_moved:
            kept.append(attestation)
            continue
        if not drift.slots.available:
            dropped.append(f"{attestation.item}: a mapping decision moved and this contract recorded no slot digests")
            continue
        if attestation.item == "finding_id.synthesized" and "finding.finding_id" in drift.slots.unchanged:
            kept.append(attestation)
            continue
        dropped.append(
            f"{attestation.item}: a mapping decision moved and no stored digest covers the region it attests to"
        )
    return kept, dropped


def parse_attestations(pairs: list[str], *, at: str) -> list[Attestation]:
    """`ITEM=TEXT`, split on the FIRST `=` so the text may contain one.
    Every offender in one message, the same discipline as
    `ProblemCollector.raise_if_fatal`. This is `ATTESTATION_ITEMS`' first
    consumer -- `Attestation.item` is a bare `str`, so without this a typo
    (`exclusion` for `exclusions`) constructs happily and V18 then refuses
    for a missing item while the file visibly contains an attestation."""
    problems: list[str] = []
    parsed: list[Attestation] = []
    seen: set[str] = set()
    for pair in pairs:
        item, sep, text = pair.partition("=")
        item, text = item.strip(), text.strip()
        if not sep:
            problems.append(f"{pair!r}: expected ITEM=TEXT")
            continue
        if item not in ATTESTATION_ITEMS:
            problems.append(f"{item!r}: not an attestation item (known: {sorted(ATTESTATION_ITEMS)})")
            continue
        if not text:
            problems.append(f"{item!r}: the attestation text is empty -- it is the whole point of the item")
            continue
        if item in seen:
            problems.append(f"{item!r}: supplied more than once in one invocation")
            continue
        seen.add(item)
        parsed.append(Attestation(item=item, text=text, at=at))
    if problems:
        raise ReviewError("bad --attest argument(s):\n" + "\n".join(f"  - {p}" for p in problems))
    return parsed


def review_contract(
    path: Path,
    contract: Contract,
    data_dir: Path,
    *,
    at: str,
    by: str | None = None,
    attest: list[str] | None = None,
    sign: bool = False,
    reconfirm: bool = False,
    reset_identity: bool = False,
) -> ReviewOutcome:
    """Measure, diff, gate, and -- only for `sign=True` and only if every
    gate passed -- stamp and write. `sign=False` is `rhino adapt rereview`
    and cannot write: there is no code path from it to `overwrite_contract`.

    Refusals accumulate into `ReviewOutcome.refusals` rather than raising,
    so a caller can print all of them at once; only a malformed request
    (`ReviewError`) raises."""
    drift = compute_drift(contract)
    kept, dropped_reasons = carried_attestations(contract, drift)
    supplied = parse_attestations(attest or [], at=at)

    by_item = {a.item: a for a in kept}
    added: list[Attestation] = []
    replaced: list[tuple[Attestation, Attestation]] = []
    for attestation in supplied:
        previous = by_item.get(attestation.item)
        if previous is None:
            added.append(attestation)
        else:
            replaced.append((previous, attestation))
        by_item[attestation.item] = attestation
    merged = [by_item[item] for item in sorted(by_item)]

    # The attestations must be merged BEFORE measuring, not after.
    # `ConfiguredAdapter.load_assets` runs `validate_contract` on every load,
    # and V18's STRUCTURAL requirements (enrichment / union /
    # finding_id.synthesized) depend only on the contract's shape -- so a
    # contract that does not already carry them makes the measurement itself
    # refuse. Measuring the pre-merge contract therefore made
    # `--attest` unable to ever help: the pass halted with 0 rows and the
    # refusal blamed the source. That is the normal state of a
    # freshly-proposed contract, so it would have blocked the whole
    # propose -> confirm flow. (`exclusions` is different -- it depends on
    # the measurement, and `_provisional` clears `observed` so a stale count
    # cannot make the fresh measurement refuse itself.)
    base = contract.model_copy(update={"attestations": merged})
    measurement = measure(base, data_dir)
    refusals: list[str] = []

    if sign and contract.review.state == "confirmed" and not reconfirm:
        refusals.append(
            f"{path.name} is already confirmed (at {contract.review.confirmed_at} by "
            f"{contract.review.confirmed_by}). Re-signing it replaces that signature and rewrites the "
            "file -- pass --reconfirm to say so on purpose, or use `rhino adapt rereview` to inspect it "
            "without writing."
        )

    if sign and not reset_identity and drift.decisions_moved:
        # The identity freeze. `check_identity_recipe_unchanged` (config_io)
        # cannot be used here: it needs the OLD contract and the NEW one, and
        # both verbs read a single file -- its real caller is the propose
        # step, which holds both at the moment it mints a revision.
        #
        # Phrased as "refuse unless the identity slot is PROVABLY unchanged",
        # never "refuse when it is known to have changed". The difference is
        # load-bearing: `review` sits outside both digests
        # (`compute_content_digest` excludes it outright), so `slot_digests`
        # is unsigned evidence that can be absent, partial, or deleted by
        # hand. Keying the gate on `in changed` left three ways past it -- no
        # slot_digests at all (the state of both committed contracts), that
        # one entry deleted (`partition_slots` then calls it `new`, not
        # `changed`), or the whole map removed -- each of which re-keys every
        # decision `memory.decisions` holds for the format, in silence.
        identity_proven_unchanged = drift.slots.available and "finding.finding_id" in drift.slots.unchanged
        if drift.slots.available and "finding.finding_id" in drift.slots.changed:
            refusals.append(
                "finding.finding_id's mapping changed since this contract was confirmed. "
                "memory.decisions keys on the rendered finding_id, so re-signing re-keys every "
                "decision this format has ever recorded, silently orphaning that history. Pass "
                "--reset-identity to confirm you understand that. (A digest cannot reconstruct what "
                "it hashed -- `git show HEAD:<path>` has the previous recipe.)"
            )
        elif not identity_proven_unchanged:
            # A mapping decision moved and no stored digest proves the
            # identity slot held still -- either none were recorded, or that
            # one is missing from the map. Whether the recipe changed is
            # unknowable from this file alone, and silence would let a changed
            # one through unremarked.
            why = (
                "this contract recorded no slot_digests"
                if not drift.slots.available
                else "no stored slot digest covers finding.finding_id"
            )
            refusals.append(
                f"a mapping decision moved and {why}, so whether finding.finding_id's recipe "
                "changed cannot be determined from this file. memory.decisions keys on the rendered "
                "finding_id. Compare against the previous revision (`git show HEAD:<path>`) and pass "
                "--reset-identity once you have confirmed the identity recipe is either unchanged or "
                "safe to re-key."
            )

    observed = build_observed(
        measurement, contract, at=at, by=by or "", command="confirm" if sign else "rereview"
    )
    candidate = base.model_copy(update={"observed": observed})
    required = required_attestations(candidate)
    still_missing = missing_attestations(candidate)

    # An attestation for a condition that does not hold is refused rather
    # than recorded: a signed acknowledgment of something that never happened
    # reads later as evidence someone looked at something.
    spurious = [a.item for a in supplied if a.item not in required]
    if spurious:
        refusals.append(
            f"--attest supplied for {sorted(spurious)}, which this contract and this measurement do not "
            f"require (required: {sorted(required) or 'none'})."
        )

    outcome_kwargs = dict(
        path=path,
        contract=contract,
        measurement=measurement,
        drift=drift,
        required=required,
        still_missing=still_missing,
        attestations_added=added,
        attestations_replaced=replaced,
        attestations_dropped=dropped_reasons,
    )

    if not sign:
        return ReviewOutcome(refusals=refusals, **outcome_kwargs)

    if by is None:
        raise ReviewError("signing requires an identity")
    # Missing attestations are listed BEFORE the generic fatal-problems line:
    # V18 runs inside the measurement too, so a missing attestation can be the
    # CAUSE of the halt rather than a second, independent problem, and leading
    # with "fatal problems on this source" would point the reader at the
    # export when the fix is a sentence.
    if still_missing:
        refusals.append(
            f"missing attestation(s) {still_missing} -- supply each with --attest ITEM=\"...\". "
            "Nothing is auto-generated: the whole value of the item is that a person wrote the sentence."
        )
    if not measurement.is_clean:
        refusals.append("the mapping hit fatal problems on this source (listed above); nothing was written.")
    if refusals:
        return ReviewOutcome(refusals=refusals, **outcome_kwargs)

    signed = confirm_contract(candidate, at=at, by=by)
    # Validate LAST, and against the engine's own filtered header view -- see
    # the module docstring's "Order of operations".
    validate_contract(signed, measurement.headers)
    _verify_round_trip(signed)
    overwrite_contract(path, signed)
    return ReviewOutcome(signed=signed, written=True, refusals=[], **outcome_kwargs)


def _verify_round_trip(signed: Contract) -> None:
    """Serialize exactly as the file will be written, re-parse, and re-run
    the engine's own gate -- before anything touches the filesystem.

    `Path.replace` guarantees a reader never sees a half-written file; it
    does not guarantee the file that lands is one the engine accepts. That
    gap is not theoretical here: `config_io.dump_for_disk` writes
    `by_alias=True` for `from_`/`from`, and this command is the first thing
    that ever writes a contract containing a `derived` block back to disk."""
    reloaded = Contract.model_validate(json.loads(json.dumps(dump_for_disk(signed))))
    assert_confirmed(reloaded)


__all__ = [
    "Drift",
    "Measurement",
    "ReviewError",
    "ReviewOutcome",
    "SlotPartition",
    "build_observed",
    "carried_attestations",
    "compute_drift",
    "measure",
    "parse_attestations",
    "partition_slots",
    "review_contract",
]
