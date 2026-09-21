"""Two read/write surfaces closing the upload-flow gap CLAUDE.md's
"Future direction: a conversational front end" left open: an `ingest_
propose` job reporting "N slot(s) still unresolved" had no browser path
forward except hand-editing a JSON file under `out/` and running a CLI
command by hand with a 40-character upload id.

Mounted by `create_app()` only when `jobs_enabled=True` -- the same
`if jobs_enabled:` branch that already imports `web/jobs.py`/`web/uploads
.py`/`web/route.py`, and for the identical reason: everything here either
reads a proposal `ingest_propose` already wrote, or writes a contract via
the exact same `adapters.review.review_contract` `rhino adapt confirm`
itself calls -- neither has a purpose without the upload/job substrate
already running. Requires `mount_upload_routes` to have run first (needs
`app.state.upload_registry`), the same ordering `mount_route_routes`
already depends on.

Two capabilities, deliberately different in shape, matching the design's
own distinction between resolving a mapping (ordinary structured data
entry) and confirming a contract (a dedicated, non-conversational
signature):

- `GET /api/adapters/{name}/proposal?upload_id=...` -- read-only. Returns
  the saved proposal (`out/propose_<name>.json`) plus FOUR lists needing a
  human's eyes before this can be confirmed:
  - `unresolved` -- every `SlotUnresolved` slot, with the real measured
    profile of its candidate column(s) (`ColumnProfile.distinct_values` --
    already computed by `check_grounding` today, just not previously
    surfaced to a human) and the target field's own closed vocabulary/range
    (`config_model.describe_target_vocabulary`).
  - `illegal` -- every slot that IS `SlotMapped` but individually fails
    `validate_contract` (`schema_inference.illegal_mapped_slots`,
    `_illegal_mapped_detail` below). A DIFFERENT fact from `unresolved`,
    on purpose (see `illegal_mapped_slots`'s own docstring for the argued
    reason it is a separate function, not folded into `unresolved_slots`):
    a mapping exists here and the validator rejects it, never "no mapping
    could be found." This is exactly the slot `assemble_provisional_
    contract`'s degrade path (or, on the strict path, `assemble_contract`'s
    own refusal) would otherwise silently drop and paper over with a
    placeholder or a bare, unreachable error -- before this existed, the
    only documented recourse was hand-editing the saved proposal JSON and
    re-running `rhino adapt propose --from-proposal` on the CLI. Renders
    through the identical `resolveSlotRowHtml` widget `unresolved`/
    `low_confidence` already use, worded distinctly (app.js reads each
    entry's `"kind"`).
  - `grounding_failed` -- every slot (or structural reference) that fails
    `check_grounding`: `_grounding_failed_detail` below. A mapping that IS
    present, IS individually legal, and fails only grounding matched
    neither list above, so the panel drew no row for it and its Resubmit
    was a no-op (docs/handoff.md 4.2.1). Each entry carries
    `grounding_kinds` (`schema_inference.GroundingKind`), so the row can
    say whether the file does not support the mapping or the schema
    registry disagrees with it. Deliberately NOT an override: a
    `registry_anchor` row lets the human change the value to match; a table
    that still contradicts the anchor is refused by the same gate.
  - `low_confidence` -- every `SCORING_ENUM_TARGETS` slot the model DID map,
    but at a self-reported confidence below `config_model
    .LOW_CONFIDENCE_THRESHOLD` (`_low_confidence_detail`, below). This is
    the real gap `check_grounding` cannot close on its own: it verifies a
    vocabulary table's cited tokens are real observed source values, never
    that the table's target-side VALUES are semantically right -- a scale
    the model guessed at 0.50 confidence (e.g. inventing where
    Critical/High/Medium/Low falls on a 1-5 integer scale) passes grounding
    cleanly regardless, because every source token it cited really is in
    the file. Scoped to `SCORING_ENUM_TARGETS` specifically because that's
    where a wrong value silently corrupts a real risk score, not just a
    free-text display field.
  All four lists share one shape for a reason: a slot is RESOLVED (an
  unresolved one), CORRECTED (an illegal or grounding-failed one), or
  CHANGED (a low-confidence one) the identical way -- editing the returned `proposal` JSON client-side
  and resubmitting the WHOLE thing through the EXISTING generic `POST
  /api/jobs` with `kind="ingest_propose"` and a new, additive job input,
  `edited_saved_proposal` (`_run_ingest_propose`, web/jobs.py) -- this
  module mounts no dispatch route of its own for that step. A human may
  also leave a low-confidence slot exactly as the model proposed it and
  simply attest to having reviewed it (below) -- unlike `unresolved`/
  `illegal`, a low-confidence mapping is not REQUIRED to change, only
  required to be seen. Either way, an illegal edit is refused by the
  identical `check_grounding`/`assemble_contract` gate a bad model output
  already goes through, never a second validator built for this surface
  that could disagree with it.
  Both endpoints also carry `open_questions`: what the model itself asked while
  proposing and nothing has answered. Display only. On `/proposal` it is the
  saved proposal's own list; on `/review` (the signing form) it is shown only
  when the saved proposal descends from the same model call as that contract
  (`_open_questions_for_contract`; lineage, not proof), and is empty otherwise.
- `GET /api/adapters/{name}/review?upload_id=...` and `POST /api/adapters
  /{name}/confirm` -- the dedicated confirmation form, calling `adapters
  .review.review_contract` with `sign=False`/`sign=True` exactly as `rhino
  adapt rereview`/`rhino adapt confirm` do. Deliberately NOT reachable
  through `/api/route` or any `OperationKind` -- see `agents/router.py`'s
  own docstring on why `INGEST_CONFIRM` is absent from the Router's
  vocabulary entirely, and why that absence has to live in the Router's
  closed enum, not in what routes happen to be mounted: nothing here
  changes `agents/router.py`. `POST /api/adapters/{name}/confirm` is this
  design's non-conversational form: a real identity (`by`) and one
  hand-written attestation sentence per item `required_attestations`
  reports as required -- never a checkbox (`Attestation.text` must be
  non-empty, config_model.py; nothing here auto-fills one). A refusal
  (missing attestations, a dirty measurement, an already-confirmed
  contract without `--reconfirm`'s browser equivalent) is a normal 200
  response with `written: false` and a `refusals` list, matching `review
  _contract`'s own "refusals accumulate ... rather than raising" design
  (and `_run_ingest_propose`'s identical `contract_written: false`
  convention) -- not an HTTP error status, since nothing here is a
  malformed request.

Re-confirming an already-signed contract (`--reconfirm`/`--reset-identity`)
is deliberately out of scope for this slice -- `POST .../confirm` always
signs a fresh, first-time confirmation; see this module's own test suite
for what that means for an already-confirmed name (a normal refusal, not
an exception).

**A real gap found running this live, not assumed away:** `GET .../review`
checks `required_attestations`/`missing_attestations` (config_model.py,
pure functions over the contract's own shape, no measurement) BEFORE ever
calling `review_contract`. A freshly-proposed contract carries none of its
own attestations yet, and `review_contract(sign=False)`'s real measurement
pass runs `validate_contract` inside `ConfiguredAdapter`'s own construction
-- which refuses immediately on a required-but-missing attestation, before
reading a single row. Calling it anyway would report "0 asset(s) loaded"
and a false "fatal problems" warning for a mapping that was actually fine;
the fix returns `measurement: null` instead and lets the confirm form
collect attestations first. One consequence that has no fix here, only a
UI accommodation: `exclusions` depends on `observed`, which does not exist
until a measurement actually runs -- so it can be invisible at preview
time and only surface once `POST .../confirm` itself measures for real
(confirmed live: a real 3-Workstation-only-role contract against 5 real
rows needed `enrichment`/`union`/`finding_id.synthesized` at preview, then
additionally refused for a missing `exclusions` attestation on the first
confirm attempt). The frontend handles this by adding a row for any
newly-discovered item in `still_missing` rather than only reporting its
name (`app.js`'s `submitConfirm`)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError

from rhinosecure.adapters import resolve_config_path
from rhinosecure.adapters.config_io import read_contract
from rhinosecure.adapters.config_model import (
    ABSENT_FACT_LEGAL_TARGETS,
    GAP_LEGAL_TARGETS,
    LOW_CONFIDENCE_THRESHOLD,
    PARSER_POSITIONS,
    REGISTERED_DEFAULT_TABLES,
    SCORING_ENUM_TARGETS,
    _composed_columns,
    describe_target_vocabulary,
    missing_attestations,
    required_attestations,
)
from rhinosecure.adapters.configured import _apply_case, _parse_scalar
from rhinosecure.adapters.probe import profile_source
from rhinosecure.adapters.review import Measurement, ReviewError, ReviewOutcome, review_contract
from rhinosecure.adapters.schema_registry import TARGET_REGISTRY
from rhinosecure.agents.schema_inference import (
    AdapterProposal,
    GroundingIssue,
    SchemaInferenceError,
    SlotMapped,
    check_grounding,
    dump_saved_proposal,
    illegal_mapped_slots,
    load_saved_proposal,
    unresolved_slots,
)
from rhinosecure.ingest import IngestError
from rhinosecure.web import uploads as uploads_module

_WEB_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _WEB_DIR.parents[2]  # .../web -> rhinosecure -> src -> repo root


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _saved_proposal_path(name: str) -> Path:
    """The one convention every writer of a saved proposal already shares
    (cli.py, web/jobs.py's `_run_ingest_propose`) -- not re-derived, just
    matched, since nothing in this codebase exports it as a constant."""
    return _REPO_ROOT / "out" / f"propose_{name}.json"


def _resolve_upload_dir(upload_registry: Any, upload_id: str) -> Path:
    upload_set = upload_registry.get(upload_id)
    if upload_set is None:
        raise HTTPException(404, f"no such upload set: {upload_id!r}")
    return upload_set.dir_path


def _mapping_source_columns(mapping: Any, derived: dict) -> list[str]:
    """Best-effort: the real CSV column(s) a mapping actually reads, so a
    low-confidence review can show that column's measured profile next to
    the mapping the model chose -- `check_grounding` already verifies a
    vocabulary table's KEYS are real observed tokens, but has no way to
    check the table's VALUES are semantically right (Contract
    .mapping_confidence's own docstring); showing the reviewer the same
    profile the model saw is how a human closes that gap. Returns `[]`
    rather than guessing for a mapping kind with no single column to point
    at (`composed`, `content_address`, `literal`, `not_collected`) -- the
    reviewer still sees the mapping's own shape and confidence, just not a
    column profile."""
    kind = getattr(mapping, "kind", None)
    if kind in ("column", "vocabulary", "parsed"):
        column = getattr(mapping, "column", None)
        return [column] if column else []
    if kind == "derived":
        deriv = derived.get(mapping.from_)
        return [deriv.column] if deriv else []
    if kind == "default_by":
        deriv = derived.get(mapping.keyed_by.from_)
        return [deriv.column] if deriv else []
    return []


def _mapping_all_columns(mapping: Any, derived: dict) -> list[str]:
    """EVERY column a mapping reads, for the form's column bookkeeping.

    Deliberately not `_mapping_source_columns`, which answers a different
    question ("which single column can a picker or a profile point at?") and
    so returns `[]` for `content_address` and `composed`. Settling from that
    list left a replaced content_address's columns in neither `mapped` nor
    `unmapped_columns`: `settle_columns` came out empty, the form settled
    nothing, and the contract was refused with no row left to repair it
    (found by the second adversarial-review round, 2026-09-21)."""
    kind = getattr(mapping, "kind", None)
    if kind == "content_address":
        return list(dict.fromkeys(mapping.columns))
    if kind == "composed":
        return sorted(_composed_columns(mapping))
    return _mapping_source_columns(mapping, derived)


def _predict_current_values(mapping: Any, derived: dict[str, Any], distinct_values: dict[str, int]) -> dict[str, Any]:
    """For every raw value the candidate column was actually observed to
    contain, what the CURRENTLY proposed mapping would resolve it to --
    computed with the SAME case-transform and scalar-parser functions the
    real engine (`adapters.configured.ConfiguredAdapter._resolve_target`)
    applies at read time, imported and called directly rather than a
    second, hand-written copy of that logic. That duplication is exactly
    what produced this function's own reason to exist: an earlier version
    of the browser corrector re-implemented the vocabulary-table lookup
    inline in JS without applying the mapping's declared `case` transform
    first, so a mixed-case source column silently showed no "proposed"
    hint at all for a mapping that was actually correct. Reusing the real
    functions here means there is only one place case/parsing logic can
    disagree with the engine, and it's the engine's own module.

    Covers every `SCORING_ENUM_TARGETS`-legal mapping kind that reads a
    single column (`column`, `vocabulary`, `parsed`, `default_by`,
    `derived`) -- not just `vocabulary`, which is all the previous version
    handled. `literal`/`composed`/`content_address`/`not_collected` have no
    single source column to predict per-value against
    (`_mapping_source_columns` already returns `[]` for them) and never
    reach this function with a non-empty `distinct_values`.

    Returns only the values this mapping actually resolves. A value the
    mapping doesn't recognize (absent from a vocabulary/derivation/default
    table, or one a parser rejects) is simply omitted -- the browser
    corrector then starts that value on "(exclude this value)" with no
    false "proposed:" hint, the same honest-blank behavior an unresolved
    slot already has, rather than guessing what the model "must have
    meant"."""
    predicted: dict[str, Any] = {}
    kind = getattr(mapping, "kind", None)
    for raw in distinct_values:
        cased = _apply_case(raw.strip(), getattr(mapping, "case", "exact"))
        if not cased:
            continue
        if kind == "column":
            predicted[raw] = cased
        elif kind == "vocabulary":
            value = mapping.table.get(cased)
            if value is not None:
                predicted[raw] = value
        elif kind == "parsed":
            # `_parse_scalar` asserts for a parser with no scalar resolver
            # (today: "timestamp", legal only inside `asset_grouping.
            # order_by` -- `PARSER_POSITIONS`, the same registry `config_
            # model._check_parser_placement` reads). The real engine never
            # reaches it with one, because `validate_contract` refuses that
            # placement first -- but THIS function runs against a proposal
            # that has not been validated yet, which is exactly how a
            # misplaced parser is supposed to surface here: as one more row
            # in `illegal`, not a 500 out of the route handler. Skipping it
            # is the same "omit what this mapping doesn't resolve" rule
            # already applied to every other missed lookup below, not a
            # special case -- a mapping the validator will refuse outright
            # has no meaningful "currently resolves to" value to predict.
            if "row" not in PARSER_POSITIONS.get(mapping.parser, frozenset()):
                continue
            value = _parse_scalar(mapping.parser, cased, mapping.params)
            if value is not None:
                predicted[raw] = value
        elif kind in ("default_by", "derived"):
            deriv_name = mapping.keyed_by.from_ if kind == "default_by" else mapping.from_
            deriv_output = mapping.keyed_by.output if kind == "default_by" else mapping.output
            deriv = derived.get(deriv_name)
            if deriv is None:
                continue
            # `cased` above already applied `mapping`'s own case (a no-op --
            # neither DefaultByMapping nor DerivedMapping HAS a `case`
            # field), so re-derive from the raw value using the
            # DERIVATION's own case, exactly matching
            # `_resolve_derivation`'s `_apply_case(raw, derivation.case)`.
            deriv_cased = _apply_case(raw.strip(), deriv.case)
            outputs = deriv.table.get(deriv_cased)
            if outputs is None:
                continue
            if deriv_output not in deriv.outputs:
                continue
            key = outputs[deriv.outputs.index(deriv_output)]
            if kind == "derived":
                predicted[raw] = key
            else:
                table = REGISTERED_DEFAULT_TABLES.get(mapping.table, {})
                if key in table:
                    predicted[raw] = table[key]
    return predicted


def _low_confidence_detail(
    proposal: AdapterProposal, profiles: dict
) -> list[dict[str, Any]]:
    """One entry per `SCORING_ENUM_TARGETS` slot mapped below
    `LOW_CONFIDENCE_THRESHOLD` -- the slots a wrong value silently corrupts
    a real risk score for, rather than merely showing up wrong in a
    report (config_model.py's own reasoning for scoping the gate to this
    set). Always asset-side: every `SCORING_ENUM_TARGETS` member is an
    asset field."""
    detail = []
    for target in SCORING_ENUM_TARGETS:
        slot = proposal.asset[target]
        if not isinstance(slot, SlotMapped) or slot.confidence >= LOW_CONFIDENCE_THRESHOLD:
            continue
        filename = _side_filename(proposal, "asset", slot.mapping)
        candidate_columns = _real_columns(
            profiles, _mapping_source_columns(slot.mapping, proposal.derived), filename
        )
        column_profiles = {
            column: profile
            for column in candidate_columns
            if (profile := _column_profile_dict(profiles, column, filename)) is not None
        }
        # Predicted per-value, not just the raw mapping JSON: the browser
        # corrector pre-fills "proposed: X" from this, and it has to be
        # right for every mapping kind this slot can carry (`default_by`,
        # `parsed`, `column` -- not only `vocabulary`), computed the one
        # place that can't disagree with the real engine. Empty when there
        # is no single candidate column to predict against (`literal` etc.)
        # or the column's profile wasn't measured.
        current_values: dict[str, Any] = {}
        if candidate_columns:
            profile = column_profiles.get(candidate_columns[0])
            if profile is not None:
                current_values = _predict_current_values(
                    slot.mapping, proposal.derived, profile["distinct_values"]
                )
        detail.append(
            {
                "slot": f"asset.{target}",
                "confidence": slot.confidence,
                "reason": slot.evidence.note,
                "current_mapping": slot.mapping.model_dump(mode="json"),
                "current_values": current_values,
                "candidate_columns": candidate_columns,
                "settle_columns": _real_columns(
                    profiles, _mapping_all_columns(slot.mapping, proposal.derived), filename
                ),
                "column_profiles": column_profiles,
                # Whether "mark not collected" is even a legal correction for
                # THIS target -- `role` is not a `NOT_COLLECTED_DEFAULTS` key
                # (it falls back through `default_by`/`ROLE_DEFAULT_BY_OS_CLASS`
                # instead), so a bare `not_collected` mapping on it fails
                # `validate_contract` exactly the way it does for `product`/
                # `evidence` below -- the browser corrector must not offer an
                # illegal escape hatch here either.
                "gap_legal": target in GAP_LEGAL_TARGETS,
                "target_vocabulary": describe_target_vocabulary(target),
            }
        )
    return detail


def _illegal_mapped_detail(proposal: AdapterProposal, profiles: dict) -> list[dict[str, Any]]:
    """One entry per slot `illegal_mapped_slots` reports -- a mapping DOES
    exist here, but `validate_contract` itself would refuse it. Shaped
    like `_low_confidence_detail`'s own entries on purpose (`current_
    mapping`/`current_values`/`candidate_columns`/`column_profiles`/
    `gap_legal`/`target_vocabulary`): the browser widget that renders a
    row from this dict (`resolveSlotRowHtml`, app.js) is the SAME one
    `_low_confidence_detail` already feeds, since both describe "a
    mapping exists, here's what it currently resolves to, correct it
    through the identical controls." `"kind": "illegal"` is the one new
    field, read by that widget to word the row differently from a
    genuinely unresolved one -- see `illegal_mapped_slots`'s own
    docstring for why that distinction has to survive all the way to the
    row, not just to this function's return shape.

    Not scoped to `SCORING_ENUM_TARGETS` the way `_low_confidence_detail`
    is: a mapping validate_contract refuses can be any target, not only a
    scoring axis -- `finding.detected_date` with a misplaced `timestamp`
    parser is exactly as illegal, and exactly as invisible before this
    function existed, as a bad `asset.role` mapping.

    `reason` is the validator's own text for this slot, verbatim -- never
    a generic "this mapping is invalid" placeholder. Multiple problems for
    one slot (rare, but `_mapped_slot_legality_problems` allows it) are
    joined, not truncated, so nothing the validator said is silently
    dropped from what the human reads before correcting it."""
    detail = []
    for slot, problems in illegal_mapped_slots(proposal, profiles).items():
        section, _, target = slot.partition(".")
        sp = (proposal.asset if section == "asset" else proposal.finding)[target]
        filename = _side_filename(proposal, section, sp.mapping)
        candidate_columns = _real_columns(
            profiles, _mapping_source_columns(sp.mapping, proposal.derived), filename
        )
        column_profiles = {
            column: profile
            for column in candidate_columns
            if (profile := _column_profile_dict(profiles, column, filename)) is not None
        }
        current_values: dict[str, Any] = {}
        if candidate_columns:
            profile = column_profiles.get(candidate_columns[0])
            if profile is not None:
                current_values = _predict_current_values(sp.mapping, proposal.derived, profile["distinct_values"])
        detail.append(
            {
                "slot": slot,
                "kind": "illegal",
                "reason": "; ".join(problems),
                "current_mapping": sp.mapping.model_dump(mode="json"),
                "current_values": current_values,
                "candidate_columns": candidate_columns,
                "settle_columns": _real_columns(
                    profiles, _mapping_all_columns(sp.mapping, proposal.derived), filename
                ),
                "column_profiles": column_profiles,
                "gap_legal": target in GAP_LEGAL_TARGETS,
                "absent_fact_legal": target in ABSENT_FACT_LEGAL_TARGETS,
                "fatal_legal": _fatal_legal(target),
                "target_vocabulary": describe_target_vocabulary(target),
            }
        )
    return detail


def _open_questions_for_contract(name: str, contract: Any) -> list[str]:
    """The model's own `open_questions` for the proposal that produced
    `contract` -- shown next to the signature, where an unanswered question
    matters most. Empty unless the saved proposal DESCENDS FROM THE SAME
    MODEL CALL as this contract: their `generator.call_log_digest` (the
    phase-1 LLM call's own log, copied unchanged into the contract by every
    assembly path and carried through every human edit) must match.

    That is lineage, not proof that this proposal produced this contract,
    and the docstring used to say "provably". A refused resubmit saves the
    edited proposal but leaves the older contract in place, and the two
    still share a digest, so a signer can then see the questions of an
    edited proposal beside the contract it did not produce (found by
    adversarial review, 2026-09-21). Accepted as display-only and narrow:
    the edit is a human's own, and the browser form cannot reach it.

    What the check does catch is the common way the two files disagree:
    `rhino adapt propose` under a name that already has a contract writes
    its new proposal even when assembly is refused, so an old contract can
    sit beside a newer proposal from a different model call. A hand-authored
    contract has no saved proposal at all, and a contract with no
    `generator` cannot be matched; both show nothing rather than guess.
    (The existing `low_confidence` list trusts the pairing without this
    check; it is not changed here.)

    Never raises: a saved proposal that cannot be read, decoded or parsed
    is `SchemaInferenceError` from `load_saved_proposal` (its
    `UnicodeDecodeError` and `attempt_usage` `TypeError` used to escape it
    and 500 the signing form over a display-only lookup)."""
    try:
        saved = load_saved_proposal(_saved_proposal_path(name))
    except SchemaInferenceError:
        return []
    generator = getattr(contract, "generator", None)
    if generator is None or generator.call_log_digest != saved.generator.call_log_digest:
        return []
    return list(saved.proposal.open_questions)


def _fatal_legal(target: str) -> bool:
    """Whether `blank: "fatal"` (refuse the batch on a blank) is a legal
    policy for `target`, read off the same registry `validate_contract`
    enforces. Sent per row because the browser cannot otherwise build a
    column mapping for an identity-like target (`hostname`, `cve_id`,
    `asset_id`, `finding_id`): each has `fatal` as its ONLY legal blank
    policy, and the picker offered a column only when `gap` or
    `absent_fact` was legal -- so a slot no source column could be
    mapped to from the form, however obvious the column was."""
    spec = TARGET_REGISTRY.get(target)
    return spec is not None and "fatal" in spec.legal_blank_policies


def _grounding_failed_detail(
    proposal: AdapterProposal,
    profiles: dict,
    failures: list[GroundingIssue],
    *,
    existing_by_slot: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """One row per slot (or structural reference) that fails grounding --
    the row source docs/handoff.md 4.2.1 found missing. A slot that IS
    mapped, IS individually legal, and fails only grounding matched
    neither `unresolved` nor `illegal`, so the panel drew nothing for it
    and its Resubmit button was a no-op that reproduced the identical
    refusal.

    Every failing issue gets a row, correctable or not: a correctable one
    carries the controls the form already has (`resolveSlotControls`,
    app.js -- which alone decides what THIS FORM can build), and one it
    cannot correct still names the real reason and the recourse. Nothing
    here decides whether a human may overrule a registry anchor: a
    `registry_anchor` row shows the disagreement and the same per-value
    pickers, and a table that still contradicts the anchor is refused by
    the identical `check_grounding` gate as before -- this only makes the
    refusal visible and fixable in place.

    Two de-duplications, so the panel never shows one slot twice:
    - a slot that already has a row in `existing_by_slot` (an `unresolved`
      or `illegal` one) gets the grounding text MERGED into that row's
      `reason` rather than a second row, since one `.resolve-slot` per
      `data-slot` is what the JS looks rows up by. This used to SKIP an
      unresolved slot on the claim that a hallucinated candidate column
      "changes nothing about what the human has to do". It does: that
      failure is what blocks assembly, and skipping it left the panel
      silent about the only thing stopping the contract (found by
      adversarial review, 2026-09-21);
    - issues are grouped by slot, so two failures on one slot are one row.

    `candidate_columns` is filtered to columns the slot's OWN file really
    has (`_side_filename`): a column picker must never offer the very
    column that failed, and in a two-file source "a file" is not enough.
    The one exception is deliberate and narrow -- a `missing_column`
    failure on a FREE-TEXT target (no closed vocabulary), where the whole
    real header of that slot's file is offered instead, because picking a
    real column IS the correction. For a closed-vocabulary target the
    form's per-value picker needs one specific column and its profile,
    which a missing column cannot supply, so the row stays uncorrectable
    and says so.

    `settle_columns` is a DIFFERENT list, and the difference is the point:
    the columns the CURRENT mapping (or the model's own candidates) read,
    which the form must account for when it replaces them. The picker's
    list is "what the human may choose from"; only the settle list is "what
    this edit is responsible for". The form used one list for both, so the
    whole-header picker made a one-slot fix declare every unaccounted
    column ignored (found by adversarial review, 2026-09-21)."""
    by_slot: dict[str, list[GroundingIssue]] = {}
    for issue in failures:
        by_slot.setdefault(issue.slot, []).append(issue)

    detail: list[dict[str, Any]] = []
    for slot, issues in by_slot.items():
        reason = "; ".join(i.message for i in issues)
        kinds = sorted({i.kind for i in issues})

        merged = existing_by_slot.get(slot)
        if merged is not None:
            merged["reason"] = f"{merged['reason']}; also fails grounding: {reason}"
            merged["grounding_kinds"] = kinds
            # A FREE-TEXT slot whose every candidate was hallucinated has
            # nothing left to choose from after filtering, and for a target
            # like `hostname` "not collected" is illegal too, so the row was
            # a dead end. Offer the slot's real header, exactly as an already
            # mapped slot with a missing column gets (found by the second
            # adversarial-review round, 2026-09-21). Only when NOTHING real
            # is left: a real candidate the model did name stays the
            # suggestion. A closed-vocabulary target is not widened: its
            # picker needs one column and that column's profile.
            if "missing_column" in kinds and merged.get("target_vocabulary") is None and not merged["candidate_columns"]:
                section = slot.partition(".")[0]
                merged["candidate_columns"] = list(profiles[_side_filename(proposal, section)].columns)
            continue

        section, _, target = slot.partition(".")
        slot_map = proposal.asset if section == "asset" else proposal.finding if section == "finding" else None
        sp = slot_map.get(target) if slot_map is not None else None
        if not isinstance(sp, SlotMapped):
            # Structural: no target field exists to correct. `structural`
            # tells the row to name the reference instead of claiming a
            # target has "no candidate column".
            detail.append(
                {
                    "slot": slot,
                    "kind": "grounding",
                    "structural": True,
                    "grounding_kinds": kinds,
                    "reason": reason,
                    "current_mapping": None,
                    "current_values": {},
                    "candidate_columns": [],
                    "settle_columns": [],
                    "column_profiles": {},
                    "gap_legal": False,
                    "absent_fact_legal": False,
                    "fatal_legal": False,
                    "target_vocabulary": None,
                }
            )
            continue

        vocabulary = describe_target_vocabulary(target)
        filename = _side_filename(proposal, section, sp.mapping)
        own_columns = _real_columns(profiles, _mapping_source_columns(sp.mapping, proposal.derived), filename)
        candidate_columns = list(own_columns)
        if vocabulary is None and "missing_column" in kinds:
            candidate_columns = list(profiles[filename].columns)
        # Profiles only for the columns the mapping ACTUALLY reads, never for
        # a widened whole-header list: the free-text picker needs names, not
        # profiles (resolveSlotControls builds a value picker only for a
        # closed vocabulary), and a real source can have hundreds of columns
        # each carrying a distinct-value table.
        column_profiles = {
            column: profile
            for column in own_columns
            if (profile := _column_profile_dict(profiles, column, filename)) is not None
        }
        current_values: dict[str, Any] = {}
        if own_columns:
            current_values = _predict_current_values(
                sp.mapping, proposal.derived,
                _column_profile_dict(profiles, own_columns[0], filename)["distinct_values"],
            )
        detail.append(
            {
                "slot": slot,
                "kind": "grounding",
                "grounding_kinds": kinds,
                "reason": reason,
                "current_mapping": sp.mapping.model_dump(mode="json"),
                "current_values": current_values,
                "candidate_columns": candidate_columns,
                "settle_columns": _real_columns(
                    profiles, _mapping_all_columns(sp.mapping, proposal.derived), filename
                ),
                "column_profiles": column_profiles,
                "gap_legal": target in GAP_LEGAL_TARGETS,
                "absent_fact_legal": target in ABSENT_FACT_LEGAL_TARGETS,
                "fatal_legal": _fatal_legal(target),
                "target_vocabulary": vocabulary,
            }
        )
    return detail


def _side_filename(proposal: AdapterProposal, section: str, mapping: Any = None) -> str:
    """The file a slot's columns live in: `asset.*` reads the assets file and
    `finding.*` the findings file. A `derived`/`default_by` mapping is the
    exception -- `check_grounding` grounds a derivation against the assets
    file whichever side asks (`_ground_derivation`), so this does too. Equal
    for a single-file source; for two files, looking a column up in the
    OTHER file is a wrong answer, not a harmless one."""
    kind = getattr(mapping, "kind", None)
    if section == "asset" or kind in ("derived", "default_by"):
        return proposal.meta.assets_filename
    return proposal.meta.findings_filename


def _real_columns(profiles: dict, columns: list[str], filename: str) -> list[str]:
    """`columns`, in order, restricted to those `filename` actually has."""
    profile = profiles.get(filename)
    return [c for c in columns if profile is not None and c in profile.columns]


def _column_profile_dict(profiles: dict, column: str, filename: str | None = None) -> dict[str, Any] | None:
    """One column's measured profile. With `filename`, looks in THAT file
    only; without it, in the first file that has the name (kept for callers
    with no side to name). Every slot-shaped caller passes `filename`:
    searching every file returned the assets file's `Kind` for a findings
    slot in a two-file source, so a row showed values the mapping never
    reads and offered a column the slot's own file lacked."""
    candidates = [profiles[filename]] if filename is not None and filename in profiles else (
        [] if filename is not None else list(profiles.values())
    )
    for profile in candidates:
        column_profile = profile.columns.get(column)
        if column_profile is not None:
            return {
                # value -> occurrence count, not just the value list -- a
                # low-confidence review needs "how many rows does this
                # source value affect", not only "what values exist"
                # (ColumnProfile.distinct_values' own docstring already
                # carries the count; `sorted()` over the dict alone would
                # silently discard it).
                "distinct_values": dict(sorted(column_profile.distinct_values.items())),
                "distinct_overflow": column_profile.distinct_overflow,
                "blank": column_profile.blank,
                "non_blank": column_profile.non_blank,
                "samples": list(column_profile.sample_values[:5]),
            }
    return None


def _measurement_dict(m: Measurement) -> dict[str, Any]:
    return {
        "assets_loaded": m.assets_loaded,
        "findings_loaded": m.findings_loaded,
        "duplicate_assets_collapsed": m.duplicate_assets_collapsed,
        "duplicate_findings_collapsed": m.duplicate_findings_collapsed,
        "excluded_assets": dict(m.excluded_assets),
        "excluded_findings": dict(m.excluded_findings),
        "asset_gaps": dict(m.asset_gaps),
        "finding_gaps": dict(m.finding_gaps),
        "header_notices": list(m.header_notices),
        "fatal_problems": list(m.fatal_problems),
        "halted_by": m.halted_by,
        "value_distribution": {k: dict(v) for k, v in m.value_distribution.items()},
        "is_clean": m.is_clean,
    }


def _review_outcome_dict(outcome: ReviewOutcome) -> dict[str, Any]:
    return {
        "ok": outcome.ok,
        "written": outcome.written,
        "measurement": _measurement_dict(outcome.measurement),
        # Mirrors cli.py's `_print_review_header` "dialect:" line -- both
        # are MEASURED (schema_inference.py's _assemble_and_validate), never
        # model-authored, and both decide what every count/sample below
        # even means. Shown here, not just in the CLI, because this is the
        # payload the confirm form itself reads before a human signs
        # (app.js's renderConfirmPanel) -- the one browser-side surface a
        # signer actually looks at, same as _print_review_header is the
        # first thing a CLI signer sees.
        "source": {"encoding": outcome.contract.source.encoding, "delimiter": outcome.contract.source.delimiter},
        "required_attestations": dict(outcome.required),
        "still_missing": list(outcome.still_missing),
        "refusals": list(outcome.refusals),
    }


class ConfirmRequest(BaseModel):
    upload_id: str
    by: str
    attestations: dict[str, str] = {}


def mount_adapter_routes(app: FastAPI) -> None:
    """Called by `create_app()` only when `jobs_enabled=True` -- see module
    docstring. Reads `app.state.upload_registry`, set by
    `mount_upload_routes`; must be mounted after it."""

    @app.get("/api/adapters/{name}/proposal")
    def get_proposal(name: str, upload_id: str) -> dict[str, Any]:
        path = _saved_proposal_path(name)
        try:
            saved = load_saved_proposal(path)
        except SchemaInferenceError as exc:
            raise HTTPException(404, str(exc))

        data_dir = _resolve_upload_dir(app.state.upload_registry, upload_id)
        try:
            profiles = {p.path.name: p for p in profile_source(data_dir)}
        except Exception as exc:  # a source that changed shape since it was proposed
            raise HTTPException(500, f"could not profile {data_dir}: {exc}")

        unresolved_detail = []
        for slot in unresolved_slots(saved.proposal):
            section, _, target = slot.partition(".")
            slot_map = saved.proposal.asset if section == "asset" else saved.proposal.finding
            entry = slot_map[target]
            # Only columns the slot's own file has: the model's candidate list
            # is unverified, and `resolveSlotControls` takes candidate_columns[0]
            # and needs its profile, so a hallucinated FIRST candidate hid the
            # value picker entirely. The failure itself is not lost: it is
            # merged into this row's reason below, where the human can read it.
            filename = _side_filename(saved.proposal, section)
            real_candidates = _real_columns(profiles, list(entry.candidate_columns), filename)
            column_profiles = {
                column: profile
                for column in real_candidates
                if (profile := _column_profile_dict(profiles, column, filename)) is not None
            }
            unresolved_detail.append(
                {
                    "slot": slot,
                    "kind": "unresolved",
                    "reason": entry.reason,
                    "candidate_columns": real_candidates,
                    "settle_columns": list(real_candidates),
                    "column_profiles": column_profiles,
                    "target_vocabulary": describe_target_vocabulary(target),
                    # A free-text target (target_vocabulary is None, e.g.
                    # finding.product/evidence) has no per-value picker at
                    # all -- the browser's only other tool is "mark not
                    # collected", which is illegal whenever the target has no
                    # NOT_COLLECTED_DEFAULTS entry (validate_contract refuses
                    # it: "not_collected has no NOT_COLLECTED_DEFAULTS entry
                    # for '<target>'"). Confirmed live, not assumed: a
                    # standalone repro resolving finding.product this way
                    # reproduced exactly the reported bug -- 0 unresolved
                    # slots, contract still not written, real reason hidden
                    # by the frontend's old message. `absent_fact_legal` is
                    # the legal escape hatch for that case instead (a real
                    # `column` mapping with `blank: "absent_fact"`) -- both
                    # flags are read off the SAME registries
                    # `validate_contract` itself enforces, never guessed at
                    # in JS.
                    "gap_legal": target in GAP_LEGAL_TARGETS,
                    "absent_fact_legal": target in ABSENT_FACT_LEGAL_TARGETS,
                    "fatal_legal": _fatal_legal(target),
                }
            )

        illegal = _illegal_mapped_detail(saved.proposal, profiles)
        try:
            report = check_grounding(saved.proposal, profiles)
        except SchemaInferenceError as exc:
            # The saved proposal names files this upload does not contain:
            # it was generated for a different source. Refused loudly --
            # the alternative, an empty grounding list, would present a
            # proposal nobody has actually checked as though it were clean.
            raise HTTPException(409, f"the saved proposal does not match this upload: {exc}")
        grounding_failed = _grounding_failed_detail(
            saved.proposal,
            profiles,
            report.failures,
            existing_by_slot={e["slot"]: e for e in (*unresolved_detail, *illegal)},
        )

        return {
            "name": name,
            # Where the file the browser is editing actually lives. The
            # form needs it for exactly one thing: naming the recourse on a
            # slot it cannot correct itself ("edit THIS file by hand and
            # re-run --from-proposal"). Supplied here rather than rebuilt
            # in JS because `out/propose_<name>.json` is a server-side
            # convention three writers already share -- a fourth copy of it
            # in the browser is precisely the kind of re-derived rule that
            # drifts. Note what this deliberately is NOT: a flag saying
            # whether a row is correctable. That depends on which controls
            # `buildSlotMapping` can emit, which only app.js knows -- see
            # `resolveSlotControls`' own comment for the argument.
            "saved_proposal_path": str(path),
            "saved_proposal": dump_saved_proposal(saved),
            "unresolved": unresolved_detail,
            "illegal": illegal,
            "grounding_failed": grounding_failed,
            "low_confidence": _low_confidence_detail(saved.proposal, profiles),
            # What the model itself asked while proposing this mapping and
            # nothing has answered (AdapterProposal.open_questions). Display
            # only: no gate, no attestation, never read by anything that
            # decides. Model-authored free text, so the browser must escape it.
            "open_questions": list(saved.proposal.open_questions),
        }

    @app.get("/api/adapters/{name}/review")
    def get_review(name: str, upload_id: str) -> dict[str, Any]:
        config_path = resolve_config_path(name)
        try:
            contract = read_contract(config_path)
        except (IngestError, ValidationError) as exc:
            raise HTTPException(404, f"no proposed contract named {name!r}: {exc}")

        # required_attestations/missing_attestations are pure -- they read
        # only the contract's own shape, no measurement. Checked FIRST: a
        # contract that structurally needs an attestation it doesn't have
        # yet makes `review_contract`'s own real measurement pass halt at
        # V18 before reading a single row (validate_contract runs inside
        # ConfiguredAdapter's construction, and a freshly-proposed contract
        # carries none of its own attestations yet) -- confirmed live
        # against a real content_address/enrichment/union proposal before
        # this check existed: the preview showed "0 asset(s) loaded" and a
        # false "fatal problems" warning for a mapping that was actually
        # fine, because nothing had merged the human's not-yet-typed
        # attestations in. Skipping the real measurement in that case
        # avoids running (and reporting) a halt this form itself hasn't
        # given the contract any chance to pass yet -- `POST .../confirm`
        # merges supplied attestations before measuring, exactly as `rhino
        # adapt confirm` does, and that call DOES see the real numbers.
        required = required_attestations(contract)
        still_missing = missing_attestations(contract)
        open_questions = _open_questions_for_contract(name, contract)
        if still_missing:
            return {
                "ok": False,
                "written": False,
                "open_questions": open_questions,
                "measurement": None,
                # The dialect is a structural fact of the contract itself,
                # not something the real measurement below computes -- a
                # signer still filling in attestation text should see it
                # too, not only once every attestation is supplied.
                "source": {"encoding": contract.source.encoding, "delimiter": contract.source.delimiter},
                "required_attestations": required,
                "still_missing": still_missing,
                "refusals": [],
            }

        data_dir = _resolve_upload_dir(app.state.upload_registry, upload_id)
        try:
            outcome = review_contract(config_path, contract, data_dir, at=_now(), sign=False)
        except ReviewError as exc:
            raise HTTPException(400, str(exc))
        return {**_review_outcome_dict(outcome), "open_questions": open_questions}

    @app.post("/api/adapters/{name}/confirm")
    def post_confirm(name: str, body: ConfirmRequest) -> dict[str, Any]:
        if not body.by.strip():
            raise HTTPException(400, "by (identity) must be non-empty")

        config_path = resolve_config_path(name)
        try:
            contract = read_contract(config_path)
        except (IngestError, ValidationError) as exc:
            raise HTTPException(404, f"no proposed contract named {name!r}: {exc}")

        data_dir = _resolve_upload_dir(app.state.upload_registry, body.upload_id)
        attest = [f"{item}={text}" for item, text in body.attestations.items()]
        try:
            outcome = review_contract(
                config_path, contract, data_dir, at=_now(), by=body.by, attest=attest, sign=True
            )
        except ReviewError as exc:
            raise HTTPException(400, str(exc))
        return _review_outcome_dict(outcome)
