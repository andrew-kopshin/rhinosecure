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
  the saved proposal (`out/propose_<name>.json`) plus, for every currently
  `unresolved` slot, the real measured profile of its candidate column(s)
  (`ColumnProfile.distinct_values` -- already computed by `check_grounding`
  today, just not previously surfaced to a human) and the target field's
  own closed vocabulary/range (`config_model.describe_target_vocabulary`).
  A slot is RESOLVED by editing the returned `proposal` JSON client-side
  (turning a `SlotUnresolved` entry into a `SlotMapped` one, choosing only
  among what `column_profiles`/`target_vocabulary` actually offer) and
  resubmitting the WHOLE thing through the EXISTING generic `POST
  /api/jobs` with `kind="ingest_propose"` and a new, additive job input,
  `edited_saved_proposal` (`_run_ingest_propose`, web/jobs.py) -- this
  module mounts no dispatch route of its own for that step. An illegal
  edit is refused by the identical `check_grounding`/`assemble_contract`
  gate a bad model output already goes through, never a second validator
  built for this surface that could disagree with it.
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
    describe_target_vocabulary,
    missing_attestations,
    required_attestations,
)
from rhinosecure.adapters.probe import profile_source
from rhinosecure.adapters.review import Measurement, ReviewError, ReviewOutcome, review_contract
from rhinosecure.agents.schema_inference import SchemaInferenceError, dump_saved_proposal, load_saved_proposal, unresolved_slots
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


def _column_profile_dict(profiles: dict, column: str) -> dict[str, Any] | None:
    for profile in profiles.values():
        column_profile = profile.columns.get(column)
        if column_profile is not None:
            return {
                "distinct_values": sorted(column_profile.distinct_values),
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
            column_profiles = {
                column: profile
                for column in entry.candidate_columns
                if (profile := _column_profile_dict(profiles, column)) is not None
            }
            unresolved_detail.append(
                {
                    "slot": slot,
                    "reason": entry.reason,
                    "candidate_columns": list(entry.candidate_columns),
                    "column_profiles": column_profiles,
                    "target_vocabulary": describe_target_vocabulary(target),
                }
            )

        return {
            "name": name,
            "saved_proposal": dump_saved_proposal(saved),
            "unresolved": unresolved_detail,
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
        if still_missing:
            return {
                "ok": False,
                "written": False,
                "measurement": None,
                "required_attestations": required,
                "still_missing": still_missing,
                "refusals": [],
            }

        data_dir = _resolve_upload_dir(app.state.upload_registry, upload_id)
        try:
            outcome = review_contract(config_path, contract, data_dir, at=_now(), sign=False)
        except ReviewError as exc:
            raise HTTPException(400, str(exc))
        return _review_outcome_dict(outcome)

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
