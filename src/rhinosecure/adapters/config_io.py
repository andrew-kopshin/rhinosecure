"""File I/O and the confirm/re-confirm workflow for ingest contracts
(adapters/config_model.py). Nothing here is read by `ConfiguredAdapter`
(adapters/configured.py) at ingest time -- confirmation happens BEFORE a
contract is ever handed to the engine, and `ConfiguredAdapter.__init__`
independently re-checks what `confirm_contract` stamped, via
`config_model.assert_confirmed`. That is deliberate, not redundant: the
engine's gate must hold even against a contract this module never touched
(a hand-written one, or one edited after confirmation) -- it cannot assume
everything reaching it came through here.

No clock, no randomness, same discipline as config_model.py's own engine
code: `confirm_contract` takes `at`/`by` as explicit parameters rather than
reading `datetime.now()` itself, so confirming is deterministic and
testable without mocking the clock. The caller (a later slice's CLI) is
where "now" and "who" actually get read.
"""

from __future__ import annotations

import json
from pathlib import Path

from rhinosecure.adapters.config_model import (
    Contract,
    ContractError,
    ContentAddressMapping,
    compute_content_digest,
    compute_decision_digest,
    compute_slot_digests,
)


class ContractIOError(ContractError):
    """A contract file could not be read or parsed."""


class IdentityRecipeChangedError(ContractError):
    """`finding.finding_id`'s content-address recipe differs between two
    revisions of a contract without an explicit override -- see
    `check_identity_recipe_unchanged`."""


def read_contract(path: Path) -> Contract:
    """Load and validate a contract from `path`. Raises `ContractIOError`
    for anything that stops it being read as JSON at all; a structurally
    invalid contract still raises pydantic's own `ValidationError` (letting
    the caller see exactly which field failed, the same as everywhere else
    a `Contract` is constructed)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContractIOError(f"{path}: could not be read -- {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ContractIOError(f"{path}: not valid JSON -- {exc}") from exc
    return Contract.model_validate(data)


def write_contract(path: Path, contract: Contract) -> Contract:
    """Persist `contract` to `path`, bumping `version` if a contract
    already exists there rather than overwriting it silently -- mirrors
    `enrich/cache.py`'s `SnapshotCache.write` routine verbatim (CLAUDE.md
    Section 8 rule 4): read the existing file's version if present, write
    the new one to a `.tmp` sibling, atomic `replace` onto the real path.
    An existing file that fails to parse is treated as absent for
    versioning purposes (version resets to 1) rather than blocking the
    write -- the write itself is what a caller reaches for to FIX a broken
    file.

    Returns the contract actually written (with the bumped `version`),
    since the caller's `contract` argument may still carry a stale one --
    the same shape as `SnapshotCache.write` returning the `SnapshotEntry`
    it just persisted rather than the payload the caller handed in.

    This ALWAYS bumps -- correct for `rhino adapt propose` (a later slice),
    which genuinely mints a new candidate revision every time it runs.
    Confirming an EXISTING revision is a different operation with a
    different invariant (the version being signed must not silently
    change out from under the signature): see `overwrite_contract`, which
    `confirm_contract` pairs with instead."""
    existing_version: int | None = None
    if path.exists():
        try:
            existing_version = read_contract(path).version
        except Exception:
            existing_version = None
    version = (existing_version + 1) if existing_version is not None else 1
    to_write = contract.model_copy(update={"version": version})
    _atomic_write_json(path, dump_for_disk(to_write))
    return to_write


def overwrite_contract(path: Path, contract: Contract) -> None:
    """Persist `contract` to `path` EXACTLY as given -- no version bump.

    `write_contract`'s "always bump" rule is right for a genuinely new
    proposal, but wrong for confirming one that already exists on disk:
    `confirm_contract`'s digests are computed against a specific `version`,
    and `write_contract`'s bump would silently write a DIFFERENT version
    than the one just signed -- the signature and the content would
    disagree the moment the file is re-read (`assert_confirmed` would then
    refuse a contract this module itself just confirmed). Still atomic
    (`.tmp` sibling, then `replace`), and still written through
    `_dump_for_disk` -- see its docstring for the `from`/`from_` alias that
    preserves."""
    _atomic_write_json(path, dump_for_disk(contract))


def dump_for_disk(contract: Contract) -> dict:
    """`by_alias=True`, and that matters: `DerivedMapping.from_` /
    `DefaultByKeyedBy.from_` carry `alias="from"` because `from` is a Python
    keyword, and a plain `model_dump()` emits the FIELD name -- so a contract
    read from disk with `"from": "os_platform"` and written back through here
    would silently become `"from_": "os_platform"`, a key the design document
    and every hand-written contract spell `from`. It still re-validates
    (`populate_by_name=True` accepts both), which is exactly why this went
    unnoticed: nothing before `rhino adapt confirm` ever wrote a contract
    containing a `derived` mapping back to disk.

    Digest-neutral, verified: `compute_content_digest`/`compute_decision_digest`
    always hash `model_dump(mode="json")` WITHOUT `by_alias`, so what is
    hashed is unchanged by this and both committed contracts' stored digests
    still verify after a round trip through here. The alias belongs to the
    file format, not to the signature."""
    return contract.model_dump(mode="json", by_alias=True)


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    tmp_path.replace(path)


def confirm_contract(contract: Contract, *, at: str, by: str) -> Contract:
    """Returns a new `Contract` with `review` stamped: `state="confirmed"`,
    `confirmed_at=at`, `confirmed_by=by`, `confirmed_version=contract.version`,
    and freshly computed `content_digest`/`decision_digest`/`slot_digests`.

    Does not write anything. Pair with `overwrite_contract`, not
    `write_contract` -- the digests here are computed against
    `contract.version` exactly as given, so persisting the result must not
    silently change that version out from under them. The realistic
    sequence: `write_contract` (propose -- mints and persists a new,
    bumped version), then later `confirm_contract` on what `read_contract`
    loads back (signs THAT version), then `overwrite_contract` (persists
    the signed result at the SAME version, no further bump).

    Digests are computed from `contract` BEFORE `review` is replaced (both
    digest functions already exclude `review` from what they hash, so this
    ordering is not load-bearing, but computing them against the pre-stamp
    object makes that independence obvious at the call site rather than
    assumed)."""
    content_digest = compute_content_digest(contract)
    decision_digest = compute_decision_digest(contract)
    slot_digests = compute_slot_digests(contract)
    review_cls = type(contract.review)
    return contract.model_copy(
        update={
            "review": review_cls(
                state="confirmed",
                confirmed_at=at,
                confirmed_by=by,
                confirmed_version=contract.version,
                content_digest=content_digest,
                decision_digest=decision_digest,
                slot_digests=slot_digests,
            )
        }
    )


#: The `ContentAddressMapping` fields that make up the actual hashing
#: recipe -- `recipe_version` is deliberately excluded: it is the field a
#: contract author bumps to acknowledge an intentional change, not part of
#: what is being compared for one.
_IDENTITY_RECIPE_FIELDS = ("algorithm", "columns", "join", "prefix", "hex_len", "case")


def check_identity_recipe_unchanged(old: Contract, new: Contract, *, allow_reset: bool = False) -> None:
    """Refuses a `new` contract whose `finding.finding_id` content-address
    recipe differs from `old`'s, unless `allow_reset=True` (a later slice's
    `--reset-identity` flag). `memory.decisions` (not built yet, but its
    schema is already fixed) keys on the rendered `finding_id` -- changing
    which columns feed it, their order, the join byte, the prefix, or the
    truncation length re-keys every finding this format has ever produced
    a decision for, silently orphaning that history. This is a one-way
    door a reviewer should have to open on purpose, not a mapping edit that
    looks like any other.

    A no-op whenever neither contract's `finding_id` is a `content_address`
    (nothing to freeze), or the recipe is unchanged apart from
    `recipe_version` (the field that exists specifically to record that a
    reset happened)."""
    old_mapping = old.finding.get("finding_id")
    new_mapping = new.finding.get("finding_id")
    if not isinstance(old_mapping, ContentAddressMapping) or not isinstance(new_mapping, ContentAddressMapping):
        return
    changed = [
        field
        for field in _IDENTITY_RECIPE_FIELDS
        if getattr(old_mapping, field) != getattr(new_mapping, field)
    ]
    if not changed or allow_reset:
        return
    raise IdentityRecipeChangedError(
        f"finding.finding_id's content_address recipe changed ({changed}) since this contract was "
        f"confirmed (old: {old_mapping.model_dump(mode='json')}, new: {new_mapping.model_dump(mode='json')}). "
        "memory.decisions keys on the rendered finding_id, so this change orphans every decision this "
        "format has recorded so far -- pass allow_reset=True (a later slice's --reset-identity) to "
        "confirm you understand that and proceed anyway."
    )
