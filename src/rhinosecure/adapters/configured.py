"""`ConfiguredAdapter` -- the phase-2 engine that interprets a declarative
ingest contract (`adapters/config_model.py`). One hand-written, reviewed,
LLM-free class executes a data structure; nothing here is generated, and
nothing here reaches a network, a model, or the clock.

This module is deliberately proven, not merely written: its differential
test suite (`tests/test_adapters_configured_differential.py`) asserts that
`ConfiguredAdapter` driven by a hand-written contract produces Asset and
Finding tuples -- `not_collected` included -- identical field-for-field to
`BluePeakAdapter`'s and `DefenderAdapter`'s own output on the real committed
files, with identical `IngestStats`. Where the two disagree on purpose (the
`finding_id` prefix, and one deliberately different disposition for a blank
scope-vocabulary cell), the contract's own `divergences` list says so, and
the test compares around it rather than pretending it does not exist.

Fatal vs. exclude, resolved here and nowhere else
--------------------------------------------------
`config_model.py`'s contract grammar has no `on_unmapped` key (see its own
module docstring). The engine is what makes that omission meaningful:
`_role_reference` forward-traces which check decides `Asset.role`'s value
-- either a `vocabulary` mapping directly on `asset.role`, or the `derived`
block a `default_by` mapping is keyed by -- and only THAT check's unmapped
values are scope-exclusions (`ProblemCollector.exclude`). Every other
vocabulary or derivation-table miss anywhere else in the contract is
`ProblemCollector.add`: a whole-batch, data-quality refusal. Neither the
contract nor a human confirming it gets a knob for this; it is derived
structurally, every time, the same way.

Per-row not_collected
----------------------
`self.contract.not_collected.always_asset` / `.always_finding` (validated
against the mappings at load time, V09 in config_model.py) are trusted
outright -- every record gets those targets unconditionally. A target in
`.per_row_eligible_asset` / `.per_row_eligible_finding` joins ONE record's
own `not_collected` only when that record's own cell was genuinely blank
and its mapping's `blank` policy is `"gap"` -- computed while resolving
that one row, never guessed from the format as a whole.
"""

from __future__ import annotations

import csv
import hashlib
import re
from collections import Counter
from collections.abc import Collection, Iterator
from datetime import date, datetime, timezone
from pathlib import Path
from typing import IO, Any

from pydantic import ValidationError

from rhinosecure import ingest
from rhinosecure.adapters.base import AdapterError, IngestAdapter, ProblemCollector
from rhinosecure.adapters.config_model import (
    REGISTERED_DEFAULT_TABLES,
    ColumnMapping,
    ComposedMapping,
    ComposedPartJoin,
    ComposedPartTemplate,
    Contract,
    ContentAddressMapping,
    DefaultByMapping,
    Derivation,
    DerivedMapping,
    ContractValidationError,
    LiteralMapping,
    NotCollectedMapping,
    ParsedMapping,
    VocabularyMapping,
    assert_confirmed,
    validate_contract,
)
from rhinosecure.schema import Asset, Finding, SourceEnrichment

_PLACEHOLDER_PATTERN = re.compile(r"\{([^{}]+)\}")
_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ATTACK_TECHNIQUE_PATTERN = re.compile(r"^(T\d{4}(?:\.\d{3})?)\s*-\s*(.+)$")
_ISO_DATE_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2})")
_US_EU_SLASH = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})$")
_FRACTIONAL_SECONDS = re.compile(r"(\.\d{1,6})\d*")

#: Sentinel distinguishing "resolution failed, already recorded on the
#: collector" from any real value (including None, "", or 0) a mapping
#: might legitimately produce. A module-level singleton, never compared by
#: value -- only `is _FAIL`.
_FAIL = object()

_BLANK_BEARING_KINDS = (ColumnMapping, VocabularyMapping, ParsedMapping)
_COLUMN_BEARING_KINDS = (ColumnMapping, VocabularyMapping, ParsedMapping)


def _apply_case(text: str, case: str) -> str:
    if case == "lower":
        return text.lower()
    if case == "upper":
        return text.upper()
    return text


def _parse_bool(cased: str, params: dict[str, Any] | None) -> bool | None:
    params = params or {}
    if cased in set(params.get("true", ())):
        return True
    if cased in set(params.get("false", ())):
        return False
    return None


def _parse_float(cased: str, params: dict[str, Any] | None) -> float | None:
    params = params or {}
    try:
        value = float(cased)
    except ValueError:
        return None
    lo, hi = params.get("min", float("-inf")), params.get("max", float("inf"))
    return value if lo <= value <= hi else None


def _parse_date(cased: str, params: dict[str, Any] | None) -> str | None:
    fmt = (params or {}).get("format", "iso")
    if fmt == "iso":
        try:
            return date.fromisoformat(cased).isoformat()
        except ValueError:
            return None
    if fmt == "iso_prefix":
        match = _ISO_DATE_PREFIX.match(cased)
        if match is None:
            return None
        try:
            return date.fromisoformat(match.group(1)).isoformat()
        except ValueError:
            return None
    if fmt in ("us_slash", "eu_slash"):
        match = _US_EU_SLASH.match(cased)
        if match is None:
            return None
        first, second, year = match.groups()
        month, day = (first, second) if fmt == "us_slash" else (second, first)
        try:
            return date(int(year), int(month), int(day)).isoformat()
        except ValueError:
            return None
    return None


def _parse_timestamp(cased: str) -> datetime | None:
    """ISO 8601 as a snapshot table typically writes it -- mirrors
    defender.py's `_parse_timestamp` exactly (up to seven fractional
    digits, `Z`/naive both taken as UTC, used only for ordering)."""
    t = cased.strip()
    if t.endswith(("Z", "z")):
        t = t[:-1] + "+00:00"
    t = _FRACTIONAL_SECONDS.sub(r"\1", t, count=1)
    try:
        parsed = datetime.fromisoformat(t)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_cve_id(cased: str) -> str | None:
    return cased if _CVE_ID_PATTERN.match(cased) else None


def _parse_scalar(kind: str, cased: str, params: dict[str, Any] | None) -> Any:
    if kind == "bool":
        return _parse_bool(cased, params)
    if kind == "float":
        return _parse_float(cased, params)
    if kind == "date":
        return _parse_date(cased, params)
    if kind == "cve_id":
        return _parse_cve_id(cased)
    raise AssertionError(f"parser {kind!r} has no scalar resolver (timestamp is order_by-only)")


def _render_composed(mapping: ComposedMapping, row: dict[str, str]) -> str:
    rendered: list[str] = []
    for part in mapping.parts:
        if isinstance(part, ComposedPartTemplate):
            text = _render_composed_template_part(part, row)
        else:
            text = _render_composed_join_part(part, row)
        if text is not None:
            rendered.append(text)
    return mapping.join.join(rendered)[: mapping.max_chars]


def _render_composed_template_part(part: ComposedPartTemplate, row: dict[str, str]) -> str | None:
    columns_needed: set[str] = set(_PLACEHOLDER_PATTERN.findall(part.template))
    if part.fallback_template:
        columns_needed |= set(_PLACEHOLDER_PATTERN.findall(part.fallback_template))
    columns_needed |= set(part.required_non_blank) | set(part.emit_if_any or ())
    values = {c: (row.get(c) or "").strip() for c in columns_needed}

    if part.emit_if_any and not any(values.get(c, "") for c in part.emit_if_any):
        return None
    if part.required_non_blank and not all(values.get(c, "") for c in part.required_non_blank):
        return part.fallback_template.format_map(values) if part.fallback_template is not None else None
    return part.template.format_map(values)


def _render_composed_join_part(part: ComposedPartJoin, row: dict[str, str]) -> str:
    values = [(row.get(c) or "").strip() for c in part.join_nonblank]
    return (part.prefix or "") + part.join.join(v for v in values if v)


def _open_csv(contract: Contract, path: Path) -> tuple[IO[str], csv.DictReader]:
    encoding = ingest.detect_encoding(path) if contract.source.encoding == "auto" else contract.source.encoding
    f = path.open(newline="", encoding=encoding)
    for _ in range(contract.source.first_data_row - 2):
        f.readline()  # a banner line above the real header, if the source declares one
    reader = csv.DictReader(f, delimiter=contract.source.delimiter, quotechar=contract.source.quotechar)
    return f, reader


def _read_header(contract: Contract, path: Path) -> list[str]:
    f, reader = _open_csv(contract, path)
    with f:
        return list(reader.fieldnames or [])


def _check_header_mode(mode: str, filename: str, declared_columns: list[str], real_columns: list[str]) -> list[str]:
    """Compares `declared_columns` (what the contract recorded when it was
    confirmed, `contract.header.assets`/`.findings`) against `real_columns`
    (what the file has right now), under `mode`. Returns a list of NOTICE
    strings -- non-empty only under "declared", for a column the contract
    has never seen -- and raises `ContractValidationError` for anything the
    mode treats as a hard refusal.

    "declared" (the default): every declared column must still be present
    -- missing or renamed refuses. A NEW column is a NOTICE, not an error:
    a vendor growing one harmless field must not stop a scheduled run (a
    guarantee people route around weekly is worse than none) -- but it is
    never silent, since a column nobody has looked at may carry the patch
    window this plan is missing. Column ORDER is irrelevant under this
    mode: nothing in this engine maps positionally (every mapping reads a
    column by name), so a reorder cannot change one byte of output, and
    refusing on it would be a pure false positive that trains an operator
    toward the looser mode for the wrong reason.

    "frozen": the ordered column list must match exactly. Reorder,
    addition, and removal all refuse -- the strictest mode, for a source
    whose shape must never move without a human looking at it again.
    """
    real_set = set(real_columns)
    declared_set = set(declared_columns)
    missing = [c for c in declared_columns if c not in real_set]

    if mode == "frozen":
        if real_columns == declared_columns:
            return []
        added = [c for c in real_columns if c not in declared_set]
        detail = []
        if missing:
            detail.append(f"missing {missing}")
        if added:
            detail.append(f"new {added}")
        if not missing and not added:
            detail.append("column order changed")
        raise ContractValidationError(
            f"{filename}: header.mode is 'frozen' and the header no longer matches exactly -- "
            + "; ".join(detail)
            + f". Declared: {declared_columns}. Actual: {real_columns}."
        )

    # declared
    if missing:
        raise ContractValidationError(
            f"{filename}: declared column(s) {missing} are missing from the real header {real_columns} "
            "-- renamed or removed since this contract was confirmed"
        )
    added = [c for c in real_columns if c not in declared_set]
    if not added:
        return []
    return [
        f"{filename} has {len(added)} column(s) this contract has never seen: {added}. It is not read. "
        "A column nobody has looked at may carry the patch window this plan is missing."
    ]


def _filtered_for_validation(mode: str, declared_columns: list[str], real_columns: list[str]) -> list[str]:
    """The header `validate_contract`'s own completeness check (V08) should
    reason about. Under "frozen", `_check_header_mode` already guarantees
    `real_columns == declared_columns` by the time this runs (anything else
    raised already), so the real header is used unchanged. Under
    "declared", a column new since confirmation is real but UNDECLARED --
    `_check_header_mode` already turned it into a notice above, and V08
    must not also demand it be mapped or listed in unmapped_columns (both
    of which describe DECLARED columns only); this filters it out of what
    V08 sees, so a harmless new field doesn't refuse an otherwise-clean run."""
    if mode == "frozen":
        return real_columns
    declared_set = set(declared_columns)
    return [c for c in real_columns if c in declared_set]


class ConfiguredAdapter(IngestAdapter):
    """Interprets one CONFIRMED `Contract` -- `__init__` refuses to
    construct at all against anything else (`config_model.assert_confirmed`,
    checked before a single byte of the source CSV is read: no file is
    opened, no instance attribute is set, until the contract itself passes).
    `collector_factory` defaults to the real `ProblemCollector`; a probe (a
    later slice) passes a non-raising recording subclass instead, so the
    review a human reads is produced by exactly this code, not a second
    implementation of it."""

    def __init__(self, contract: Contract, *, collector_factory: type[ProblemCollector] = ProblemCollector) -> None:
        assert_confirmed(contract)
        super().__init__()
        self.contract = contract
        self.format = contract.format
        self.assets_filename = contract.source.assets_filename
        self.findings_filename = contract.source.findings_filename
        self.provides_enrichment = contract.enrichment is not None
        self._collector_factory = collector_factory
        self._derivation_output_index: dict[str, dict[str, int]] = {
            name: {output: i for i, output in enumerate(d.outputs)} for name, d in contract.derived.items()
        }
        #: Populated by `load_assets` -- notices for a header difference
        #: `header.mode` tolerates (a new column under "declared") rather
        #: than refuses. Empty before `load_assets` runs, and whenever
        #: nothing has drifted.
        self.header_notices: list[str] = []

    @property
    def run_label(self) -> str:
        return f"{self.contract.format}@v{self.contract.version}"

    def _role_reference(self) -> tuple[str, str]:
        """See the module docstring's "Fatal vs. exclude" section. Returns
        `("vocabulary", "role")` when `asset.role` is a direct vocabulary
        lookup, `("derivation", <name>)` when it comes from a `default_by`
        keyed to derivation `<name>`, or `("none", "")` when role has no
        forward-traceable vocabulary at all (a plain `column`/`literal`
        mapping -- no exclusion concept applies; an invalid value there
        fails at `Asset` construction instead, same as any other schema
        `ValidationError` this module already catches)."""
        mapping = self.contract.asset["role"]
        if isinstance(mapping, VocabularyMapping):
            return ("vocabulary", "role")
        if isinstance(mapping, DefaultByMapping):
            return ("derivation", mapping.keyed_by.from_)
        return ("none", "")

    # --- shared row-reading helpers --------------------------------------

    def _open(self, path: Path) -> tuple[IO[str], csv.DictReader]:
        return _open_csv(self.contract, path)

    def _resolve_derivation(
        self, name: str, row: dict[str, str], row_no: int, problems: ProblemCollector, cache: dict[str, tuple[Any, ...] | None], identity: str | None
    ) -> tuple[Any, ...] | None:
        if name in cache:
            return cache[name]
        derivation: Derivation = self.contract.derived[name]
        raw = (row.get(derivation.column) or "").strip()
        cased = _apply_case(raw, derivation.case)
        if not cased:
            problems.add(f"row {row_no}: blank {derivation.column!r} -- cannot resolve derivation {name!r}")
            cache[name] = None
            return None
        outputs = derivation.table.get(cased)
        if outputs is None:
            if self._role_reference() == ("derivation", name):
                problems.exclude(
                    identity or f"row {row_no}",
                    f"{derivation.column} {raw!r} has no honest role equivalent in this contract's vocabulary "
                    f"(known: {sorted(derivation.table)}) -- not guessing a blast-radius weight for it",
                )
            else:
                problems.add(f"row {row_no}: {derivation.column} {raw!r} is not one of {sorted(derivation.table)}")
            cache[name] = None
            return None
        result = tuple(outputs)
        cache[name] = result
        return result

    def _resolve_target(
        self,
        mapping: Any,
        target: str,
        row: dict[str, str],
        row_no: int,
        problems: ProblemCollector,
        derivation_cache: dict[str, tuple[Any, ...] | None],
        identity: str | None,
    ) -> Any:
        """Returns the resolved value for `target`, or `_FAIL` if
        resolution failed and has already been recorded on `problems` (via
        `.add` or `.exclude`) -- the caller must abort this row."""
        if isinstance(mapping, NotCollectedMapping):
            from rhinosecure.adapters.base import NOT_COLLECTED_DEFAULTS

            return NOT_COLLECTED_DEFAULTS[target]

        if isinstance(mapping, LiteralMapping):
            return mapping.value

        if isinstance(mapping, DerivedMapping):
            outputs = self._resolve_derivation(mapping.from_, row, row_no, problems, derivation_cache, identity)
            if outputs is None:
                return _FAIL
            return outputs[self._derivation_output_index[mapping.from_][mapping.output]]

        if isinstance(mapping, DefaultByMapping):
            outputs = self._resolve_derivation(mapping.keyed_by.from_, row, row_no, problems, derivation_cache, identity)
            if outputs is None:
                return _FAIL
            keyed_value = outputs[self._derivation_output_index[mapping.keyed_by.from_][mapping.keyed_by.output]]
            return REGISTERED_DEFAULT_TABLES[mapping.table][keyed_value]

        if isinstance(mapping, _COLUMN_BEARING_KINDS):
            raw = (row.get(mapping.column) or "").strip()
            cased = _apply_case(raw, mapping.case)
            if not cased:
                return self._resolve_blank(mapping.blank, target, row_no, mapping.column, problems)
            if isinstance(mapping, ColumnMapping):
                return cased
            if isinstance(mapping, VocabularyMapping):
                value = mapping.table.get(cased)
                if value is None:
                    if self._role_reference() == ("vocabulary", target):
                        problems.exclude(
                            identity or f"row {row_no}",
                            f"{mapping.column} {raw!r} has no honest role equivalent in this contract's "
                            f"vocabulary (known: {sorted(mapping.table)}) -- not guessing a blast-radius "
                            "weight for it",
                        )
                    else:
                        problems.add(f"row {row_no}: {mapping.column} {raw!r} is not one of {sorted(mapping.table)}")
                    return _FAIL
                return value
            # ParsedMapping
            value = _parse_scalar(mapping.parser, cased, mapping.params)
            if value is None:
                problems.add(f"row {row_no}: {mapping.column} {raw!r} is not a valid {mapping.parser}")
                return _FAIL
            return value

        raise AssertionError(f"unexpected mapping kind on target {target!r}: {mapping!r}")

    def _resolve_blank(self, blank: str, target: str, row_no: int, column: str, problems: ProblemCollector) -> Any:
        from rhinosecure.adapters.base import NOT_COLLECTED_DEFAULTS

        if blank == "fatal":
            problems.add(f"row {row_no}: blank {column!r} -- nothing to key {target!r} on, or no honest default")
            return _FAIL
        if blank == "gap":
            return NOT_COLLECTED_DEFAULTS[target]
        return ""  # absent_fact

    # --- assets -----------------------------------------------------------

    def load_assets(self, path: Path) -> Iterator[Asset]:
        self.stats.duplicate_assets_collapsed = 0
        problems = self._collector_factory(path)
        data_dir = path.parent
        findings_path = data_dir / self.findings_filename
        assets_header = _read_header(self.contract, path)
        findings_header = (
            assets_header if self.contract.source.layout == "single_file" else _read_header(self.contract, findings_path)
        )

        header = self.contract.header
        notices: list[str] = []
        notices += _check_header_mode(header.mode, self.assets_filename, header.assets.columns, assets_header)
        if self.contract.source.layout == "two_file":
            notices += _check_header_mode(header.mode, self.findings_filename, header.findings.columns, findings_header)
        self.header_notices = notices

        validate_contract(
            self.contract,
            {
                self.assets_filename: _filtered_for_validation(header.mode, header.assets.columns, assets_header),
                self.findings_filename: _filtered_for_validation(
                    header.mode,
                    header.assets.columns if self.contract.source.layout == "single_file" else header.findings.columns,
                    findings_header,
                ),
            },
        )
        self._assets_header_set = set(assets_header)

        grouping = self.contract.asset_grouping
        union_targets = set(grouping.union_fields)
        # key -> (comparison fields excluding union targets, order_by value, row_no)
        resolved: dict[str, tuple[dict[str, Any], Any, int]] = {}
        union_seen: dict[str, dict[str, set[str]]] = {}
        order: list[str] = []

        f, reader = self._open(path)
        with f:
            for row_no, row in ingest.iter_csv_rows(path, reader):
                mapped = self._map_asset_row(row, row_no, problems)
                if mapped is None:
                    continue
                fields, key, order_value, union_row_values = mapped
                prior = resolved.get(key)
                if prior is None:
                    resolved[key] = (fields, order_value, row_no)
                    order.append(key)
                else:
                    prior_fields, prior_order, prior_row = prior
                    if fields == prior_fields:
                        self.stats.duplicate_assets_collapsed += 1
                    elif order_value is not None and prior_order is not None and order_value != prior_order:
                        self.stats.duplicate_assets_collapsed += 1
                        if order_value > prior_order:
                            resolved[key] = (fields, order_value, row_no)
                    else:
                        differing = sorted(k for k in fields if fields[k] != prior_fields.get(k))
                        problems.add(
                            f"row {row_no}: {grouping.key} {key!r} also appears on row {prior_row} with "
                            f"different resolved values and no later recency signal to prefer -- "
                            f"differing field(s): {differing}"
                        )
                for field_name, value in union_row_values.items():
                    if value:
                        union_seen.setdefault(key, {}).setdefault(field_name, set()).add(value)

        problems.raise_if_fatal(f"{self.assets_filename} (assets)")
        self.stats.excluded_assets = dict(problems.excluded)

        for key in order:
            fields, _order_value, row_no = resolved[key]
            final_fields = dict(fields)
            for target in union_targets:
                joined = ", ".join(sorted(v for v in union_seen.get(key, {}).get(target, ())))
                final_fields[target] = joined
            try:
                yield Asset(**final_fields)
            except ValidationError as exc:
                raise AdapterError(f"{path}: {grouping.key} {key!r} (row {row_no}): {exc}") from exc

    def _map_asset_row(
        self, row: dict[str, str], row_no: int, problems: ProblemCollector
    ) -> tuple[dict[str, Any], str, Any, dict[str, str]] | None:
        """Returns (fields excluding union targets, grouping key, order_by
        value, {union target: this row's own resolved value}), or None if
        the row failed (already recorded on `problems`)."""
        derivation_cache: dict[str, tuple[Any, ...] | None] = {}
        contract = self.contract
        grouping = contract.asset_grouping
        union_targets = set(grouping.union_fields)
        gap_eligible = set(contract.not_collected.per_row_eligible_asset)
        always_not_collected = frozenset(contract.not_collected.always_asset)

        asset_id_mapping = contract.asset["asset_id"]
        asset_id = self._resolve_target(asset_id_mapping, "asset_id", row, row_no, problems, derivation_cache, None)
        hostname_mapping = contract.asset["hostname"]
        hostname_val = self._resolve_target(hostname_mapping, "hostname", row, row_no, problems, derivation_cache, asset_id if asset_id is not _FAIL else None)
        if asset_id is _FAIL or hostname_val is _FAIL:
            return None

        role_kind, role_ref_name = self._role_reference()
        if role_kind == "derivation":
            # Resolve the role-deciding derivation FIRST, mirroring
            # defender.py's own "check the platform right after identity"
            # order -- an unrecognized value here excludes the WHOLE asset
            # before any other field is evaluated.
            if self._resolve_derivation(role_ref_name, row, row_no, problems, derivation_cache, asset_id) is None:
                return None
        elif role_kind == "vocabulary":
            role_mapping = contract.asset["role"]
            probe = self._resolve_target(role_mapping, "role", row, row_no, problems, derivation_cache, asset_id)
            if probe is _FAIL:
                return None

        fields: dict[str, Any] = {"asset_id": asset_id, "hostname": hostname_val}
        row_not_collected: set[str] = set()
        union_row_values: dict[str, str] = {}
        for target, mapping in contract.asset.items():
            if target in ("asset_id", "hostname"):
                continue
            if target == "role" and role_kind == "vocabulary":
                # Already resolved above (as `probe`) -- resolving twice
                # would double up any problems.add/.exclude call.
                fields["role"] = probe
                continue
            was_blank_column = (
                isinstance(mapping, _COLUMN_BEARING_KINDS)
                and target in gap_eligible
                and not _apply_case((row.get(mapping.column) or "").strip(), mapping.case)
                and mapping.blank == "gap"
            )
            value = self._resolve_target(mapping, target, row, row_no, problems, derivation_cache, asset_id)
            if value is _FAIL:
                return None
            if was_blank_column:
                row_not_collected.add(target)
            if target in union_targets:
                # Tracked separately, excluded from the comparison fields --
                # reuse the value _resolve_target already produced (correct
                # for whatever mapping kind this is) rather than re-deriving
                # it from the raw cell, which would silently skip a
                # vocabulary/parsed transform if this target were ever
                # mapped that way.
                union_row_values[target] = value if isinstance(value, str) else str(value)
                continue
            fields[target] = value

        fields["not_collected"] = frozenset(always_not_collected | row_not_collected)

        order_value: Any = None
        if grouping.order_by is not None:
            order_by = grouping.order_by
            raw = (row.get(order_by.column) or "").strip()
            if raw:
                order_value = _parse_date(raw, order_by.params) if order_by.parser == "date" else _parse_timestamp(raw)
                if order_value is None:
                    problems.add(f"row {row_no}: {order_by.column} {raw!r} is not a valid {order_by.parser}")
                    return None

        return fields, asset_id, order_value, union_row_values

    # --- findings -----------------------------------------------------------

    def load_findings(self, path: Path, asset_ids: Collection[str]) -> Iterator[Finding]:
        self.stats.duplicate_findings_collapsed = 0
        self._validate_findings(path, asset_ids)

        yielded: set[str] = set()
        excluded = self.stats.excluded_findings
        f, reader = self._open(path)
        with f:
            for row_no, row in ingest.iter_csv_rows(path, reader):
                mapped = self._map_finding_row(row, row_no, self._collector_factory(path))
                assert mapped is not None  # the validation pass already refused anything unmappable
                identity_key, _content, finding = mapped
                if finding.finding_id in excluded:
                    continue
                if identity_key in yielded:
                    self.stats.duplicate_findings_collapsed += 1
                    continue
                yielded.add(identity_key)
                yield finding

    def _validate_findings(self, path: Path, asset_ids: Collection[str]) -> None:
        """The yield-nothing pass. `identity_key` is the true dedup key --
        for a `content_address` finding_id it is the FULL, untruncated
        digest, never the rendered (possibly truncated) `finding_id`
        string, mirroring defender.py's own two-key shape exactly: two rows
        with the same full digest are the same finding re-observed (collapse
        or conflict, by `content`); two DIFFERENT full digests truncating to
        the same rendered `finding_id` is a distinct problem (a collision),
        checked separately via `ids` below. For a plain-column finding_id
        (BluePeak's Record_ID) `identity_key IS finding_id` and the
        collision check is trivially inert."""
        problems = self._collector_factory(path)
        orphans: Counter[str] = Counter()
        seen: dict[str, tuple[tuple[Any, ...], int]] = {}  # identity_key -> (content, row_no)
        ids: dict[str, str] = {}  # finding_id -> identity_key (first seen)

        f, reader = self._open(path)
        with f:
            for row_no, row in ingest.iter_csv_rows(path, reader):
                mapped = self._map_finding_row(row, row_no, problems)
                if mapped is None:
                    continue
                identity_key, content, finding = mapped
                if finding.asset_id not in asset_ids:
                    reason = self.stats.excluded_assets.get(finding.asset_id)
                    if reason is not None:
                        problems.exclude(finding.finding_id, f"its asset ({finding.asset_id}) was excluded: {reason}")
                    else:
                        orphans[finding.asset_id] += 1
                    continue
                prior = seen.get(identity_key)
                if prior is None:
                    seen[identity_key] = (content, row_no)
                    if ids.setdefault(finding.finding_id, identity_key) != identity_key:
                        problems.add(
                            f"row {row_no}: finding_id {finding.finding_id} collides with a different "
                            "finding -- raise content_address.hex_len or revisit the recipe"
                        )
                elif prior[0] != content:
                    problems.add(
                        f"row {row_no}: conflicts with row {prior[1]} -- same identity but different "
                        f"{self.contract.finding_dedup.content_targets} ({prior[0]} vs {content})"
                    )
        if orphans:
            listed = ", ".join(f"{a} ({n} finding(s))" for a, n in sorted(orphans.items())[:25])
            more = len(orphans) - min(len(orphans), 25)
            problems.add(
                f"{sum(orphans.values())} finding row(s) reference {len(orphans)} asset id(s) absent from "
                f"{self.assets_filename}: {listed}{f', ... and {more} more' if more else ''} -- a finding "
                "cannot be scored without its asset context"
            )
        problems.raise_if_fatal(f"{self.findings_filename} (findings)")
        self.stats.excluded_findings = dict(problems.excluded)

    def _finding_dedup_content(self, finding: Finding) -> tuple[Any, ...]:
        values = []
        for target in self.contract.finding_dedup.content_targets:
            if target.startswith("source_enrichment."):
                suffix = target[len("source_enrichment.") :]
                values.append(getattr(finding.source_enrichment, suffix, None) if finding.source_enrichment else None)
            else:
                values.append(getattr(finding, target))
        return tuple(values)

    def _map_finding_row(
        self, row: dict[str, str], row_no: int, problems: ProblemCollector
    ) -> tuple[str, tuple[Any, ...], Finding] | None:
        contract = self.contract
        derivation_cache: dict[str, tuple[Any, ...] | None] = {}
        gap_eligible = set(contract.not_collected.per_row_eligible_finding)
        always_not_collected = frozenset(contract.not_collected.always_finding)

        fields: dict[str, Any] = {}
        row_not_collected: set[str] = set()
        for target in ("asset_id", "cve_id", "detected_date", "scanner_severity", "product", "version", "port", "service", "evidence"):
            mapping = contract.finding[target]
            if isinstance(mapping, ComposedMapping):
                fields[target] = _render_composed(mapping, row)
                continue
            was_blank_column = (
                isinstance(mapping, _COLUMN_BEARING_KINDS)
                and target in gap_eligible
                and not _apply_case((row.get(mapping.column) or "").strip(), mapping.case)
                and mapping.blank == "gap"
            )
            value = self._resolve_target(mapping, target, row, row_no, problems, derivation_cache, None)
            if value is _FAIL:
                return None
            if was_blank_column:
                row_not_collected.add(target)
            fields[target] = value

        finding_id_mapping = contract.finding["finding_id"]
        if isinstance(finding_id_mapping, ContentAddressMapping):
            full_digest, finding_id = self._compute_content_address(finding_id_mapping, row)
            identity_key = full_digest
        else:
            value = self._resolve_target(finding_id_mapping, "finding_id", row, row_no, problems, derivation_cache, None)
            if value is _FAIL:
                return None
            finding_id = value
            identity_key = finding_id

        blank_identity = [c for c, v in (("finding_id", finding_id), ("asset_id", fields["asset_id"])) if not v]
        if blank_identity:
            problems.add(f"row {row_no}: blank identity column(s) {blank_identity} -- nothing to key this finding on")
            return None

        source_enrichment = None
        if contract.enrichment is not None:
            source_enrichment = self._resolve_enrichment(row, row_no, problems)
            if source_enrichment is _FAIL:
                return None

        try:
            finding = Finding(
                finding_id=finding_id,
                not_collected=frozenset(always_not_collected | row_not_collected),
                source_enrichment=source_enrichment,
                **fields,
            )
        except ValidationError as exc:
            problems.add(f"row {row_no}: {exc}")
            return None

        content = self._finding_dedup_content(finding)
        return identity_key, content, finding

    def _compute_content_address(self, mapping: ContentAddressMapping, row: dict[str, str]) -> tuple[str, str]:
        """Returns (full digest, rendered finding_id). The full,
        untruncated digest is always the true dedup identity; the rendered
        id -- `prefix` plus `hex_len` hex characters -- is what a human and
        `memory.decisions` actually see, and is never itself the identity
        key (see `_validate_findings`'s own docstring for why the two must
        stay separate)."""
        parts = [(row.get(c) or "").strip() for c in mapping.columns]
        identity = mapping.join.join(parts)
        full_digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        hexpart = full_digest[: mapping.hex_len]
        hexpart = hexpart.upper() if mapping.case == "upper" else hexpart.lower()
        return full_digest, f"{mapping.prefix}{hexpart}"

    def _resolve_enrichment(self, row: dict[str, str], row_no: int, problems: ProblemCollector) -> SourceEnrichment | Any:
        e = self.contract.enrichment
        assert e is not None
        raw_score = (row.get(e.severity_score.column) or "").strip()
        cased_score = _apply_case(raw_score, e.severity_score.case)
        if not cased_score:
            problems.add(f"row {row_no}: blank {e.severity_score.column!r} -- enrichment.severity_score has no honest default")
            return _FAIL
        score = _parse_float(cased_score, e.severity_score.params)
        if score is None:
            problems.add(f"row {row_no}: {e.severity_score.column} {raw_score!r} is not a valid float")
            return _FAIL

        known_exploited: bool | None = None
        if e.known_exploited is not None:
            raw_ke = (row.get(e.known_exploited.column) or "").strip()
            cased_ke = _apply_case(raw_ke, e.known_exploited.case)
            if not cased_ke:
                problems.add(f"row {row_no}: blank {e.known_exploited.column!r} -- enrichment.known_exploited has no honest default")
                return _FAIL
            known_exploited = _parse_bool(cased_ke, e.known_exploited.params)
            if known_exploited is None:
                problems.add(f"row {row_no}: {e.known_exploited.column} {raw_ke!r} is not a valid bool")
                return _FAIL

        technique_id, technique_name = "", ""
        if e.attack_technique is not None:
            raw_tech = (row.get(e.attack_technique.column) or "").strip()
            if raw_tech:
                match = _ATTACK_TECHNIQUE_PATTERN.match(raw_tech)
                if match is not None:
                    technique_id, technique_name = match.group(1), match.group(2).strip()
                # else: degrade -- the raw text still reaches evidence via
                # whatever composed part cites it; no fatal, no exclusion.

        return SourceEnrichment(
            severity_score=score,
            severity_label=self.contract.format,
            known_exploited=known_exploited,
            attack_technique_id=technique_id,
            attack_technique_name=technique_name,
        )
