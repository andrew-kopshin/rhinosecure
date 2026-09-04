"""CSV ingest for the two input files, plus attaching live threat signals
to what was ingested.

Rows are read and validated one at a time via generators — nothing here
collects a whole file into memory, and nothing branches on how many rows a
particular dataset happens to have. A future adapter for a real scanner
export (Nessus/Qualys/InsightVM/Defender VM) sits in front of these loaders:
it normalizes that export's native columns into assets.csv / findings.csv
shape and hands rows to the same `Asset` / `Finding` models. Nothing below
needs to change for that to work.

That adapter layer now exists: `adapters/` (base.py for the contract and
the `not_collected` representation of fields a source format lacks;
defender.py for Microsoft Defender Vulnerability Management). `join` is the
loader-agnostic half of the old `join_findings`: an adapter hands it an
already-indexed inventory and a lazy finding stream in whatever way its
source format requires, and it does the one thing every format needs
identically -- attach each finding to its asset, refusing an orphan.
`join_findings` (the native two-path form every existing caller uses) is
unchanged in behavior and delegates to it; `load_batch` is what cli.py
calls for any format. `IngestStats`/`IngestReport` live here rather than
in `adapters/` because they describe a batch, not a format, and cli.py
prints them for every format alike.

`attach_threat_signals` was originally private to `cli.py`'s deterministic
`run()`. Moved here (public, unchanged behavior) so `agents/coordinator.py`'s
fleet-wide capacity constraint flow can reuse the exact same real,
network/cache-sourced KEV/EPSS/NVD/ATT&CK enrichment without going through
the Research agent -- CLAUDE.md Section 10's "only five patches fit this
window" example needs the *real* bucket a finding is in to decide who
competes for capacity, but the reallocation itself has to stay
deterministic (Section 8 rule 2's "no LLM calls" discipline, applied here
to "no LLM call decides who's in the competing pool" too -- see
scoring.apply_capacity_limit's own docstring). `coordinator.py` importing
this from `cli.py` directly would have been the wrong direction (the
entry-point module reaching down into a lower-level one); this module
already sits below both and was the natural shared home -- ingest a
finding, then attach what's known about its real-world threat, are two
facets of "get a finding ready for score_finding," not different concerns.
This module still makes no LLM calls and needs none of `crewai` -- only
network/cache access via `SnapshotCache`, safe to import from either the
deterministic or agents path.
"""

from __future__ import annotations

import codecs
import csv
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING

from pydantic import ValidationError

from rhinosecure.enrich.attack import TechniqueIndex
from rhinosecure.enrich.cache import SnapshotCache
from rhinosecure.enrich.epss import lookup as epss_lookup
from rhinosecure.enrich.kev import KevCatalog
from rhinosecure.enrich.nvd import lookup as nvd_lookup
from rhinosecure.schema import Asset, AttackTechniqueRef, EnrichedFinding, Finding

if TYPE_CHECKING:  # adapters/base.py imports this module; keep the runtime import graph one-directional
    from rhinosecure.adapters.base import IngestAdapter


class IngestError(Exception):
    """A row failed schema validation, or an adapter refused its input
    (adapters.AdapterError subclasses this)."""


@dataclass
class IngestStats:
    """What an adapter collapsed or excluded on the way in. Mutable: a
    streaming `load_findings` can only count as its iterator is consumed.

    `excluded_assets`/`excluded_findings` (identity -> reason) are scope-
    boundary exclusions -- adapters/base.py's `ProblemCollector.exclude`,
    e.g. Defender's non-Windows `OSPlatform` or BluePeak's unmapped
    `Asset_Type`: the record is well-formed, it just describes something
    outside this project's declared Windows-fleet scope, so it is skipped
    and reported rather than blocking the whole batch the way a genuine
    data-quality problem (a blank identity column, a malformed value, an
    unresolvable conflict) still does via `ProblemCollector.add`/
    `raise_if_fatal`. An excluded finding's reason may itself be cascading
    ("its asset was excluded: ...") when the finding's own row was fine
    but its asset's wasn't -- see each adapter's `load_findings`."""

    duplicate_assets_collapsed: int = 0
    duplicate_findings_collapsed: int = 0
    excluded_assets: dict[str, str] = field(default_factory=dict)
    excluded_findings: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class IngestReport:
    """One batch's data-gap summary -- how many records left each schema
    field `not_collected` (adapters/base.py), plus what was collapsed and
    what was excluded. Empty for a native run (no gaps, nothing collapsed
    or excluded), so cli.py prints nothing and the demo fixture's output
    stays byte-identical.

    `assets_total`/`findings_total` count only what was actually loaded
    (excluded records are not in that count) -- the original, pre-
    exclusion total is `assets_total + len(excluded_assets)` /
    `findings_total + len(excluded_findings)`, computed by whoever prints
    it (cli.py's `_print_exclusions`), not stored again here."""

    format: str
    assets_total: int
    findings_total: int
    duplicate_assets_collapsed: int
    duplicate_findings_collapsed: int
    asset_gaps: dict[str, int] = field(default_factory=dict)  # field -> assets where not collected
    finding_gaps: dict[str, int] = field(default_factory=dict)
    excluded_assets: dict[str, str] = field(default_factory=dict)  # asset_id -> reason
    excluded_findings: dict[str, str] = field(default_factory=dict)  # finding_id -> reason

    @property
    def has_gaps(self) -> bool:
        return bool(self.asset_gaps or self.finding_gaps)

    @property
    def has_exclusions(self) -> bool:
        return bool(self.excluded_assets or self.excluded_findings)

    @property
    def has_anything_to_report(self) -> bool:
        return (
            self.has_gaps
            or self.has_exclusions
            or bool(self.duplicate_assets_collapsed or self.duplicate_findings_collapsed)
        )


class GapTally:
    """Accumulates `IngestReport` counts while a caller streams findings,
    so the report costs no second pass over anything."""

    def __init__(self) -> None:
        self.findings_total = 0
        self._finding_gaps: Counter[str] = Counter()

    def observe(self, finding: Finding) -> None:
        self.findings_total += 1
        self._finding_gaps.update(finding.not_collected)

    def report(self, fmt: str, assets: Mapping[str, Asset], stats: IngestStats) -> IngestReport:
        asset_gaps: Counter[str] = Counter()
        for asset in assets.values():
            asset_gaps.update(asset.not_collected)
        return IngestReport(
            format=fmt,
            assets_total=len(assets),
            findings_total=self.findings_total,
            duplicate_assets_collapsed=stats.duplicate_assets_collapsed,
            duplicate_findings_collapsed=stats.duplicate_findings_collapsed,
            asset_gaps=dict(sorted(asset_gaps.items())),
            finding_gaps=dict(sorted(self._finding_gaps.items())),
            excluded_assets=dict(sorted(stats.excluded_assets.items())),
            excluded_findings=dict(sorted(stats.excluded_findings.items())),
        )


# Byte-order marks, longest first: UTF-32-LE's BOM begins with UTF-16-LE's, so
# checking UTF-16 first would decode a UTF-32 file as UTF-16 and produce
# garbage rather than a refusal. The "utf-16"/"utf-32" codecs (no -le/-be
# suffix) read the BOM to pick endianness and strip it, so one entry covers
# both byte orders.
_BOM_ENCODINGS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
    (codecs.BOM_UTF8, "utf-8-sig"),
)


def detect_encoding(path: Path) -> str:
    """The codec `path` declares through its byte-order mark, or utf-8.

    Windows PowerShell 5.1's `Export-Csv` writes UTF-16LE with a BOM by
    default, and Excel writes UTF-8 with one -- so a real export is very
    often not the bare UTF-8 every loader here used to assume. Sniffing the
    BOM is not guessing: a BOM is the file stating its own encoding. A file
    with no BOM is read as UTF-8 and refused by `open_csv` if it isn't.
    """
    # A missing or unreadable file raises OSError from here, exactly as the
    # `path.open(...)` this replaced did. Deliberately not wrapped in
    # IngestError: `Coordinator.__init__`'s native-only fallback load depends
    # on the bare FileNotFoundError (pinned by test_coordinator.py), and
    # whether that constructor's error contract should change is its own
    # decision, not something an encoding fix gets to make on the way past.
    with path.open("rb") as f:
        prefix = f.read(4)
    for bom, encoding in _BOM_ENCODINGS:
        if prefix.startswith(bom):
            return encoding
    return "utf-8"


def open_csv(path: Path) -> tuple[IO[str], csv.DictReader]:
    """Open a source CSV in the encoding it declares, header already read.

    Every adapter reads its files through here so encoding handling, and the
    refusal when it fails, are identical across formats. The header is forced
    now rather than on first iteration so a wrong codec is reported by this
    function -- which knows the path and the encoding -- instead of surfacing
    later as a bare `UnicodeDecodeError` from inside whatever code happens to
    touch `fieldnames` first. That error is a `ValueError`, not an
    `IngestError`, so before this it escaped every `except IngestError` in
    cli.py and reached the user as a traceback.
    """
    encoding = detect_encoding(path)
    f = path.open(newline="", encoding=encoding)
    reader = csv.DictReader(f)
    try:
        reader.fieldnames  # noqa: B018 -- forces the header read; a bad codec fails here
    except UnicodeDecodeError as exc:
        f.close()
        raise IngestError(_decode_error_message(path, encoding, exc)) from exc
    return f, reader


def _decode_error_message(path: Path, encoding: str, exc: UnicodeDecodeError) -> str:
    return (
        f"{path}: could not be decoded as {encoding} (byte {exc.object[exc.start:exc.end]!r} "
        f"at position {exc.start}: {exc.reason}). The file declares no byte-order mark, so it "
        "was read as UTF-8. Re-export it as UTF-8, or as UTF-8/UTF-16 with a BOM."
    )


def iter_csv_rows(path: Path, reader: csv.DictReader) -> Iterator[tuple[int, dict[str, str]]]:
    """`(row number, row)` for every data row, refusing loudly on a decode
    error mid-file rather than part-way through a batch.

    The single place every adapter's row loop goes through, so a rule about
    what a readable row *is* is stated once instead of per format.

    The row number is `reader.line_num` -- the count of physical lines
    consumed so far -- not an `enumerate(reader, start=2)` counter. Every
    adapter used to count records, and the two agree only when every record
    is exactly one physical line. A record whose evidence text has an
    embedded newline (legal inside a quoted CSV field, and exactly the kind
    of free-text column this project's own evidence fields are) consumes two
    physical lines for one record, and every enumerate-based row number after
    it in the file is then one low -- silently, since nothing about that
    record itself looks wrong. `line_num` reports the true line and needs no
    adjustment for what came before it.

    A row whose field count disagrees with the header is refused here. That
    matters most in the short-row direction: `csv.DictReader` fills a missing
    trailing column with `None`, every adapter reads cells as
    `(row.get(col) or "").strip()`, and a blank cell is exactly what the
    `not_collected` machinery turns into a documented default plus a recorded
    gap -- so without this check a truncated row is laundered into an
    honest-looking "this source didn't collect that", in the code path built
    to prevent precisely that. A long row is worse in a quieter way: the
    overflow lands under the `None` key and is discarded with no trace.

    Unlike a bad *value* in a well-formed row, this is a structural problem
    with the file, so it refuses immediately rather than accumulating through
    a `ProblemCollector` the way per-row value problems do -- a CSV whose
    field counts do not line up is not a file to report forty separate
    findings about.
    """
    columns = list(reader.fieldnames or [])
    try:
        for row in reader:
            row_no = reader.line_num
            overflow = row.get(None)
            if overflow is not None:
                raise IngestError(
                    f"{path}: row {row_no} has {len(columns) + len(overflow)} fields but the header "
                    f"declares {len(columns)}; the {len(overflow)} extra value(s) {overflow!r} belong "
                    "to no column and would be discarded silently. Re-export the file."
                )
            missing = [column for column in columns if row.get(column) is None]
            if missing:
                raise IngestError(
                    f"{path}: row {row_no} has {len(columns) - len(missing)} fields but the header "
                    f"declares {len(columns)}; column(s) {missing} are absent from the row entirely. "
                    "A truncated row is not a row with blank cells -- treating it as one would record "
                    "a data-quality problem as a collected-but-empty field. Re-export the file."
                )
            yield row_no, row
    except UnicodeDecodeError as exc:
        raise IngestError(_decode_error_message(path, exc.encoding, exc)) from exc


def _rows(path: Path) -> Iterator[dict[str, str]]:
    f, reader = open_csv(path)
    with f:
        for _row_no, row in iter_csv_rows(path, reader):
            yield row


def load_assets(path: Path) -> Iterator[Asset]:
    for row in _rows(path):
        try:
            yield Asset.model_validate(row)
        except ValidationError as exc:
            raise IngestError(f"{path}: invalid asset row {row!r}: {exc}") from exc


def load_findings(path: Path) -> Iterator[Finding]:
    for row in _rows(path):
        try:
            yield Finding.model_validate(row)
        except ValidationError as exc:
            raise IngestError(f"{path}: invalid finding row {row!r}: {exc}") from exc


def load_asset_index(path: Path) -> dict[str, Asset]:
    """Build an asset_id -> Asset lookup.

    Findings are the side of this join expected to scale with fleet size, so
    only they are kept as a lazy stream; the asset inventory is the natural
    side to index for O(1) lookup during that stream's consumption.
    """
    index: dict[str, Asset] = {}
    for asset in load_assets(path):
        index[asset.asset_id] = asset
    return index


def join(
    assets: Mapping[str, Asset], findings: Iterable[Finding], *, source: str = "findings"
) -> Iterator[EnrichedFinding]:
    """Attach each finding to its asset, lazily. `source` only labels the
    error. Raises on the first orphan -- an adapter that wants to report
    every orphan at once checks membership itself before handing rows here
    (adapters/defender.py does)."""
    for finding in findings:
        asset = assets.get(finding.asset_id)
        if asset is None:
            raise IngestError(
                f"{source}: finding {finding.finding_id!r} references "
                f"unknown asset_id {finding.asset_id!r}"
            )
        yield EnrichedFinding(finding=finding, asset=asset)


def join_findings(
    findings_path: Path, assets_path: Path
) -> Iterator[EnrichedFinding]:
    yield from join(load_asset_index(assets_path), load_findings(findings_path), source=str(findings_path))


def _describe_directory_contents(data_dir: Path) -> str:
    """Human-readable summary of what's actually in `data_dir`, for
    `_require_adapter_files`'s message below.

    Directories are listed too, marked "(not a file)", rather than
    silently filtered out -- otherwise a stray same-named directory
    (someone ran `mkdir devices.csv` by mistake, say) would be called
    "missing" by `_require_adapter_files` while this listing claimed the
    directory had nothing in it: a contradiction visible to anyone who
    runs `ls`/`dir` on the same path themselves.
    """
    if not data_dir.exists():
        return "(directory does not exist)"
    if not data_dir.is_dir():
        return "(not a directory)"
    entries = sorted(data_dir.iterdir(), key=lambda p: p.name)
    if not entries:
        return "(no files)"
    return ", ".join(p.name if p.is_file() else f"{p.name}/ (not a file)" for p in entries)


def _require_adapter_files(data_dir: Path, adapter: IngestAdapter) -> None:
    """Refuse up front, before either file is opened, if `data_dir` lacks
    the files `adapter` expects.

    The overwhelmingly common cause is a `--format`/`--data` mismatch --
    e.g. `--format defender` against a directory that only has the
    native `assets.csv`/`findings.csv` (or the reverse, `--data` left at
    its default and `--format` changed). Without this check, that
    mismatch surfaces as a bare `FileNotFoundError` raised from deep
    inside an adapter's own `csv.DictReader` construction -- naming
    neither the directory nor the reason, and different in shape for
    every adapter that opens its file differently (`native.py`'s vs.
    `defender.py`'s `_open_csv`). One check here, in the function every
    `load_batch` caller (`run`, `run --agents`, `constraint add`) already
    goes through, means all three report the mismatch identically, and
    `IngestError` is already caught by name in all three (`cli.py`) --
    no new except clause needed anywhere.

    Two things an adversarial review caught in the first pass of this
    function, both fixed here: `Path.iterdir()` -- unlike
    `.is_file()`/`.is_dir()`/`.exists()` -- does NOT swallow a genuine
    OS-level failure, so a directory the process can stat but not list
    (a realistic locked-down deployment share) would otherwise crash
    this very function with the unhandled exception it exists to
    prevent; every filesystem check below is wrapped in one
    `except OSError`. And the "likely cause" is only stated as a
    format/data mismatch when EVERY expected file is missing -- when
    only some are, an incomplete or corrupted export is the more likely
    story, and naming a mismatch there would send the user toward the
    wrong fix.
    """
    # dict.fromkeys: order-preserving de-dup, in case a future adapter
    # ever reuses one filename for both roles -- otherwise both the
    # "needs" and "missing" clauses below would repeat that name.
    expected = list(dict.fromkeys((adapter.assets_filename, adapter.findings_filename)))
    try:
        missing = [name for name in expected if not (data_dir / name).is_file()]
        if not missing:
            return
        contents = _describe_directory_contents(data_dir)
    except OSError as exc:
        raise IngestError(
            f"{data_dir}: could not check whether the files --format {adapter.format!r} needs "
            f"({', '.join(expected)}) are present -- {exc}."
        ) from exc

    if len(missing) == len(expected):
        explanation = (
            "This is almost always a --format/--data mismatch -- pass --format matching what "
            "--data actually contains, or point --data at a directory that has the files this "
            "format expects."
        )
    else:
        explanation = (
            "Only part of this format's file set is missing, which usually means an incomplete "
            "or corrupted export rather than a --format/--data mismatch -- restore or re-export "
            "the missing file(s), or double check --data points at the right directory."
        )

    raise IngestError(
        f"{data_dir}: --format {adapter.format!r} needs {', '.join(expected)}, but "
        f"{', '.join(missing)} {'is' if len(missing) == 1 else 'are'} missing. "
        f"{data_dir} contains: {contents}. {explanation}"
    )


def load_batch(data_dir: Path, adapter: IngestAdapter) -> tuple[dict[str, Asset], Iterator[EnrichedFinding]]:
    """The format-agnostic entry point cli.py uses: the adapter's inventory,
    indexed, and its findings joined to it, lazily. The inventory is
    materialized here (it always was -- load_asset_index) and returned so
    the caller can report per-asset data gaps without a second load.

    Raises `IngestError` (via `_require_adapter_files`, above) before
    either file is opened if `data_dir` doesn't have what `adapter`
    expects -- see that function's docstring."""
    _require_adapter_files(data_dir, adapter)
    assets = {a.asset_id: a for a in adapter.load_assets(data_dir / adapter.assets_filename)}
    findings_path = data_dir / adapter.findings_filename
    findings = adapter.load_findings(findings_path, assets)
    return assets, join(assets, findings, source=str(findings_path))


def attach_threat_signals(
    enriched: EnrichedFinding,
    kev_catalog: KevCatalog,
    attack_index: TechniqueIndex,
    cache: SnapshotCache,
) -> EnrichedFinding:
    """Live KEV/EPSS/NVD/ATT&CK signals, via `SnapshotCache` (offline-capable,
    see `enrich/cache.py`) -- the real, sourced enrichment `scoring.score_finding`
    needs, computed with no LLM call. `kev_catalog`/`attack_index` are the two
    bulk, single-fetch resources (load once per run, not once per finding --
    see both callers)."""
    cve_id = enriched.finding.cve_id
    epss = epss_lookup(cve_id, cache)
    nvd_cvss = nvd_lookup(cve_id, cache)
    matches = attack_index.lookup(cve_id, enriched.finding.product, enriched.finding.evidence)
    confirmed_prevalence = [m.technique.prevalence for m in matches if m.confidence == "confirmed"]
    return enriched.model_copy(
        update={
            "is_kev": kev_catalog.status(cve_id).is_listed,
            "epss": epss.score if epss.is_scored else None,
            "nvd_base_score": nvd_cvss.base_score if nvd_cvss is not None else None,
            "nvd_severity": nvd_cvss.base_severity if nvd_cvss is not None else None,
            "attack_techniques": tuple(
                AttackTechniqueRef(
                    technique_id=m.technique.technique_id,
                    name=m.technique.name,
                    confidence=m.confidence,
                )
                for m in matches
            ),
            "attack_prevalence": max(confirmed_prevalence, default=None),
        }
    )


def attach_source_enrichment(enriched: EnrichedFinding) -> EnrichedFinding:
    """Counterpart to `attach_threat_signals` for a pre-enriched source
    (`enriched.finding.source_enrichment is not None` -- adapters/bluepeak.py
    and any future adapter shaped like it): copies what the source already
    supplied instead of calling NVD/KEV/EPSS/ATT&CK, which would spend
    retries finding nothing for a CVE ID that was never real to begin with.
    No network, no cache, no LLM call -- still deterministic, still callable
    from either the deterministic path or agents/coordinator.py's capacity
    flow, same as attach_threat_signals.

    `attack_prevalence` is deliberately left untouched (not set to
    anything): it is enrich/attack.py's own corpus-wide percentile-rank
    statistic for a technique in the local ATT&CK index, and a source-
    reported technique ID carries no such figure -- leaving it at
    EnrichedFinding's own default (None) is the honest state, identical to
    "no confirmed technique found" (see scoring.score_threat and
    scoring._attack_rationale_lines, which both already treat
    attack_prevalence=None as a no-op multiplier, not an error).

    A finding with no `source_enrichment` is returned unchanged -- this
    should never happen for a `provides_enrichment` adapter (every Finding
    it yields sets the field), but this function never assumes that; a
    missing signal degrades to EnrichedFinding's own defaults rather than
    raising, the same "don't block a whole run over one row" discipline
    adapters/defender.py's own refuse-vs-degrade split already follows.
    """
    source = enriched.finding.source_enrichment
    if source is None:
        return enriched
    techniques: tuple[AttackTechniqueRef, ...] = ()
    if source.attack_technique_id:
        techniques = (
            AttackTechniqueRef(
                technique_id=source.attack_technique_id,
                name=source.attack_technique_name,
                confidence="source_reported",
            ),
        )
    return enriched.model_copy(
        update={
            "is_kev": bool(source.known_exploited),
            "attack_techniques": techniques,
            "source_severity_score": source.severity_score,
            "source_severity_label": source.severity_label,
        }
    )
