"""Slice 6 of the LLM-assisted adapter-generation design
(docs/adapter-generation.md): a bounded, full-file column profiler for a
source nobody has written a mapping for yet, plus the reusable non-raising
collector that goes with it. `rhino adapt probe <name>` / `rhino adapt list`
(cli.py) are the only things that call this module. No LLM, no API key, no
network, and nothing here writes to disk -- it only reads and reports.

Why this looks nothing like the rest of adapters/
--------------------------------------------------
Every other module here (`native.py`, `defender.py`, `bluepeak.py`,
`configured.py`) reads a source it already has an authoritative target
mapping for, and its whole discipline is refusing loudly the moment a value
doesn't fit that mapping (adapters/base.py's module docstring). This module
runs BEFORE any mapping exists -- there is nothing yet to be unfaithful to.
Its job is the opposite one: look at an arbitrary CSV and describe what is
actually there, without ever blocking on what it finds, so a human (and,
later, Slice 8's phase-1 inference agent) has real, measured facts to build
a mapping from instead of guessing from a handful of eyeballed rows.

`NonRaisingProblemCollector` is not a probe-only convenience. `configured.py`
`ConfiguredAdapter.__init__`'s own docstring already names it: `a probe (a
later slice) passes a non-raising recording subclass instead` of the real
`ProblemCollector`, so that a later re-probe (Slice 7's `rhino adapt
rereview`) can drive the same engine that will actually ingest the file and
read back every problem it would have raised, without the run aborting on
the first one. It is defined here, now, because this is the slice the design
document assigns it to -- nothing yet passes it as a `collector_factory`.

Bounded AND full-file, not one or the other
---------------------------------------------
CLAUDE.md Section 1: "Nothing may assume the dataset is small enough to hold
in memory or fetch in one pass." A profiler that only peeks at the first N
rows would violate that outright -- a rare value, a data-quality problem, or
the true cardinality of a column can all be invisible in a small head
sample. So this scans every row, exactly once, streaming. What it does NOT
do is remember everything it sees: each column's distinct-value tracking is
capped at MAX_DISTINCT_TRACKED, past which new values still count toward
`non_blank` (the blank rate stays exact regardless of file size) but stop
being individually retained (`distinct_overflow=True` marks the count as a
lower bound, not a guess dressed up as an exact one). Memory per column is
therefore bounded independent of row count; only the single pass is
required to be complete.

`looks_like` is a hint, not a parser
--------------------------------------
config_model.py's Rule 2 ("patterns are code-owned, never model-authored")
governs what a CONTRACT may invoke at ingest time -- `configured.py`'s own
`_CVE_ID_PATTERN`/`_parse_date`/etc. are that catalog, and they alone decide
what a real ingest run accepts. The tags this module computes are a
deliberately separate, smaller set of structural observations ("every
non-blank value here parses as an ISO date") meant to help a human or a
future LLM guess which of those code-owned parsers might apply -- they are
never fed into a contract automatically, and a wrong guess here costs
nothing, since nothing downstream trusts it. Two disclosed limitations
follow directly from that: a column can honestly satisfy both
`date_us_slash` and `date_eu_slash` at once (e.g. every day-of-month value
seen is <=12, so neither reading is contradicted) -- shown as both rather
than one guessed and the other silently dropped; and there is no `bool` tag
at all, because unlike CVE ids or ISO dates a boolean vocabulary is not
fixed across sources (`"True"/"False"`, `"Y"/"N"`, `"1"/"0"` all appear in
real exports) -- a column taking exactly two distinct values is tagged
`binary` instead, an honest, weaker claim a human confirms by reading the
two actual values in its `sample_values`.

Also not attempted here, named so it is not assumed done by omission: a
banner row above the real header (`configured.py`'s `Source.first_data_row`
handles this for a CONFIRMED contract, which already knows how many banner
lines to skip). Nothing here guesses which row is the real header -- that
is exactly the kind of judgment call a human confirms in the propose/confirm
flow (Slices 7-8), not something this mechanical pass decides on its own.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import date, datetime
from pathlib import Path
import csv
import re

from rhinosecure.adapters.base import MAX_PROBLEMS_SHOWN, AdapterError, ProblemCollector
from rhinosecure.adapters.configured import COMMON_DELIMITERS
from rhinosecure.ingest import detect_encoding

MAX_DISTINCT_TRACKED = 500
MAX_SAMPLE_VALUES = 8

#: Relocated from `agents/schema_inference.py` (which now imports it back
#: under the identical name -- the same relocate-not-duplicate move
#: `schema_registry.py` did for `ASSET_SLOTS`/`FINDING_SLOTS`, PROGRESS.md
#: 2026-09-07) once this module gained a second consumer for it:
#: `detect_delimiter`'s own pre-pass (below) is bounded to the same row
#: count schema_inference.py already bounds its LLM sample rows to, so the
#: two stay governed by one number instead of two that could drift apart.
DEFAULT_SAMPLE_ROWS = 20

# Deliberately duplicated from configured.py's own constants of the same
# name rather than imported -- config_model.py's own module docstring notes
# this codebase's precedent of a small, private, per-module copy of a
# pattern constant (e.g. _BLANK_BEARING_KINDS appears independently in both
# config_model.py and configured.py) rather than a shared import, and the
# stakes of drift here are much lower than there: these are hints a human
# reviews, never a recipe an engine executes.
_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
_US_EU_SLASH = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})$")
_FRACTIONAL_SECONDS = re.compile(r"(\.\d{1,6})\d*")


class ProbeError(AdapterError):
    """A file or directory could not be profiled at all: unreadable, no
    header, or no .csv file found. Distinct from the messy-reality
    observations `profile_csv` records on `NonRaisingProblemCollector`
    (duplicate header names, ragged rows, a mid-file decode failure) --
    those are exactly what probing exists to surface, so they are recorded,
    never raised."""


class NonRaisingProblemCollector(ProblemCollector):
    """A `ProblemCollector` (adapters/base.py) whose `raise_if_fatal` never
    raises -- every `.add`/`.exclude` call still records normally, so a
    caller reads `.fatal`/`.excluded` back as data after a full pass
    instead of stopping at the first fatal problem. See this module's own
    docstring and `configured.py`'s `ConfiguredAdapter` docstring, which
    names this exact class as the seam a later re-probe (Slice 7) uses."""

    def raise_if_fatal(self, what: str) -> None:
        return


def _is_int(value: str) -> bool:
    unsigned = value[1:] if value.startswith("-") else value
    return unsigned.isdigit() and unsigned != ""


def _is_float(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def _is_cve_id(value: str) -> bool:
    return _CVE_ID_PATTERN.match(value) is not None


def _is_iso_date(value: str) -> bool:
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _is_timestamp(value: str) -> bool:
    """True for a full ISO 8601 datetime -- deliberately False whenever
    `_is_iso_date` already accepts the same value, so a column of plain
    dates is tagged `date_iso` only, never `date_iso` AND `timestamp` for
    the same underlying fact (mirrors configured.py's `_parse_timestamp`,
    which this hint is not authoritative over -- see the module
    docstring)."""
    if _is_iso_date(value):
        return False
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _FRACTIONAL_SECONDS.sub(r"\1", text, count=1)
    try:
        datetime.fromisoformat(text)
    except ValueError:
        return False
    return True


def _is_us_slash_date(value: str) -> bool:
    match = _US_EU_SLASH.match(value)
    if match is None:
        return False
    month, day, year = match.groups()
    try:
        date(int(year), int(month), int(day))
    except ValueError:
        return False
    return True


def _is_eu_slash_date(value: str) -> bool:
    match = _US_EU_SLASH.match(value)
    if match is None:
        return False
    day, month, year = match.groups()
    try:
        date(int(year), int(month), int(day))
    except ValueError:
        return False
    return True


#: Checked in order for every non-blank value; a column keeps a tag only if
#: EVERY non-blank value it contains satisfies that check (module docstring:
#: a hint, computed exactly over the whole file, never approximated from a
#: sample).
_PATTERN_CHECKS: tuple[tuple[str, Callable[[str], bool]], ...] = (
    ("cve_id", _is_cve_id),
    ("int", _is_int),
    ("float", _is_float),
    ("date_iso", _is_iso_date),
    ("timestamp", _is_timestamp),
    ("date_us_slash", _is_us_slash_date),
    ("date_eu_slash", _is_eu_slash_date),
)


@dataclass(frozen=True)
class ColumnProfile:
    """One column's measured shape. `distinct_count`/`sample_values` are
    exact only while `not distinct_overflow`; past the cap they are a
    verified lower bound and a first-seen subset, never a guess presented
    as complete. `looks_like` is empty whenever `non_blank == 0` -- a
    pattern with no evidence for or against it is not "matched".

    `distinct_values` is the same (value -> occurrence count) mapping the
    accumulator already builds to compute `distinct_count`/`sample_values` --
    exposed in full here rather than discarded, so a caller that needs to
    check every value a column actually takes (Slice 8's grounding pass,
    `agents/schema_inference.check_grounding`: is every key a proposed
    vocabulary table declares one this column really contains?) doesn't have
    to re-scan the file to get past `MAX_SAMPLE_VALUES`. No new pass over
    the data -- this is exactly the dict `observe` was already retaining;
    only the truncation to 8 entries for human display is skipped. Subject
    to the identical `distinct_overflow` caveat as `distinct_count`: past
    `MAX_DISTINCT_TRACKED`, this is a lower bound (the first values seen,
    not necessarily all of them), never a guess presented as complete."""

    name: str
    non_blank: int
    blank: int
    distinct_count: int
    distinct_overflow: bool
    min_length: int | None
    max_length: int | None
    sample_values: list[str]
    looks_like: list[str]
    distinct_values: dict[str, int]


class _ColumnAccumulator:
    """Streaming, bounded per-column state -- see the module docstring's
    "Bounded AND full-file" section. Mirrors `ingest.GapTally`'s shape: a
    plain accumulating class, not a `@dataclass`, because it is scan state
    consumed once into a `ColumnProfile`, not a record handed around."""

    def __init__(self) -> None:
        self.non_blank = 0
        self.blank = 0
        self.distinct: dict[str, int] = {}
        self.distinct_overflow = False
        self.min_length: int | None = None
        self.max_length: int | None = None
        self._still_matches: dict[str, bool] = {name: True for name, _check in _PATTERN_CHECKS}

    def observe(self, raw: str) -> None:
        value = raw.strip()
        if not value:
            self.blank += 1
            return
        self.non_blank += 1
        length = len(value)
        self.min_length = length if self.min_length is None else min(self.min_length, length)
        self.max_length = length if self.max_length is None else max(self.max_length, length)
        if value in self.distinct:
            self.distinct[value] += 1
        elif len(self.distinct) < MAX_DISTINCT_TRACKED:
            self.distinct[value] = 1
        else:
            self.distinct_overflow = True
        for tag_name, check in _PATTERN_CHECKS:
            if self._still_matches[tag_name] and not check(value):
                self._still_matches[tag_name] = False

    def finalize(self, name: str) -> ColumnProfile:
        tags: list[str] = []
        if self.non_blank > 0:
            tags = [tag_name for tag_name, _check in _PATTERN_CHECKS if self._still_matches[tag_name]]
            if "int" in tags and "float" in tags:
                tags.remove("float")  # every int-looking value is also float-looking; show the tighter tag
            if not self.distinct_overflow:
                if len(self.distinct) == 1:
                    tags.append("constant")
                elif len(self.distinct) == 2:
                    tags.append("binary")
                if self.blank == 0 and len(self.distinct) == self.non_blank:
                    tags.append("identity_candidate")
        return ColumnProfile(
            name=name,
            non_blank=self.non_blank,
            blank=self.blank,
            distinct_count=len(self.distinct),
            distinct_overflow=self.distinct_overflow,
            min_length=self.min_length,
            max_length=self.max_length,
            sample_values=list(self.distinct)[:MAX_SAMPLE_VALUES],
            looks_like=tags,
            distinct_values=dict(self.distinct),
        )


@dataclass(frozen=True)
class FileProfile:
    """One CSV file's full-file profile. `header` may contain a repeated
    name (recorded in `duplicate_header_names` and in `problems`, never
    silently resolved) -- `columns` is keyed by name, one entry per
    DISTINCT name, accumulated last-occurrence-wins across a row exactly
    the way `csv.DictReader` (and so `configured.py`'s own engine) would
    read it -- see `profile_csv`'s own comment on this. `truncated=True`
    means a mid-file decode error stopped the scan early; `row_count` and
    every column's counts then describe only the rows read before that
    point, not the whole file.

    `delimiter` is whatever `profile_csv` actually read this file with --
    the literal default, an explicit caller-supplied value (`review.py`'s
    `measure`, re-profiling against a confirmed contract's own declared
    dialect), or `profile_source`'s own `detect_delimiter` result. Recorded
    so a caller that re-opens the file itself (`agents/schema_inference.py`'s
    `_sample_rows`, for the model's literal sample rows) reads it back
    instead of re-detecting -- the two are then structurally unable to
    disagree, rather than merely unlikely to."""

    path: Path
    encoding: str
    delimiter: str
    header: list[str]
    duplicate_header_names: list[str]
    row_count: int
    ragged_rows: int
    truncated: bool
    columns: dict[str, ColumnProfile]
    problems: list[str]


def profile_csv(
    path: Path,
    *,
    delimiter: str = ",",
    quotechar: str = '"',
    encoding: str | None = None,
    skip_lines: int = 0,
) -> FileProfile:
    """Profile one CSV file, streaming, in a single pass. Never raises for
    a messy file -- a duplicate header name, a ragged row, or a mid-file
    decode failure is recorded on a `NonRaisingProblemCollector` and
    scanning either continues (ragged rows) or stops early with
    `truncated=True` (a decode failure, since nothing after an undecodable
    byte can be trusted). Only raises `ProbeError` when there is nothing at
    all to profile: the path is not a file, or it has no header row.

    The dialect arguments all default to what `rhino adapt probe` assumes
    for a source nobody has described yet -- a comma-delimited file whose
    first line is the header. They exist for a caller that DOES know
    better: `adapters/review.py` profiles the columns a confirmed contract
    declares it ignores, and that contract states its own `delimiter` /
    `quotechar` / `encoding` / `first_data_row`. Without them a
    semicolon-delimited or banner-prefixed source parses as one giant
    column, every declared name is missed, and the section vanishes from
    the review in silence -- the worst failure mode for a report whose job
    is to show what a mapping does not read."""
    if not path.is_file():
        raise ProbeError(f"{path}: not a file")

    encoding = encoding or detect_encoding(path)
    problems = NonRaisingProblemCollector(path)

    try:
        f = path.open(newline="", encoding=encoding)
    except OSError as exc:
        raise ProbeError(f"{path}: could not be opened -- {exc}") from exc

    with f:
        for _ in range(skip_lines):
            f.readline()  # a banner above the real header, if one is declared
        reader = csv.reader(f, delimiter=delimiter, quotechar=quotechar)
        try:
            header = next(reader)
        except StopIteration:
            raise ProbeError(f"{path}: empty file -- no header row") from None
        except UnicodeDecodeError as exc:
            raise ProbeError(f"{path}: could not decode the header as {encoding} -- {exc}") from None
        if not header:
            raise ProbeError(f"{path}: header row is empty")

        duplicate_header_names = sorted({name for name in header if header.count(name) > 1})
        if duplicate_header_names:
            problems.add(
                f"header: column name(s) {duplicate_header_names} appear more than once -- a row "
                "reader keeps only the LAST occurrence's value for a repeated name, and this profile "
                "does the same"
            )

        # dict comprehension collapses a repeated name to one accumulator,
        # matching the last-occurrence-wins semantics `duplicate_header_names`
        # already warns about.
        accumulators = {name: _ColumnAccumulator() for name in header}

        row_count = 0
        ragged_rows = 0
        truncated = False
        try:
            for row in reader:
                row_count += 1
                row_no = reader.line_num
                if len(row) != len(header):
                    ragged_rows += 1
                    if ragged_rows <= MAX_PROBLEMS_SHOWN:
                        problems.add(f"row {row_no}: expected {len(header)} field(s), found {len(row)}")
                # dict(zip(...)) gives last-occurrence-wins for a repeated
                # header name, and a SHORT row simply never reaches the
                # trailing column names -- they are not observed for this
                # row at all, not counted as blank (a truncated field is
                # not a field with an empty value; see ingest.iter_csv_rows,
                # whose docstring draws the identical distinction for the
                # real engine).
                for name, value in dict(zip(header, row)).items():
                    accumulators[name].observe(value)
        except UnicodeDecodeError as exc:
            truncated = True
            problems.add(
                f"row {row_count + 1}: could not decode as {encoding} -- {exc}; profiling stopped here, "
                "counts above reflect only the rows read before this point"
            )
        if ragged_rows > MAX_PROBLEMS_SHOWN:
            problems.add(f"... and {ragged_rows - MAX_PROBLEMS_SHOWN} more ragged row(s)")

    columns = {name: acc.finalize(name) for name, acc in accumulators.items()}
    for name, profile in columns.items():
        if profile.distinct_overflow:
            problems.add(
                f"column {name!r}: reached the tracked-distinct-values cap ({MAX_DISTINCT_TRACKED}); "
                "it has at least that many distinct values, the true count is not known"
            )

    return FileProfile(
        path=path,
        encoding=encoding,
        delimiter=delimiter,
        header=header,
        duplicate_header_names=duplicate_header_names,
        row_count=row_count,
        ragged_rows=ragged_rows,
        truncated=truncated,
        columns=columns,
        problems=list(problems.fatal),
    )


# ---------------------------------------------------------------------------
# Delimiter detection -- `profile_source` only. `profile_csv` itself is
# unchanged above: its `delimiter` parameter still defaults to a literal
# comma and nothing about it auto-detects anything, exactly as before this
# was added (test_a_non_comma_delimiter_can_be_declared, tests/
# test_adapters_probe.py, pins this: `profile_csv(path)` with no delimiter
# argument on a semicolon file still profiles as one giant column). That
# call is what `adapters/review.py`'s `measure()` depends on -- it always
# knows the real delimiter already (a confirmed contract's own
# `contract.source.delimiter`) and must never have it silently second-
# guessed. Detection belongs only where nothing is known yet: the propose
# path, via `profile_source`.
#
# Scope, stated so it isn't assumed wider by omission: this decides which
# delimiter `profile_source` profiles WITH -- it makes the resulting
# `FileProfile` (and so the model's rendered column summary and its literal
# sample rows) correct for a non-comma source. It does not write anywhere
# into `AdapterProposal` or `Source.delimiter` -- both still exist only as
# the literal comma default `_assemble_and_validate` (agents/
# schema_inference.py) has always used, and nothing here changes that. A
# contract assembled from a correctly-detected semicolon file still
# declares `delimiter=","` today; wiring the detected value through to the
# contract, and rendering it somewhere a human confirms, is separate,
# not-yet-started work (see the module docstring's own "Also not attempted
# here" convention, immediately above -- this section is that same kind of
# disclosure for what THIS addition does and does not do).
# ---------------------------------------------------------------------------


def _row_shape(
    path: Path, *, encoding: str, delimiter: str, quotechar: str, skip_lines: int, sample_rows: int
) -> tuple[int, bool] | OSError | UnicodeDecodeError | None:
    """`(header field count, whether every one of the first `sample_rows`
    data rows agrees with it)` for `path` read with `delimiter` -- quote-
    aware (`csv.reader`, the identical reader `profile_csv` itself builds),
    so a delimiter character that only ever appears inside a quoted value
    is correctly never counted as a split point.

    Two DIFFERENT things can stop this from producing a shape, and this
    function reports them differently on purpose -- `detect_delimiter`
    (below) treats them as opposite outcomes, not the same "inconclusive"
    result:

    - The real `OSError`/`UnicodeDecodeError` is returned -- not swallowed
      into `None` -- when `path` could not even be OPENED or DECODED as
      `encoding` at all. This is a fact about the file's BYTES, independent
      of which `delimiter` was being tried: decoding happens on the
      underlying text stream before any candidate-specific splitting ever
      runs, so every one of `COMMON_DELIMITERS` hits the IDENTICAL
      exception at the IDENTICAL byte position for a given `path`/
      `encoding`/`skip_lines` -- there is no such thing as "undecodable
      under comma but fine under tab." Real bytes handed a non-text file
      (confirmed live against a real `.xlsx`, a ZIP container, not a
      decode-declaration mismatch a human could fix by re-exporting).
    - `None` means the file decoded FINE but had no header row at all (a
      genuinely empty text file) -- ordinary, and semantically nothing like
      the case above. `StopIteration` is deliberately NOT caught alongside
      the decode exceptions, so it can never be mistaken for one;
      `profile_csv`'s own subsequent real pass already raises a clear,
      specific `ProbeError` for an empty file, so this function has nothing
      useful to add about that case beyond not crashing on it.

    A file with zero data rows (header only, but not empty) can never make
    any candidate "consistent" -- `saw_row` stays `False` and the returned
    flag is `False` regardless of the header's own shape, so a header's
    shape alone (with nothing behind it to confirm it) can never win a
    candidate the "beats comma" comparison in `detect_delimiter`. Comma's
    OWN field count is read from this function's return value too, but --
    deliberately -- only ever `[0]`, never `[1]`: comma is `profile_csv`'s
    literal default regardless of whether it is internally consistent,
    exactly as it always has been (a genuinely ragged real file still
    profiles with comma today, reported via `ragged_rows`, never refused);
    only a CHALLENGER to comma has to prove consistency to be preferred
    over it."""
    try:
        with path.open(newline="", encoding=encoding) as f:
            for _ in range(skip_lines):
                f.readline()
            reader = csv.reader(f, delimiter=delimiter, quotechar=quotechar)
            try:
                header = next(reader)
            except StopIteration:
                return None
            header_count = len(header)
            consistent = True
            saw_row = False
            for i, row in enumerate(reader):
                if i >= sample_rows:
                    break
                saw_row = True
                if len(row) != header_count:
                    consistent = False
                    break
            return (header_count, consistent and saw_row)
    except (OSError, UnicodeDecodeError) as exc:
        return exc


def detect_delimiter(
    path: Path,
    *,
    encoding: str,
    quotechar: str = '"',
    skip_lines: int = 0,
    sample_rows: int = DEFAULT_SAMPLE_ROWS,
    problems: ProblemCollector | None = None,
) -> str:
    """The delimiter `profile_source` should profile `path` with, decided
    from a cheap pre-pass over the header plus the first `sample_rows` data
    rows -- never a second full-file scan; the one expensive pass stays
    `profile_csv`'s own, made exactly once, with whatever this function
    returns.

    Verification, not a frequency count. A raw character count over the raw
    line text would pick comma for a tab-delimited file whose values
    legitimately contain commas (a free-text description column, say) --
    counting doesn't know a quoted or merely-incidental comma from a real
    separator. Instead: a candidate is accepted only when splitting the
    header AND every one of the sampled rows under it produces the
    IDENTICAL field count throughout (`_row_shape`, above). A genuine
    embedded comma in a tab-delimited file splits some rows and not others
    under a comma reading, so comma fails consistency there while tab (the
    real delimiter) does not.

    Comma is `profile_csv`'s existing default and stays the answer unless
    some OTHER candidate (`configured.COMMON_DELIMITERS` -- reused, not
    duplicated; see that constant's own docstring for why drift here would
    be a correctness bug) is BOTH fully consistent AND produces MORE
    columns than comma's own header count already does. A file that is
    genuinely one column -- no real delimiter present at all -- never has
    another candidate clear that bar (nothing else can be internally
    consistent at a higher column count than 1 if it doesn't actually
    appear as a separator), and reports nothing: there is no fallback
    language for it, because there is nothing to fall back FROM. This is
    what keeps a bare CVE-ID list from being treated as a detection
    failure.

    That silence is deliberately NOT what happens when every candidate is
    inconclusive because the file couldn't be decoded at all (`_row_shape`
    returning the real exception, not `None`, for every one of
    `COMMON_DELIMITERS` -- they agree, always, per that function's own
    docstring). Those are two different situations that both end up
    "nothing beat comma," and conflating them was the actual bug here: a
    genuine single-column CSV decodes fine and has an honest, quiet answer
    (comma); a file that isn't text at all (confirmed live against a real
    `.xlsx`) never even reaches the point of having an opinion about
    delimiters, and returning "," for it with no signal reads as that same
    honest quiet answer when it is not one. Reported via `problems` the
    same way genuine ambiguity is (below) -- one exception, real and
    specific, is what distinguishes the two, not a guess about the file's
    shape.

    Two or more non-comma candidates each independently clearing that bar
    is genuine ambiguity -- this function cannot tell which is really the
    delimiter, so, matching every other refusal in this codebase's ingest
    layer, it does not guess between them. Reported via `problems` (the
    same `ProblemCollector`/`FileProfile.problems` channel `profile_csv`
    already populates -- no new mechanism) and resolved to comma, the safe
    default. No check here reads header TOKEN content at all (no "do these
    look like names" heuristic) -- only field counts, the same structural,
    non-semantic signal `profile_csv` already computes as `ragged_rows`.

    Never touches `Source.delimiter`, the contract schema, or anything an
    LLM's structured output declares -- see this module's own "Delimiter
    detection" section comment for the scope boundary."""
    shapes: dict[str, tuple[int, bool]] = {}
    decode_error: OSError | UnicodeDecodeError | None = None
    for char, _name in COMMON_DELIMITERS:
        shape = _row_shape(
            path, encoding=encoding, delimiter=char, quotechar=quotechar, skip_lines=skip_lines, sample_rows=sample_rows
        )
        if isinstance(shape, (OSError, UnicodeDecodeError)):
            decode_error = shape
        elif shape is not None:
            shapes[char] = shape

    if decode_error is not None:
        if problems is not None:
            problems.add(
                f"delimiter: could not be determined -- {path.name} could not be read as text under "
                f"encoding {encoding!r} at all ({decode_error}), independent of which delimiter was "
                "tried; this may not be a CSV/text file. Defaulted to comma."
            )
        return ","

    comma_count = shapes.get(",", (0, False))[0]
    detected = [
        (char, name, shapes[char][0])
        for char, name in COMMON_DELIMITERS
        if char != "," and char in shapes and shapes[char][1] and shapes[char][0] > comma_count
    ]

    if not detected:
        return ","

    if len(detected) > 1:
        if problems is not None:
            listing = ", ".join(f"{name} ({char!r}, {count} column(s))" for char, name, count in detected)
            problems.add(
                f"delimiter: ambiguous -- {listing} each split the header and every one of the first "
                f"{sample_rows} data row(s) into a consistent field count, more than comma's "
                f"{comma_count}; neither is preferred over the other. Defaulted to comma -- sample "
                "values may be wrong if comma is not this file's real delimiter."
            )
        return ","

    return detected[0][0]


def _profile_with_delimiter_detection(path: Path) -> FileProfile:
    """`profile_csv`, but with `detect_delimiter`'s answer instead of
    `profile_csv`'s own literal comma default -- `profile_csv` itself is
    unchanged and unaware this happens. Any ambiguity `detect_delimiter`
    reports is folded into the returned `FileProfile.problems` alongside
    whatever `profile_csv`'s own pass already found, rather than kept on a
    separate collector a caller would have to know to check."""
    encoding = detect_encoding(path)
    problems = NonRaisingProblemCollector(path)
    delimiter = detect_delimiter(path, encoding=encoding, problems=problems)
    profile = profile_csv(path, delimiter=delimiter, encoding=encoding)
    if problems.fatal:
        profile = replace(profile, problems=[*profile.problems, *problems.fatal])
    return profile


def profile_source(data_dir: Path) -> list[FileProfile]:
    """Profile every `.csv` file directly inside `data_dir` (not recursive
    -- nothing in this project's data/ layout nests CSVs), sorted by name.
    Raises `ProbeError` if `data_dir` is not a directory or contains none.

    Each file's delimiter is `detect_delimiter`'s answer, not a literal
    comma -- see that function's own docstring and the "Delimiter
    detection" section comment above for what this does and, just as
    deliberately, does not yet do."""
    if not data_dir.is_dir():
        raise ProbeError(f"{data_dir}: not a directory")
    try:
        csv_paths = sorted(p for p in data_dir.iterdir() if p.is_file() and p.suffix.lower() == ".csv")
    except OSError as exc:
        raise ProbeError(f"{data_dir}: could not list directory contents -- {exc}") from exc
    if not csv_paths:
        raise ProbeError(f"{data_dir}: no .csv file found -- nothing to probe")
    return [_profile_with_delimiter_detection(path) for path in csv_paths]
