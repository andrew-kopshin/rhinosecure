"""adapters/probe.py -- Slice 6 of docs/adapter-generation.md: the bounded
full-file column profiler and its reusable non-raising collector. No
mapping, no LLM, no network anywhere in this module, so every test here
drives `profile_csv`/`profile_source` directly against tmp_path CSVs (or
the real committed sample files, for a few end-to-end sanity checks) --
no fixture-specific asset_id/finding_id/CVE VALUE is asserted on, only
column names and structural facts, since those files are shared with other
tests and may grow over time."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from rhinosecure.adapters.base import ProblemCollector
from rhinosecure.adapters.probe import (
    MAX_DISTINCT_TRACKED,
    ColumnProfile,
    NonRaisingProblemCollector,
    ProbeError,
    profile_csv,
    profile_source,
)
import rhinosecure.adapters.probe as probe_module

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = REPO_ROOT / "data" / "demo"
BLUEPEAK_DIR = REPO_ROOT / "data" / "bluepeak"
DEFENDER_DIR = REPO_ROOT / "data" / "defender-sample"


def _write_csv(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)


# --- NonRaisingProblemCollector ---------------------------------------------


def test_non_raising_collector_is_a_problem_collector(tmp_path):
    collector = NonRaisingProblemCollector(tmp_path / "x.csv")
    assert isinstance(collector, ProblemCollector)


def test_non_raising_collector_never_raises_but_still_records():
    collector = NonRaisingProblemCollector(Path("x.csv"))
    collector.add("something is wrong")
    collector.add("something else is wrong")
    collector.raise_if_fatal("test")  # must not raise
    assert collector.fatal == ["something is wrong", "something else is wrong"]


def test_non_raising_collector_exclude_still_works_normally():
    collector = NonRaisingProblemCollector(Path("x.csv"))
    collector.exclude("A01", "out of scope")
    assert collector.excluded == {"A01": "out of scope"}


# --- profile_csv: basic shape -----------------------------------------------


def test_basic_counts_header_and_row_count(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["id", "name"], ["1", "alice"], ["2", "bob"], ["3", ""]])
    profile = profile_csv(path)
    assert profile.header == ["id", "name"]
    assert profile.row_count == 3
    assert profile.encoding == "utf-8"
    assert profile.duplicate_header_names == []
    assert profile.ragged_rows == 0
    assert not profile.truncated
    assert profile.problems == []


def test_blank_cell_is_counted_and_stripped(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["v"], ["  x  "], [""], ["   "]])
    col = profile_csv(path).columns["v"]
    assert col.non_blank == 1
    assert col.blank == 2
    assert col.sample_values == ["x"]  # stripped, not "  x  "


def test_sample_values_are_first_seen_order_and_bounded(tmp_path):
    path = tmp_path / "data.csv"
    rows = [["v"]] + [[str(i)] for i in range(20)]
    _write_csv(path, rows)
    col = profile_csv(path).columns["v"]
    assert col.distinct_count == 20
    assert col.sample_values == [str(i) for i in range(8)]  # MAX_SAMPLE_VALUES, first-seen order


def test_distinct_values_holds_every_distinct_value_past_the_8_sample_cap(tmp_path):
    """Slice 8's grounding pass (agents/schema_inference.check_grounding)
    needs the full (bounded) distinct set, not just the 8-entry human-display
    sample -- this is the same dict `sample_values` is truncated from, not a
    second scan."""
    path = tmp_path / "data.csv"
    rows = [["v"]] + [[str(i)] for i in range(20)]
    _write_csv(path, rows)
    col = profile_csv(path).columns["v"]
    assert col.distinct_values == {str(i): 1 for i in range(20)}


def test_distinct_values_counts_repeated_occurrences(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["v"], ["a"], ["a"], ["b"]])
    col = profile_csv(path).columns["v"]
    assert col.distinct_values == {"a": 2, "b": 1}


def test_distinct_values_is_a_lower_bound_once_overflowed(tmp_path):
    from rhinosecure.adapters.probe import MAX_DISTINCT_TRACKED

    path = tmp_path / "data.csv"
    rows = [["v"]] + [[f"val-{i}"] for i in range(MAX_DISTINCT_TRACKED + 5)]
    _write_csv(path, rows)
    col = profile_csv(path).columns["v"]
    assert col.distinct_overflow
    assert len(col.distinct_values) == MAX_DISTINCT_TRACKED
    assert "val-0" in col.distinct_values  # first-seen values are what's retained
    assert f"val-{MAX_DISTINCT_TRACKED + 4}" not in col.distinct_values


# --- profile_csv: looks_like pattern hints ----------------------------------


def test_cve_id_column_is_tagged(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["cve"], ["CVE-2021-26855"], ["CVE-2020-1472"]])
    assert "cve_id" in profile_csv(path).columns["cve"].looks_like


def test_one_non_cve_value_removes_the_tag(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["cve"], ["CVE-2021-26855"], ["not-a-cve"]])
    assert "cve_id" not in profile_csv(path).columns["cve"].looks_like


def test_int_column_is_tagged_int_not_float(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["n"], ["1"], ["-5"], ["300"]])
    col = profile_csv(path).columns["n"]
    assert "int" in col.looks_like
    assert "float" not in col.looks_like  # the tighter tag suppresses the looser one


def test_decimal_column_is_tagged_float_only(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["n"], ["1.5"], ["9.8"]])
    col = profile_csv(path).columns["n"]
    assert col.looks_like[:1] == ["float"]  # int/cve_id/date* are all correctly absent
    assert "int" not in col.looks_like


def test_iso_date_column_is_tagged(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["d"], ["2026-08-27"], ["2026-09-01"]])
    col = profile_csv(path).columns["d"]
    assert "date_iso" in col.looks_like
    assert "timestamp" not in col.looks_like  # a plain date is not also tagged timestamp


def test_timestamp_column_is_tagged_and_not_date_iso(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["t"], ["2026-08-30T02:10:44.123Z"], ["2026-08-29T23:59:59"]])
    col = profile_csv(path).columns["t"]
    assert "timestamp" in col.looks_like
    assert "date_iso" not in col.looks_like


def test_ambiguous_slash_date_gets_both_tags_when_day_is_at_most_12(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["d"], ["01/05/2026"], ["03/07/2026"]])
    col = profile_csv(path).columns["d"]
    assert "date_us_slash" in col.looks_like
    assert "date_eu_slash" in col.looks_like


def test_unambiguous_us_slash_date_excludes_eu_reading(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["d"], ["05/25/2026"]])  # day=25 -- not a valid EU month
    col = profile_csv(path).columns["d"]
    assert "date_us_slash" in col.looks_like
    assert "date_eu_slash" not in col.looks_like


def test_free_text_column_has_no_pattern_tags(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["notes"], ["the quick brown fox"], ["jumps over"]])
    col = profile_csv(path).columns["notes"]
    assert not any(tag in col.looks_like for tag in ("cve_id", "int", "float", "date_iso", "timestamp"))


def test_column_with_no_non_blank_values_has_no_tags(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["v"], [""], [""]])
    col = profile_csv(path).columns["v"]
    assert col.looks_like == []
    assert col.non_blank == 0


# --- profile_csv: constant / binary / identity_candidate --------------------


def test_single_distinct_value_is_constant(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["v"], ["x"], ["x"], ["x"]])
    assert "constant" in profile_csv(path).columns["v"].looks_like


def test_two_distinct_values_is_binary(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["v"], ["yes"], ["no"], ["yes"]])
    assert "binary" in profile_csv(path).columns["v"].looks_like


def test_all_distinct_no_blanks_is_identity_candidate(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["id"], ["a"], ["b"], ["c"]])
    assert "identity_candidate" in profile_csv(path).columns["id"].looks_like


def test_a_blank_disqualifies_identity_candidate_even_if_rest_are_distinct(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["id"], ["a"], ["b"], [""]])
    assert "identity_candidate" not in profile_csv(path).columns["id"].looks_like


# --- profile_csv: distinct-value cap (bounded, not unbounded) ---------------


def test_distinct_values_beyond_the_cap_are_not_individually_retained(tmp_path, monkeypatch):
    monkeypatch.setattr(probe_module, "MAX_DISTINCT_TRACKED", 3)
    path = tmp_path / "data.csv"
    rows = [["v"]] + [[f"val{i}"] for i in range(10)]
    _write_csv(path, rows)
    col = profile_csv(path).columns["v"]
    assert col.distinct_overflow is True
    assert col.distinct_count == 3
    assert len(col.sample_values) == 3
    assert col.non_blank == 10  # the overall count stays exact even once tracking is capped


def test_overflowing_a_column_is_recorded_as_a_problem(tmp_path, monkeypatch):
    monkeypatch.setattr(probe_module, "MAX_DISTINCT_TRACKED", 2)
    path = tmp_path / "data.csv"
    _write_csv(path, [["v"], ["a"], ["b"], ["c"]])
    profile = profile_csv(path)
    assert any("v" in p and "cap" in p for p in profile.problems)


def test_overflow_never_falsely_claims_identity_candidate(tmp_path, monkeypatch):
    """Without the cap, every value here is genuinely distinct -- but once
    overflowed, the profiler must not assert that as fact any more (module
    docstring: a lower bound, never a guess presented as complete)."""
    monkeypatch.setattr(probe_module, "MAX_DISTINCT_TRACKED", 2)
    path = tmp_path / "data.csv"
    _write_csv(path, [["v"], ["a"], ["b"], ["c"]])
    col = profile_csv(path).columns["v"]
    assert "identity_candidate" not in col.looks_like


# --- profile_csv: duplicate header names ------------------------------------


def test_duplicate_header_name_is_recorded_not_raised(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["a", "b", "a"], ["1", "x", "2"]])
    profile = profile_csv(path)  # must not raise
    assert profile.duplicate_header_names == ["a"]
    assert any("a" in p and "more than once" in p for p in profile.problems)


def test_duplicate_header_name_accumulates_last_occurrence_wins(tmp_path):
    """Matches ingest.open_csv's own documented csv.DictReader behavior --
    a mapping written against a repeated name would read the LAST column's
    values, so the profile must reflect the same column, not the first."""
    path = tmp_path / "data.csv"
    _write_csv(path, [["a", "b", "a"], ["first", "x", "last1"], ["first", "y", "last2"]])
    col = profile_csv(path).columns["a"]
    assert set(col.sample_values) == {"last1", "last2"}
    assert col.non_blank == 2  # not double-counted despite two header occurrences


# --- profile_csv: ragged rows -----------------------------------------------


def test_short_row_is_recorded_and_does_not_crash(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["a", "b", "c"], ["1", "2", "3"], ["4", "5"]])
    profile = profile_csv(path)
    assert profile.ragged_rows == 1
    assert any("expected 3 field" in p and "found 2" in p for p in profile.problems)


def test_short_row_does_not_count_the_missing_trailing_column_as_blank(tmp_path):
    """A truncated row is not a row with a blank cell -- mirrors
    ingest.iter_csv_rows's own documented distinction for the real engine."""
    path = tmp_path / "data.csv"
    _write_csv(path, [["a", "b"], ["1", "2"], ["3"]])
    col_b = profile_csv(path).columns["b"]
    assert col_b.non_blank == 1
    assert col_b.blank == 0  # the second row's missing "b" was never observed at all


def test_long_row_is_recorded_and_extra_fields_are_dropped(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["a", "b"], ["1", "2"], ["3", "4", "5"]])
    profile = profile_csv(path)
    assert profile.ragged_rows == 1
    assert any("expected 2 field" in p and "found 3" in p for p in profile.problems)


def test_many_ragged_rows_are_capped_with_a_trailer(tmp_path):
    from rhinosecure.adapters.base import MAX_PROBLEMS_SHOWN

    path = tmp_path / "data.csv"
    rows = [["a", "b"]] + [["1"] for _ in range(MAX_PROBLEMS_SHOWN + 5)]
    _write_csv(path, rows)
    profile = profile_csv(path)
    assert profile.ragged_rows == MAX_PROBLEMS_SHOWN + 5
    assert any("more ragged row" in p for p in profile.problems)
    # capped messages plus the trailer, not one line per ragged row
    assert len(profile.problems) == MAX_PROBLEMS_SHOWN + 1


# --- profile_csv: encoding -----------------------------------------------


def test_a_non_comma_delimiter_can_be_declared(tmp_path):
    """Found reviewing slice 7. `adapters/review.py` profiles the columns a
    contract declares it ignores, and that contract states its own dialect --
    without these arguments a semicolon-delimited source parsed as one giant
    column and the whole section vanished from the review in silence."""
    path = tmp_path / "data.csv"
    path.write_text("a;b\n1;2\n3;4\n", encoding="utf-8")
    assert profile_csv(path).header == ["a;b"]  # the default assumption, unchanged
    profile = profile_csv(path, delimiter=";")
    assert profile.header == ["a", "b"]
    assert profile.columns["b"].sample_values == ["2", "4"]


def test_a_banner_row_above_the_header_can_be_skipped(tmp_path):
    path = tmp_path / "data.csv"
    path.write_text("Exported by SomeTool v3\na,b\n1,2\n", encoding="utf-8")
    profile = profile_csv(path, skip_lines=1)
    assert profile.header == ["a", "b"]
    assert profile.row_count == 1


def test_an_explicit_encoding_overrides_bom_sniffing(tmp_path):
    path = tmp_path / "data.csv"
    path.write_bytes("a,b\r\n1,2\r\n".encode("utf-16"))
    assert profile_csv(path, encoding="utf-16").header == ["a", "b"]


def test_utf16_bom_is_detected_via_ingest_detect_encoding(tmp_path):
    path = tmp_path / "data.csv"
    text = "a,b\r\n1,2\r\n"
    path.write_bytes(text.encode("utf-16"))
    profile = profile_csv(path)
    assert profile.encoding == "utf-16"
    assert profile.row_count == 1


# --- profile_csv / profile_source: failure modes ----------------------------


def test_profile_csv_missing_file_raises_probe_error(tmp_path):
    with pytest.raises(ProbeError, match="not a file"):
        profile_csv(tmp_path / "nope.csv")


def test_profile_csv_empty_file_raises_probe_error(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("")
    with pytest.raises(ProbeError, match="empty file"):
        profile_csv(path)


def test_profile_csv_header_only_file_has_zero_row_count_and_no_crash(tmp_path):
    path = tmp_path / "data.csv"
    _write_csv(path, [["a", "b"]])
    profile = profile_csv(path)
    assert profile.row_count == 0
    assert profile.columns["a"].non_blank == 0


def test_profile_source_returns_every_csv_sorted_by_name(tmp_path):
    _write_csv(tmp_path / "b.csv", [["x"], ["1"]])
    _write_csv(tmp_path / "a.csv", [["x"], ["1"]])
    (tmp_path / "notes.txt").write_text("ignore me")
    profiles = profile_source(tmp_path)
    assert [p.path.name for p in profiles] == ["a.csv", "b.csv"]


def test_profile_source_no_csv_raises_probe_error(tmp_path):
    (tmp_path / "notes.txt").write_text("ignore me")
    with pytest.raises(ProbeError, match="no .csv file"):
        profile_source(tmp_path)


def test_profile_source_missing_directory_raises_probe_error(tmp_path):
    with pytest.raises(ProbeError, match="not a directory"):
        profile_source(tmp_path / "does-not-exist")


# --- smoke tests against the real committed sample files -------------------
#
# Structural facts only (column names, that a value-shaped column gets the
# tag its own data actually has) -- never a specific asset_id/finding_id/CVE
# VALUE, since these files are shared with other tests and may legitimately
# grow (CLAUDE.md Section 8 rule 1) without this file needing to change.


def test_bluepeak_real_file_cve_column_is_tagged_cve_id():
    profile = profile_csv(BLUEPEAK_DIR / "synthetic_cve_inventory_50.csv")
    assert "cve_id" in profile.columns["CVE_ID"].looks_like
    assert profile.problems == []  # the real file is clean -- no ragged rows, no duplicate headers


def test_defender_sample_real_files_profile_cleanly():
    devices = profile_csv(DEFENDER_DIR / "devices.csv")
    vulnerabilities = profile_csv(DEFENDER_DIR / "vulnerabilities.csv")
    assert "cve_id" in vulnerabilities.columns["CveId"].looks_like
    assert devices.columns["DeviceId"].non_blank == devices.row_count  # every device row has one
    assert not devices.truncated and not vulnerabilities.truncated


def test_demo_fixture_profiles_via_profile_source():
    profiles = profile_source(DEMO_DIR)
    by_name = {p.path.name: p for p in profiles}
    assert set(by_name) == {"assets.csv", "findings.csv"}
    assert "identity_candidate" in by_name["assets.csv"].columns["asset_id"].looks_like
    assert by_name["assets.csv"].row_count == by_name["assets.csv"].columns["asset_id"].non_blank
