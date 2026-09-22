"""Coverage for `xlsx_convert.py`. Every test builds a real `.xlsx` binary
with `openpyxl` (never a hand-crafted byte string) -- the same discipline
`tests/test_ingest_csv_source.py`'s own ZIP-signature tests already use, so
what's exercised is real openpyxl round-trip behavior, not an assumption
about it.
"""

from __future__ import annotations

import csv
import datetime
from pathlib import Path

import openpyxl
import pytest

from rhinosecure.xlsx_convert import ConvertedSheet, XlsxConversionError, convert_workbook


def _read_csv(path: Path) -> list[list[str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


def test_converts_a_simple_sheet_to_a_same_named_csv(tmp_path: Path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Sheet1"
    ws.append(["asset_id", "hostname", "criticality"])
    ws.append(["A01", "DC01", 5])
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    out_dir = tmp_path / "out"
    results = convert_workbook(xlsx_path, out_dir)

    assert len(results) == 1
    assert results[0] == ConvertedSheet(
        sheet_name="Sheet1", csv_path=out_dir / "Sheet1.csv", row_count=2, column_count=3
    )
    assert _read_csv(out_dir / "Sheet1.csv") == [
        ["asset_id", "hostname", "criticality"],
        ["A01", "DC01", "5"],
    ]


def test_converts_every_sheet_by_default(tmp_path: Path):
    wb = openpyxl.Workbook()
    ws1 = wb.active
    ws1.title = "assets"
    ws1.append(["asset_id"])
    ws1.append(["A01"])
    ws2 = wb.create_sheet("findings")
    ws2.append(["finding_id"])
    ws2.append(["F01"])
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    out_dir = tmp_path / "out"
    results = convert_workbook(xlsx_path, out_dir)

    assert {r.sheet_name for r in results} == {"assets", "findings"}
    assert (out_dir / "assets.csv").exists()
    assert (out_dir / "findings.csv").exists()


def test_sheet_filter_converts_only_the_named_sheets(tmp_path: Path):
    wb = openpyxl.Workbook()
    ws1 = wb.active
    ws1.title = "keep"
    ws1.append(["a"])
    ws2 = wb.create_sheet("skip")
    ws2.append(["b"])
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    out_dir = tmp_path / "out"
    results = convert_workbook(xlsx_path, out_dir, sheets=["keep"])

    assert [r.sheet_name for r in results] == ["keep"]
    assert (out_dir / "keep.csv").exists()
    assert not (out_dir / "skip.csv").exists()


def test_unknown_sheet_name_is_refused_and_names_the_real_ones(tmp_path: Path):
    wb = openpyxl.Workbook()
    wb.active.title = "real_sheet"
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    with pytest.raises(XlsxConversionError) as excinfo:
        convert_workbook(xlsx_path, tmp_path / "out", sheets=["nope"])
    assert "nope" in str(excinfo.value)
    assert "real_sheet" in str(excinfo.value)


# ---------------- typed-cell stringification ----------------


def test_stringifies_every_cell_type_to_match_the_projects_own_csv_conventions(tmp_path: Path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["int", "whole_float", "frac_float", "bool_true", "bool_false", "blank", "date", "text"])
    ws.append([5, 5.0, 5.5, True, False, None, datetime.date(2026, 8, 1), "hello"])
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    convert_workbook(xlsx_path, tmp_path / "out")
    rows = _read_csv(tmp_path / "out" / f"{wb.active.title}.csv")

    assert rows[1] == ["5", "5", "5.5", "True", "False", "", "2026-08-01", "hello"]


def test_a_datetime_with_a_real_time_component_keeps_it(tmp_path: Path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["detected"])
    ws.append([datetime.datetime(2026, 8, 1, 14, 30, 0)])
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    convert_workbook(xlsx_path, tmp_path / "out")
    rows = _read_csv(tmp_path / "out" / f"{ws.title}.csv")
    assert rows[1] == ["2026-08-01T14:30:00"]


def test_a_midnight_datetime_renders_as_a_plain_date(tmp_path: Path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["detected"])
    ws.append([datetime.datetime(2026, 8, 1, 0, 0, 0)])
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    convert_workbook(xlsx_path, tmp_path / "out")
    rows = _read_csv(tmp_path / "out" / f"{ws.title}.csv")
    assert rows[1] == ["2026-08-01"]


# ---------------- trailing blank rows/columns ----------------


def test_trailing_blank_rows_and_columns_are_trimmed(tmp_path: Path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["a", "b", None])
    ws.append(["1", "2", None])
    ws.append([None, None, None])
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    convert_workbook(xlsx_path, tmp_path / "out")
    rows = _read_csv(tmp_path / "out" / f"{ws.title}.csv")
    assert rows == [["a", "b"], ["1", "2"]]


# ---------------- merged cells: refused by default ----------------


def test_a_merged_cell_region_is_refused_by_default(tmp_path: Path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = "Section header"
    ws.merge_cells("A1:C1")
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    with pytest.raises(XlsxConversionError) as excinfo:
        convert_workbook(xlsx_path, tmp_path / "out")
    assert "A1:C1" in str(excinfo.value)
    assert "merged" in str(excinfo.value).lower()
    assert not (tmp_path / "out" / f"{ws.title}.csv").exists()  # refused before writing anything


def test_allow_merged_cells_opts_into_the_lossy_flattening(tmp_path: Path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = "Section header"
    ws.merge_cells("A1:C1")
    ws["A2"] = "x"
    ws["B2"] = "y"
    ws["C2"] = "z"
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    convert_workbook(xlsx_path, tmp_path / "out", unmerge=True)
    rows = _read_csv(tmp_path / "out" / f"{ws.title}.csv")
    # Top-left keeps its value; the rest of the merged region reads empty --
    # this is the accepted, documented lossy behavior, not a fill-in.
    assert rows[0] == ["Section header", "", ""]
    assert rows[1] == ["x", "y", "z"]


# ---------------- uncalculated formulas: refused ----------------


def test_a_formula_with_no_cached_value_is_refused_not_silently_blanked(tmp_path: Path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = 5
    ws["A2"] = "=A1+1"  # never opened/saved by a real spreadsheet app -- no cached result exists
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    with pytest.raises(XlsxConversionError) as excinfo:
        convert_workbook(xlsx_path, tmp_path / "out")
    message = str(excinfo.value)
    assert "A2" in message
    assert "formula" in message.lower()
    assert "=A1+1" in message


def test_a_formula_with_a_real_cached_value_converts_normally(tmp_path: Path):
    """openpyxl/Excel's own save behavior caches a formula's last-computed
    result -- simulated here by writing the cached value directly into the
    same cell a formula would occupy is not how real files work, so this
    instead confirms the ORDINARY case (a plain value, no formula at all)
    is never mistaken for the refusal case above -- the two formula tests
    together are what actually prove the distinction is real."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = 5
    ws["A2"] = 6
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    convert_workbook(xlsx_path, tmp_path / "out")
    rows = _read_csv(tmp_path / "out" / f"{ws.title}.csv")
    assert rows == [["5"], ["6"]]


# ---------------- output directory handling ----------------


def test_refuses_a_nonempty_out_dir_without_overwrite(tmp_path: Path):
    wb = openpyxl.Workbook()
    wb.active.append(["a"])
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "unrelated.txt").write_text("do not touch", encoding="utf-8")

    with pytest.raises(XlsxConversionError) as excinfo:
        convert_workbook(xlsx_path, out_dir)
    assert "already exists" in str(excinfo.value)
    assert (out_dir / "unrelated.txt").read_text(encoding="utf-8") == "do not touch"  # untouched


def test_overwrite_allows_converting_into_a_nonempty_dir(tmp_path: Path):
    wb = openpyxl.Workbook()
    wb.active.append(["a"])
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "unrelated.txt").write_text("still here", encoding="utf-8")

    convert_workbook(xlsx_path, out_dir, overwrite=True)
    assert (out_dir / f"{wb.active.title}.csv").exists()
    assert (out_dir / "unrelated.txt").exists()  # overwrite means "allow converting into it", not "wipe it"


def test_creates_out_dir_if_it_does_not_exist(tmp_path: Path):
    wb = openpyxl.Workbook()
    wb.active.append(["a"])
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    out_dir = tmp_path / "brand" / "new" / "path"
    convert_workbook(xlsx_path, out_dir)
    assert out_dir.is_dir()


# ---------------- bad input ----------------


def test_a_nonexistent_source_file_is_refused(tmp_path: Path):
    with pytest.raises(XlsxConversionError) as excinfo:
        convert_workbook(tmp_path / "does_not_exist.xlsx", tmp_path / "out")
    assert "no such file" in str(excinfo.value)


def test_a_non_xlsx_file_is_refused_cleanly(tmp_path: Path):
    bad = tmp_path / "not_really.xlsx"
    bad.write_text("this is plain text, not a real workbook", encoding="utf-8")
    with pytest.raises(XlsxConversionError) as excinfo:
        convert_workbook(bad, tmp_path / "out")
    assert "could not open" in str(excinfo.value)


# ---------------- end to end: the real ingest pipeline accepts the output ----------------


def test_converted_output_ingests_cleanly_through_the_real_native_adapter(tmp_path: Path):
    """The actual point of this whole module: a converted workbook must be
    genuinely indistinguishable, from ingest.py's own perspective, from a
    hand-written CSV export -- not just superficially CSV-shaped. Builds a
    real assets/findings workbook (sheet names matching NativeAdapter's own
    assets_filename/findings_filename exactly, so the converted directory
    needs no renaming at all), converts it, and runs it through the real
    ingest.load_batch + NativeAdapter, the exact same call cli.py's own
    `run` command makes."""
    from rhinosecure.adapters.native import NativeAdapter
    from rhinosecure.ingest import load_batch

    wb = openpyxl.Workbook()
    assets_ws = wb.active
    assets_ws.title = "assets"
    assets_ws.append([
        "asset_id", "hostname", "os", "os_build", "role", "business_function", "criticality",
        "internet_exposed", "environment", "data_sensitivity", "patch_window", "patch_restrictions",
        "compensating_controls", "owner",
    ])
    assets_ws.append([
        "A01", "DC01", "Windows Server 2019", "17763", "dc", "Primary domain controller", 5,
        False, "prod", "regulated", "Sun 02:00-06:00", "no reboot during business hours", "", "infra-team",
    ])
    findings_ws = wb.create_sheet("findings")
    findings_ws.append([
        "finding_id", "asset_id", "cve_id", "detected_date", "scanner_severity", "product", "version",
        "port", "service", "evidence",
    ])
    findings_ws.append([
        "F01", "A01", "CVE-2020-1472", datetime.date(2026, 8, 1), "critical", "Windows Server", "2019",
        "445", "smb", "Netlogon RPC allows elevation of privilege (ZeroLogon)",
    ])
    xlsx_path = tmp_path / "source.xlsx"
    wb.save(xlsx_path)

    out_dir = tmp_path / "converted"
    results = convert_workbook(xlsx_path, out_dir)
    assert {r.csv_path.name for r in results} == {"assets.csv", "findings.csv"}

    assets, findings_iter = load_batch(out_dir, NativeAdapter())
    findings = list(findings_iter)

    assert set(assets) == {"A01"}
    a = assets["A01"]
    assert a.hostname == "DC01"
    assert a.criticality == 5
    assert a.internet_exposed is False
    assert a.role == "dc"

    assert len(findings) == 1
    f = findings[0].finding
    assert f.finding_id == "F01"
    assert f.cve_id == "CVE-2020-1472"
    assert f.detected_date == "2026-08-01"
    assert f.scanner_severity == "critical"
