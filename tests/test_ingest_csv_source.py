"""The shared CSV reading path every adapter goes through
(`ingest.open_csv` / `ingest.iter_csv_rows`).

These are rules about what a readable source row *is*, so they are stated
once here rather than per format: which encoding a file is read in, and
which malformed inputs are refused rather than silently reinterpreted.
Each rule is exercised both directly and end to end through a real
adapter, because the failure they were written for -- a PowerShell-encoded
export -- reached the user as a traceback from inside adapter code, not
from the helper that owns the decision.
"""

from __future__ import annotations

import codecs
import csv
from pathlib import Path

import pytest

from rhinosecure import ingest
from rhinosecure.adapters import get_adapter
from rhinosecure.ingest import IngestError, load_batch

DEFENDER_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "defender-sample"


def _write(path: Path, rows: list[dict[str, str]], columns: list[str], encoding: str = "utf-8") -> Path:
    with path.open("w", newline="", encoding=encoding) as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _reencode(src_dir: Path, dst_dir: Path, encoding: str) -> Path:
    """Copy every CSV in `src_dir` to `dst_dir`, re-encoded."""
    dst_dir.mkdir(parents=True, exist_ok=True)
    for csv_path in sorted(src_dir.glob("*.csv")):
        (dst_dir / csv_path.name).write_text(csv_path.read_text(encoding="utf-8"), encoding=encoding)
    return dst_dir


# --- encoding detection -------------------------------------------------


@pytest.mark.parametrize(
    "encoding, expected",
    [
        ("utf-8", "utf-8"),
        ("utf-8-sig", "utf-8-sig"),  # Excel
        ("utf-16", "utf-16"),  # PowerShell 5.1 Export-Csv default (LE + BOM)
        ("utf-32", "utf-32"),
    ],
)
def test_detect_encoding_reads_the_byte_order_mark(tmp_path, encoding, expected):
    path = _write(tmp_path / "x.csv", [{"a": "1"}], ["a"], encoding=encoding)
    assert ingest.detect_encoding(path) == expected


def test_a_big_endian_bom_is_detected(tmp_path):
    """Python's `utf-16-be` codec writes no BOM of its own -- the -be/-le
    variants are BOM-less by definition -- so a real big-endian file has to
    be built the way a producer would: BOM first, then BE-encoded text."""
    path = tmp_path / "x.csv"
    path.write_bytes(codecs.BOM_UTF16_BE + "CveId\nCVE-2020-1472\n".encode("utf-16-be"))
    assert ingest.detect_encoding(path) == "utf-16"
    f, reader = ingest.open_csv(path)
    with f:
        assert [row for _n, row in ingest.iter_csv_rows(path, reader)] == [{"CveId": "CVE-2020-1472"}]


def test_a_bomless_file_is_read_as_utf8(tmp_path):
    """No BOM is not a claim about encoding, so nothing is guessed: UTF-8 is
    the documented assumption, and a file that isn't UTF-8 is refused rather
    than decoded as something plausible."""
    path = _write(tmp_path / "x.csv", [{"a": "1"}], ["a"], encoding="utf-8")
    assert ingest.detect_encoding(path) == "utf-8"


def test_a_utf32_file_is_not_mistaken_for_utf16(tmp_path):
    """UTF-32-LE's BOM begins with UTF-16-LE's, so BOM order matters: read as
    UTF-16 the file decodes to NUL-padded garbage instead of failing."""
    path = _write(tmp_path / "x.csv", [{"header": "value"}], ["header"], encoding="utf-32")
    f, reader = ingest.open_csv(path)
    with f:
        assert reader.fieldnames == ["header"]
        assert [row for _n, row in ingest.iter_csv_rows(path, reader)] == [{"header": "value"}]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-32"])
def test_open_csv_round_trips_every_supported_encoding(tmp_path, encoding):
    path = _write(
        tmp_path / "x.csv",
        [{"CveId": "CVE-2020-1472", "Note": "naïve café"}],
        ["CveId", "Note"],
        encoding=encoding,
    )
    f, reader = ingest.open_csv(path)
    with f:
        rows = [row for _n, row in ingest.iter_csv_rows(path, reader)]
    assert rows == [{"CveId": "CVE-2020-1472", "Note": "naïve café"}]


# --- decode failures are IngestError, never a raw traceback -------------


def test_undecodable_header_raises_ingest_error_naming_the_file(tmp_path):
    """The regression this file exists for. UnicodeDecodeError is a
    ValueError, so before the shared reader it escaped every `except
    IngestError` in cli.py and reached the user as a traceback."""
    path = tmp_path / "x.csv"
    path.write_bytes(b"\xffCveId,Severity\nCVE-2020-1472,High\n")  # 0xFF, no BOM
    with pytest.raises(IngestError) as excinfo:
        ingest.open_csv(path)
    message = str(excinfo.value)
    assert str(path) in message
    assert "utf-8" in message
    assert "Re-export" in message


def test_undecodable_row_beyond_the_first_buffer_raises_ingest_error(tmp_path):
    """A clean header does not prove the rest of the file decodes. Reading the
    header pulls a whole buffer, so a bad byte early in a small file is caught
    at open; one past that buffer is only reached while iterating, which is
    why the guard has to be on both. The padding here is what puts the bad
    byte in the lazily-read half -- without it this test passes for the wrong
    reason."""
    padding = b"".join(b"CVE-2020-1472,High\n" for _ in range(4000))  # ~76KB
    path = tmp_path / "x.csv"
    path.write_bytes(b"CveId,Severity\n" + padding + b"CVE-2021-34527,\xffigh\n")
    f, reader = ingest.open_csv(path)  # header, and the first buffer, are fine
    with f, pytest.raises(IngestError) as excinfo:
        list(ingest.iter_csv_rows(path, reader))
    assert str(path) in str(excinfo.value)


# --- end to end through a real adapter ----------------------------------


@pytest.mark.parametrize("encoding", ["utf-16", "utf-8-sig"])
def test_a_powershell_or_excel_encoded_export_loads(tmp_path, encoding):
    """`Export-Csv` writes UTF-16LE with a BOM by default on Windows
    PowerShell 5.1, which is how a real Defender export most often arrives."""
    data_dir = _reencode(DEFENDER_SAMPLE, tmp_path / encoding, encoding)
    assets, findings = load_batch(data_dir, get_adapter("defender"))
    scored = list(findings)
    assert len(assets) == 5
    assert len(scored) == 9


def test_the_reencoded_export_produces_the_same_records_as_the_utf8_one(tmp_path):
    """Encoding is a transport detail: it must not change one field."""
    utf8_assets, utf8_findings = load_batch(DEFENDER_SAMPLE, get_adapter("defender"))
    utf8 = (utf8_assets, [f.finding for f in utf8_findings])

    data_dir = _reencode(DEFENDER_SAMPLE, tmp_path / "utf16", "utf-16")
    utf16_assets, utf16_findings = load_batch(data_dir, get_adapter("defender"))
    utf16 = (utf16_assets, [f.finding for f in utf16_findings])

    assert utf8[0] == utf16[0]
    assert utf8[1] == utf16[1]


# --- ragged rows are refused, never reinterpreted ------------------------


def test_a_short_row_is_refused_not_read_as_blank_cells(tmp_path):
    """The dangerous direction. DictReader fills a missing trailing column
    with None, adapters read `(row.get(c) or "").strip()`, and a blank is what
    becomes a documented default plus a not_collected marker -- so a truncated
    row would be recorded as "the source didn't collect that"."""
    path = tmp_path / "x.csv"
    path.write_bytes(b"CveId,Severity,Product\nCVE-2020-1472,High,Netlogon\nCVE-2021-34527,High\n")
    f, reader = ingest.open_csv(path)
    with f, pytest.raises(IngestError) as excinfo:
        list(ingest.iter_csv_rows(path, reader))
    message = str(excinfo.value)
    assert "row 3" in message
    assert "'Product'" in message
    assert "2 fields" in message and "declares 3" in message


def test_a_long_row_is_refused_not_silently_truncated(tmp_path):
    path = tmp_path / "x.csv"
    path.write_bytes(b"CveId,Severity\nCVE-2020-1472,High\nCVE-2021-34527,High,extra,more\n")
    f, reader = ingest.open_csv(path)
    with f, pytest.raises(IngestError) as excinfo:
        list(ingest.iter_csv_rows(path, reader))
    message = str(excinfo.value)
    assert "row 3" in message
    assert "4 fields" in message and "declares 2" in message
    assert "extra" in message


def test_a_genuinely_blank_cell_is_still_a_blank_cell(tmp_path):
    """The check must not catch the case it exists to distinguish from: a row
    with the right field count and an empty value is well-formed data."""
    path = tmp_path / "x.csv"
    path.write_bytes(b"CveId,Severity,Product\nCVE-2020-1472,,Netlogon\n")
    f, reader = ingest.open_csv(path)
    with f:
        rows = [row for _n, row in ingest.iter_csv_rows(path, reader)]
    assert rows == [{"CveId": "CVE-2020-1472", "Severity": "", "Product": "Netlogon"}]


def test_a_trailing_newline_is_not_a_ragged_row(tmp_path):
    """csv.reader yields [] for a blank line and DictReader skips it -- worth
    pinning, since every well-formed CSV ends with one."""
    path = tmp_path / "x.csv"
    path.write_bytes(b"CveId,Severity\nCVE-2020-1472,High\n\n")
    f, reader = ingest.open_csv(path)
    with f:
        rows = [row for _n, row in ingest.iter_csv_rows(path, reader)]
    assert rows == [{"CveId": "CVE-2020-1472", "Severity": "High"}]


def test_a_ragged_row_refuses_through_a_real_adapter(tmp_path):
    """End to end: the refusal must reach the CLI as an IngestError, which is
    what every `except IngestError` in cli.py already catches."""
    data_dir = _reencode(DEFENDER_SAMPLE, tmp_path / "ragged", "utf-8")
    devices = data_dir / "devices.csv"
    devices.write_text(devices.read_text(encoding="utf-8") + "2026-08-30T02:10:44Z,truncated\n", encoding="utf-8")
    with pytest.raises(IngestError) as excinfo:
        assets, findings = load_batch(data_dir, get_adapter("defender"))
        list(findings)
    assert "fields but the header" in str(excinfo.value)


# --- row numbers are physical line numbers, not record counts -----------


def test_row_numbers_survive_an_embedded_newline(tmp_path):
    """A quoted field may legally contain a newline -- exactly the shape of
    a free-text evidence column. That record consumes two physical lines,
    so a record-counting row number and the true line number diverge for
    every row after it. iter_csv_rows must report the physical line."""
    path = tmp_path / "x.csv"
    path.write_bytes(
        b'CveId,Evidence\n'
        b'CVE-2020-1472,"line one\nline two"\n'  # rows 2-3
        b'CVE-2021-34527,ok\n'  # row 4, not row 3
    )
    f, reader = ingest.open_csv(path)
    with f:
        numbers = [n for n, _row in ingest.iter_csv_rows(path, reader)]
    assert numbers == [3, 4]


def test_ragged_row_message_names_the_true_line_after_an_embedded_newline(tmp_path):
    """The bug this guards: a message about a later row was off by one (or
    more) for every embedded newline earlier in the file. Confirmed here by
    also proving what the old enumerate-based count would have said (3),
    against what the real line is (4)."""
    path = tmp_path / "x.csv"
    path.write_bytes(
        b'CveId,Evidence,Extra\n'
        b'CVE-2020-1472,"line one\nline two",ok\n'  # rows 2-3
        b'CVE-2021-34527,ok\n'  # short row: physical line 4, record-count 3
    )
    f, reader = ingest.open_csv(path)
    with f, pytest.raises(IngestError) as excinfo:
        list(ingest.iter_csv_rows(path, reader))
    message = str(excinfo.value)
    assert "row 4" in message
    assert "row 3" not in message


# --- duplicate header names are refused, not silently corrupted ---------


def test_a_duplicate_column_name_is_refused(tmp_path):
    """The silent-corruption path this guards. csv.DictReader reports every
    occurrence in fieldnames but keeps only the LAST one's value in every
    row -- confirmed: reading back ['CveId','Severity','CveId'] against
    'A,High,B' gives {'CveId': 'B', 'Severity': 'High'}, with the first
    CveId column's value gone and no error raised anywhere."""
    path = tmp_path / "x.csv"
    path.write_bytes(b"CveId,Severity,CveId\nCVE-2020-1472,High,CVE-2021-34527\n")
    with pytest.raises(IngestError) as excinfo:
        ingest.open_csv(path)
    message = str(excinfo.value)
    assert str(path) in message
    assert "'CveId'" in message
    assert "more than once" in message


def test_a_duplicate_column_name_refuses_through_a_real_adapter(tmp_path):
    data_dir = _reencode(DEFENDER_SAMPLE, tmp_path / "dup", "utf-8")
    devices = data_dir / "devices.csv"
    header, rest = devices.read_text(encoding="utf-8").split("\n", 1)
    devices.write_text(f"{header},DeviceId\n{rest}", encoding="utf-8")
    with pytest.raises(IngestError) as excinfo:
        load_batch(data_dir, get_adapter("defender"))
    assert "more than once" in str(excinfo.value)


def test_no_duplicate_columns_is_unaffected(tmp_path):
    """The check must not false-positive on an ordinary well-formed header."""
    path = _write(tmp_path / "x.csv", [{"a": "1", "b": "2"}], ["a", "b"])
    f, reader = ingest.open_csv(path)
    with f:
        assert reader.fieldnames == ["a", "b"]
