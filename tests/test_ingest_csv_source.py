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
# A REAL Windows PowerShell 5.1 `Export-Csv -Encoding Default` output, not a
# Python .encode() simulation -- produced live on this project's own stated
# environment (Windows, PowerShell 5.1) via
# `$rows | Export-Csv -Path assets.csv -NoTypeInformation -Encoding Default`,
# confirmed against this machine's own `[System.Text.Encoding]::Default`
# (WebName: Windows-1252, CodePage 1252) before being committed. Carries
# curly quotes (U+201C/U+201D), an em dash (U+2014), and an en dash
# (U+2013) in free-text fields -- exactly the cp1252-only byte range
# (0x80-0x9F) a legacy Windows export puts real content in, confirmed to
# fail strict UTF-8 decoding at that exact byte (see the tests below).
CP1252_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "cp1252-sample" / "assets.csv"
# A REAL Excel 16.0 (Microsoft 365) "CSV UTF-8 (Comma delimited)" export, not
# a Python .encode() simulation -- produced live via COM automation
# (`Workbooks.Add`, `Cells.NumberFormat = "@"` to stop Excel autoconverting
# "false"/"3" to a boolean/number before it's ever written, then
# `Workbook.SaveAs(path, 62)` -- 62 is `xlCSVUTF8`, the same file type the
# "CSV UTF-8" entry in Excel's own Save As dialog writes) on this project's
# own stated environment, confirmed against the raw bytes before being
# committed: a genuine `EF BB BF` BOM, `\r\n` line endings, and -- unlike
# CP1252_SAMPLE's PowerShell-produced every-field quoting -- no quote
# characters at all, since Excel only quotes a field that actually needs
# it. Carries real multi-byte UTF-8 content (Japanese kanji/katakana in a
# business_function field) so the round trip below proves more than "a BOM
# was present": it proves the BOM was stripped and the real multi-byte
# bytes after it decoded correctly.
EXCEL_UTF8SIG_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "excel-utf8sig-sample" / "assets.csv"
# A REAL Windows PowerShell 5.1 `Export-Csv -Encoding Unicode` output, not a
# Python .encode() simulation -- produced live the same way CP1252_SAMPLE
# was, via `@($row1, $row2) | Export-Csv -Path assets.csv -NoTypeInformation
# -Encoding Unicode` on this project's own stated environment. "Unicode" is
# PowerShell's own name for UTF-16LE with a BOM -- confirmed against the raw
# bytes before being committed: `FF FE`, then every character (ASCII
# included) as a two-byte little-endian code unit, and every field quoted
# (Export-Csv's default, exactly like CP1252_SAMPLE, and unlike
# EXCEL_UTF8SIG_SAMPLE's Excel-only-quotes-when-needed behavior). Carries
# real non-ASCII content (Cyrillic "Служба поддержки" -- "support desk" -- in
# a business_function field) so the round trip below proves the body
# decoded, not just that the BOM was recognized.
POWERSHELL_UTF16_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "powershell-utf16-sample" / "assets.csv"


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


# --- cp1252: never sniffed, refused loudly, naming the one remedy that ----
# --- did not exist before Source.encoding grew a legacy-encoding member ---


def test_detect_encoding_never_returns_cp1252_on_the_real_file(tmp_path):
    """No BOM exists for a single-byte encoding, so there is nothing to
    sniff -- confirmed against the real PowerShell-produced fixture, not a
    synthetic one, so this is the genuine byte-for-byte case a human would
    actually hit."""
    assert ingest.detect_encoding(CP1252_SAMPLE) == "utf-8"


def test_the_real_cp1252_fixture_fails_strict_utf8_decoding(tmp_path):
    """Pins WHY detect_encoding's utf-8 fallback cannot silently succeed on
    this file -- the curly-quote byte is not a valid UTF-8 lead byte, so
    open_csv's own decode failure below is not a coincidence of this
    particular fixture, it is the whole reason cp1252 needs a declared
    remedy at all."""
    with pytest.raises(UnicodeDecodeError):
        CP1252_SAMPLE.read_text(encoding="utf-8")


def test_the_real_cp1252_fixture_refuses_loudly_through_open_csv_and_names_the_remedy(tmp_path):
    """`ingest.open_csv` has no `Source` to declare anything in (native/
    defender/bluepeak have no per-run config surface at all) -- it still
    fails loudly, and the message now points at the path that DOES have
    one, rather than only naming the two encodings that existed before
    this fixture could ever be read at all."""
    with pytest.raises(IngestError) as excinfo:
        ingest.open_csv(CP1252_SAMPLE)
    message = str(excinfo.value)
    assert str(CP1252_SAMPLE) in message
    assert "utf-8" in message
    assert "cp1252" in message
    assert "source.encoding" in message


# --- utf-8-sig: a real Excel export, not a Python .encode() simulation --


def test_detect_encoding_recognizes_the_real_excel_bom(tmp_path):
    """Confirms the sniff against genuine Excel-written bytes, not a
    Python-encoded stand-in for them."""
    assert ingest.detect_encoding(EXCEL_UTF8SIG_SAMPLE) == "utf-8-sig"


def test_the_real_excel_utf8_sig_fixture_round_trips_through_open_csv(tmp_path):
    f, reader = ingest.open_csv(EXCEL_UTF8SIG_SAMPLE)
    with f:
        rows = [row for _n, row in ingest.iter_csv_rows(EXCEL_UTF8SIG_SAMPLE, reader)]
    assert len(rows) == 2
    assert rows[0]["asset_id"] == "A21"
    assert rows[0]["business_function"] == "Tokyo support desk - 東京サポート"
    assert rows[1]["business_function"] == "大阪支社 ERP backend"
    # Excel's own NumberFormat="@" guard at fixture-build time is what this
    # pins: a naive read of "false"/"3" through Excel would risk the cell
    # having been autocorrected to a real boolean/number before it was ever
    # saved, silently changing the value this test would see.
    assert rows[0]["internet_exposed"] == "false"
    assert rows[0]["criticality"] == "3"


# --- utf-16: a real PowerShell export, not a Python .encode() simulation -


def test_detect_encoding_recognizes_the_real_powershell_bom(tmp_path):
    """Confirms the sniff against genuine `Export-Csv -Encoding Unicode`
    bytes, not a Python-encoded stand-in for them."""
    assert ingest.detect_encoding(POWERSHELL_UTF16_SAMPLE) == "utf-16"


def test_the_real_powershell_utf16_fixture_round_trips_through_open_csv(tmp_path):
    f, reader = ingest.open_csv(POWERSHELL_UTF16_SAMPLE)
    with f:
        rows = [row for _n, row in ingest.iter_csv_rows(POWERSHELL_UTF16_SAMPLE, reader)]
    assert len(rows) == 2
    assert rows[0]["asset_id"] == "A31"
    assert rows[0]["business_function"] == "Moscow support desk - Служба поддержки"
    assert rows[1]["business_function"] == "Служба поддержки ERP backend"
    assert rows[0]["internet_exposed"] == "false"
    assert rows[0]["criticality"] == "3"


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
    """This re-encodes the real UTF-8 Defender sample with Python's own
    `.encode()` -- it is not a genuine PowerShell or Excel export. That claim
    belongs to POWERSHELL_UTF16_SAMPLE / EXCEL_UTF8SIG_SAMPLE / CP1252_SAMPLE
    above, each produced by the real tool it's named for. What this test
    actually proves is narrower, and re-encoding is the right tool for it:
    loading the SAME records through a real adapter's full ingest path (not
    just open_csv/iter_csv_rows in isolation) does not depend on which
    supported encoding the bytes happen to be in."""
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
