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
