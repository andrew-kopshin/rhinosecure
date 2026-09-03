"""The adapter registry and the native adapter -- the seam itself, as
opposed to test_adapters_defender.py's one concrete format."""

from __future__ import annotations

from pathlib import Path

import pytest

from rhinosecure.adapters import DEFAULT_FORMAT, FORMATS, AdapterError, get_adapter
from rhinosecure.adapters.base import NOT_COLLECTED_DEFAULTS, IngestAdapter
from rhinosecure.adapters.native import NativeAdapter
from rhinosecure.ingest import GapTally, IngestError, IngestStats, join_findings, load_batch
from rhinosecure.schema import Asset, Finding

DEMO_DIR = Path(__file__).resolve().parents[1] / "data" / "demo"


def test_native_is_the_default_format_and_defender_is_registered():
    assert DEFAULT_FORMAT == "native"
    assert set(FORMATS) == {"native", "defender"}
    assert all(issubclass(cls, IngestAdapter) for cls in FORMATS.values())
    assert isinstance(get_adapter("native"), NativeAdapter)


def test_unknown_format_is_an_adapter_error():
    with pytest.raises(AdapterError, match="unknown ingest format 'qualys'"):
        get_adapter("qualys")


def test_native_adapter_reproduces_join_findings_exactly_on_the_demo_fixture():
    """Routing the native format through the adapter seam must change
    nothing: same EnrichedFinding objects, same order, no gaps, nothing
    collapsed -- the byte-identical-output guarantee starts here."""
    adapter = get_adapter("native")
    assets, enriched = load_batch(DEMO_DIR, adapter)
    via_adapter = list(enriched)
    direct = list(join_findings(DEMO_DIR / "findings.csv", DEMO_DIR / "assets.csv"))

    assert via_adapter == direct
    assert set(assets) == {e.asset.asset_id for e in direct}
    assert all(e.asset.not_collected == frozenset() for e in via_adapter)
    assert all(e.finding.not_collected == frozenset() for e in via_adapter)
    assert adapter.stats == IngestStats()


def test_native_gap_report_is_empty():
    adapter = get_adapter("native")
    assets, enriched = load_batch(DEMO_DIR, adapter)
    tally = GapTally()
    for e in enriched:
        tally.observe(e.finding)
    report = tally.report("native", assets, adapter.stats)
    assert not report.has_gaps
    assert not report.has_anything_to_report
    assert report.assets_total == len(assets) and report.findings_total == tally.findings_total


def test_every_not_collected_default_is_valid_for_the_schema():
    """The defaults table must produce records the schema accepts, or an
    adapter would fail on the first row of a format that lacks a field."""
    asset_defaults = {k: v for k, v in NOT_COLLECTED_DEFAULTS.items() if k in Asset.model_fields}
    finding_defaults = {k: v for k, v in NOT_COLLECTED_DEFAULTS.items() if k in Finding.model_fields}
    assert set(asset_defaults) | set(finding_defaults) == set(NOT_COLLECTED_DEFAULTS)

    asset = Asset(asset_id="x", hostname="h", os="Windows 10", role="workstation", **asset_defaults,
                  not_collected=frozenset(asset_defaults))
    finding = Finding(finding_id="f", asset_id="x", cve_id="CVE-2020-1472", scanner_severity="high",
                      **finding_defaults, not_collected=frozenset(finding_defaults))
    assert asset.not_collected == set(asset_defaults)
    assert finding.not_collected == set(finding_defaults)


def test_native_csv_cannot_smuggle_a_not_collected_column(tmp_path):
    """not_collected is set by adapters, never read from a native CSV cell
    -- a stray column must fail validation loudly, not be parsed into a
    set of characters."""
    from rhinosecure.ingest import IngestError, load_assets

    path = tmp_path / "assets.csv"
    path.write_text(
        "asset_id,hostname,os,os_build,role,business_function,criticality,internet_exposed,"
        "environment,data_sensitivity,patch_window,patch_restrictions,compensating_controls,owner,not_collected\n"
        "A01,HOST1,Windows Server 2019,17763,dc,DC,5,False,prod,regulated,,,,,patch_window\n"
    )
    with pytest.raises(IngestError):
        list(load_assets(path))


# --- _require_adapter_files / load_batch: a --format/--data mismatch --------
#
# Reported bug: `rhino constraint add --format defender` with --data left
# at its default (demo, the native fixture) crashed with a raw
# FileNotFoundError from deep inside DefenderAdapter's own csv.DictReader
# construction -- naming neither the directory nor the reason. load_batch
# is the one function every CLI entry point (run, run --agents,
# constraint add) already calls, so the fix lives there once.


def test_format_mismatch_raises_ingest_error_naming_path_and_cause():
    """The exact reported scenario: --format defender against the native
    demo fixture, which has neither devices.csv nor vulnerabilities.csv."""
    with pytest.raises(IngestError) as excinfo:
        load_batch(DEMO_DIR, get_adapter("defender"))
    message = str(excinfo.value)
    assert str(DEMO_DIR) in message  # names the path
    assert "devices.csv" in message and "vulnerabilities.csv" in message  # what was expected
    assert "assets.csv" in message and "findings.csv" in message  # what's actually there
    assert "--format/--data mismatch" in message  # the likely cause


def test_reverse_format_mismatch_also_raises_before_any_file_opens(tmp_path):
    """--format native against a defender-shaped directory -- the same
    check catches the mismatch in either direction."""
    (tmp_path / "devices.csv").write_text("DeviceId,DeviceName,OSPlatform,OSBuild,IsInternetFacing,AssetValue\n")
    (tmp_path / "vulnerabilities.csv").write_text(
        "DeviceId,CveId,VulnerabilitySeverityLevel,SoftwareName,SoftwareVersion\n"
    )
    with pytest.raises(IngestError) as excinfo:
        load_batch(tmp_path, get_adapter("native"))
    message = str(excinfo.value)
    assert "assets.csv" in message and "findings.csv" in message
    assert "devices.csv" in message and "vulnerabilities.csv" in message


def test_the_check_raises_before_load_assets_or_load_findings_ever_runs(monkeypatch):
    """Confirms this is a real pre-check, not just an error that happens
    to surface early -- neither adapter method may execute at all."""
    adapter = get_adapter("defender")

    def _boom(*a, **k):
        raise AssertionError("adapter method invoked despite the missing-file precheck")

    monkeypatch.setattr(adapter, "load_assets", _boom)
    monkeypatch.setattr(adapter, "load_findings", _boom)
    with pytest.raises(IngestError, match="--format/--data mismatch"):
        load_batch(DEMO_DIR, adapter)


def test_a_nonexistent_data_dir_reports_that_rather_than_listing_files(tmp_path):
    missing_dir = tmp_path / "does-not-exist"
    with pytest.raises(IngestError, match=r"directory does not exist"):
        load_batch(missing_dir, get_adapter("defender"))


def test_matching_format_and_data_still_load_normally():
    """Regression guard: the precheck must not fire on the happy path."""
    assets, enriched = load_batch(DEMO_DIR, get_adapter("native"))
    assert len(assets) == 12
    assert len(list(enriched)) == 24


def test_partial_mismatch_names_only_the_missing_file(tmp_path):
    """One of the two expected files present, one missing -- a genuinely
    broken export, not necessarily a format swap. The message must still
    be accurate: name only what's actually missing."""
    (tmp_path / "devices.csv").write_text("DeviceId,DeviceName,OSPlatform,OSBuild,IsInternetFacing,AssetValue\n")
    with pytest.raises(IngestError) as excinfo:
        load_batch(tmp_path, get_adapter("defender"))
    message = str(excinfo.value)
    assert "vulnerabilities.csv" in message
    assert "devices.csv is missing" not in message  # devices.csv IS present
    assert "vulnerabilities.csv is missing" in message


# --- adversarial review findings on _require_adapter_files itself -----------
#
# An independent review of the fix above (three reviewers, adversarially
# verified) found four real defects in _require_adapter_files itself, all
# fixed and each covered by its own test here.


def test_a_permission_error_while_listing_the_directory_still_raises_ingesterror(tmp_path, monkeypatch):
    """Path.iterdir() -- unlike is_file()/is_dir()/exists() -- does not
    swallow a genuine OS-level failure. A directory the process can stat
    but not list (a realistic locked-down deployment share) must not
    crash this function with the exact unhandled exception it exists to
    prevent. Patches iterdir only for the exact tmp_path under test, so
    real directory listing elsewhere (including pytest's own machinery)
    is unaffected."""
    real_iterdir = Path.iterdir

    def _iterdir(self):
        if self == tmp_path:
            raise PermissionError(13, "Access is denied", str(tmp_path))
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", _iterdir)

    with pytest.raises(IngestError) as excinfo:
        load_batch(tmp_path, get_adapter("defender"))
    message = str(excinfo.value)
    assert str(tmp_path) in message
    assert "could not check whether" in message
    assert "Traceback" not in message


def test_a_same_named_directory_is_listed_not_silently_hidden(tmp_path):
    """A stray directory named exactly like an expected file (someone ran
    `mkdir devices.csv` by mistake) must not make the message claim the
    directory has no files while also calling that same name missing --
    a contradiction visible to anyone who runs `ls`/`dir` themselves."""
    (tmp_path / "devices.csv").mkdir()
    with pytest.raises(IngestError) as excinfo:
        load_batch(tmp_path, get_adapter("defender"))
    message = str(excinfo.value)
    assert "(no files)" not in message
    assert "devices.csv/ (not a file)" in message


def test_missing_list_deduplicates_when_an_adapter_reuses_a_filename(tmp_path):
    """Defensive: no currently-registered adapter reuses a filename for
    both roles (native: assets.csv/findings.csv, defender: devices.csv/
    vulnerabilities.csv), but the message must not repeat a name on
    either side of the sentence if one ever did."""

    class ComboAdapter(NativeAdapter):
        format = "combo-test"
        assets_filename = "data.csv"
        findings_filename = "data.csv"

    with pytest.raises(IngestError) as excinfo:
        load_batch(tmp_path, ComboAdapter())
    message = str(excinfo.value)
    assert message.count("data.csv") == 2  # once in "needs", once in "missing" -- never doubled


def test_a_partial_mismatch_does_not_blame_a_format_data_mismatch(tmp_path):
    """One of the two expected files present, one missing -- a genuinely
    incomplete export, not a --format/--data mismatch (that reading is
    reserved for when EVERY expected file is absent). The old wording
    would have told a user pointing --format correctly at a broken
    export to go try a different --format, exactly the wrong advice."""
    (tmp_path / "devices.csv").write_text("DeviceId,DeviceName,OSPlatform,OSBuild,IsInternetFacing,AssetValue\n")
    with pytest.raises(IngestError) as excinfo:
        load_batch(tmp_path, get_adapter("defender"))
    message = str(excinfo.value)
    assert "incomplete or corrupted export" in message
    assert "This is almost always a --format/--data mismatch" not in message


def test_a_full_mismatch_still_blames_a_format_data_mismatch(tmp_path):
    """Regression guard for the case the partial-mismatch fix must not
    touch: when EVERY expected file is missing, the format/data-mismatch
    explanation still applies."""
    with pytest.raises(IngestError) as excinfo:
        load_batch(tmp_path, get_adapter("defender"))
    assert "This is almost always a --format/--data mismatch" in str(excinfo.value)
