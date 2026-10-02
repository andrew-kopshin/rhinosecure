"""Coverage for `scripts/generate_fleet.py`, the seeded fleet-scale dataset
generator. The script is standalone (not a package, not wired into the CLI),
so it is loaded by path. Every snapshot fixture is written through the real
`SnapshotCache.write` rather than hand-built JSON, so the generator is
exercised against the actual on-disk snapshot format, not an assumption about
it -- and no test touches `data/snapshots/` or `data/demo/`.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

import pytest

from rhinosecure import ingest
from rhinosecure.enrich.cache import SnapshotCache

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_fleet.py"
_spec = importlib.util.spec_from_file_location("generate_fleet", SCRIPT)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

# (cve_id, NVD baseSeverity, baseScore, KEV-listed)
SERVABLE = [
    ("CVE-2001-0001", "CRITICAL", 9.8, True),
    ("CVE-2001-0002", "HIGH", 8.1, True),
    ("CVE-2001-0003", "MEDIUM", 5.5, True),
    ("CVE-2001-0004", "LOW", 3.1, True),
    ("CVE-2001-0005", "CRITICAL", 9.1, False),
    ("CVE-2001-0006", "HIGH", 7.5, False),
    ("CVE-2001-0007", "MEDIUM", 6.0, False),
    ("CVE-2001-0008", "LOW", 2.0, False),
]
NO_EPSS = "CVE-2001-0090"  # has NVD CVSS, no EPSS snapshot -> cannot run offline
NO_CVSS = "CVE-2001-0091"  # has EPSS, NVD recorded no CVSS -> nothing to score


def _nvd_payload(severity: str, score: float) -> dict:
    return {
        "vulnerabilities": [{
            "cve": {
                "affected": [{"affectedData": [{"product": "Fixture Product"}]}],
                "metrics": {"cvssMetricV31": [{
                    "type": "Primary", "source": "nvd@nist.gov",
                    "cvssData": {
                        "version": "3.1", "baseScore": score, "baseSeverity": severity,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }]},
            }
        }]
    }


@pytest.fixture
def snapshots(tmp_path: Path) -> Path:
    root = tmp_path / "snapshots"
    cache = SnapshotCache(root)
    for cve_id, severity, score, _ in SERVABLE:
        cache.write("nvd", cve_id, _nvd_payload(severity, score))
        cache.write("epss", cve_id, {"data": [{"cve": cve_id, "epss": "0.5", "percentile": "0.5"}]})
    cache.write("nvd", NO_EPSS, _nvd_payload("HIGH", 8.0))
    cache.write("nvd", NO_CVSS, {"vulnerabilities": [{"cve": {"metrics": {}}}]})
    cache.write("epss", NO_CVSS, {"data": [{"cve": NO_CVSS, "epss": "0.1", "percentile": "0.1"}]})
    cache.write("kev", None, {"vulnerabilities": [
        {"cveID": cve_id, "dateAdded": "2024-01-01", "dueDate": "2024-02-01"}
        for cve_id, _, _, is_kev in SERVABLE if is_kev
    ]})
    return root


def _run(snapshots: Path, out: Path, **overrides) -> dict:
    params = dict(
        out=out, assets=40, findings=120, seed=42, as_of=date(2026, 9, 1),
        disagreement_rate=0.125, snapshot_dir=snapshots,
    )
    params.update(overrides)
    return gen.generate(**params)


def _rows(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


# ---- the CVE pool ----------------------------------------------------------


def test_pool_holds_only_cves_the_snapshots_can_serve_fully_offline(snapshots: Path):
    pool = gen.discover_cve_pool(snapshots)
    ids = {c["cve_id"] for c in pool}
    assert ids == {c[0] for c in SERVABLE}
    assert NO_EPSS not in ids and NO_CVSS not in ids
    assert {c["cve_id"] for c in pool if c["kev"]} == {c[0] for c in SERVABLE if c[3]}


def test_pool_is_discovered_not_hardcoded(tmp_path: Path):
    # A snapshot set with a single, different CVE yields exactly that CVE: no
    # CVE id lives in the generator's logic.
    root = tmp_path / "snap"
    cache = SnapshotCache(root)
    cache.write("nvd", "CVE-1999-9999", _nvd_payload("HIGH", 7.5))
    cache.write("epss", "CVE-1999-9999", {"data": []})
    cache.write("kev", None, {"vulnerabilities": []})
    assert [c["cve_id"] for c in gen.discover_cve_pool(root)] == ["CVE-1999-9999"]


def test_missing_kev_snapshot_is_a_named_refusal(tmp_path: Path):
    root = tmp_path / "snap"
    cache = SnapshotCache(root)
    cache.write("nvd", "CVE-1999-9999", _nvd_payload("HIGH", 7.5))
    cache.write("epss", "CVE-1999-9999", {"data": []})
    with pytest.raises(gen.GenerationError, match="KEV snapshot is missing"):
        gen.discover_cve_pool(root)


# ---- determinism (Section 8 rule 2/3) --------------------------------------


def test_same_arguments_produce_byte_identical_files(snapshots: Path, tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    _run(snapshots, a)
    _run(snapshots, b)
    for name in ("assets.csv", "findings.csv", gen.MARKER_NAME):
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


def test_a_different_seed_changes_the_output(snapshots: Path, tmp_path: Path):
    _run(snapshots, tmp_path / "a", seed=1)
    _run(snapshots, tmp_path / "b", seed=2)
    assert (tmp_path / "a" / "findings.csv").read_bytes() != (tmp_path / "b" / "findings.csv").read_bytes()
    assert (tmp_path / "a" / "assets.csv").read_bytes() != (tmp_path / "b" / "assets.csv").read_bytes()


def test_marker_hashes_describe_exactly_what_is_on_disk(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    marker = _run(snapshots, out)
    on_disk = json.loads((out / gen.MARKER_NAME).read_text(encoding="utf-8"))
    assert on_disk == marker
    assert marker["files"]["assets.csv"] == _sha(out / "assets.csv")
    assert marker["files"]["findings.csv"] == _sha(out / "findings.csv")


# ---- the output is real native-format data ---------------------------------


def test_output_passes_the_real_native_ingest_and_counts_are_exact(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    _run(snapshots, out, assets=40, findings=120)
    assets = list(ingest.load_assets(out / "assets.csv"))
    findings = list(ingest.load_findings(out / "findings.csv"))
    assert len(assets) == 40
    assert len(findings) == 120
    index = ingest.index_assets(assets, source="test")
    assert len(index) == 40  # no duplicate asset ids
    assert {f.asset_id for f in findings} <= set(index)  # no orphaned findings
    assert len({f.finding_id for f in findings}) == 120  # finding ids unique


def test_every_cve_is_from_the_pool_and_no_asset_repeats_one(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    _run(snapshots, out)
    rows = _rows(out / "findings.csv")
    assert {r["cve_id"] for r in rows} <= {c[0] for c in SERVABLE}
    pairs = Counter((r["asset_id"], r["cve_id"]) for r in rows)
    assert max(pairs.values()) == 1


def test_detected_dates_are_relative_to_as_of_never_to_today(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    as_of = date(2031, 3, 15)
    _run(snapshots, out, as_of=as_of)
    dates = {date.fromisoformat(r["detected_date"]) for r in _rows(out / "findings.csv")}
    assert min(dates) >= as_of - timedelta(days=90)
    assert max(dates) <= as_of


def test_findings_are_spread_unevenly_across_assets(snapshots: Path, tmp_path: Path):
    # A uniform spread would hide every "one asset with a great many findings"
    # problem a real scan has; the generator is meant to produce a tail.
    out = tmp_path / "out"
    _run(snapshots, out, assets=200, findings=600)
    per_asset = Counter(r["asset_id"] for r in _rows(out / "findings.csv"))
    assert max(per_asset.values()) > 2 * (600 / 200)


# ---- scanner severity vs NVD ----------------------------------------------


def test_zero_disagreement_rate_reports_nvds_own_severity(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    _run(snapshots, out, disagreement_rate=0.0)
    nvd_says = {c[0]: c[1].lower() for c in SERVABLE}
    assert all(r["scanner_severity"] == nvd_says[r["cve_id"]] for r in _rows(out / "findings.csv"))


def test_full_disagreement_rate_is_always_exactly_one_tier_off(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    _run(snapshots, out, disagreement_rate=1.0)
    tiers = gen.SEVERITY_TIERS
    nvd_says = {c[0]: c[1].lower() for c in SERVABLE}
    for r in _rows(out / "findings.csv"):
        assert abs(tiers.index(r["scanner_severity"]) - tiers.index(nvd_says[r["cve_id"]])) == 1


# ---- --kev-share ------------------------------------------------------------


def _realized_kev(out: Path) -> float:
    kev = {c[0] for c in SERVABLE if c[3]}
    rows = _rows(out / "findings.csv")
    return sum(r["cve_id"] in kev for r in rows) / len(rows)


def test_a_stated_kev_share_is_met_and_reported(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    marker = _run(snapshots, out, assets=300, findings=900, kev_share=0.25)
    assert _realized_kev(out) == pytest.approx(0.25, abs=0.05)
    assert marker["realized_kev_share"] == pytest.approx(_realized_kev(out), abs=1e-4)
    assert marker["params"]["kev_share"] == 0.25


def test_without_kev_share_the_realized_share_is_still_recorded(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    marker = _run(snapshots, out)
    assert marker["params"]["kev_share"] is None
    assert marker["realized_kev_share"] == pytest.approx(_realized_kev(out), abs=1e-4)


def test_a_kev_share_bounds_findings_per_asset_by_the_smaller_side(snapshots: Path, tmp_path: Path):
    # 4 KEV / 4 non-KEV in the fixture pool -> no asset may hold more than 4,
    # otherwise the fallback would quietly override the stated share.
    out = tmp_path / "out"
    _run(snapshots, out, assets=300, findings=900, kev_share=0.25)
    per_asset = Counter(r["asset_id"] for r in _rows(out / "findings.csv"))
    assert max(per_asset.values()) <= 4


def test_a_kev_share_that_the_pool_cannot_carry_is_refused_not_missed(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    with pytest.raises(gen.GenerationError, match="cannot fit"):
        _run(snapshots, out, assets=10, findings=100, kev_share=0.25)
    assert not out.exists()


def test_a_kev_share_needs_both_kinds_of_cve_in_the_pool(tmp_path: Path):
    root = tmp_path / "snap"
    cache = SnapshotCache(root)
    for cve_id in ("CVE-1999-0001", "CVE-1999-0002"):
        cache.write("nvd", cve_id, _nvd_payload("HIGH", 7.5))
        cache.write("epss", cve_id, {"data": []})
    cache.write("kev", None, {"vulnerabilities": [{"cveID": "CVE-1999-0001"}, {"cveID": "CVE-1999-0002"}]})
    with pytest.raises(gen.GenerationError, match="both KEV-listed and non-KEV"):
        _run(root, tmp_path / "out", assets=5, findings=5, kev_share=0.5)


# ---- refusals: never write something wrong, never clobber anything ---------


def test_more_findings_than_the_pool_can_place_is_refused_before_writing(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    with pytest.raises(gen.GenerationError, match="cannot fit"):
        _run(snapshots, out, assets=2, findings=100)  # 2 assets x 8 CVEs = 16 max
    assert not out.exists()


@pytest.mark.parametrize("kwargs", [{"assets": 0}, {"findings": 0}, {"disagreement_rate": 1.5}])
def test_nonsense_parameters_are_refused(snapshots: Path, tmp_path: Path, kwargs):
    with pytest.raises(gen.GenerationError):
        _run(snapshots, tmp_path / "out", **kwargs)


def test_refuses_to_write_into_a_directory_it_did_not_generate(snapshots: Path, tmp_path: Path):
    # This is what keeps the frozen fixture (CLAUDE.md Section 8 rule 1)
    # untouchable without the generator knowing its name.
    frozen = tmp_path / "demo"
    frozen.mkdir()
    (frozen / "assets.csv").write_text("precious,fixture\n", encoding="utf-8")
    with pytest.raises(gen.GenerationError, match="not safe to overwrite"):
        _run(snapshots, frozen)
    assert (frozen / "assets.csv").read_text(encoding="utf-8") == "precious,fixture\n"
    assert not (frozen / "findings.csv").exists()


def test_a_forged_marker_from_a_different_generator_is_not_trusted(snapshots: Path, tmp_path: Path):
    other = tmp_path / "other"
    other.mkdir()
    (other / gen.MARKER_NAME).write_text(json.dumps({"generator": "somebody-else"}), encoding="utf-8")
    (other / "assets.csv").write_text("x\n", encoding="utf-8")
    with pytest.raises(gen.GenerationError, match="not safe to overwrite"):
        _run(snapshots, other)


def test_it_may_overwrite_its_own_earlier_output(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    _run(snapshots, out, seed=1)
    first = (out / "findings.csv").read_bytes()
    _run(snapshots, out, seed=2)
    assert (out / "findings.csv").read_bytes() != first


def test_an_empty_existing_directory_is_fine(snapshots: Path, tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    _run(snapshots, out)
    assert (out / "assets.csv").is_file()


# ---- command line -----------------------------------------------------------


def test_cli_reports_success_with_exit_zero_and_refusal_with_exit_two(snapshots: Path, tmp_path: Path, capsys):
    out = tmp_path / "out"
    ok = gen.main([
        "--assets", "10", "--findings", "30", "--out", str(out), "--snapshots", str(snapshots),
    ])
    printed = capsys.readouterr().out
    assert ok == 0
    assert "Wrote 10 assets / 30 findings" in printed
    assert "KEV-listed findings" in printed

    bad = gen.main([
        "--assets", "1", "--findings", "999", "--out", str(tmp_path / "x"), "--snapshots", str(snapshots),
    ])
    assert bad == 2
    assert "cannot fit" in capsys.readouterr().err
