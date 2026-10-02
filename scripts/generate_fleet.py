"""Standalone generator for a fleet-scale, native-format dataset.

NOT part of the pytest suite and NOT wired into the CLI (the same convention
as `scripts/smoke_test.py`). Produces `assets.csv` + `findings.csv` in the
same shape as `data/demo/`, at whatever size is asked for -- hundreds to
thousands of findings -- so the scale defects CLAUDE.md Section 1 says must
be found and fixed ("no interface may assume demo scale") can be measured
against something bigger than the 24-finding fixture.

Design constraints, each inherited from CLAUDE.md rather than chosen here:

* **Offline and deterministic (Section 8 rule 2, Section 4).** The CVE pool is
  whatever `data/snapshots/` already holds an NVD record *and* an EPSS record
  for, discovered at runtime -- no CVE id appears in this file. So
  `rhino run --data <out> --offline` works with no network and no snapshot
  changes. Same arguments plus same snapshots gives byte-identical CSVs (a
  fixed `--as-of` date instead of "today"; a seeded `random.Random`; sorted
  iteration; `\\n` line endings, UTF-8, no BOM).
* **The demo fixture is frozen (Section 8 rule 1).** Output goes to a new
  directory (default `data/full`, gitignored). The generator refuses to write
  into a directory that already holds anything it did not itself generate: a
  directory is only ever overwritten if it carries this script's own
  `GENERATED.json` marker. There is no `--force`.
* **A scaffold, not the design (Section 1).** Nothing here is imported by
  `src/`; nothing in `src/` may learn that this data is synthetic.

What this does NOT exercise, on purpose: per-CVE enrichment fan-out. The pool
is only as large as the snapshot set (28 CVEs at the time of writing), so
this measures rows / assets / export size / UI / chat at scale, not "fetch 500
unique CVEs from NVD". That was decided separately (CLAUDE.md, 2026-09-25).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import random
import sys
from datetime import date, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from rhinosecure.enrich import kev, nvd  # noqa: E402
from rhinosecure.enrich.cache import DEFAULT_SNAPSHOT_DIR, OfflineCacheMissError, SnapshotCache  # noqa: E402

MARKER_NAME = "GENERATED.json"
GENERATOR_VERSION = 1

ASSET_COLUMNS = [
    "asset_id", "hostname", "os", "os_build", "role", "business_function", "criticality",
    "internet_exposed", "environment", "data_sensitivity", "patch_window", "patch_restrictions",
    "compensating_controls", "owner",
]
FINDING_COLUMNS = [
    "finding_id", "asset_id", "cve_id", "detected_date", "scanner_severity", "product", "version",
    "port", "service", "evidence",
]

# Tiers in descending order; a deliberate scanner/NVD disagreement moves a
# finding one step along this list, so it stays a plausible mis-call rather
# than an absurd one.
SEVERITY_TIERS = ["critical", "high", "medium", "low"]

SERVER_OSES = [("Windows Server 2016", "14393"), ("Windows Server 2019", "17763"), ("Windows Server 2022", "20348")]
SERVER_OS_WEIGHTS = [0.25, 0.45, 0.30]
CLIENT_OSES = [("Windows 10", "19045"), ("Windows 11", "22631")]
CLIENT_OS_WEIGHTS = [0.60, 0.40]

PATCH_WINDOWS = ["Sun 02:00-06:00", "Sat 22:00-02:00", "Wed 01:00-05:00"]
SERVER_CONTROLS = [
    "network isolated",
    "host firewall restricted to management VLAN",
    "application allowlisting",
    "WAF",
]
CLIENT_CONTROLS = ["EDR with exploit protection"]

# Fleet mix, and how much more findings-heavy a role is than a workstation.
# Servers carry many more findings each than a laptop does in a real scan, and
# a lognormal factor on top gives the long tail (a few assets with a great
# many findings) that a uniform spread would not.
ROLE_PROFILES = {
    "workstation": {
        "share": 0.70, "finding_weight": 1.0, "criticality": (1, 3), "exposed": 0.0,
        "sensitivity": (["none", "internal", "confidential"], [0.30, 0.55, 0.15]),
        "window": 0.10, "restriction": 0.05, "control": 0.10, "owner": "it-helpdesk",
        "function": "Employee workstation", "prefix": "WKS", "server": False,
    },
    "dev": {
        "share": 0.08, "finding_weight": 1.5, "criticality": (1, 2), "exposed": 0.02,
        "sensitivity": (["none", "internal"], [0.60, 0.40]),
        "window": 0.0, "restriction": 0.0, "control": 0.15, "owner": "dev-tools-team",
        "function": "Developer / lab machine", "prefix": "DEV", "server": False,
    },
    "file": {
        "share": 0.06, "finding_weight": 3.0, "criticality": (2, 4), "exposed": 0.0,
        "sensitivity": (["internal", "confidential", "regulated"], [0.35, 0.50, 0.15]),
        "window": 0.75, "restriction": 0.40, "control": 0.30, "owner": "infra-team",
        "function": "File server", "prefix": "FILE", "server": True,
    },
    "sql": {
        "share": 0.05, "finding_weight": 3.5, "criticality": (3, 5), "exposed": 0.02,
        "sensitivity": (["confidential", "regulated"], [0.55, 0.45]),
        "window": 0.80, "restriction": 0.50, "control": 0.35, "owner": "db-team",
        "function": "SQL Server", "prefix": "SQL", "server": True,
    },
    "iis_web": {
        "share": 0.06, "finding_weight": 3.0, "criticality": (3, 5), "exposed": 0.70,
        "sensitivity": (["none", "internal", "confidential"], [0.25, 0.50, 0.25]),
        "window": 0.70, "restriction": 0.30, "control": 0.40, "owner": "web-team",
        "function": "IIS web server", "prefix": "WEB", "server": True,
    },
    "exchange": {
        "share": 0.02, "finding_weight": 4.0, "criticality": (4, 5), "exposed": 0.50,
        "sensitivity": (["internal", "confidential"], [0.40, 0.60]),
        "window": 0.85, "restriction": 0.60, "control": 0.20, "owner": "messaging-team",
        "function": "Mail server", "prefix": "EXCH", "server": True,
    },
    "dc": {
        "share": 0.03, "finding_weight": 3.0, "criticality": (5, 5), "exposed": 0.0,
        "sensitivity": (["confidential", "regulated"], [0.30, 0.70]),
        "window": 0.90, "restriction": 0.70, "control": 0.10, "owner": "infra-team",
        "function": "Domain controller", "prefix": "DC", "server": True,
    },
}


class GenerationError(Exception):
    """A request this generator refuses rather than half-satisfies."""


def _weighted(rng: random.Random, options: list, weights: list):
    return rng.choices(options, weights=weights, k=1)[0]


def discover_cve_pool(snapshot_dir: Path) -> list[dict]:
    """Every CVE the snapshots can fully serve offline, sorted by id.

    A CVE qualifies only if BOTH its NVD and EPSS snapshots exist and NVD
    recorded a CVSS score for it -- otherwise `rhino run --offline` over the
    generated data would fail on it. Returns the NVD-derived severity and a
    best-effort product name (used only to make the evidence text read like a
    scanner's; nothing scores on it), and whether CISA lists it as KEV (used
    only to steer `--kev-share` and to report the realized share).
    """
    nvd_dir = snapshot_dir / "nvd"
    if not nvd_dir.is_dir():
        raise GenerationError(f"no NVD snapshot directory at {nvd_dir}")
    cache = SnapshotCache(snapshot_dir, offline=True)
    try:
        catalog = kev.load_catalog(cache)
    except OfflineCacheMissError as exc:
        raise GenerationError(f"the KEV snapshot is missing, so the pool cannot be classified: {exc}") from exc
    pool = []
    for path in sorted(nvd_dir.glob("*.json")):
        cve_id = path.stem
        if cache.read("epss", cve_id) is None:
            continue
        cvss = nvd.lookup(cve_id, cache)
        if cvss is None:
            continue
        severity = cvss.base_severity if cvss.base_severity in SEVERITY_TIERS else (
            "low" if cvss.base_score > 0 else "informational"
        )
        pool.append({
            "cve_id": cve_id, "severity": severity, "product": _product_of(cache.read("nvd", cve_id)),
            "kev": catalog.status(cve_id).is_listed,
        })
    if not pool:
        raise GenerationError(f"no CVE under {snapshot_dir} has both an NVD (with CVSS) and an EPSS snapshot")
    return pool


def _product_of(entry) -> str:
    try:
        cve = entry.payload["vulnerabilities"][0]["cve"]
        return cve["affected"][0]["affectedData"][0]["product"] or "Microsoft Windows"
    except (KeyError, IndexError, TypeError):
        return "Microsoft Windows"


def _allocate_findings(rng: random.Random, weights: list[float], total: int, cap: int) -> list[int]:
    """Split `total` findings across assets in proportion to `weights`, with
    no asset holding more than `cap` (an asset can only have each CVE once).
    Largest-remainder rounding, ties broken by asset index, so the split is a
    pure function of its inputs."""
    n = len(weights)
    weight_sum = sum(weights)
    raw = [total * w / weight_sum for w in weights]
    counts = [math.floor(r) for r in raw]
    order = sorted(range(n), key=lambda i: (-(raw[i] - counts[i]), i))
    for i in order[: total - sum(counts)]:
        counts[i] += 1
    excess = sum(max(0, c - cap) for c in counts)
    counts = [min(c, cap) for c in counts]
    while excess:
        room = sorted((i for i in range(n) if counts[i] < cap), key=lambda i: (-weights[i], i))
        if not room:
            # Unreachable while `build_fleet` checks capacity first; kept so a
            # future caller that skips that check gets a refusal, not a hang.
            raise GenerationError(f"internal: {excess} findings have no asset with room left (cap {cap} each)")
        for i in room:
            if not excess:
                break
            counts[i] += 1
            excess -= 1
    return counts


def _pick_cves(rng: random.Random, pool: list[dict], count: int, kev_share: float | None) -> list[dict]:
    """`count` distinct CVEs for one asset. With no `kev_share` this is a
    plain uniform sample. With one, each slot is KEV with that probability,
    falling back to the other side only when this asset has exhausted it --
    so the request is always satisfiable and the fleet-wide share converges to
    the target instead of being an accident of how the pool happens to be
    composed."""
    if kev_share is None:
        return rng.sample(pool, count)
    kev_left = [c for c in pool if c["kev"]]
    other_left = [c for c in pool if not c["kev"]]
    chosen = []
    for _ in range(count):
        want_kev = rng.random() < kev_share
        side = kev_left if (want_kev and kev_left) or not other_left else other_left
        chosen.append(side.pop(rng.randrange(len(side))))
    return chosen


def build_fleet(
    *, assets: int, findings: int, seed: int, as_of: date, disagreement_rate: float, pool: list[dict],
    kev_share: float | None = None,
) -> tuple[list[dict], list[dict]]:
    if assets < 1 or findings < 1:
        raise GenerationError("--assets and --findings must both be at least 1")
    if not 0.0 <= disagreement_rate <= 1.0:
        raise GenerationError("--severity-disagreement-rate must be between 0 and 1")
    if kev_share is not None:
        if not 0.0 <= kev_share <= 1.0:
            raise GenerationError("--kev-share must be between 0 and 1")
        if not any(c["kev"] for c in pool) or all(c["kev"] for c in pool):
            raise GenerationError(
                "--kev-share needs a pool with both KEV-listed and non-KEV CVEs; "
                f"this snapshot set has {sum(c['kev'] for c in pool)} KEV of {len(pool)}."
            )
    # An asset can carry each CVE at most once, so this is the most findings
    # any one asset can hold. A stated KEV share tightens it to the smaller of
    # the two sides: with that bound neither side can run out partway through
    # an asset, so the target is met instead of being quietly overridden by
    # the fallback in `_pick_cves`.
    kev_n = sum(c["kev"] for c in pool)
    per_asset_cap = len(pool)
    if kev_share is not None:
        per_asset_cap = kev_n if kev_share >= 1.0 else (len(pool) - kev_n) if kev_share <= 0.0 else min(kev_n, len(pool) - kev_n)
    if findings > assets * per_asset_cap:
        why = (
            f"each asset can carry each CVE once, so at most {per_asset_cap} findings per asset"
            + (f" with --kev-share {kev_share} (the smaller of {kev_n} KEV / {len(pool) - kev_n} non-KEV CVEs)"
               if kev_share is not None else "")
        )
        raise GenerationError(
            f"{findings} findings cannot fit on {assets} assets from a pool of {len(pool)} CVEs "
            f"({why}, so at most {assets * per_asset_cap} in total). Raise --assets or lower --findings."
        )

    rng = random.Random(seed)
    roles = list(ROLE_PROFILES)
    role_shares = [ROLE_PROFILES[r]["share"] for r in roles]
    id_width = max(4, len(str(assets)))
    finding_width = max(5, len(str(findings)))

    asset_rows: list[dict] = []
    asset_weights: list[float] = []
    per_role_seq = {r: 0 for r in roles}
    for index in range(1, assets + 1):
        role = _weighted(rng, roles, role_shares)
        prof = ROLE_PROFILES[role]
        per_role_seq[role] += 1
        oses, os_weights = (SERVER_OSES, SERVER_OS_WEIGHTS) if prof["server"] else (CLIENT_OSES, CLIENT_OS_WEIGHTS)
        os_name, os_build = _weighted(rng, oses, os_weights)
        if role == "dev":
            environment = _weighted(rng, ["dev", "staging"], [0.7, 0.3])
        elif role == "workstation":
            environment = "prod"
        else:
            environment = _weighted(rng, ["prod", "staging", "dev"], [0.85, 0.10, 0.05])
        lo, hi = prof["criticality"]
        sensitivity, sens_weights = prof["sensitivity"]
        controls = SERVER_CONTROLS if prof["server"] else CLIENT_CONTROLS
        asset_rows.append({
            "asset_id": f"A{index:0{id_width}d}",
            "hostname": f"{prof['prefix']}{per_role_seq[role]:0{id_width}d}",
            "os": os_name,
            "os_build": os_build,
            "role": role,
            "business_function": prof["function"],
            "criticality": rng.randint(lo, hi),
            "internet_exposed": rng.random() < prof["exposed"],
            "environment": environment,
            "data_sensitivity": _weighted(rng, sensitivity, sens_weights),
            "patch_window": rng.choice(PATCH_WINDOWS) if rng.random() < prof["window"] else "",
            "patch_restrictions": "no reboot during business hours" if rng.random() < prof["restriction"] else "",
            "compensating_controls": rng.choice(controls) if rng.random() < prof["control"] else "",
            "owner": prof["owner"],
        })
        asset_weights.append(prof["finding_weight"] * rng.lognormvariate(0.0, 0.6))

    counts = _allocate_findings(rng, asset_weights, findings, cap=per_asset_cap)

    finding_rows: list[dict] = []
    seq = 0
    for asset, count in zip(asset_rows, counts):
        for cve in _pick_cves(rng, pool, count, kev_share):
            seq += 1
            severity = cve["severity"]
            if severity in SEVERITY_TIERS and rng.random() < disagreement_rate:
                at = SEVERITY_TIERS.index(severity)
                candidates = [i for i in (at - 1, at + 1) if 0 <= i < len(SEVERITY_TIERS)]
                severity = SEVERITY_TIERS[rng.choice(candidates)]
            finding_rows.append({
                "finding_id": f"F{seq:0{finding_width}d}",
                "asset_id": asset["asset_id"],
                "cve_id": cve["cve_id"],
                "detected_date": (as_of - timedelta(days=rng.randint(0, 90))).isoformat(),
                "scanner_severity": severity,
                "product": cve["product"],
                "version": "",
                "port": "",
                "service": "",
                "evidence": f"Detected by scheduled credentialed scan: {cve['product']}",
            })
    return asset_rows, finding_rows


def _render_csv(columns: list[str], rows: list[dict]) -> bytes:
    """The exact bytes written -- rendered in memory first so the marker's
    hashes describe precisely what is on disk, and so 'same inputs, same
    bytes' does not depend on file-system behavior."""
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: ("True" if v is True else "False" if v is False else v) for k, v in row.items()})
    return buffer.getvalue().encode("utf-8")


def _guard_output_dir(out: Path) -> None:
    """Only ever write into somewhere that is empty/new or holds this
    script's own earlier output. This is what keeps the frozen fixture
    (Section 8 rule 1) out of reach without a hard-coded list of names."""
    if not out.exists():
        return
    if not out.is_dir():
        raise GenerationError(f"{out} exists and is not a directory")
    if not any(out.iterdir()):
        return
    marker = out / MARKER_NAME
    if marker.is_file():
        try:
            if json.loads(marker.read_text(encoding="utf-8")).get("generator") == "scripts/generate_fleet.py":
                return
        except (OSError, ValueError):
            pass
    raise GenerationError(
        f"{out} is not empty and has no valid {MARKER_NAME} from this generator, so it is not "
        "safe to overwrite (this is what protects data/demo, the frozen fixture). "
        "Pick a new --out directory."
    )


def generate(
    *,
    out: Path,
    assets: int,
    findings: int,
    seed: int,
    as_of: date,
    disagreement_rate: float,
    snapshot_dir: Path,
    kev_share: float | None = None,
) -> dict:
    """Write the dataset and return the marker dict that was written."""
    _guard_output_dir(out)
    pool = discover_cve_pool(snapshot_dir)
    asset_rows, finding_rows = build_fleet(
        assets=assets, findings=findings, seed=seed, as_of=as_of,
        disagreement_rate=disagreement_rate, pool=pool, kev_share=kev_share,
    )
    kev_by_cve = {c["cve_id"]: c["kev"] for c in pool}
    realized_kev = sum(kev_by_cve[f["cve_id"]] for f in finding_rows) / len(finding_rows)
    assets_bytes = _render_csv(ASSET_COLUMNS, asset_rows)
    findings_bytes = _render_csv(FINDING_COLUMNS, finding_rows)
    marker = {
        "generator": "scripts/generate_fleet.py",
        "generator_version": GENERATOR_VERSION,
        "params": {
            "assets": assets, "findings": findings, "seed": seed, "as_of": as_of.isoformat(),
            "severity_disagreement_rate": disagreement_rate, "kev_share": kev_share,
        },
        "realized_kev_share": round(realized_kev, 4),
        "cve_pool": [c["cve_id"] for c in pool],
        "files": {
            "assets.csv": "sha256:" + hashlib.sha256(assets_bytes).hexdigest(),
            "findings.csv": "sha256:" + hashlib.sha256(findings_bytes).hexdigest(),
        },
        "note": "Synthetic scale fixture. Not the frozen demo dataset (CLAUDE.md Section 8 rule 1).",
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "assets.csv").write_bytes(assets_bytes)
    (out / "findings.csv").write_bytes(findings_bytes)
    (out / MARKER_NAME).write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return marker


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a seeded, offline-runnable, fleet-scale native-format dataset.",
    )
    parser.add_argument("--assets", type=int, required=True, help="number of assets to generate")
    parser.add_argument("--findings", type=int, required=True, help="total findings across all assets")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed (default 42, CLAUDE.md Section 8 rule 3)")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "data" / "full", help="output directory (default data/full)")
    parser.add_argument("--as-of", type=date.fromisoformat, default=date(2026, 9, 1),
                        help="date findings are detected relative to, ISO format (default 2026-09-01); fixed, never 'today', so output is reproducible")
    parser.add_argument("--severity-disagreement-rate", type=float, default=0.125,
                        help="fraction of findings whose scanner severity is one tier off NVD's (default 0.125, CLAUDE.md Section 3)")
    parser.add_argument("--kev-share", type=float, default=None,
                        help="target fraction of findings whose CVE is CISA-KEV-listed. Default: none (uniform over the "
                             "snapshot pool, which is mostly famous KEV anchor CVEs -- so KEV-heavy; the realized share "
                             "is always printed). Real fleets are far lower, and every KEV-driven quantity (contested "
                             "rate, patch_now count) moves with it")
    parser.add_argument("--snapshots", type=Path, default=DEFAULT_SNAPSHOT_DIR, help="snapshot directory the CVE pool is read from")
    args = parser.parse_args(argv)

    try:
        marker = generate(
            out=args.out, assets=args.assets, findings=args.findings, seed=args.seed,
            as_of=args.as_of, disagreement_rate=args.severity_disagreement_rate, snapshot_dir=args.snapshots,
            kev_share=args.kev_share,
        )
    except GenerationError as exc:
        print(f"generate_fleet: {exc}", file=sys.stderr)
        return 2

    print(f"Wrote {args.assets} assets / {args.findings} findings to {args.out}")
    print(f"  CVE pool: {len(marker['cve_pool'])} snapshotted CVEs (offline-runnable)")
    print(f"  KEV-listed findings: {marker['realized_kev_share']:.1%}"
          + ("" if args.kev_share is not None else "  (uniform over pool; use --kev-share for a stated rate)"))
    for name, digest in marker["files"].items():
        print(f"  {name}  {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
