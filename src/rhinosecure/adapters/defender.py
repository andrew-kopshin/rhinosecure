"""Microsoft Defender Vulnerability Management (MDVM) ingest adapter.

Reads two CSV files, each an export of one advanced-hunting table Microsoft
documents for the Defender portal (Defender XDR > Advanced hunting > Export,
or the same tables via the streaming API):

    devices.csv          <- DeviceInfo
    vulnerabilities.csv  <- DeviceTvmSoftwareVulnerabilities

Column names are the tables' own, verbatim and case-sensitive, from
https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table
and https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table
(both checked 2026-09-03). The optional finding columns come from the
per-device assessment export (`/api/machines/SoftwareVulnerabilitiesByMachine`,
https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities),
which flattens to the same required columns plus FirstSeenTimestamp,
DiskPaths, RegistryPaths, and friends -- a CSV made from it works here too.
Columns not named below are ignored. A file missing a required column is
refused as "not this export" with the columns it did have listed, so a
portal-grid export (display names like "Device name") or a Qualys file
fails at the header, not halfway through the rows.

Mapping
-------
Asset (from DeviceInfo)
  asset_id          <- DeviceId              required, blank is fatal
  hostname          <- DeviceName (FQDN)     required, blank is fatal
  os, OS class      <- OSPlatform            required; must be a key of OS_PLATFORMS
  os_build          <- OSBuild               required column; blank cell -> not collected
  internet_exposed  <- IsInternetFacing      required column; blank cell -> not collected
  criticality       <- AssetValue            required column; Low/Normal/High -> 1/3/5,
                                             blank cell -> not collected
  role              <- (none)                not collected; defaulted by OS class
  environment, data_sensitivity, business_function, owner, patch_window,
  patch_restrictions, compensating_controls
                    <- (none)                not collected -- Defender has no such fields.
                                             DeviceInfo's own `DeviceRoles` (JSON, undocumented
                                             vocabulary) and `DeviceManualTags` are the natural
                                             future sources for role/environment; not read.
  Timestamp                                  optional; when present, the latest row per
                                             DeviceId wins (DeviceInfo is a snapshot table, one
                                             row per report -- Microsoft's own sample query is
                                             `summarize arg_max(Timestamp, *) by DeviceId`)

Finding (from DeviceTvmSoftwareVulnerabilities)
  finding_id        <- MDVM-<16 hex of sha256(DeviceId, SoftwareVendor, SoftwareName,
                       SoftwareVersion, CveId)> -- Microsoft's own documented uniqueness key
                       for a per-device vulnerability record. Defender exports no stable
                       per-finding id of its own, so this one is content-addressed: the same
                       finding gets the same id across exports (memory.py's decisions table
                       keys on it)
  asset_id          <- DeviceId              required, blank is fatal
  cve_id            <- CveId                 required; must look like CVE-YYYY-NNNN (upper-cased)
  scanner_severity  <- VulnerabilitySeverityLevel  required; Critical/High/Medium/Low
  product           <- SoftwareName          required, blank is fatal
  version           <- SoftwareVersion       required column; blank cell -> not collected
  detected_date     <- FirstSeenTimestamp    optional column (per-device assessment export
                                             only; the hunting table has no timestamp);
                                             absent/blank -> not collected
  evidence          <- SoftwareVendor, RecommendedSecurityUpdate(Id), DiskPaths, RegistryPaths
                       (whichever are present), composed verbatim
  port, service     <- (none)                not collected -- Defender is agent-based and
                                             never observes a listening port

Messy realities, and what each one does
---------------------------------------
- Missing columns: AdapterError at the header, listing missing and found.
- Missing cells: fatal for identity columns (nothing to key the record on);
  every other blank becomes that field's documented default and the field
  name goes into `not_collected` (adapters/base.py) -- the row is kept, the
  gap is recorded, nothing is invented.
- Devices with two rows (DeviceInfo is per-report): identical rows collapse;
  differing rows collapse to the latest `Timestamp` when the column is
  present; differing rows with no Timestamp to order them are a conflict
  and refused.
- Non-Windows or unrecognized OSPlatform: refused, with every offending
  device listed. CLAUDE.md Section 2 scopes the fleet to Windows; a macOS
  or Linux device is not a messy reality to smooth over but out of scope,
  and silently dropping it would hide from the operator that part of the
  fleet went unscored. Filter the export to Windows platforms instead.
- Findings whose DeviceId is not in devices.csv: refused, every orphaned
  device listed with its finding count. A finding cannot be scored without
  its asset context, and a plan that quietly omits findings is exactly the
  thing this project refuses to produce. Re-export DeviceInfo to cover them.
- Duplicate findings: identity is Microsoft's uniqueness key above. Rows
  with the same identity and the same severity and first-seen date are
  duplicates -- collapsed, counted in `stats`, the first row's evidence
  kept. Same identity with a different severity or date is a conflict and
  refused: two claims about one finding, no way to pick one without
  guessing.
- Non-CVE advisory ids: refused. Enrichment (NVD/KEV/EPSS) is keyed by CVE,
  so a row without one cannot be scored; filter it out of the export.
- UTF-8 BOM (Excel and PowerShell both write one): tolerated.

Two passes over vulnerabilities.csv
-----------------------------------
`load_findings` reads the file twice: a validation pass that yields nothing
and collects every problem above (bounded memory -- it keeps one digest per
distinct finding, never a row), then the yielding pass. One pass would have
to either raise on the first bad row (the operator fixes 40 problems one
rerun at a time) or yield good rows before discovering a bad one (the run
has already spent NVD/EPSS lookups on a batch it is about to abort). The
second read of a CSV costs far less than either.
"""

from __future__ import annotations

import csv
import hashlib
import re
from collections import Counter
from collections.abc import Collection, Iterator
from datetime import date, datetime, timezone
from pathlib import Path
from typing import IO

from pydantic import ValidationError

from rhinosecure.adapters.base import (
    NOT_COLLECTED_DEFAULTS,
    ROLE_DEFAULT_BY_OS_CLASS,
    AdapterError,
    IngestAdapter,
)
from rhinosecure.schema import Asset, Finding

DEVICE_COLUMNS_REQUIRED = ("DeviceId", "DeviceName", "OSPlatform", "OSBuild", "IsInternetFacing", "AssetValue")
DEVICE_COLUMNS_OPTIONAL = ("Timestamp",)
VULNERABILITY_COLUMNS_REQUIRED = ("DeviceId", "CveId", "VulnerabilitySeverityLevel", "SoftwareName", "SoftwareVersion")
VULNERABILITY_COLUMNS_OPTIONAL = (
    "SoftwareVendor",
    "RecommendedSecurityUpdate",
    "RecommendedSecurityUpdateId",
    "FirstSeenTimestamp",
    "DiskPaths",
    "RegistryPaths",
)

# OSPlatform -> (native `os` string, OS class for ROLE_DEFAULT_BY_OS_CLASS).
# Anything not listed is refused, not mapped to the nearest neighbour.
OS_PLATFORMS: dict[str, tuple[str, str]] = {
    "Windows7": ("Windows 7", "client"),
    "Windows8.1": ("Windows 8.1", "client"),
    "Windows10": ("Windows 10", "client"),
    "Windows11": ("Windows 11", "client"),
    "WindowsServer2008R2": ("Windows Server 2008 R2", "server"),
    "WindowsServer2012": ("Windows Server 2012", "server"),
    "WindowsServer2012R2": ("Windows Server 2012 R2", "server"),
    "WindowsServer2016": ("Windows Server 2016", "server"),
    "WindowsServer2019": ("Windows Server 2019", "server"),
    "WindowsServer2022": ("Windows Server 2022", "server"),
    "WindowsServer2025": ("Windows Server 2025", "server"),
}

# AssetValue is Defender's own three-tier asset-importance input to its
# exposure score ("Low, Normal (Default), High"); mapped monotonically onto
# the schema's 1-5 criticality, ends to ends.
ASSET_VALUE_TO_CRITICALITY: dict[str, int] = {"low": 1, "normal": 3, "high": 5}
SEVERITY_LEVELS = frozenset({"critical", "high", "medium", "low"})
_TRUE = frozenset({"true", "yes", "1"})
_FALSE = frozenset({"false", "no", "0"})

# Schema fields Defender has no concept of, on every record of the format.
ASSET_FIELDS_NEVER_EXPORTED = frozenset(
    {
        "role",
        "business_function",
        "environment",
        "data_sensitivity",
        "patch_window",
        "patch_restrictions",
        "compensating_controls",
        "owner",
    }
)
FINDING_FIELDS_NEVER_EXPORTED = frozenset({"port", "service"})

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ISO_DATE_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2})")
_FRACTIONAL_SECONDS = re.compile(r"(\.\d{1,6})\d*")

MAX_PROBLEMS_SHOWN = 25
FINDING_ID_PREFIX = "MDVM-"
FINDING_ID_HEX_LEN = 16


class _Problems:
    """Collects every problem in a file so one AdapterError can list them
    all (bounded to MAX_PROBLEMS_SHOWN in the message, full count kept)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.items: list[str] = []

    def add(self, message: str) -> None:
        self.items.append(message)

    def raise_if_any(self, what: str) -> None:
        if not self.items:
            return
        shown = self.items[:MAX_PROBLEMS_SHOWN]
        hidden = len(self.items) - len(shown)
        lines = [f"{self.path}: {len(self.items)} problem(s) in {what}; refusing to guess:"]
        lines += [f"  - {item}" for item in shown]
        if hidden:
            lines.append(f"  ... and {hidden} more")
        raise AdapterError("\n".join(lines))


def _open_csv(path: Path) -> tuple[IO[str], csv.DictReader]:
    f = path.open(newline="", encoding="utf-8-sig")  # -sig: strip a BOM if Excel/PowerShell wrote one
    return f, csv.DictReader(f)


def _require_columns(path: Path, reader: csv.DictReader, required: tuple[str, ...], what: str) -> None:
    found = list(reader.fieldnames or [])
    missing = [c for c in required if c not in found]
    if missing:
        raise AdapterError(
            f"{path}: not a {what} export -- missing required column(s) {missing}; "
            f"found columns: {found or '(none -- empty file?)'}"
        )


def _parse_timestamp(text: str) -> datetime | None:
    """ISO 8601 as Defender writes it (`2024-01-15T10:22:31.1234567Z` from
    advanced hunting, `2020-11-03 10:13:34.8476880` from the assessment
    API -- seven fractional digits either way). Returns None when
    unparsable. Naive values are taken as UTC -- Defender exports are --
    purely to make rows orderable; the value is never stored."""
    t = text.strip()
    if t.endswith(("Z", "z")):
        t = t[:-1] + "+00:00"
    t = _FRACTIONAL_SECONDS.sub(r"\1", t, count=1)
    try:
        parsed = datetime.fromisoformat(t)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_date_prefix(text: str) -> str | None:
    """`YYYY-MM-DD` from the front of an ISO 8601 timestamp, validated as a
    real calendar date. None when it isn't one."""
    match = _ISO_DATE_PREFIX.match(text.strip())
    if match is None:
        return None
    try:
        return date.fromisoformat(match.group(1)).isoformat()
    except ValueError:
        return None


def _finding_identity(
    device_id: str, vendor: str, software_name: str, software_version: str, cve_id: str
) -> tuple[str, str]:
    """(full digest, finding_id). The full digest is the dedup key; the id
    is its 16-hex prefix -- 64 bits, which keeps accidental collisions
    negligible at fleet scale, and load_findings still checks for one."""
    identity = "\x1f".join((device_id, vendor, software_name, software_version, cve_id))
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return digest, FINDING_ID_PREFIX + digest[:FINDING_ID_HEX_LEN].upper()


class DefenderAdapter(IngestAdapter):
    format = "defender"
    assets_filename = "devices.csv"
    findings_filename = "vulnerabilities.csv"

    # --- assets ---------------------------------------------------------

    def load_assets(self, path: Path) -> Iterator[Asset]:
        """Consumes the whole file before yielding: the latest-Timestamp-wins
        rule for repeated DeviceIds can't be applied on a stream, and the
        inventory is the small, indexed side anyway (see IngestAdapter)."""
        self.stats.duplicate_assets_collapsed = 0
        problems = _Problems(path)
        latest: dict[str, tuple[datetime | None, Asset, int]] = {}
        order: list[str] = []

        f, reader = _open_csv(path)
        with f:
            _require_columns(path, reader, DEVICE_COLUMNS_REQUIRED, "DeviceInfo")
            has_timestamp = "Timestamp" in (reader.fieldnames or [])
            for row_no, row in enumerate(reader, start=2):
                mapped = self._map_device(row, row_no, problems, has_timestamp)
                if mapped is None:
                    continue
                asset, stamp = mapped
                prior = latest.get(asset.asset_id)
                if prior is None:
                    latest[asset.asset_id] = (stamp, asset, row_no)
                    order.append(asset.asset_id)
                    continue
                prior_stamp, prior_asset, prior_row = prior
                if asset == prior_asset:
                    self.stats.duplicate_assets_collapsed += 1
                elif stamp is not None and prior_stamp is not None and stamp != prior_stamp:
                    self.stats.duplicate_assets_collapsed += 1
                    if stamp > prior_stamp:
                        latest[asset.asset_id] = (stamp, asset, row_no)
                else:
                    problems.add(
                        f"row {row_no} ({asset.hostname}): DeviceId {asset.asset_id!r} also appears on row "
                        f"{prior_row} with different values and no later Timestamp to prefer -- "
                        "summarize the export to one row per device (arg_max(Timestamp, *) by DeviceId)"
                    )
        problems.raise_if_any("DeviceInfo export")
        for device_id in order:
            yield latest[device_id][1]

    def _map_device(
        self, row: dict[str, str], row_no: int, problems: _Problems, has_timestamp: bool
    ) -> tuple[Asset, datetime | None] | None:
        device_id = (row.get("DeviceId") or "").strip()
        hostname = (row.get("DeviceName") or "").strip()
        platform = (row.get("OSPlatform") or "").strip()
        blank_identity = [
            c for c, v in (("DeviceId", device_id), ("DeviceName", hostname), ("OSPlatform", platform)) if not v
        ]
        if blank_identity:
            problems.add(f"row {row_no}: blank identity column(s) {blank_identity} -- nothing to key this device on")
            return None
        if platform not in OS_PLATFORMS:
            problems.add(
                f"row {row_no} ({hostname}): OSPlatform {platform!r} is not a Windows platform this adapter "
                f"maps (known: {sorted(OS_PLATFORMS)}); filter the export to Windows devices or extend OS_PLATFORMS"
            )
            return None
        os_name, os_class = OS_PLATFORMS[platform]
        not_collected = set(ASSET_FIELDS_NEVER_EXPORTED)

        os_build = (row.get("OSBuild") or "").strip()
        if not os_build:
            not_collected.add("os_build")

        exposed_raw = (row.get("IsInternetFacing") or "").strip().lower()
        if exposed_raw == "":
            internet_exposed = bool(NOT_COLLECTED_DEFAULTS["internet_exposed"])
            not_collected.add("internet_exposed")
        elif exposed_raw in _TRUE:
            internet_exposed = True
        elif exposed_raw in _FALSE:
            internet_exposed = False
        else:
            problems.add(f"row {row_no} ({hostname}): IsInternetFacing {row['IsInternetFacing']!r} is not a boolean")
            return None

        value_raw = (row.get("AssetValue") or "").strip().lower()
        if value_raw == "":
            criticality = int(NOT_COLLECTED_DEFAULTS["criticality"])
            not_collected.add("criticality")
        elif value_raw in ASSET_VALUE_TO_CRITICALITY:
            criticality = ASSET_VALUE_TO_CRITICALITY[value_raw]
        else:
            problems.add(
                f"row {row_no} ({hostname}): AssetValue {row['AssetValue']!r} is not one of "
                f"{sorted(ASSET_VALUE_TO_CRITICALITY)}"
            )
            return None

        stamp: datetime | None = None
        if has_timestamp:
            stamp_raw = (row.get("Timestamp") or "").strip()
            if stamp_raw:
                stamp = _parse_timestamp(stamp_raw)
                if stamp is None:
                    problems.add(f"row {row_no} ({hostname}): Timestamp {stamp_raw!r} is not ISO 8601")
                    return None

        try:
            asset = Asset(
                asset_id=device_id,
                hostname=hostname,
                os=os_name,
                os_build=os_build,
                role=ROLE_DEFAULT_BY_OS_CLASS[os_class],
                business_function=str(NOT_COLLECTED_DEFAULTS["business_function"]),
                criticality=criticality,
                internet_exposed=internet_exposed,
                environment=str(NOT_COLLECTED_DEFAULTS["environment"]),
                data_sensitivity=str(NOT_COLLECTED_DEFAULTS["data_sensitivity"]),
                patch_window=str(NOT_COLLECTED_DEFAULTS["patch_window"]),
                patch_restrictions=str(NOT_COLLECTED_DEFAULTS["patch_restrictions"]),
                compensating_controls=str(NOT_COLLECTED_DEFAULTS["compensating_controls"]),
                owner=str(NOT_COLLECTED_DEFAULTS["owner"]),
                not_collected=frozenset(not_collected),
            )
        except ValidationError as exc:
            problems.add(f"row {row_no} ({hostname}): {exc}")
            return None
        return asset, stamp

    # --- findings -------------------------------------------------------

    def load_findings(self, path: Path, asset_ids: Collection[str]) -> Iterator[Finding]:
        self.stats.duplicate_findings_collapsed = 0
        self._validate_findings(path, asset_ids)

        yielded: set[str] = set()
        f, reader = _open_csv(path)
        with f:
            has_first_seen = "FirstSeenTimestamp" in (reader.fieldnames or [])
            for row_no, row in enumerate(reader, start=2):
                mapped = self._map_vulnerability(row, row_no, _Problems(path), has_first_seen)
                assert mapped is not None  # the validation pass already refused anything unmappable
                digest, _content, finding = mapped
                if digest in yielded:
                    self.stats.duplicate_findings_collapsed += 1
                    continue
                yielded.add(digest)
                yield finding

    def _validate_findings(self, path: Path, asset_ids: Collection[str]) -> None:
        """The yield-nothing pass -- see the module docstring. Memory is one
        (digest -> content, row) entry per distinct finding plus one
        (finding_id -> digest) entry, never a Finding object."""
        problems = _Problems(path)
        orphans: Counter[str] = Counter()
        seen: dict[str, tuple[tuple[str, str], int]] = {}
        ids: dict[str, str] = {}

        f, reader = _open_csv(path)
        with f:
            _require_columns(path, reader, VULNERABILITY_COLUMNS_REQUIRED, "DeviceTvmSoftwareVulnerabilities")
            has_first_seen = "FirstSeenTimestamp" in (reader.fieldnames or [])
            for row_no, row in enumerate(reader, start=2):
                mapped = self._map_vulnerability(row, row_no, problems, has_first_seen)
                if mapped is None:
                    continue
                digest, content, finding = mapped
                if finding.asset_id not in asset_ids:
                    orphans[finding.asset_id] += 1
                    continue
                prior = seen.get(digest)
                if prior is None:
                    seen[digest] = (content, row_no)
                    if ids.setdefault(finding.finding_id, digest) != digest:
                        problems.add(
                            f"row {row_no}: finding_id {finding.finding_id} collides with a different finding "
                            "-- raise FINDING_ID_HEX_LEN"
                        )
                elif prior[0] != content:
                    problems.add(
                        f"row {row_no}: conflicts with row {prior[1]} -- same DeviceId/SoftwareVendor/"
                        f"SoftwareName/SoftwareVersion/CveId but different VulnerabilitySeverityLevel or "
                        f"FirstSeenTimestamp ({prior[0]} vs {content})"
                    )
        if orphans:
            listed = ", ".join(f"{d} ({n} finding(s))" for d, n in sorted(orphans.items())[:MAX_PROBLEMS_SHOWN])
            more = len(orphans) - min(len(orphans), MAX_PROBLEMS_SHOWN)
            problems.add(
                f"{sum(orphans.values())} finding row(s) reference {len(orphans)} DeviceId(s) absent from "
                f"{self.assets_filename}: {listed}{f', ... and {more} more' if more else ''} -- a finding "
                "cannot be scored without its asset context; re-export DeviceInfo to cover these devices "
                "or filter the vulnerabilities export to the inventory"
            )
        problems.raise_if_any("DeviceTvmSoftwareVulnerabilities export")

    def _map_vulnerability(
        self, row: dict[str, str], row_no: int, problems: _Problems, has_first_seen: bool
    ) -> tuple[str, tuple[str, str], Finding] | None:
        device_id = (row.get("DeviceId") or "").strip()
        cve_id = (row.get("CveId") or "").strip().upper()
        severity = (row.get("VulnerabilitySeverityLevel") or "").strip().lower()
        vendor = (row.get("SoftwareVendor") or "").strip()
        software_name = (row.get("SoftwareName") or "").strip()
        software_version = (row.get("SoftwareVersion") or "").strip()
        blank_identity = [
            c for c, v in (("DeviceId", device_id), ("CveId", cve_id), ("SoftwareName", software_name)) if not v
        ]
        if blank_identity:
            problems.add(f"row {row_no}: blank identity column(s) {blank_identity} -- nothing to key this finding on")
            return None
        if not _CVE_ID.match(cve_id):
            problems.add(
                f"row {row_no}: CveId {row['CveId']!r} is not a CVE identifier -- NVD/KEV/EPSS enrichment "
                "is keyed by CVE, so a non-CVE advisory cannot be scored; filter it out of the export"
            )
            return None
        if severity not in SEVERITY_LEVELS:
            problems.add(
                f"row {row_no} ({cve_id}): VulnerabilitySeverityLevel {row['VulnerabilitySeverityLevel']!r} "
                f"is not one of {sorted(SEVERITY_LEVELS)}"
            )
            return None

        not_collected = set(FINDING_FIELDS_NEVER_EXPORTED)
        if not software_version:
            not_collected.add("version")

        detected_date = str(NOT_COLLECTED_DEFAULTS["detected_date"])
        first_seen_raw = (row.get("FirstSeenTimestamp") or "").strip() if has_first_seen else ""
        if first_seen_raw:
            parsed = _parse_date_prefix(first_seen_raw)
            if parsed is None:
                problems.add(f"row {row_no} ({cve_id}): FirstSeenTimestamp {first_seen_raw!r} is not ISO 8601")
                return None
            detected_date = parsed
        else:
            not_collected.add("detected_date")

        digest, finding_id = _finding_identity(device_id, vendor, software_name, software_version, cve_id)
        try:
            finding = Finding(
                finding_id=finding_id,
                asset_id=device_id,
                cve_id=cve_id,
                detected_date=detected_date,
                scanner_severity=severity,
                product=software_name,
                version=software_version,
                port=str(NOT_COLLECTED_DEFAULTS["port"]),
                service=str(NOT_COLLECTED_DEFAULTS["service"]),
                evidence=_evidence(row, vendor, software_name, software_version),
                not_collected=frozenset(not_collected),
            )
        except ValidationError as exc:
            problems.add(f"row {row_no} ({cve_id}): {exc}")
            return None
        return digest, (severity, detected_date), finding


def _evidence(row: dict[str, str], vendor: str, software_name: str, software_version: str) -> str:
    """Defender's detection note, composed verbatim from whichever
    evidence-bearing columns the export carries. Free text from an external
    source -- untrusted, per CLAUDE.md's open prompt-injection item."""
    parts = [f"Defender MDVM: {' '.join(p for p in (vendor, software_name, software_version) if p)}"]
    update = (row.get("RecommendedSecurityUpdate") or "").strip()
    update_id = (row.get("RecommendedSecurityUpdateId") or "").strip()
    if update or update_id:
        parts.append(f"recommended update: {update}{f' ({update_id})' if update_id else ''}".strip())
    for label, column in (("disk", "DiskPaths"), ("registry", "RegistryPaths")):
        value = (row.get(column) or "").strip()
        if value:
            parts.append(f"{label}: {value}")
    return "; ".join(parts)
