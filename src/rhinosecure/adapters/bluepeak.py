"""BluePeak Technologies (fictional) pre-enriched CSV ingest adapter.

One flat file, `synthetic_cve_inventory_50.csv` -- a finding per row, with
the row's own asset carried inline (Asset_ID, Asset_Hostname, Asset_Type,
Department, Environment, Asset_Criticality, Internet_Exposed) rather than a
separate inventory file. `assets_filename` and `findings_filename` are the
same string on purpose: `adapters.base.IngestAdapter`'s docstring and
`ingest._require_adapter_files`'s own `dict.fromkeys` dedup were written to
allow exactly this shape, so this adapter is not a workaround for the
contract -- it is the case it was designed for. `load_assets` and
`load_findings` each make their own full pass over the file; assets are
derived by grouping repeated Asset_ID rows, the same way `defender.py`
groups repeated DeviceId rows across a snapshot table.

Unlike Defender, this source's own CVE IDs are synthetic (`CVE-2099-NNNNN`)
and will never resolve at NVD/KEV/EPSS, and every row's `Data_Source`
column says so outright ("Synthetic internal training record; not an NVD,
CISA, or vendor CVE entry."). The export already carries its own CVSS
score, exploitation status, and ATT&CK technique per finding, so this
adapter sets `provides_enrichment = True` and populates
`Finding.source_enrichment` (schema.py) instead of leaving it for a live
lookup that would cleanly find nothing -- see `ingest.attach_source_enrichment`
and `adapters.base.IngestAdapter`'s docstring for the mechanism, and
`scoring._resolve_severity` for how a source-reported score is labeled
without being mistaken for NVD's.

Mapping
-------
Asset (grouped from repeated Asset_ID rows)
  asset_id           <- Asset_ID              required, blank is fatal
  hostname            <- Asset_Hostname        required, blank is fatal
  role                <- Asset_Type            required; must be a key of ROLE_BY_ASSET_TYPE
                                                (see "The role boundary" below)
  business_function   <- Department            required column
  criticality         <- Asset_Criticality     required; Critical/High/Medium/Low -> 5/4/3/2
  internet_exposed    <- Internet_Exposed      required; Yes/No
  environment         <- Environment           required; Production/Development/Staging ->
                                                prod/dev/staging
  patch_window        <- Patch_Window          pass-through; a blank cell means "no window",
                                                the same as a native asset -- this source
                                                does have the column, so a blank is not
                                                not_collected
  compensating_controls <- Compensating_Control union of every distinct non-blank value
                                                across the asset's rows (see "The
                                                compensating-control union" below) --
                                                pass-through in shape, but resolved
                                                fleet-wide, not per row
  os, os_build, data_sensitivity, patch_restrictions, owner
                      <- (none)                not collected -- this source has none of
                                                these columns at all (Assigned_Team names
                                                who's fixing *one finding*, not who owns the
                                                asset -- see "Assigned_Team is not an owner"
                                                below -- so it is not a stand-in for owner
                                                either; it still reaches evidence). Notably
                                                smaller than Defender's not-collected
                                                footprint even so: this source is unusually
                                                rich in the operational/business-context
                                                fields Defender lacks, and lacks the
                                                asset-level OS fact Defender has.

Finding (one per row)
  finding_id          <- Record_ID             required, already unique -- no synthesis needed
  asset_id            <- Asset_ID              required, blank is fatal
  cve_id              <- CVE_ID                required; must look like CVE-YYYY-NNNN
  scanner_severity    <- Severity              required; Critical/High/Medium/Low/Informational
  product             <- Affected_Product      required column
  version             <- Affected_Version      required column
  detected_date       <- First_Detected        required; YYYY-MM-DD
  evidence            <- composed from Detection_Source, Vulnerability_Description,
                          Exploit_Maturity, Business_Impact, Assigned_Team, and Asset_Type --
                          see _evidence. Recommended_Action is deliberately excluded: piping
                          a source's own suggested remediation into evidence risks an agent
                          echoing BluePeak's verdict back as this project's own, which is
                          exactly the single-signal dependence CLAUDE.md's thesis argues
                          against.
  source_enrichment.severity_score   <- CVSS_Base_Score   required; parsed as float, 0.0-10.0
  source_enrichment.severity_label   <- "bluepeak" (fixed -- names this adapter, not a column)
  source_enrichment.known_exploited  <- Known_Exploited   required; Yes/No
  source_enrichment.attack_technique_id/name <- MITRE_ATTACK_Technique, parsed as
                          "T1210 - Exploitation of Remote Services"; unparsable is not fatal
                          (the raw text still reaches evidence via Vulnerability_Description),
                          just leaves the technique fields unset for that finding
  port, service        <- (none)               not collected -- this source has no port/
                                                service columns

The role boundary
------------------
`Asset.role`'s vocabulary was originally 7 values (dc, exchange, iis_web,
sql, file, workstation, dev) built for a Windows Active Directory
enterprise fleet (CLAUDE.md Section 2). BluePeak's `Asset_Type` column has
~28 distinct values describing a modern, heterogeneous, largely non-Windows
fleet: firewalls, a Kubernetes cluster, a container host, network and
identity/email gateways, a wireless controller, printers, cloud portals,
and web applications/APIs with no IIS or Windows evidence (one is
literally a Java gateway, another sits on `DEV-LNX-07`). An earlier
version of this adapter excluded every Asset_Type without one of the 7
original roles as a scope-boundary problem (adapters/base.py's "Two kinds
of refusal") rather than fabricate a blast-radius weight for it -- 23 of
50 rows in the real file. Running the adapter against that real file
directly motivated a scoring-model decision instead: `scoring
.ROLE_BLAST_RADIUS` gained 8 new roles (CLAUDE.md Section 3 has the full
weight table and reasoning for each), and `ROLE_BY_ASSET_TYPE` below now
maps all ~28 known Asset_Type values, not just the original 13. Nothing
in this adapter decided the weights -- that stayed a scoring.py decision,
same discipline as `role`'s OS-class default in adapters/base.py's own
docstring -- this file only decided which Asset_Type maps to which
*name*.

An Asset_Type genuinely outside even this wider vocabulary would still
exclude, not guess -- the mechanism in "Messy realities" below is
unchanged, there is simply nothing left in the real file that triggers
it today.

The compensating-control union
-------------------------------
A real device with two findings can have two different, both-real,
compensating controls -- one covering each vulnerability, not the whole
asset (`FILE-SRV-01` in the fixture: "SMB access segmented by department"
on one finding, "Archive extraction limited to authenticated file
services" on another). `Asset.compensating_controls` is a single
asset-level field, though, so `load_assets` resolves this by union rather
than requiring every row's `Compensating_Control` to agree the way it
requires role/criticality/environment/etc. to: every distinct non-blank
value seen across an Asset_ID's rows is collected and joined
(`compensating_control_list` already splits on comma/semicolon, so a
joined string is exactly what every other consumer already expects). This
is not a guess -- both controls are real, declared facts about the asset,
just declared on different rows -- and only makes `score_impact`'s decay
stronger (each additional distinct control counts, capped at
MAX_CONTROLS_COUNTED), never weaker.

Assigned_Team is not an owner
-------------------------------
Assigned_Team names which team is remediating *one finding*
("Endpoint Engineering" on one of FIN-WS-014's two findings,
"Database Operations" on the other), not who owns the asset -- an early
version of this adapter mapped it to `Asset.owner` and hit a spurious
refusal on exactly that asset, because the same box's two findings are
legitimately assigned to different teams. `owner` is not_collected instead
(see the mapping table above); Assigned_Team still reaches the model, via
`evidence` on each finding it actually belongs to.

Messy realities, and what each one does
---------------------------------------
- Missing columns: AdapterError at the header, listing missing and found.
- Blank identity columns (Record_ID, Asset_ID, Asset_Hostname, CVE_ID):
  fatal, nothing to key the record on.
- Asset_Type with no entry in ROLE_BY_ASSET_TYPE: excluded, not fatal --
  see "The role boundary" above. Its findings are excluded too, cascading,
  reported as "its asset was excluded: ..." rather than a separate orphan
  message for the same root cause. Nothing in the real 50-row file
  triggers this today (the table now covers every Asset_Type it contains);
  kept as a real, exercised code path for whatever a future export names.
- Repeated Asset_ID rows (the same asset has more than one finding):
  compensating controls union (see above); every other asset field must
  agree across rows or collapse to the later Last_Observed date (this
  source's own per-row recency signal, the same role Defender's optional
  Timestamp column plays); a tie or unparsable dates with no way to
  prefer one is a conflict and refused -- mirrors defender.py's own
  DeviceId handling exactly, just against Last_Observed instead of a
  dedicated Timestamp column.
- Duplicate Record_ID with identical content: collapsed, counted in
  `stats`. Same Record_ID with different content: a conflict and refused.
- Non-CVE ids: refused -- unscoreable without a real CVE identity, same as
  defender.py.
- Unparsable MITRE_ATTACK_Technique text: not fatal -- the finding is
  still scored, just without a source-reported technique (the raw text is
  still visible in evidence via Vulnerability_Description).
"""

from __future__ import annotations

import csv
import re
from collections.abc import Collection, Iterator
from datetime import date
from pathlib import Path
from typing import IO

from pydantic import ValidationError

from rhinosecure import ingest
from rhinosecure.adapters.base import (
    MAX_PROBLEMS_SHOWN,
    NOT_COLLECTED_DEFAULTS,
    AdapterError,
    IngestAdapter,
    ProblemCollector,
)
from rhinosecure.schema import Asset, Finding, SourceEnrichment

REQUIRED_COLUMNS = (
    "Record_ID",
    "CVE_ID",
    "Vulnerability_Description",
    "Affected_Product",
    "Affected_Version",
    "Asset_ID",
    "Asset_Hostname",
    "Asset_Type",
    "Department",
    "Environment",
    "Asset_Criticality",
    "Internet_Exposed",
    "Detection_Source",
    "First_Detected",
    "Last_Observed",
    "CVSS_Base_Score",
    "Severity",
    "Known_Exploited",
    "Compensating_Control",
    "Patch_Window",
    "Assigned_Team",
)
OPTIONAL_COLUMNS = ("MITRE_ATTACK_Technique", "Exploit_Maturity", "Business_Impact")

# Asset_Type -> AssetRole. Anything not listed is excluded, not mapped to
# the nearest neighbour -- see "The role boundary" in the module docstring.
# Weights and reasoning for the non-Windows-core roles: scoring.py's
# ROLE_BLAST_RADIUS, CLAUDE.md Section 3.
ROLE_BY_ASSET_TYPE: dict[str, str] = {
    # Windows AD-enterprise core
    "Domain Controller": "dc",
    "Database Server": "sql",
    "Workstation": "workstation",
    "Laptop": "workstation",
    "Privileged Workstation": "workstation",
    "Server": "file",
    "Storage Appliance": "file",
    "Application Server": "file",
    "Monitoring Server": "file",
    "Reporting Server": "file",
    "Network Management Server": "file",
    "DNS Server": "file",
    "Development Server": "file",
    # Perimeter/platform infrastructure
    "Identity Gateway": "identity_gateway",
    "Cloud Management Portal": "identity_gateway",  # its own impact framing is credential theft, not workload control
    "Firewall": "firewall",
    "Kubernetes Cluster": "container_orchestrator",
    "Email Security Gateway": "email_gateway",
    "Network Appliance": "network_appliance",
    "Application Gateway": "network_appliance",
    "Wireless Controller": "network_appliance",
    "Reverse Proxy": "network_appliance",
    "Mobile Sync Gateway": "network_appliance",
    "Web Application": "web_app",
    "Web API": "web_app",
    "Web Server": "web_app",
    "Container Host": "container_host",
    "Printer": "printer",
}

CRITICALITY_BY_SOURCE: dict[str, int] = {"critical": 5, "high": 4, "medium": 3, "low": 2}
ENVIRONMENT_BY_SOURCE: dict[str, str] = {"production": "prod", "development": "dev", "staging": "staging"}
SEVERITY_BY_SOURCE: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}
_TRUE = frozenset({"yes", "true", "1"})
_FALSE = frozenset({"no", "false", "0"})

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ATTACK_TECHNIQUE = re.compile(r"^(T\d{4}(?:\.\d{3})?)\s*-\s*(.+)$")

# Schema fields this source has no concept of, on every asset it produces.
# Notably smaller than Defender's: this source is business-context-rich
# (role, environment, patch window, compensating controls, owner are all
# real columns) but has no asset-level OS fact -- see the module docstring.
ASSET_FIELDS_NEVER_EXPORTED = frozenset({"os", "os_build", "data_sensitivity", "patch_restrictions", "owner"})
FINDING_FIELDS_NEVER_EXPORTED = frozenset({"port", "service"})


def _open_csv(path: Path) -> tuple[IO[str], csv.DictReader]:
    # See adapters/defender.py's _open_csv -- one shared reader for every format.
    return ingest.open_csv(path)


def _require_columns(path: Path, reader: csv.DictReader, required: tuple[str, ...]) -> None:
    found = list(reader.fieldnames or [])
    missing = [c for c in required if c not in found]
    if missing:
        raise AdapterError(
            f"{path}: not a BluePeak synthetic_cve_inventory export -- missing required "
            f"column(s) {missing}; found columns: {found or '(none -- empty file?)'}"
        )


def _parse_date(text: str) -> date | None:
    try:
        return date.fromisoformat(text.strip())
    except ValueError:
        return None


def _parse_cvss(text: str) -> float | None:
    try:
        value = float(text.strip())
    except ValueError:
        return None
    if not (0.0 <= value <= 10.0):
        return None
    return value


def _parse_bool(text: str) -> bool | None:
    v = text.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    return None


def _evidence(row: dict[str, str], asset_type: str) -> str:
    """Free text an agent can cite as color -- untrusted, per CLAUDE.md's
    open prompt-injection item. Recommended_Action is deliberately
    excluded; see the module docstring's Finding mapping table."""
    detection = (row.get("Detection_Source") or "").strip()
    description = (row.get("Vulnerability_Description") or "").strip()
    parts = [f"[{asset_type}] {detection}: {description}" if detection else f"[{asset_type}] {description}"]
    maturity = (row.get("Exploit_Maturity") or "").strip()
    if maturity:
        parts.append(f"exploit maturity (source-reported): {maturity}")
    impact = (row.get("Business_Impact") or "").strip()
    if impact:
        parts.append(f"business impact (source-reported): {impact}")
    team = (row.get("Assigned_Team") or "").strip()
    if team:
        # Per-finding, not asset-level -- see the module docstring's
        # "Assigned_Team is not an owner".
        parts.append(f"assigned team (source-reported): {team}")
    return "; ".join(parts)


class BluePeakAdapter(IngestAdapter):
    format = "bluepeak"
    assets_filename = "synthetic_cve_inventory_50.csv"
    findings_filename = "synthetic_cve_inventory_50.csv"
    provides_enrichment = True

    # --- assets -----------------------------------------------------------

    def load_assets(self, path: Path) -> Iterator[Asset]:
        """One row per asset, grouped from repeated Asset_ID rows -- see
        the module docstring's "Messy realities" section for the
        collapse/conflict rule, and "The compensating-control union" for
        why that one field is resolved differently from the rest.
        Consumes the whole file before yielding, same reason as
        defender.py's load_assets."""
        self.stats.duplicate_assets_collapsed = 0
        problems = ProblemCollector(path)
        # asset_id -> (core fields excluding compensating_controls, Last_Observed, row_no)
        resolved: dict[str, tuple[dict[str, object], date | None, int]] = {}
        controls_seen: dict[str, set[str]] = {}
        order: list[str] = []

        f, reader = _open_csv(path)
        with f:
            _require_columns(path, reader, REQUIRED_COLUMNS)
            for row_no, row in ingest.iter_csv_rows(path, reader):
                mapped = self._map_asset(row, row_no, problems)
                if mapped is None:
                    continue
                fields, control, observed = mapped
                asset_id = fields["asset_id"]
                if control:
                    controls_seen.setdefault(asset_id, set()).add(control)
                else:
                    controls_seen.setdefault(asset_id, set())
                prior = resolved.get(asset_id)
                if prior is None:
                    resolved[asset_id] = (fields, observed, row_no)
                    order.append(asset_id)
                    continue
                prior_fields, prior_observed, prior_row = prior
                if fields == prior_fields:
                    self.stats.duplicate_assets_collapsed += 1
                elif observed is not None and prior_observed is not None and observed != prior_observed:
                    self.stats.duplicate_assets_collapsed += 1
                    if observed > prior_observed:
                        resolved[asset_id] = (fields, observed, row_no)
                else:
                    problems.add(
                        f"row {row_no} ({fields['hostname']}): Asset_ID {asset_id!r} also appears on row "
                        f"{prior_row} with different values and no later Last_Observed to prefer -- "
                        "reconcile the export to one consistent set of asset facts per Asset_ID"
                    )
        problems.raise_if_fatal("synthetic_cve_inventory export (assets)")
        self.stats.excluded_assets = dict(problems.excluded)
        for asset_id in order:
            fields, _observed, row_no = resolved[asset_id]
            controls = ", ".join(sorted(controls_seen.get(asset_id, ())))
            try:
                yield Asset(
                    **fields,
                    compensating_controls=controls,
                    not_collected=frozenset(ASSET_FIELDS_NEVER_EXPORTED),
                )
            except ValidationError as exc:
                raise AdapterError(f"{path}: row {row_no} (Asset_ID {asset_id!r}): {exc}") from exc

    def _map_asset(
        self, row: dict[str, str], row_no: int, problems: ProblemCollector
    ) -> tuple[dict[str, object], str, date | None] | None:
        """Returns (core fields excluding compensating_controls, this
        row's Compensating_Control value, Last_Observed) -- Asset
        construction is deferred to load_assets, once per Asset_ID, after
        every row's controls have been unioned (see the module
        docstring)."""
        asset_id = (row.get("Asset_ID") or "").strip()
        hostname = (row.get("Asset_Hostname") or "").strip()
        asset_type = (row.get("Asset_Type") or "").strip()
        blank_identity = [c for c, v in (("Asset_ID", asset_id), ("Asset_Hostname", hostname)) if not v]
        if blank_identity:
            problems.add(f"row {row_no}: blank identity column(s) {blank_identity} -- nothing to key this asset on")
            return None

        role = ROLE_BY_ASSET_TYPE.get(asset_type)
        if role is None:
            # Scope boundary, not a data-quality problem -- the row is
            # well-formed, it just describes an asset outside CLAUDE.md
            # Section 2's Windows-only fleet. Excluded, not fatal: see
            # adapters/base.py's "Two kinds of refusal".
            problems.exclude(
                asset_id,
                f"Asset_Type {asset_type!r} has no honest equivalent in this project's Windows-fleet role "
                f"vocabulary (known: {sorted(ROLE_BY_ASSET_TYPE)}) -- not guessing a blast-radius weight "
                'for it; see the module docstring\'s "The role boundary"',
            )
            return None

        criticality_raw = (row.get("Asset_Criticality") or "").strip().lower()
        criticality = CRITICALITY_BY_SOURCE.get(criticality_raw)
        if criticality is None:
            problems.add(
                f"row {row_no} ({hostname}): Asset_Criticality {row.get('Asset_Criticality')!r} is not one "
                f"of {sorted(CRITICALITY_BY_SOURCE)}"
            )
            return None

        exposed = _parse_bool(row.get("Internet_Exposed") or "")
        if exposed is None:
            problems.add(f"row {row_no} ({hostname}): Internet_Exposed {row.get('Internet_Exposed')!r} is not a boolean")
            return None

        environment_raw = (row.get("Environment") or "").strip().lower()
        environment = ENVIRONMENT_BY_SOURCE.get(environment_raw)
        if environment is None:
            problems.add(
                f"row {row_no} ({hostname}): Environment {row.get('Environment')!r} is not one of "
                f"{sorted(ENVIRONMENT_BY_SOURCE)}"
            )
            return None

        observed_raw = (row.get("Last_Observed") or "").strip()
        observed = _parse_date(observed_raw) if observed_raw else None
        if observed_raw and observed is None:
            problems.add(f"row {row_no} ({hostname}): Last_Observed {observed_raw!r} is not ISO 8601 (YYYY-MM-DD)")
            return None

        fields: dict[str, object] = {
            "asset_id": asset_id,
            "hostname": hostname,
            "os": str(NOT_COLLECTED_DEFAULTS["os"]),
            "os_build": str(NOT_COLLECTED_DEFAULTS["os_build"]),
            "role": role,
            "business_function": (row.get("Department") or "").strip(),
            "criticality": criticality,
            "internet_exposed": exposed,
            "environment": environment,
            "data_sensitivity": str(NOT_COLLECTED_DEFAULTS["data_sensitivity"]),
            "patch_window": (row.get("Patch_Window") or "").strip(),
            "patch_restrictions": str(NOT_COLLECTED_DEFAULTS["patch_restrictions"]),
            "owner": str(NOT_COLLECTED_DEFAULTS["owner"]),
        }
        control = (row.get("Compensating_Control") or "").strip()
        return fields, control, observed

    # --- findings -----------------------------------------------------------

    def load_findings(self, path: Path, asset_ids: Collection[str]) -> Iterator[Finding]:
        """A finding whose Asset_ID isn't in `asset_ids` is, in practice,
        always a cascading exclusion here (never a true orphan): every
        finding row is also an asset row in this single-file format, so
        the only way `_map_asset` didn't yield that Asset_ID is either a
        scope-boundary exclusion (self.stats.excluded_assets -- the
        expected case) or a fatal data-quality problem on the asset's own
        row, which would already have raised out of load_assets before
        load_findings ever ran. The true-orphan branch below is kept only
        as a defensive fallback, mirroring defender.py's shape."""
        self.stats.duplicate_findings_collapsed = 0
        problems = ProblemCollector(path)
        seen: dict[str, tuple[str, int]] = {}  # finding_id -> (content digest, row_no)
        orphans: list[str] = []

        f, reader = _open_csv(path)
        with f:
            _require_columns(path, reader, REQUIRED_COLUMNS)
            for row_no, row in ingest.iter_csv_rows(path, reader):
                mapped = self._map_finding(row, row_no, problems)
                if mapped is None:
                    continue
                finding, content = mapped
                if finding.asset_id not in asset_ids:
                    excluded_reason = self.stats.excluded_assets.get(finding.asset_id)
                    if excluded_reason is not None:
                        problems.exclude(finding.finding_id, f"its asset ({finding.asset_id}) was excluded: {excluded_reason}")
                    else:
                        orphans.append(f"{finding.finding_id} (asset {finding.asset_id})")
                    continue
                prior = seen.get(finding.finding_id)
                if prior is None:
                    seen[finding.finding_id] = (content, row_no)
                elif prior[0] == content:
                    self.stats.duplicate_findings_collapsed += 1
                    continue
                else:
                    problems.add(
                        f"row {row_no}: Record_ID {finding.finding_id!r} also appears on row {prior[1]} "
                        "with different values -- two claims about one finding, refusing to pick one"
                    )
                    continue
                yield finding

        if orphans:
            listed = ", ".join(sorted(orphans)[:MAX_PROBLEMS_SHOWN])
            more = len(orphans) - min(len(orphans), MAX_PROBLEMS_SHOWN)
            problems.add(
                f"{len(orphans)} finding(s) reference an Asset_ID this adapter never saw as an asset row "
                f"and cannot explain: {listed}{f', ... and {more} more' if more else ''} -- a finding "
                "cannot be scored without its asset context"
            )
        problems.raise_if_fatal("synthetic_cve_inventory export (findings)")
        self.stats.excluded_findings = dict(problems.excluded)

    def _map_finding(self, row: dict[str, str], row_no: int, problems: ProblemCollector) -> tuple[Finding, str] | None:
        finding_id = (row.get("Record_ID") or "").strip()
        asset_id = (row.get("Asset_ID") or "").strip()
        cve_id = (row.get("CVE_ID") or "").strip().upper()
        blank_identity = [
            c for c, v in (("Record_ID", finding_id), ("Asset_ID", asset_id), ("CVE_ID", cve_id)) if not v
        ]
        if blank_identity:
            problems.add(f"row {row_no}: blank identity column(s) {blank_identity} -- nothing to key this finding on")
            return None
        if not _CVE_ID.match(cve_id):
            problems.add(
                f"row {row_no}: CVE_ID {row.get('CVE_ID')!r} is not a CVE identifier -- refusing to score "
                "a finding without one"
            )
            return None

        severity_raw = (row.get("Severity") or "").strip().lower()
        scanner_severity = SEVERITY_BY_SOURCE.get(severity_raw)
        if scanner_severity is None:
            problems.add(f"row {row_no} ({cve_id}): Severity {row.get('Severity')!r} is not one of {sorted(SEVERITY_BY_SOURCE)}")
            return None

        cvss = _parse_cvss(row.get("CVSS_Base_Score") or "")
        if cvss is None:
            problems.add(
                f"row {row_no} ({cve_id}): CVSS_Base_Score {row.get('CVSS_Base_Score')!r} is not a number "
                "in [0.0, 10.0]"
            )
            return None

        known_exploited = _parse_bool(row.get("Known_Exploited") or "")
        if known_exploited is None:
            problems.add(f"row {row_no} ({cve_id}): Known_Exploited {row.get('Known_Exploited')!r} is not a boolean")
            return None

        detected_raw = (row.get("First_Detected") or "").strip()
        detected_date = _parse_date(detected_raw)
        if detected_date is None:
            problems.add(f"row {row_no} ({cve_id}): First_Detected {detected_raw!r} is not ISO 8601 (YYYY-MM-DD)")
            return None

        technique_id = ""
        technique_name = ""
        technique_raw = (row.get("MITRE_ATTACK_Technique") or "").strip()
        if technique_raw:
            match = _ATTACK_TECHNIQUE.match(technique_raw)
            if match is not None:
                technique_id, technique_name = match.group(1), match.group(2).strip()
            # else: not fatal -- the raw text still reaches evidence via
            # Vulnerability_Description; see the module docstring.

        asset_type = (row.get("Asset_Type") or "").strip()
        product = (row.get("Affected_Product") or "").strip()
        version = (row.get("Affected_Version") or "").strip()

        try:
            finding = Finding(
                finding_id=finding_id,
                asset_id=asset_id,
                cve_id=cve_id,
                detected_date=detected_date.isoformat(),
                scanner_severity=scanner_severity,
                product=product,
                version=version,
                port=str(NOT_COLLECTED_DEFAULTS["port"]),
                service=str(NOT_COLLECTED_DEFAULTS["service"]),
                evidence=_evidence(row, asset_type),
                not_collected=frozenset(FINDING_FIELDS_NEVER_EXPORTED),
                source_enrichment=SourceEnrichment(
                    severity_score=cvss,
                    severity_label="bluepeak",
                    known_exploited=known_exploited,
                    attack_technique_id=technique_id,
                    attack_technique_name=technique_name,
                ),
            )
        except ValidationError as exc:
            problems.add(f"row {row_no} ({cve_id}): {exc}")
            return None
        content = f"{scanner_severity}|{cvss}|{known_exploited}|{detected_date.isoformat()}|{product}|{version}"
        return finding, content
