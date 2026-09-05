# RhinoSecure — Project Spec

**Author:** Andrew Kopshin
**Course:** Carnegie Mellon University, Agentic AI Program — Capstone
**Status:** Reset baseline, written after Checkpoint 5. This file supersedes any conflicting
statement in Checkpoints 1–5. Where a checkpoint disagrees with this file, this file wins.

This document is the single source of truth for the rebuild. It exists because the five
submitted checkpoints drifted: the scope changed, the subject of Tree-of-Thought reasoning
changed, and several committed components silently disappeared. Everything below is
reconciled and explicit so it stops moving.

---

## 1. What RhinoSecure is

An AI agent that turns raw vulnerability scanner output into a defensible, ranked
remediation plan for a synthetic Windows enterprise.

The thesis: **CVSS alone is an insufficient prioritization signal.** Technical severity must
be modulated by business context — asset criticality, internet exposure, environment, and
operational patching constraints. The same CVE on three different machines should produce
three different verdicts, and the agent must be able to explain why.

### In scope

- Ingest two synthetic CSVs: asset inventory and scanner findings
- Enrich each CVE from live public sources: NVD, CISA KEV, FIRST EPSS, MITRE ATT&CK
- Score each finding by combining technical severity with business context
- Rank and bucket findings into an actionable plan
- Emit per-finding reasoning with cited evidence
- Accept human operational constraints, re-plan, and explain what changed
- Persist constraints and prior decisions across sessions

### Explicitly out of scope

These are named because at least one checkpoint drifted toward them. They are not part of
this project.

- Live scanning of real systems
- Discovering new vulnerabilities
- Exploiting anything
- EDR/telemetry ingestion, log analysis, PowerShell behavior analysis
- Alert triage or incident investigation
- Automated remediation execution
- Production-grade vulnerability management features

### Synthetic data is a scaffold, not the design

The fixture and generated datasets are a **prototyping constraint**, not a property of the
system. RhinoSecure is designed to read real enterprise vulnerability data; synthetic data is
used here because real fleet data isn't available for a course project and because a frozen
fixture is what makes results reproducible.

This has a binding design consequence: **no component may assume its input is synthetic.**

- CSV columns mirror the fields real scanners export (Nessus, Qualys, Rapid7 InsightVM,
  Microsoft Defender Vulnerability Management), so the ingest layer can later accept real
  exports through a format adapter rather than a rewrite
- No hardcoded asset IDs, CVE IDs, or row counts anywhere in the logic
- No branching on fixture-specific values
- Nothing may assume the dataset is small enough to hold in memory or fetch in one pass

Swapping in a real scanner export should require a new ingest adapter and nothing else.

**Built.** The adapter seam exists: `src/rhinosecure/adapters/` — `base.py` (the `IngestAdapter`
contract every format implements, `AdapterError`, and the representation of fields a source
format has no concept of, below), `native.py` (the existing `assets.csv`/`findings.csv` loaders,
wrapped so "native" is one format among several rather than the one everything silently
assumes), and `defender.py`, the first real-export adapter: Microsoft Defender Vulnerability
Management, reading `devices.csv` (the `DeviceInfo` advanced-hunting table) and
`vulnerabilities.csv` (`DeviceTvmSoftwareVulnerabilities`) under their documented column names,
verified against Microsoft Learn rather than remembered. `rhino run --format {native,defender}`
selects the adapter; scoring, enrichment, and agents are untouched, and the demo fixture's
output is byte-identical with or without the seam. A real export carries technical facts and
almost none of the business context the Impact axis is built on — Defender exports no patch
window, compensating controls, environment, data sensitivity, role, business function, or owner
— so the adapter layer had to decide how to represent a field the source never collected
without changing what a blank already means to `bucket_for`. Decided: the *value* stays the
schema's absent encoding (or, for the enumerated Impact inputs that have none, a documented
modal default — `adapters/base.py`'s `NOT_COLLECTED_DEFAULTS`: prod, internal, criticality 3,
role by OS class), and the *claim* moves into a separate machine-readable field,
`Asset.not_collected` / `Finding.not_collected`, the set of field names the source had no
concept of. `rhino run` prints the gaps after the table and `--explain` names them per finding
with the value in effect. Section 3's open item on blank `patch_window` is resolved that way —
see there for what remains. Two things the adapter deliberately does: refuse rather than guess
(a missing column, a non-Windows device, a non-CVE id, a finding whose host isn't in the
inventory, or two conflicting rows for one finding all fail loudly, every offender listed in one
message), and dedupe rather than double-count (exact duplicate rows collapse and are counted).
`--format` works on all three paths — the deterministic pipeline, `--agents`, and `rhino
constraint add`. `Coordinator` no longer reads `<data>/assets.csv` itself; it takes the
already-loaded, already-validated inventory as `assets=` (plus `ingest_format=`, recorded on the
`runs` row). That matters most for the constraint path, and is why it was worth doing rather than
leaving refused: an export that carries no patch window, no compensating control, and no role is
precisely the input a human has to fill in by hand, so the fill-in command is the one that has to
accept it. Full mechanics, including the mapping table and each messy-reality rule:
`adapters/base.py`'s and `adapters/defender.py`'s module docstrings. `data/defender-sample/` is a
synthetic export (CVEs from the committed snapshots, so `--offline` works) that exercises the
whole path; it is not the frozen fixture and not covered by Section 8 rule 1.

**Bug fixed: a `--format`/`--data` mismatch used to crash instead of erroring.** Every one of the
three CLI paths (`run`, `run --agents`, `constraint add`) shared `ingest.load_batch` without that
function ever checking that `--data`'s resolved directory actually had the files the chosen
`--format` expects — `rhino constraint add --format defender` with `--data` left at its default
(`demo`, the native fixture) raised a raw, unhandled `FileNotFoundError` from deep inside the
adapter's own `csv.DictReader` construction, naming neither the directory nor the reason.
`ingest._require_adapter_files`, called first thing inside `load_batch`, now checks before either
file is opened and raises `IngestError` — already caught by name in all three CLI paths — naming
the resolved path, what was expected versus what's missing, what the directory actually contains,
and a stated likely cause. One check in the one function every path already shares is what makes
`--data`/`--format` handling identical across `run` and `constraint add`, rather than two
parallel implementations to keep in sync. An adversarial review of the first version of this fix
(three independent reviewers, each finding adversarially re-verified by two more) found and this
version fixes four real defects in `_require_adapter_files` itself: `Path.iterdir()`, unlike
`.is_file()`/`.is_dir()`/`.exists()`, does not swallow a genuine `OSError`, so a directory the
process could stat but not list (a locked-down deployment share) crashed the precheck with the
exact unhandled exception it exists to prevent — now wrapped; a same-named directory shadowing an
expected filename was silently excluded from the "contains" listing while still being called
missing, a visible contradiction — directories are now listed too, marked `(not a file)`; the
missing-file list wasn't deduplicated, which would garble the message for a hypothetical future
adapter reusing one filename for both roles — now deduplicated; and the "likely cause" was stated
as a `--format`/`--data` mismatch even when only one of the two expected files was missing, which
is exactly the case where an incomplete or corrupted export — not the wrong format entirely — is
the likelier story, and the old wording would have pointed the user at the wrong fix. Left
untouched, and flagged rather than silently fixed: `agents/coordinator.py`'s `Coordinator.__init__`
has its own, separate native-only fallback file load (`ingest.load_asset_index`, used only when a
caller omits `assets=`) that still raises a bare `FileNotFoundError` — confirmed unreachable from
any of the three CLI commands today (they always pass `assets=` from `load_batch`'s own result),
and pinned as intentional by an existing test (`test_without_an_inventory_and_without_assets_csv_it_fails_loudly`,
`tests/test_coordinator.py`). Same defect class, different code path and a different, separate
decision about whether that constructor's own contract should change.

**The fill-in loop, demonstrated end to end** (real LLM calls, `data/defender-sample`, scratch DB).
`CVE-2020-1472` on `dc01.corp.example.com` scores 35.5 and lands `contested` — KEV-listed, and
neither a control nor a window is *known*, which is the honest verdict on an export that collects
neither. Submitting `rhino constraint add "dc01.corp.example.com can only be rebooted on Sundays
between 02:00 and 06:00" --format defender` resolves the host by hostname, persists an
asset-scoped `patch_window`, and moves that finding `contested → next_window` with `risk_score`
unchanged at 35.5 — the constraint changed which bucket is *honest*, not how risky the finding is.
The Interpreter's own rationale recorded that it relied on the hostname match and not on the
asset's `patch_window`, "since it appears in not_collected" — the marker reaching a model's
reasoning, not just the CLI's output. Constraints apply on `--agents` runs (which construct a
`Memory`), not on the plain deterministic path, which never touches `memory.py` — pre-existing
behavior, documented in `cli.py`.

**Resolving an asset off a placeholder is refused.** `search_assets` skips any field named in
`Asset.not_collected` when matching (`constraint_intake._matches`) and reports the marker on every
candidate. Without that, all three servers in the Defender sample carry the same defaulted
`role="file"`, so "the file server can only be patched on Saturdays" would match every one of them
and a constraint could land on a domain controller. Confirmed against a real run: that statement
returns zero candidates and refuses, instead of resolving to a defaulted role.

**A third adapter, and a second enrichment mode: `adapters/bluepeak.py`, a single-file,
pre-enriched source, and `IngestAdapter.provides_enrichment`.** `data/bluepeak/
synthetic_cve_inventory_50.csv` (BluePeak Technologies, fictional) is one denormalized file --
a finding per row with its asset carried inline -- instead of the two-file assets/findings
split every prior format used. `assets_filename == findings_filename` on this adapter, which
`ingest._require_adapter_files`'s own `dict.fromkeys` dedup was already written to allow; the
format is not a workaround for the `IngestAdapter` contract, it is the case that dedup was
built for. It also breaks the "no live lookup will ever find anything" assumption in the
opposite direction from Defender: its CVE IDs are synthetic (`CVE-2099-NNNNN`, every row's own
`Data_Source` column says so) so NVD/KEV/EPSS/ATT&CK would cleanly find nothing, but the export
already carries its own CVSS score, exploitation status, and ATT&CK technique per finding --
discarding that to flatten it through the scanner-tier proxy would be a real loss of signal,
not a gap to fill in later. `IngestAdapter.provides_enrichment` (`adapters/base.py`) is the new
seam: `True` only for a source shaped like this, read by `cli.py`'s `run_with_report` to call
`ingest.attach_source_enrichment` instead of `attach_threat_signals`, skipping the two bulk
KEV/ATT&CK loads and every per-CVE lookup entirely rather than spending them on retries that
would just find nothing. Mechanically: `Finding.source_enrichment` (a new, optional
`SourceEnrichment` model, `schema.py`) carries what the adapter mapped; `attach_source_enrichment`
copies it onto `EnrichedFinding.is_kev`/`attack_techniques` (tagged `confidence="source_reported"`,
a value `AttackTechniqueRef.confidence`'s plain `str` type already accepted with no schema
change) and onto two new, honestly-labeled fields, `EnrichedFinding.source_severity_score`/
`source_severity_label`. `scoring._resolve_severity` checks the labeled pair first, before
`nvd_base_score` -- never reusing the NVD-branded fields for a number NVD never scored, so the
rationale can never misattribute a vendor's own self-reported CVSS to NVD (confirmed in
`--explain` output: `"bluepeak-reported CVSS 8.8 used directly (source=bluepeak, not fetched..."`,
distinct from either the `source=nvd` or `source=scanner` wording). `attack_prevalence` is
deliberately left unset for a source-reported technique: it is `enrich/attack.py`'s own
corpus-wide percentile stat, and a source has no such figure to report, so leaving it at
`EnrichedFinding`'s own default is the honest state, not an oversight -- `_attack_rationale_lines`
gained a third branch so the rationale says so explicitly rather than falling into "no
technique mapping found." `run_agents`/`submit_constraint` are not wired for this yet -- they
still dispatch Research's live-lookup tools for every format, harmless for this source (a
graceful "not found" per lookup, the same as any not-yet-scored CVE) but without the precision
`provides_enrichment` gives the deterministic path.

The role vocabulary this project's `AssetRole` (`dc`, `exchange`, `iis_web`, `sql`, `file`,
`workstation`, `dev`) was built for a Windows AD enterprise fleet (Section 2's own deliberate
narrowing), and BluePeak's `Asset_Type` column describes a modern, largely non-Windows one --
firewalls, a Kubernetes cluster, a container host, identity/email/network gateways, a wireless
controller, printers, and web applications/APIs with no IIS or Windows evidence (one is
literally a Java gateway). Decided (asked, not assumed): refuse every `Asset_Type` with no
honest equivalent, same posture `adapters/defender.py` already takes for a non-Windows
`OSPlatform` -- forcing e.g. a Kubernetes cluster into `file` would assert something false and
produce a confident-looking but fabricated blast-radius weight, exactly the "wrong-but-plausible
number" the whole not_collected/refuse-rather-than-guess discipline exists to prevent. Confirmed
against the real file: 13 of ~28 distinct `Asset_Type` values map (`ROLE_BY_ASSET_TYPE`,
`adapters/bluepeak.py`); the other 23 of the 50 rows refuse the whole batch at once, every
offender listed -- there is no per-row skip-and-continue anywhere in this adapter layer (Defender
doesn't have one either: one bad `OSPlatform` fails its whole file too), so running the file
as-is prints one message naming exactly where the Windows-only scope boundary sits rather than a
partial table. A filtered 27-row subset (the mappable rows only) runs and scores cleanly end to
end -- table, `Contested: 0/27`, full `--explain` rationale, zero network calls.

**Superseded below, twice.** The whole-batch refusal above was replaced by per-record exclusion
(reported, not fatal -- the entry further down this section on the mechanism), and the 27-mapped/
23-excluded role split was then closed almost entirely by extending `scoring.ROLE_BLAST_RADIUS`
itself (Section 3's own "Decided" note) -- the real file now scores all 50 rows. Both entries
below are kept as-is rather than rewritten, since they're accurate history of what was actually
built and in what order, not the current state on their own.

Two mapping mistakes running against the real file caught before they became bugs. **`Asset_ID`
rows repeat** (a device can have more than one finding) and most per-row fields must then agree
across an asset's rows or the batch refuses the same way Defender's `DeviceId` handling does --
but two fields legitimately don't have to: `Assigned_Team` names which team is fixing *one
finding*, not who owns the asset (`FIN-WS-014`'s two findings are assigned to different teams in
the fixture), so an early version mapping it to `Asset.owner` hit a spurious refusal on exactly
that asset; `owner` is `not_collected` instead now, and `Assigned_Team` still reaches the model
via each finding's own `evidence`. `Compensating_Control` can also legitimately differ per
finding on one asset (`FILE-SRV-01`'s two findings each declare a different real control --
"SMB access segmented by department" on one, "Archive extraction limited to authenticated file
services" on the other) -- unioning every distinct value across an asset's rows into
`Asset.compensating_controls`, rather than requiring row-for-row agreement, is not a guess (both
are real, declared facts, just declared on different rows) and only strengthens
`score_impact`'s decay, never weakens it. Neither of these was anticipated before running the
adapter against data it had never seen; both are recorded in `adapters/bluepeak.py`'s own module
docstring, not just here.

**A real usability gap, then a real posture change: whole-batch refusal on a scope boundary was
too blunt.** Running the real 50-row file above hit it directly: 23 rows have an `Asset_Type`
with no honest role, and refusing the *whole file* over that meant `rhino run --format bluepeak
--data bluepeak` produced no plan at all -- exactly the same all-or-nothing shape
`defender.py`'s own non-Windows-`OSPlatform` refusal already had. Investigated before touching
anything: this "refuse loudly" rule was never one behavior. Native fails on the *first* bad row
(no accumulation at all); Defender and BluePeak accumulate every problem across a full pass and
then refuse the *whole* batch if any exist. All three agreed on the outcome (refuse everything)
but not the mechanism, and neither shape distinguished a genuine data-quality problem (a blank
identity column, a malformed value, an unresolvable conflict -- the "never guess" rule is
squarely about these) from a scope-boundary one (the row is well-formed, it just describes
something outside this project's declared Windows-fleet scope). `defender.py`'s own docstring
for the non-Windows case already said the intent was that the device "went **unscored**" --
language that assumed a partial result, which the all-or-nothing implementation never actually
delivered.

**Decided** (asked, not assumed; the alternative of leaving every row-level problem, data
quality included, as skip-and-report was rejected -- that would start silently absorbing real
export corruption, which is precisely what "never guess" exists to prevent): split by reason,
layer-wide. A scope-boundary refusal is now excluded -- skipped and reported, never fatal to the
batch; a data-quality refusal still refuses the whole batch, unchanged, in every adapter. Built:
`adapters/base.py`'s `ProblemCollector` (promoted out of `defender.py`'s and `bluepeak.py`'s
previously-separate, identically-shaped private collectors) carries both `.add` (fatal) and
`.exclude(identity, reason)` (scope-boundary) for one pass; `.raise_if_fatal` only ever looks at
the fatal list, so a batch that's going to be refused anyway never bothers reporting exclusions
that are now moot. Only two call sites actually changed classification -- Defender's non-Windows
`OSPlatform` check and BluePeak's role-boundary check -- every other refusal (blank identity, a
malformed boolean/date/number, an unresolvable Timestamp/Last_Observed conflict, a missing
required column) is untouched, in both adapters. Cascading exclusion: a finding whose asset was
excluded is excluded too (`self.stats.excluded_assets`, populated by `load_assets`, read by the
same instance's later `load_findings` call), reported as "its asset was excluded: ..." rather
than a second, confusing "orphan" message for the same root cause -- a *true* orphan (an
asset_id that never appeared as an asset row at all, a real data-integrity problem) still stays
fatal, unchanged.

`IngestStats`/`IngestReport` (ingest.py) gained `excluded_assets`/`excluded_findings`
(id -> reason), the same shape as the existing `duplicate_*_collapsed` counters, threaded through
`GapTally.report`. `cli.py`'s new `_print_exclusions` prints them **before** the ranked table,
deliberately not alongside the `not_collected` gap report that already prints after it: a plan
silently missing part of a fleet must never look complete, so it cannot be a footnote under
numbers a reader has already formed an impression from. `export.py`'s `_ingest_report_dict`/
`_ingest_detail` mirror the two new fields so `rhino web` shows the same thing a terminal run
does. `run_agents`/`submit_constraint` don't build a full `IngestReport` (no `GapTally` pass), so
they get a smaller, stderr-only `_warn_of_exclusions` instead of the full grouped-by-reason
breakdown -- enough that a shrunk agents-path batch is never silent either, pointing back at
plain `rhino run` for the details.

**Confirmed against the real file.** `rhino run --format bluepeak --data bluepeak --seed 42` now
prints `Excluded: 23/47 asset(s), 23/50 finding(s)`, each one named with its reason and (for
findings) which excluded asset it cascaded from, followed by the identical 27-finding table,
`Contested: 0/27 (0.0%)`, and the data-gap report the manually-filtered subset produced earlier
in this section -- no more manual pre-filtering needed to see the pipeline run on this dataset.
The native fixture's output is unchanged (`Contested: 3/24 (12.5%)`, byte-identical rows) --
confirmed by re-running it, not just by the fact that native never populates `excluded_*`. 3 of
the 38 existing adapter-refusal tests changed (Defender's and BluePeak's own scope-boundary
tests, rewritten to assert exclusion instead of refusal, plus two new cascading-exclusion tests);
every other refusal test -- blank identity, malformed values, conflicts, missing columns, true
orphans -- is untouched, in both adapters, exactly as the reason-based split predicts.

**Guardrail.** This is a design constraint, not a feature list. The following remain out of
scope for the capstone build: live scanner API connectors, credential handling, PII or
regulated-data handling, and multi-tenant concerns. Design so they're possible later; do not
build them now.

**Checkpoint 4 correction.** CP4 described Tree-of-Thought over *explanations for suspicious
behavior* — that is alert triage, a different product. In this build a ToT branch is a
**competing remediation strategy** for a contested finding. The search mechanics from CP4
(beam search, ~3 branches, depth ~3, critic scoring, human tie-break) are retained; only the
subject changes.

**Checkpoint 5 correction.** CP5 demoted human-in-the-loop feedback to a future add-on. That
inverts the CP1/CP2 thesis and is reversed here: constraint feedback and re-planning are core
to the MVP.

**MCP correction.** CP4 assigned MCP the job of passing state between agents and tracking
explored branches. MCP is a model-to-tool protocol, not an inter-agent state bus. Agent state
lives in the Coordinator and SQLite. MCP is optional and, if used at all, only to expose the
enrichment tools.

---

## 2. Environment: the synthetic Windows fleet

Per the CP5 decision, the fictional company runs a **Windows-only** fleet. This is a
deliberate narrowing — it makes ATT&CK technique mapping tighter, makes vendor remediation
guidance concrete (Microsoft KB articles, Patch Tuesday cadence), and gives the CVE anchor
set a coherent story.

Representative asset roles: Active Directory domain controller, Exchange server, IIS-hosted
public web server, SQL Server, file server, employee web portal, payroll server, developer
workstations, isolated dev/lab box.

**Decided, and this note is a draft for review, not a settled correction the way the ones above
are.** The role vocabulary (Section 3) grew 8 roles beyond this list once a synthetic
non-Windows-adjacent export (`adapters/bluepeak.py`, Section 1) made the gap concrete: a real
Windows enterprise's fleet was never *just* domain-joined boxes. A firewall, a VPN gateway, an
identity/SSO gateway, a Kubernetes cluster — none of it Windows — sits around every Windows AD
core in practice, and the alternative (excluding every finding on that hardware, the posture
this project actually shipped first) hid real risk rather than narrowing scope honestly; running
the adapter against a real file is what surfaced that a KEV-listed firewall and VPN gateway
finding were being dropped from the plan entirely, not merely scored conservatively.

The Windows-only decision above is not reversed by this: the fleet's *core* — the anchor CVEs,
ATT&CK technique mapping, KB-article remediation guidance — is still built for, and stays, a
Windows AD enterprise. What changed is the claim that the fleet *is* that core and nothing else.
Two things this does **not** currently do, flagged so they aren't assumed done by omission:
`enrich/attack.py`'s local ATT&CK index still filters to Windows-platform techniques only
(Section 11) — harmless for BluePeak (it self-reports its own technique, bypassing that index
entirely) but would under-serve ATT&CK enrichment for a non-Windows asset on any format that
*does* go through live lookup; and `adapters/defender.py`'s `OS_PLATFORMS` allowlist still
excludes macOS/Linux devices outright — newly *possible* to reconsider now that roles exist to
represent them, but a separate decision, not made here.

### `assets.csv`

| Column | Notes |
|---|---|
| `asset_id` | Primary key |
| `hostname` | |
| `os` | Windows Server 2016/2019/2022, Windows 10/11 |
| `os_build` | Drives applicability of a given KB |
| `role` | dc, exchange, iis_web, sql, file, workstation, dev |
| `business_function` | Free text |
| `criticality` | 1–5 |
| `internet_exposed` | bool |
| `environment` | prod / staging / dev |
| `data_sensitivity` | none / internal / confidential / regulated |
| `patch_window` | e.g. "Sun 02:00–06:00" |
| `patch_restrictions` | e.g. "no reboot during business hours" |
| `compensating_controls` | e.g. "WAF", "network isolated" |
| `owner` | |

### `findings.csv`

| Column | Notes |
|---|---|
| `finding_id` | Primary key |
| `asset_id` | FK to assets |
| `cve_id` | |
| `detected_date` | |
| `scanner_severity` | As reported by the scanner |
| `product` / `version` | Affected software |
| `port` / `service` | Where applicable |
| `evidence` | Scanner's detection note |

---

## 3. Scoring model

**Risk = Threat × Impact.** Multiplicative, not additive, between these two axes. This is the
concrete realization of the CP3 commitment that no single factor automatically decides the
outcome — a maximal score on one axis cannot rescue a near-zero on the other.

That multiplication is correct **between** Threat and Impact. It is wrong **within** Impact.
Criticality, environment, data sensitivity, and role blast radius all measure facets of the
same underlying question — how much does this asset matter — so multiplying them together
compounds overlapping signal: an asset that is merely mid-range on more than one of these
axes gets driven toward zero, even though nothing about it is actually negligible. Impact
combines these four as a weighted sum instead; see below.

**Severity source.** `severity_base` feeds both axes (`exploitability_base` in Threat,
`impact_base` in Impact) and comes from one of two places: `scanner_severity`'s fixed per-tier
proxy (critical=9.5, high=7.5, medium=5.0, low=2.5, informational=0.5) when NVD has no CVSS
record for the CVE, or NVD's authoritative CVSS `base_score` when it does. NVD overrides the
scanner's tier outright when the two disagree, and is still preferred when they happen to
agree, because it's a real sourced number instead of a fixed proxy. Which source was used, and
whether it disagreed with the scanner, is recorded on every finding and always visible in its
rationale (`rhino run --explain`) — see `scoring._resolve_severity`.

**Decided.** `F16`–`F24` (the 9 mundane CVEs added to give the threat axis spread — Section 3
"Decided" note below) originally carried `scanner_severity` values assigned by hand, for
narrative variety, not derived from any real source. Checked against NVD, 7 of the 9 turned out
to disagree — all in the same direction, NVD rating them higher (up to 7.8/high against
low/medium scanner calls). That is not a realistic scanner behavior to model; it is unexamined
placeholder data that happened to disagree with authoritative CVSS by accident. Corrected
`scanner_severity` on those 7 rows to match NVD's tier (`F16` and `F24` already agreed, no
change). This leaves exactly **three** deliberate scanner/NVD disagreements on the fixture, each
retained because it demonstrates something specific:

| Finding | CVE | Scanner said | NVD says | Direction | Why it stays |
|---|---|---|---|---|---|
| `F12` | `CVE-2023-21554` | medium | 9.8 / critical | under-called | A scanner missing a critical RCE (QueueJumper) is a realistic failure mode, not an edge case |
| `F14` | `CVE-2023-23397` | low | 9.8 / critical | under-called | The fixture's designated bad-data case — see below |
| `F15` | `CVE-2019-1068` | critical | 8.8 / high | **over-called** | The opposite failure mode: a scanner *overstating* severity, which enrichment should pull back down, not just up |

A 10-of-24 (42%) disagreement rate read as a broken scanner, not a realistic one — real scanner
deployments disagree with authoritative CVSS on a real but small minority of findings, not
nearly half. 3 of 24 (12.5%) is defensible; each of the three now has a specific, named reason
to exist rather than being noise. `F14` remains the sharpest case: scanner said low (2.5), NVD
says 9.8/critical — its risk score climbs from 1.99 to 30.62 (15.4x) once NVD is applied,
fulfilling the correction the "Decided" note below anticipated. Its bucket stays `contested`
either way, since that rule depends on `is_kev` plus control/window state, not severity.
Re-running `rhino run --data demo --seed 42` after this correction reproduces an **unchanged**
bucket distribution (`patch_now=1, next_window=8, contested=3, mitigate_monitor=3, accept=9`)
and identical scores throughout — `_resolve_severity` was already using NVD's real score for
every one of these 7 findings regardless of what the CSV said, so fixing the CSV's
`scanner_severity` column only corrects what the rationale reports, not what was scored. This
is additive fixture *correction*, the same category as the other Section 8 rule 1 exceptions —
see the note there.

**Threat** (likelihood the finding is actually attacked)
- CVSS exploitability sub-metrics
- EPSS probability
- CISA KEV membership (floor, not multiplier — see below)
- Internet exposure of the host asset
- Whether mapped ATT&CK techniques are commonly observed

KEV and EPSS are different kinds of claim, and the scoring formula treats them differently on
purpose. EPSS is a model's probability estimate; KEV is CISA's record of confirmed real-world
exploitation. An observation should not be diluted by — or, worse, multiplicatively compounded
with — a prediction that disagrees with it. So EPSS sets a likelihood multiplier
(`0.6 + epss`, ranging 0.6–1.6; unscored CVEs get a neutral ×1.0), and KEV sets a **floor**
under that multiplier (`max(epss_multiplier, 1.5)`) rather than stacking another factor on top
of it. A KEV-listed CVE the model happens to underrate gets pulled up to the floor; a KEV
finding the model already rates highly is left alone, because the floor adds nothing once EPSS
already clears it. This resolves a live case in the demo fixture: `F15` (`CVE-2019-1068` on
`SQL02`) is KEV-listed but EPSS only rates it 0.53 — well below every other KEV finding in the
fixture (all ≥0.92) — so under a naive `KEV_multiplier × EPSS_multiplier` design it would have
been *penalized* for the model's disagreement instead of credited for CISA's confirmation. The
floor fixes that without inflating findings where both signals already agree. See
`_likelihood_multiplier` in `scoring.py`.

**Impact** (what it costs if it succeeds): `severity_base × composite`, where `composite` is
an equal-weighted sum (25% each) of:
- Asset criticality (normalized to 0–1)
- Environment (prod > staging > dev)
- Data sensitivity
- Blast radius implied by role (a DC compromise is not a workstation compromise)

**Decided.** `ROLE_BLAST_RADIUS` (`scoring.py`) started as 7 Windows AD-enterprise roles.
Running `adapters/bluepeak.py`'s adapter (Section 1) against its real 50-row file made the gap
concrete: 23 of the 50 rows described assets with no honest fit in that vocabulary — a firewall,
a VPN gateway, a Kubernetes cluster, none of it Windows — and the adapter's original posture
(exclude rather than fabricate a weight) meant those 23 findings never reached a plan at all.
Extended instead, by 8 roles, each weighed against the existing seven rather than dropped in
arbitrarily:

| Role | Weight | Anchored against | Why |
|---|---|---|---|
| `identity_gateway` | 0.90 | = `exchange` | SSO/federated auth, or a cloud administrative control plane. Compromise means potential impersonation of any connected user, or theft of the credentials that manage cloud resources — reach broader than mail alone. |
| `firewall` | 0.85 | = `sql` | Perimeter traffic control. Compromise means the attacker controls what crosses the network boundary, and can intercept, redirect, or disable other defenses — not one exposed thing, the thing everything else's safety assumed was intact. |
| `container_orchestrator` | 0.85 | = `sql` | Kubernetes/cluster control plane. Compromise means potential control over the whole production workload fleet, not one box. |
| `email_gateway` | 0.75 | between `iis_web` and `sql` | Mail-plane security control. Compromise means inspection/filtering bypass and a mail-flow foothold — below `exchange` since it's a control layer around the mail store, not the store. |
| `network_appliance` | 0.65 | above `iis_web` | VPN gateways, wireless controllers, reverse proxies, API/application gateways, mobile sync gateways. Access/connectivity chokepoints serving multiple downstream consumers — narrower than a firewall's full-traffic control, still a shared dependency. |
| `web_app` | 0.60 | = `iis_web` | Platform-agnostic web application/API. Same functional blast-radius profile as `iis_web`; the only difference is not asserting an IIS/Windows host. |
| `container_host` | 0.60 | = `iis_web` | A single container host. Blast radius scoped to whatever's co-located on that one box, comparable to one exposed web server. |
| `printer` | 0.15 | below `dev` | Lowest tier by design — a typically dead-end device with limited lateral-movement value. |

No new weight reaches `dc`'s 1.0 ceiling, so `RISK_NORMALIZATION` and every already-scored
finding (demo fixture, `defender-sample`) are unaffected — additive, not a renormalization.
`adapters/bluepeak.py`'s `ROLE_BY_ASSET_TYPE` now maps all ~28 `Asset_Type` values the real file
contains onto these 15 roles; nothing in the adapter decided a weight, only which `Asset_Type`
maps to which role name — the weight itself stayed a `scoring.py` decision, the same split
`role`'s OS-class default already draws in `adapters/base.py`. Confirmed: `rhino run --format
bluepeak --data bluepeak --seed 42` now scores all 50 rows (0 excluded, was 27/50); the firewall
and VPN-gateway findings — both KEV-listed — rose to `contested` at the top of the ranked table,
which is exactly the kind of signal a Windows-only vocabulary had no way to surface. Native
fixture output confirmed unchanged (`Contested: 3/24 (12.5%)`, byte-identical).

This does not reopen Section 2's Windows-only decision for the anchor CVEs, ATT&CK mapping, or
KB-article remediation guidance — see Section 2's own note on this. A dedicated `server` role
(Section 3's "Open items" below) is a related, still-open, separate decision: it would give an
already-mapped-to-`file` asset (e.g. `Application Server`, `Development Server` — mapped, never
excluded) its own honest, OS-agnostic name at the same 0.55 weight, not a new weight tier.

Compensating controls are applied **after** the composite, as a separate multiplicative
decay — not folded into the weighted sum. A control is an actual reduction in realized
impact, not another facet of how much the asset matters, so it stays multiplicative while the
four "does this asset matter" factors do not. Controls are counted exactly once, here, in the
impact decay; `bucket_for` reads whether a control exists only to help decide whether patching
is blocked (see below) — it does not apply a second reduction.

### Output buckets

| Bucket | Meaning |
|---|---|
| `patch_now` | Emergency change, do not wait for the window |
| `next_window` | Schedule into the asset's declared patch window |
| `mitigate_monitor` | Patch blocked or deferred; apply compensating control and watch |
| `accept` | Documented acceptance with rationale |
| `contested`† | No honest bucket exists among the four above — see below and Section 6 |
| `deferred_capacity`‡ | Would be `next_window`, but lost a rank-position race under a declared fleet-wide patch-capacity limit — see below and Section 10 |

† Not a remediation category a human acts on directly. It means the deterministic scorer
could not truthfully assign one of the four real buckets and the finding needs Tree-of-Thought
or human reasoning instead (Section 6). Currently emitted only for a KEV-listed finding with
neither a compensating control nor a declared patch window.

‡ Also not assigned by `bucket_for` — unlike every bucket above it, `deferred_capacity` is never
a property of one finding in isolation; it only exists relative to every other finding competing
for the same cycle's bandwidth, so no per-finding rule could produce it. `scoring
.apply_capacity_limit` assigns it afterward, cross-finding, only when a fleet-wide capacity
constraint (CLAUDE.md Section 10's "only five patches fit this window") is in effect: it ranks
every `next_window` finding by `risk_score` descending and reclassifies whichever rank past the
declared limit. `risk_score` itself is untouched — this bucket means "ranked below the cutoff,"
not "less risky." Every other bucket (including `next_window` itself and `contested`) is exempt
from that competition by construction, not by an exemption list: `patch_now` is never
`next_window` in the first place (it means too urgent to wait for a window at all), and a
contested finding stays `contested` regardless of what Tree-of-Thought recommends for it (an
`emergency_change` winner doesn't rewrite `RiskRecommendation.bucket` — see Section 6). See
Section 10's own note for the full mechanism.

Bucket assignment is a risk-score threshold picking a tier, then asset attributes deciding
which bucket within that tier applies:

- Thresholds: `patch_now` at risk ≥ 70, `accept` below risk 18, `next_window` /
  `mitigate_monitor` occupy the range between. These are named constants in `scoring.py`
  (`PATCH_NOW_THRESHOLD`, `ACTIONABLE_THRESHOLD`) and were calibrated back when the Threat side
  was near-binary (only severity and internet exposure varied it). KEV and EPSS are wired in
  now (see above) and do add real spread to Threat. Retuning these two constants is still an
  open, separate decision — not bundled into the KEV/EPSS wiring — since it requires judgment
  about where the tier boundaries should sit against the new, wider Threat distribution, not
  just a mechanical recompute.
- **A KEV-listed finding can never be `accept`.** Confirmed real-world exploitation is not a
  fact a plan can be silent about; landing in `accept` says "we are fine with this," which is
  never true of a finding CISA has recorded as actively exploited. `is_kev` forces at least the
  actionable tier regardless of where raw `risk_pct` falls — it does not by itself pick a
  bucket, though; the control/window logic immediately below still decides which one, exactly
  as it does for any other finding already in that tier. This changed real fixture output:
  `F03`, `F08`, `F13`, and `F14` all moved out of `accept` (see the worked table above/below).
- `mitigate_monitor` requires **both** a compensating control **and** the absence of a
  declared patch window. A control alone, on an asset that still has a scheduled patch
  window, is not "blocked" — it will be patched on schedule with the control covering it
  meanwhile.
- A blank `patch_window` means **no declared scheduling restriction**, not that patching is
  impossible. On its own it does not push a finding toward `mitigate_monitor` or `patch_now`;
  absent a compensating control as well, it stays in `next_window` — **unless** the finding is
  KEV-listed, in which case neither `next_window` ("on schedule" — nothing is) nor
  `mitigate_monitor` ("a control is covering it" — none exists) is an honest description, and
  it resolves to `contested` instead of being forced into either. The demo fixture's `F14`
  (`CVE-2023-23397` on `WKS-FIN12`) is this case: KEV-listed, no compensating control, no patch
  window. It is also the fixture's designated bad-data case (Section 3, "Decided" note above) —
  its `scanner_severity=low` is still uncorrected pending the NVD fetcher, so its risk score is
  artificially low today; `contested` surfaces the bucket-assignment problem independently of
  that, since fixing severity alone wouldn't fix the fact that no bucket honestly describes a
  confirmed-exploited finding with no control and no schedule.

### Anchor demonstration

The headline result must be reproducible on the demo fixture: **one identical CVE, three
Windows hosts, three different verdicts** driven entirely by business context. Candidate
Windows-native anchors with strong KEV and ATT&CK coverage: ProxyLogon, ProxyShell,
PrintNightmare, ZeroLogon, BlueKeep, Follina. A Java/Log4j anchor also works if hosted on a
Windows IIS or VMware-adjacent asset, but at least one anchor should be Windows-native so the
Windows scoping earns its keep.

**Decided, and resolved.** `F14` (`CVE-2023-23397` on WKS-FIN12) stays at `scanner_severity=low`
in the CSV — do not "fix" it, the mismatch is the point. This was intentional bad data, not a
mistake: `CVE-2023-23397` is a KEV-listed Critical, and the low scanner value models a scanner
under-calling severity on a known-exploited vulnerability. It was a Slice 2 exit-criteria case
— enrichment must correct the assessed severity from authoritative sources — and now does: NVD
rates it 9.8/critical, `_resolve_severity` uses that instead of the scanner's proxy, and its
risk score climbs 15.4x (1.99 → 30.62). See "Severity source" above.

**Decided.** The demo fixture now includes `A12` (`SQL02`), a legacy SQL Server host running an
ERP backend that the vendor only certifies at its current patch level — a realistic asset for
the "compensating control, no patch window" combination the fixture previously had zero
coverage for. `F15` (`CVE-2019-1068`, critical) on `A12` scores 34.2, landing squarely in
`mitigate_monitor`. This is additive fixture coverage, not the regeneration Section 8 rule 1
prohibits — see the note there. Fixture is now 12 assets / 15 findings.

### Open items

- **Resolved in representation, still open in two consumers.** The schema previously had no
  way to distinguish "no patch window recorded" (a data gap — nobody has documented one yet)
  from "patching is genuinely unconstrained" (a deliberate fact about the asset); both were the
  same blank, and the first real format (Defender, Section 1's "Built" note) collects neither.
  `Asset.not_collected` / `Finding.not_collected` (`adapters/base.py`) now carries the
  distinction: the value stays blank, so this section's rule for a blank window is unchanged and
  the fixture's output is byte-identical, and the field's name sits in `not_collected` whenever
  the source never collected it. The native fixture leaves it empty; the Defender adapter fills
  it for every field Defender lacks. Every consumer now reads it. `scoring._rationale` says
  "patch window not collected — this source exports none, so when this asset may be patched is
  unknown, not unrestricted" instead of the native "no patch_window declared", names
  not-collected compensating controls rather than staying silent about them, and phrases the
  `contested` explanation as "no patch window collected" when the field is a gap; it reads the
  marker for *wording only* and never for arithmetic, so a score and a bucket are identical with
  or without it (`test_scoring.py`). `agents/environment.py`'s `lookup_asset_context` and
  `agents/constraint_intake.py`'s `search_assets` both carry the marker into the model's own view.
  A constraint that supplies a field clears that field's marker (`apply_constraints`) — once a
  human states the window it is known, and continuing to flag it would be false; fields no
  constraint touched keep theirs, so one constraint never launders an asset's other gaps.
- **The not-collected Impact enums have no fill-in path.** `rhino constraint add` supplies a
  patch window, restriction, or compensating control per asset — the operational fields, and it
  now accepts `--format`, so a Defender-sourced asset can be filled in — but nothing can supply
  `role`, `environment`, or `data_sensitivity` for an asset whose source lacked them, so a
  Defender-sourced asset scores on `NOT_COLLECTED_DEFAULTS` for those three indefinitely.
  Extending `ConstraintEffectKind` is the obvious route and deliberately not taken here: those
  three are scoring inputs rather than operational facts, so it is a scoring-model decision, not
  an intake one.
  Defender-side candidates: `DeviceInfo.DeviceRoles` (JSON, undocumented vocabulary) and
  `DeviceManualTags`; the general answer is a CMDB/context sidecar keyed by device id. Related
  consequence, visible on `data/defender-sample/`: every KEV finding on a Defender asset lands
  `contested` (6/9 there), because no window and no control are *known* for any asset — the
  honest verdict under this section's own rule, and exactly why the fill-in path matters.
- **A `server` role.** An unclassified server currently defaults to `file`, the most generic
  server role in the vocabulary (blast radius 0.55, mid-table), and is marked not collected. A
  dedicated `server` value would be the honest encoding, but it needs a weight in
  `scoring.ROLE_BLAST_RADIUS` — a scoring change, so not bundled into the adapter.

---

## 4. Retrieval design

CP3 committed to a vector database. That commitment is honored selectively, because applying
it uniformly would be theater.

**Structured lookup** — for anything keyed by CVE ID. NVD records, KEV membership, EPSS
scores. These are exact-key retrievals; embedding them adds cost and loses precision.

NVD enforces real rate limits (5 req/30s unauthenticated, 50/30s with `NVD_API_KEY`) and
returns 403/429 once exceeded; `enrich/nvd.py` retries with exponential backoff rather than
failing on the first throttle — fetching the demo fixture's 20 unique CVEs unauthenticated hit
this repeatedly and recovered every time. NVD's per-CVE response can carry more than one CVSS
entry for the same version (the reporting vendor's own score alongside NVD's own analysis, and
they can disagree substantially — ZeroLogon's Microsoft-reported score is 5.5/medium against
NVD's own 10.0/critical); array order does not reliably put NVD's entry first, so the fetcher
selects by NVD's `"type": "Primary"` tag, falling back to `source == "nvd@nist.gov"`, not by
position.

**Vector retrieval with MMR reranking** — for prose where the query genuinely is not an exact
key. MITRE ATT&CK technique descriptions, vendor remediation guidance, mitigation writeups.
Retrieve a wider candidate set, then rerank down to roughly 5–8 items so the agent gets
*diverse* evidence (description, exploitation status, technique mapping, mitigation) rather
than eight restatements of the same CVSS score. This is the Carbonell & Goldstein MMR
argument from CP3, applied where it actually bites.

Every retrieved record carries a **source and timestamp** into the agent's reasoning, so
recommendations are auditable and stale evidence is visible.

### Snapshotting

All external responses are cached to `data/snapshots/` as local JSON. Upstream KEV and EPSS
data changes daily; snapshots keep baseline runs and agent runs comparable across days. A run
must be able to execute fully offline from snapshots.

---

## 5. Agent architecture

The four CP5 roles, with the feedback edges made explicit (CP5's text contained a circular
sentence routing the Coordinator back to itself).

| Agent | Responsibility |
|---|---|
| **Coordinator** | Plans the run, dispatches work, owns shared state, owns every re-plan loop |
| **Vulnerability Research** | NVD, KEV, EPSS, ATT&CK lookup and enrichment |
| **Environment Analysis** | Maps enriched CVEs onto the Windows fleet: applicability by OS build, exposure, controls, patch constraints |
| **Risk & Recommendation** | Scores, ranks, buckets, writes cited rationale |

### Flow

Primary path is sequential:
`Coordinator → Research → Environment → Risk → Coordinator → output`

Feedback edges, all routed through the Coordinator:
- Environment finds an evidence gap → Coordinator → **Research** (re-enrich)
- Risk finds insufficient context → Coordinator → **Environment** (re-map)
- Human submits a constraint → Coordinator → **re-plan from Environment onward**

Inter-agent messages are **structured payloads, not free conversation** — CVE ID, severity,
affected products, exploitation status, ATT&CK techniques, applicability verdict. This is the
CP5 reliability argument and it also makes the handoffs testable.

---

## 6. Tree-of-Thought

ToT does **not** run on every finding. It fires only on **contested** findings — those where
signals genuinely conflict, e.g. high EPSS and KEV membership on an asset whose patch window
is blocked, or high CVSS with strong compensating controls. The gate should keep contested
findings under roughly 1% of the corpus; this is the quantitative answer to CP4's
branch-explosion risk.

**Measured, not just targeted.** `rhino run --data demo --seed 42 --offline` reports 3/24
(12.5%) via `scoring.contested_rate` — well above the ~1% target. Expected at this fixture's
size, not a sign the rule is wrong: `F14` was added specifically to exercise this path (Section
3), and `F07`/`F11` were discovered as fallout applying the same rule, not engineered in. Three
findings out of a 24-row fixture can't demonstrate a sub-1% rate regardless of how the underlying
rule behaves on a realistic-sized corpus — the target is a claim about fleet-scale data, and
stays open to verify once that's available.

**First concrete gate, now wired.** `bucket_for` (Section 3) already detects one structural
instance of this deterministically: a KEV-listed finding with neither a compensating control nor
a declared patch window has no honest bucket among the four real ones, and `score_finding`
returns `Bucket.CONTESTED` for it rather than guessing. The demo fixture's `F14`, `F07`, and
`F11` are this case today. `agents/coordinator.py`'s `_dispatch_tot` is the routing: any finding
whose Risk stage lands on `bucket="contested"` gets built into a `tot.ToTRoot` (the finding plus
its Research/Environment/Risk evidence) and run through `tot.run_tree_of_thought`. Other
contested paths (e.g. EPSS/KEV disagreement on a blocked patch window) are qualitative, not yet
formalized as a `bucket_for` rule, and remain future work.

- **A thought is a remediation strategy**, not an explanation
- Root: the contested finding plus all gathered evidence
- 3 initial branches — see "Decided" below for why these replace the canonical three this
  section originally named
- Beam width 2, max depth 3
- Critic scores each branch on: risk reduction, operational cost, constraint compliance, evidence strength, contradicting evidence
- Terminate on clear winner, depth limit, or exhausted evidence
- **Near-tie → surface both branches to the human.** Do not force a single answer.

**Decided.** The canonical three branches this section originally named — patch immediately /
compensating control + defer / accept and monitor — don't apply to the only gate that exists.
`bucket_for`'s contested case is, by construction, a KEV finding (accept is disqualified — the
scoring rule's own point) with no compensating control to defer behind (that absence is *why*
it's contested, not incidental). Branches that presuppose either one aren't weaker for this case,
they're incoherent for it. `tot.py` uses a different, fixed three instead, each viable regardless
of whether a control or window currently exists:

- **emergency_change** — patch now, outside any declared window, through an expedited change
  process
- **establish_window** — formally schedule a maintenance window for the asset going forward,
  and patch within it
- **build_control** — implement a real compensating control before the next patch cycle

If a future contested case reaches ToT through a different `bucket_for` rule where an existing
control or accept genuinely is on the table, that case may need its own branch set — this one is
scoped to the gate that actually exists.

Two more implementation decisions not fully specified above, recorded so they don't drift.
**Depth is refinement, not new branches:** each beam survivor is the SAME strategy, strengthened
round over round against the critic's own feedback, never replaced by a different strategy — a
three-branch space doesn't have enough room to explore breadth-first past depth 1, and refinement
is what makes "exhausted evidence" a coherent termination condition (a strategy can run out of
runway to improve; a branch identity can't). Once a strategy reports exhausted, it's frozen (same
score, no further LLM calls) for every remaining round rather than re-asked to say so again.
**The critic's five axes combine by a fixed, documented, deterministic weighted formula**
(`tot.AGGREGATE_WEIGHTS`; risk_reduction weighted highest, operational_cost lowest — see
`tot.py`'s own comment for the full reasoning), never an LLM-computed total: `CritiqueOutput` has
no aggregate/total field at all, the same "the model never computes the number" property
`score_finding` gives `risk_score` (Section 8 rule 2's spirit, applied to a computation
`scoring.py` itself has nothing to do with).

---

## 7. Memory

SQLite, local file, `sqlite3` from the standard library. Restored from CP2, where it was
committed and then dropped from CP3 onward.

| Table | Contents |
|---|---|
| `constraints` | Human-supplied operational limits, persisted across sessions |
| `decisions` | Prior remediation verdicts and their rationale |
| `feedback` | Raw human input and what it changed |
| `runs` | Run metadata, seed, snapshot versions |

Worked example: the user states the payroll server only reboots on Sundays. That constraint
persists and is applied automatically on the next run without being restated.

Inspect with DB Browser for SQLite (sqlitebrowser.org).

**Built: the persistence layer, and now the worked example end to end.** `memory.py`'s `Memory`
class owns all four tables (local file, default `rhinosecure.db` at the repo root, gitignored).
`constraints` is asset-scoped free text with a soft-delete `active` flag rather than
update-in-place, so a retracted constraint stays in the record, plus a structured `effect_kind`/
`effect_value` pair (nullable — a constraint can be recorded before, or without ever, being
interpreted); `runs` stores seed, a JSON `snapshot_versions` map (keyed `"source"` or
`"source:key"`, mirroring `enrich/cache.py`'s own `SnapshotEntry` fields), contested rate, and the
four per-stage `UsageMetrics` blobs (nullable — the deterministic path and a `--agents` run with
nothing contested leave some or all of them `NULL`); `decisions` is one row per finding per run,
foreign-keyed to `runs`, with nullable ToT summary columns so a contested finding's record
actually reflects what was decided; `feedback` is raw input plus what it changed, `run_id`
nullable. Cross-session persistence (closing one `Memory` and opening a new one against the same
file) is what the test suite exercises directly against Section 7's own worked example text.

`runs.ingest_format` records which adapter (Section 1) produced the inventory a run reasoned
about — nullable, because a row written before `--format` existed has no truthful answer and
defaulting it to `native` would assert one. It arrived after the table did, which `CREATE TABLE
IF NOT EXISTS` cannot deliver to a database someone already has, so `Memory._migrate` applies
idempotent `ALTER TABLE` for columns added later, guarded by `PRAGMA table_info`. Any future
column follows the same rule: added there, and nullable.

**Constraint intake is built** (`agents/constraint_intake.py`'s Constraint Interpreter agent,
dispatched by `agents/coordinator.py`'s `submit_constraint` — Section 5's "Human submits a
constraint" edge, `rhino constraint add "<text>"` on the CLI) **and a stored constraint is read
back into a run** (`agents/environment.py`'s `lookup_asset_context` and `agents/risk.py`'s
`score_finding` tools both query `constraints_for_asset` when given a `Memory`) — the two gaps
this section previously named as open. See Section 6's ToT entry's own "Decided" convention: full
mechanics are in `agents/constraint_intake.py`'s and `agents/coordinator.py`'s module docstrings,
not repeated here. This handles asset-scoped constraints — matching this section's own worked
example exactly (`memory.py`'s `constraints` table is `asset_id NOT NULL` by construction).

**A second, fleet-wide mechanism is now also built** for Section 10's own exit-criteria example,
"only five patches fit this window" — a *capacity* constraint, with no single asset to resolve
to, so it cannot live in the `constraints` table above (`asset_id NOT NULL`) or apply the same
way (asset-scoped constraints change what `bucket_for` computes for one finding; a capacity
limit reallocates *after* every finding already has a real bucket, competing findings against
each other, not against their own asset's facts). Rather than a second agent,
`agents/constraint_intake.py`'s Constraint Interpreter is extended with a third classification
(`ConstraintKind.CAPACITY`, alongside `ASSET` and the null refusal) — the same interpretation
call that resolves an asset-scoped statement now also recognizes a capacity-shaped one and
extracts its integer limit into `patch_limit`, leaving `asset_id`/`effect_kind`/`effect_value`
and `affected_finding_ids` empty (which findings compete is computed deterministically, never by
the model). `Coordinator.submit_constraint` branches on `interpretation.constraint_kind` to
`_submit_capacity_constraint`, which is LLM-free past that one interpretation call: it re-derives
every finding's real, live-enriched bucket via the same deterministic pipeline `rhino run` uses
(`ingest.attach_threat_signals` + `scoring.score_finding`, no Research/Environment/Risk/ToT
dispatch) — folding in any active asset-scoped constraint on file first, the same way
`agents/risk.py`'s `score_finding_tool` already does for a live agents run, so "real, current
bucket" means what a person would actually see right now, not the fleet's raw, un-overlaid CSV
state (an adversarial review caught this path skipping the overlay initially) — then calls
`scoring.apply_capacity_limit` — a pure sort over every `Bucket
.NEXT_WINDOW` finding, `deferred_capacity` past the limit — keeping the allocation itself in the
scoring path, not in an agent (Section 8 rule 2's discipline, applied here too). Persisted via a
fifth table, `capacity_constraints` (`memory.py`) — cycle-scoped, tied to the one `runs` row it
was applied within, with no active/deactivate lifecycle: unlike an asset constraint, a capacity
limit isn't a standing fact that stays true across future runs, so there is nothing to retract.
`decisions` gained three nullable columns (`capacity_rank`/`capacity_pool_size`/`capacity_limit`)
so a decision produced by this path records why it landed there. `cli.py`'s diff output for this
path is framed differently from the asset-scoped diff on purpose: a capacity reallocation never
changes a finding's `risk_score` (`agents/coordinator.py`'s `CapacityDelta` docstring) — only its
rank position relative to the declared limit — so `_print_capacity_result` shows rank and bucket
transition, not a risk_score before/after pair. See Section 10's own "Decided" note and
`agents/coordinator.py`'s `_submit_capacity_constraint` docstring for the full mechanism.

---

## 8. Non-negotiable build rules

1. The 24-finding demo dataset is a **fixture**. It proves specific behaviors. Do not
   regenerate it — the rule bars wholesale regeneration (reshuffling or re-deriving the
   dataset to make numbers look better), not a deliberate, individually-justified row added or
   value corrected to close a named gap (e.g. the `A12`/`F15` addition for `mitigate_monitor`,
   Section 3; `F16`–`F24`, nine real low-EPSS non-KEV Windows CVEs added so the threat axis has
   spread instead of being dominated by famous anchor CVEs; correcting `F16`–`F24`'s
   arbitrarily-assigned `scanner_severity` to match NVD once it disagreed by accident rather
   than by design, Section 3). Any such addition or correction lands in its own commit stating
   the reason.
2. Everything in `scoring.py` and the tool layer stays **deterministic**. No LLM calls in the
   scoring path. Same inputs plus same snapshots must produce byte-identical output.
3. `--seed 42` is the seed for all reported results.
4. Never overwrite a snapshot without bumping its version.
5. The old repository is **read-only reference**. Consult it; do not import from it without
   reviewing against this spec first.

---

## Trust boundary and provider independence

RhinoSecure is a program that runs independently of the tooling used to build it. At runtime
it holds its own API key and calls an LLM as its reasoning engine. This creates a data-egress
property worth stating explicitly.

**What leaves the machine.** From Slice 3 onward, findings sent to the agents are transmitted
to a third-party API. With synthetic data this is immaterial. Under the Section 1 rule that no
component may assume synthetic input, it is not: real vulnerability data is a map of where an
organization is weak.

**Design consequences.**

- The deterministic scoring path stays LLM-free. `scoring.py` never transmits anything, so the
  core prioritization runs entirely locally and remains reproducible.
- Agents receive enriched findings, not raw fleet inventory. Send what reasoning requires.
- **All LLM calls go through a single seam.** One module owns client construction and request
  dispatch; agent code calls that interface and never instantiates a provider client directly.
  This keeps a self-hosted or on-premises model a substitution rather than a rewrite — the
  realistic requirement for any organization unwilling to transmit its vulnerability data.

**Operational properties inherited from the LLM dependency:** per-run cost, availability tied
to an external service, and non-deterministic output. The first two are accepted. The third is
why the deterministic path is fenced off from the agents.

---

## Safety and guardrails

**Checkpoint 6 correction.** CP6 described the agent as monitoring live system activity,
ingesting telemetry and system logs, and taking high-impact actions on a system — deleting
files, permanently blocking software, changing security settings — that must be gated behind
human approval. None of that describes RhinoSecure. Per Section 1, live scanning,
EDR/telemetry ingestion, and automated remediation execution are explicitly out of scope.
RhinoSecure ingests two static CSVs (`assets.csv`, `findings.csv`), enriches from read-only
public sources, and emits a ranked plan — a document, not an action. It holds no write path to
any monitored system, so "gate destructive actions behind human approval" doesn't apply: there
is no system action to gate, because the agent's only write access is to its own SQLite memory
(Section 7) and `out/` plan files. Where CP6's underlying concern is real — the agent shouldn't
force a conclusion it can't support, and a human should be the backstop when signals conflict —
that concern is honored here, just realized as escalation inside a *report* rather than a
permission check on a *system call*. The rest of this section keeps what CP6 got right
(trusted-source-only enrichment, least-privilege tool access, escalate rather than force) and
drops what described a different product.

### Implemented

- **Trusted-source-only enrichment.** All external evidence comes from NVD, CISA KEV, FIRST
  EPSS, and MITRE ATT&CK (Section 4, Section 11) — the same sources CP6 named. No enrichment
  source is agent-selected or free-form-fetched; the source list is fixed in `enrich/`.
- **No agent write access to the scoring path.** `scoring.py` is deterministic and LLM-free
  (Section 8 rule 2; "Trust boundary and provider independence" above) — no agent can write to
  it, call it with model output, or shift a score except through the structured, auditable
  inputs (enriched findings, asset context) it's designed to take. This is the concrete form of
  CP6's least-privilege request: agent tool access doesn't extend to the risk arithmetic itself.
- **`contested` as escalation.** When the deterministic scorer can't truthfully assign one of
  the four real buckets — currently: KEV-listed, no compensating control, no declared patch
  window — it returns `Bucket.CONTESTED` instead of guessing (Section 3, Section 6). This is
  CP6's "know when to stop and ask for human help rather than force a decision," implemented as
  a bucket a human must read and resolve, not one a plan silently ships.
- **Refusal to force a bucket when none is honest.** `bucket_for` (`scoring.py`) is written as
  conditions that must hold, not a fallback chain that always terminates in some answer.
  `contested` exists specifically because forcing `F14` (Section 3) into `next_window` or
  `mitigate_monitor` would each assert something false about the finding. This is a design
  property, not a special case for one finding — any future finding with the same shape resolves
  to `contested` the same way.

### Open

Not yet built. Listed here so the drift CP6 introduced doesn't happen again by omission — do
not mark any of these done until there's a specific module and test to point to.

1. **Prompt-injection resistance in CVE description text.** NVD descriptions, KEV notes, and
   scanner `evidence` fields are free text pulled from external sources — exactly the kind of
   untrusted content CP6 warned about ("malicious or manipulated information would affect the
   agent's judgment"). Nothing currently sanitizes or isolates this text before it reaches an
   agent prompt.
2. **Grounding validation.** Agents should be checked to confirm their rationale cites the
   retrieved evidence actually passed to them (Section 4's "source and timestamp" requirement),
   not restated model knowledge dressed up as a citation. Two partial pieces exist; the item stays
   open because neither is the general mechanism this item asks for.
   **Labeling, not checking:** Environment Analysis's `EnvironmentAssessment.os_build_consistent`
   (`agents/environment.py`) has no tool answer to check against — there is no live "which KB
   applies to which OS build" source named in Section 11, so it is the model's own judgment from
   the finding's product/version text against the asset's declared os/os_build, not a database
   fact. `os_build_consistent_provenance` (a fixed `Literal["model_judgment"]`, so the schema
   itself cannot mislabel it) marks that explicitly rather than leaving it implicit in
   `applicability_summary`'s prose — a human or downstream consumer can tell it's unsourced, but
   nothing stops it from being wrong.
   **Actual enforcement, narrowly scoped:** Risk & Recommendation's `verify_scoring_matches_tool`
   (`agents/risk.py`) is a real pass/fail check, not a label — it compares the agent's final
   `risk_score`/`bucket`/`scoring_rationale` against what the `score_finding` tool actually
   returned for that finding_id (from the call log, not the model's retelling) and raises
   `ScoringMismatchError` on any drift; `Coordinator._dispatch_risk` calls it after every Risk
   task and propagates the exception rather than accepting a silently-diverged result. This is
   still narrow: it checks one agent's one tool against its own output, not that any agent's
   rationale cites the specific evidence strings it was actually given (e.g. nothing yet checks
   that Research's `nvd_base_score` field matches what `lookup_nvd` returned, or that
   Environment's `has_patch_window` matches `lookup_asset_context`'s result). Do not mark this
   item done — a general citation-vs-evidence checker across all three agents, and now `tot.py`'s
   Strategist/Critic (a fourth LLM surface with the same unchecked-prose-vs-evidence gap: nothing
   confirms a proposal or a critic's justification only cites facts actually present in
   `ToTRoot`), is still unbuilt. `tot.py`'s critic score itself is a *stronger* case than
   `risk_score`'s: `CriticScores.aggregate` isn't just checked against the model's output after
   the fact (`verify_scoring_matches_tool`'s pattern) — `CritiqueOutput` has no aggregate field at
   all, so there is nothing for the model to get wrong in the first place. That closes the
   number; it says nothing about the prose.
3. **Tool-call retry cap.** No bound yet on how many times an agent may retry a failed tool call
   (an NVD timeout, a malformed EPSS response) before it must stop and escalate instead of
   looping.
4. **Cost/usage visibility.** "Trust boundary and provider independence" (above) accepts
   per-run cost as an operational property of the LLM dependency, but `rhino run --agents`
   prints nothing about it — a run's actual token usage and dollar cost are currently invisible
   from the CLI. `Coordinator`'s `RunState` collects `research_usage`/`environment_usage`/
   `risk_usage` (one `crewai` `UsageMetrics` per stage) and, as of the ToT gate, `tot_usage`
   (summed across every contested finding's search, partial spend included if the search failed
   — `tot.py`'s module docstring has the accumulation mechanics) — nothing reads any of the four
   back out. The 24-finding run PROGRESS.md logged as confirming Slice 3's exit criteria could
   only report an *extrapolated* cost (≈$3.3, from an earlier smaller run's measured rate) for
   exactly this reason. `rhino run --agents` should print total tokens and an estimated dollar
   cost at the end of a run.

---

## Adapter generation (LLM-assisted contract authoring)

Section 1's adapter seam (`adapters/`) means a new source format needs a hand-written
Python adapter. `docs/adapter-generation.md` is a second, later way to add one: point
RhinoSecure at an arbitrary CSV and get a working format without writing Python at all.
That file is authoritative for every mechanism named below; this section exists so the
split and its two rules don't depend on a reader following the link.

**Two phases, and the split is the whole design.** Phase 1 (`rhino adapt propose`, not
built — Slice 8): an LLM inspects a source's headers and rows and proposes a mapping onto
`Asset`/`Finding`; a human reviews and confirms it (`rhino adapt confirm`, built). This
runs once per source, ever — again only if the source's shape changes. Phase 2
(`ConfiguredAdapter`, built): every subsequent run reads the confirmed mapping — a JSON
**contract** — with zero LLM involvement, exactly like a hand-written adapter. This is the
same discipline Section 8 rules 2–3 already require of scoring: if the mapping were
re-derived per run, the same file could score differently on different days. A confirmed
contract resolves through `rhino run --adapter-config <name>` / `rhino constraint add
... --adapter-config <name>` into the same `ingest.load_batch` every other adapter uses;
scoring, enrichment, and the agents never know a run came from a contract instead of a
built-in `--format`.

**Status.** Slices 1–7 are built: the contract schema and validator, the phase-2 engine
(proven differentially identical to the hand-written BluePeak and Defender adapters on
real data), the confirmation-digest gate, `--adapter-config` on the CLI, pre-enriched-
source support, a non-raising column profiler (`rhino adapt probe`/`list`), and the
confirm/re-review workflow itself (`rhino adapt confirm`/`rereview`) with its attestation
gate. Two contracts are confirmed and committed: `data/adapters/bluepeak-gen.json`,
`data/adapters/mdvm-gen.json` — both hand-authored, since Slice 8 doesn't exist yet to
author one from an LLM call. Slice 7 was hardened by an adversarial review round spanning
commits `48ac821` and `309b9a1` that found and fixed six defects — PROGRESS.md is
authoritative for what they were and how each was verified. Not built: Slice 8, the
phase-1 inference agent behind `rhino adapt propose`; and Slice 9, surfacing contract
provenance in `export.py`/`rhino web`.

**Rule 1 — `exclude` is legal only for a check feeding `Asset.role`, and only the
validator gets to decide that, never a config key.** The mapping grammar has no
`on_unmapped` field. Making a value's disposition (fatal — refuse the whole batch — vs.
scope-exclude the one record) a contract setting would let either the model or a human
reclassify an inconvenient refusal as "exclude" to make it disappear — the exact silent-
absorption failure the not-collected/refuse-rather-than-guess discipline (Section 1)
exists to prevent. Instead the engine decides structurally: `ConfiguredAdapter
._role_reference()` inspects how `contract.asset["role"]` is itself mapped — a direct
`VocabularyMapping`, or a `DefaultByMapping` keyed off a `derived` table — and forward-
traces which vocabulary or derivation-table lookup actually feeds that field. Only a miss
at *that specific* lookup becomes `problems.exclude(...)`, a scope-boundary skip that's
reported but not fatal (a Kubernetes cluster with no honest blast-radius role, say).
Every other vocabulary or derivation-table miss anywhere else in the contract is always
`problems.add(...)`, a fatal, whole-batch refusal.

**Rule 2 — every pattern a contract can invoke is a closed, code-owned catalog; nothing
lets an LLM author or select a regex at runtime.** `ParsedMapping.parser` is a fixed
`Literal["bool", "float", "date", "timestamp", "cve_id"]` — pydantic rejects anything
else — and the actual regexes behind each are hard-coded module constants, never built
from contract text. The one "degrade" field (an ATT&CK-technique pattern match) can only
*select* one pre-existing named pattern, never supply its own. `VocabularyMapping`/
`Derivation` tables are plain JSON dicts read only via `dict.get(...)` — never `eval`,
never `re.compile` on contract data, no code generation anywhere. `Contract.generator`
records that an LLM authored the *contract itself* in phase 1 (tool, model, token counts,
cost, a call-log digest) purely as audit trail — its own docstring: never read by the
phase-2 engine, never input to any decision it makes. Together with Rule 1, this is what
makes "confirmed once, deterministic forever" actually true: the engine's every runtime
decision — including its one qualitative judgment call, fatal vs. exclude — resolves
against fixed code and a frozen, hashed contract, never a live model call or a
model-chosen pattern.

---

## 9. Repository layout

```
rhinosecure/
  CLAUDE.md                  # this file
  README.md
  pyproject.toml
  .env.example
  data/
    demo/                    # 24-finding fixture — FROZEN
      assets.csv
      findings.csv
    defender-sample/         # synthetic Defender export for --format defender (not a fixture)
      devices.csv            #   DeviceInfo shape
      vulnerabilities.csv    #   DeviceTvmSoftwareVulnerabilities shape
    full/                    # generated, seed 42
      assets.csv
      findings.csv
    adapters/                # confirmed ingest contracts (Adapter generation, above)
      bluepeak-gen.json
      mdvm-gen.json
    snapshots/
      kev.json                 # bulk catalog, one file
      epss/                    # per-CVE, queried live against api.first.org
      nvd/
      attack/
  docs/
    adapter-generation.md    # LLM-assisted adapter generation -- authoritative for detail (above)
  src/rhinosecure/
    schema.py                # dataclasses + CSV validation
    ingest.py
    adapters/                # ingest adapters -- the format seam (Section 1)
      base.py  native.py  defender.py
      config_model.py  config_io.py  configured.py  # LLM-assisted adapter generation (above)
      probe.py  review.py                           #   contract profiling + the confirm/rereview gate
    scoring.py               # deterministic, no LLM
    tot.py
    memory.py                # sqlite
    enrich/
      nvd.py  kev.py  epss.py  attack.py  cache.py
    retrieval/
      vector.py  mmr.py
    agents/
      coordinator.py  research.py  environment.py  risk.py
    crew.py                  # CrewAI wiring
    cli.py
  tests/
  scripts/
    smoke_test.py            # standalone LLM connectivity check, not wired into the pipeline
  out/                       # generated plans, gitignored
```

---

## 10. Build plan — four vertical slices

Not a step-by-step drip, and not one monolithic build. Each slice is independently runnable
end to end, so a stalled slice never blocks a checkpoint deliverable.

### Slice 1 — Ingest and score
No LLM, no network. CSVs in, ranked and bucketed plan out.
**Exit criteria:** `rhino run --data demo --seed 42` prints a ranked table and reproduces the
three-host contrast on the anchor CVE. Deterministic across repeated runs.

### Slice 2 — Enrichment
Live NVD, KEV, EPSS, ATT&CK with the snapshot cache layer.
**Exit criteria:** the same command runs fully offline from snapshots and produces identical
output to the online run against the same snapshot version. NVD API key wired via `.env`.

### Slice 3 — Agents
The four CrewAI roles wrapping the working pipeline, with structured handoff payloads.
**Exit criteria:** an agent run reproduces the Slice 2 ranking, with any delta traceable to a
named reasoning step. Per-finding rationale cites its sources.

### Slice 4 — ToT and feedback
Contested-finding gate, beam search over remediation strategies, constraint intake, re-plan
with diff.
**Exit criteria:** submitting "only five patches fit this window" changes the plan, and the
agent explains the delta between the original and revised plan. Contested rate reported and
under ~1%.

**Decided, and now built.** This exit criteria's own example — "only five patches fit this
window" — is a fleet-wide *capacity* constraint: no single asset to resolve to, nothing in it
that maps onto one of `memory.py`'s asset-scoped `constraints` rows. The first thing built
against this sentence was exactly Section 7's worked example shape — "the payroll server only
reboots on Sundays," an *operational* constraint about one asset's patch window, compensating
controls, or patch restrictions — because that is the constraint `memory.py`'s original schema
(Section 7, `constraints.asset_id NOT NULL`) represents, and `agents/constraint_intake.py`'s
Constraint Interpreter was told to recognize a capacity-shaped statement and refuse
(`asset_id=None`) rather than force it onto one asset. **That refusal is now a real second path
instead**, exercising Section 10's own exit-criteria sentence literally rather than only proving
the operational case: the Interpreter's refusal shape gained a third classification
(`constraint_kind="capacity"`) that extracts an integer `patch_limit` instead of resolving an
asset, and `Coordinator._submit_capacity_constraint` reallocates every `Bucket.NEXT_WINDOW`
finding fleet-wide by rank against that limit (`scoring.apply_capacity_limit`,
`Bucket.DEFERRED_CAPACITY` — Section 3's own entry has the full mechanism; Section 7's entry
above has the agent-side wiring). Re-plan with diff is real and exercised on both cases now:
`agents/coordinator.py`'s `submit_constraint` re-plans exactly the resolved
`affected_finding_ids` and returns a per-finding before/after (`FindingDelta`) for the
operational case, while the capacity case returns a per-finding rank/bucket-transition record
(`CapacityDelta`) instead — deliberately not a before/after risk_score pair, since a capacity
reallocation never changes `risk_score` (only rank position does). `cli.py`'s `rhino constraint
add` prints whichever diff shape actually applies, framed accordingly (`_print_constraint_result`
vs. `_print_capacity_result`). Contested rate has been reported since the ToT entry above landed
(`scoring.contested_rate`, `Contested: 3/24 (12.5%)` on the demo fixture) — above the ~1% target
for the reason already recorded there (fixture size).

---

## 11. Environment setup

Implementation runs in **Claude Code**. This spec file lives in the repo root so Claude Code
reads it on every session.

**Runtime:** Python 3.12, virtual environment via `uv` (`.venv312`). Pinned exactly, not the
general "3.11+" floor a spec section like this would otherwise state, because CrewAI 1.x
hard-imports `chromadb` in its own `__init__` chain (`crewai` → `crewai.memory.unified_memory`
→ `crewai.rag.chromadb.config` → `chromadb.config.Settings`) whether or not this project ever
touches CrewAI's memory subsystem. `chromadb.config.Settings` subclasses `pydantic.v1
.BaseSettings`, and that shim cannot construct on Python 3.14 — `import crewai` itself raises
`pydantic.v1.errors.ConfigError: unable to infer type for attribute "chroma_server_nofile"`
before any of this project's code runs. Confirmed CrewAI 1.15.18 is PyPI's current latest, so
this isn't fixed by upgrading; confirmed Python 3.12 imports and constructs a CrewAI `Agent`
cleanly. 3.11 and 3.13 were not tested — 3.12 is the one verified to work, so it's the one
specified. `.venv` (3.14) is kept alongside `.venv312` for the rest of the toolchain that
doesn't touch CrewAI; `.venv312` is the working environment from Slice 3 onward.

**Packages:** `crewai`, `langchain`, `langchain-anthropic`, `requests`, `pydantic`,
`pandas`, `python-dotenv`, `pytest`. `chromadb` and `faiss-cpu` are no longer installed for
this project's own use — Slice 2's retrieval layer (`retrieval/vector.py`/`mmr.py`) replaced
chromadb with a from-scratch TF-IDF + MMR implementation after chromadb failed outright on
Python 3.14 (see PROGRESS.md 2026-09-01), so **no RhinoSecure code needed to change** for the
Python 3.12 pin above — chromadb is reachable only as CrewAI's own transitive dependency, not
anything this project imports. `sqlite3` is standard library — no install.

**Model:** `claude-sonnet-5` for all agent calls. Pin this exact string — from the 4.6
generation onward, a dateless model ID maps to one fixed snapshot rather than floating to the
newest release, so pinning keeps runs reproducible across the project. Sonnet is the right
tier here: agent runs make many calls and Opus costs significantly more per token.

**Keys, in `.env`, never committed:**
- `ANTHROPIC_API_KEY`
- `NVD_API_KEY` — free from NIST, raises the NVD rate limit substantially

**Endpoints:**
- NVD API v2.0 — `nvd.nist.gov/developers/vulnerabilities` (v1 is retired; key goes in the `apiKey` header)
- CISA KEV — `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- EPSS — `api.first.org/data/v1/epss`; bulk daily CSV at `epss.empiricalsecurity.com/epss_scores-current.csv.gz`
- MITRE ATT&CK — `mitre-attack/attack-stix-data` on GitHub (use the Enterprise bundle; filter to Windows platform)

**Tooling:** DB Browser for SQLite for inspecting the memory database.
