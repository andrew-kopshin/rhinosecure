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

† Not a remediation category a human acts on directly. It means the deterministic scorer
could not truthfully assign one of the four real buckets and the finding needs Tree-of-Thought
or human reasoning instead (Section 6). Currently emitted only for a KEV-listed finding with
neither a compensating control nor a declared patch window.

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

- The schema has no way to distinguish "no patch window recorded" (a data gap — nobody has
  documented one yet) from "patching is genuinely unconstrained" (a deliberate fact about the
  asset). Both currently produce the same blank `patch_window` value and the same downstream
  treatment. This matters more once real scanner data replaces the fixture, where blank
  fields are far more likely to mean "not collected" than "not applicable."

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

**First concrete gate.** `bucket_for` (Section 3) already detects one structural instance of
this deterministically, ahead of Slice 4 existing: a KEV-listed finding with neither a
compensating control nor a declared patch window has no honest bucket among the four real
ones, and `score_finding` returns `Bucket.CONTESTED` for it rather than guessing. The demo
fixture's `F14` is this case today. Until `tot.py` exists, `contested` is a terminal CLI output
— a flag for human judgment, not yet a routed beam search. When Slice 4 is built, `Bucket.CONTESTED`
is the trigger condition that should drive findings into the ToT root, and this specific case
is the first one to validate against. Note it also complicates the canonical branch set below:
"accept and monitor" is not a valid branch for it — a KEV finding is disqualified from `accept`
by definition — so the three initial branches will need a fourth option (or a substitute for
that one) for findings that reach ToT this way. Other contested paths (e.g. EPSS/KEV disagreement
on a blocked patch window) are qualitative, not yet formalized as a `bucket_for` rule, and remain
future work.

- **A thought is a remediation strategy**, not an explanation
- Root: the contested finding plus all gathered evidence
- ~3 initial branches: patch immediately / compensating control + defer / accept and monitor
- Beam width 2, max depth 3
- Critic scores each branch on: risk reduction, operational cost, constraint compliance, evidence strength, contradicting evidence
- Terminate on clear winner, depth limit, or exhausted evidence
- **Near-tie → surface both branches to the human.** Do not force a single answer.

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
   item done — a general citation-vs-evidence checker across all three agents is still unbuilt.
3. **Tool-call retry cap.** No bound yet on how many times an agent may retry a failed tool call
   (an NVD timeout, a malformed EPSS response) before it must stop and escalate instead of
   looping.
4. **Cost/usage visibility.** "Trust boundary and provider independence" (above) accepts
   per-run cost as an operational property of the LLM dependency, but `rhino run --agents`
   prints nothing about it — a run's actual token usage and dollar cost are currently invisible
   from the CLI. `Coordinator`'s `RunState` already collects `research_usage`/
   `environment_usage`/`risk_usage` (one `crewai` `UsageMetrics` per stage) — nothing reads them
   back out. The 24-finding run PROGRESS.md logged as confirming Slice 3's exit criteria could
   only report an *extrapolated* cost (≈$3.3, from an earlier smaller run's measured rate) for
   exactly this reason. `rhino run --agents` should print total tokens and an estimated dollar
   cost at the end of a run.

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
    full/                    # generated, seed 42
      assets.csv
      findings.csv
    snapshots/
      kev.json                 # bulk catalog, one file
      epss/                    # per-CVE, queried live against api.first.org
      nvd/
      attack/
  src/rhinosecure/
    schema.py                # dataclasses + CSV validation
    ingest.py
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
