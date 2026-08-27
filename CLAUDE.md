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

**Threat** (likelihood the finding is actually attacked)
- CVSS exploitability sub-metrics
- EPSS probability
- CISA KEV membership (strong multiplier — known exploited in the wild)
- Internet exposure of the host asset
- Whether mapped ATT&CK techniques are commonly observed

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

Bucket assignment is a risk-score threshold picking a tier, then asset attributes deciding
which bucket within that tier applies:

- Thresholds: `patch_now` at risk ≥ 70, `accept` below risk 18, `next_window` /
  `mitigate_monitor` occupy the range between. These are named constants in `scoring.py`
  (`PATCH_NOW_THRESHOLD`, `ACTIONABLE_THRESHOLD`) and are expected to be retuned once Slice 2
  wires in KEV and EPSS — they were calibrated against a Threat side that is currently
  near-binary (only severity and internet exposure vary it), and KEV/EPSS will add spread
  there that the current cutoffs don't yet account for.
- `mitigate_monitor` requires **both** a compensating control **and** the absence of a
  declared patch window. A control alone, on an asset that still has a scheduled patch
  window, is not "blocked" — it will be patched on schedule with the control covering it
  meanwhile.
- A blank `patch_window` means **no declared scheduling restriction**, not that patching is
  impossible. On its own it does not push a finding toward `mitigate_monitor` or `patch_now`;
  absent a compensating control as well, it stays in `next_window`.

### Anchor demonstration

The headline result must be reproducible on the demo fixture: **one identical CVE, three
Windows hosts, three different verdicts** driven entirely by business context. Candidate
Windows-native anchors with strong KEV and ATT&CK coverage: ProxyLogon, ProxyShell,
PrintNightmare, ZeroLogon, BlueKeep, Follina. A Java/Log4j anchor also works if hosted on a
Windows IIS or VMware-adjacent asset, but at least one anchor should be Windows-native so the
Windows scoping earns its keep.

**Decided.** `F14` (`CVE-2023-23397` on WKS-FIN12) stays at `scanner_severity=low`. This is
intentional bad data, not a mistake: `CVE-2023-23397` is a KEV-listed Critical, and the low
scanner value models a scanner under-calling severity on a known-exploited vulnerability. It
is a Slice 2 exit-criteria case — enrichment (NVD + KEV) must correct the assessed severity
from authoritative sources, overriding the scanner's stale/wrong call. Do not "fix" the CSV;
the mismatch is the point.

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

1. The 15-finding demo dataset is a **fixture**. It proves specific behaviors. Do not
   regenerate it — the rule bars wholesale regeneration (reshuffling or re-deriving the
   dataset to make numbers look better), not a deliberate, individually-justified row added to
   close a named coverage gap (e.g. the `A12`/`F15` addition for `mitigate_monitor`, Section 3).
   Any such addition lands in its own commit stating the reason.
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

## 9. Repository layout

```
rhinosecure/
  CLAUDE.md                  # this file
  README.md
  pyproject.toml
  .env.example
  data/
    demo/                    # 15-finding fixture — FROZEN
      assets.csv
      findings.csv
    full/                    # generated, seed 42
      assets.csv
      findings.csv
    snapshots/
      kev.json
      epss.json
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

**Runtime:** Python 3.11+, virtual environment via `uv` or `venv`.

**Packages:** `crewai`, `langchain`, `langchain-anthropic`, `requests`, `pydantic`,
`pandas`, `python-dotenv`, `pytest`. Vector store for Slice 2 retrieval: `chromadb` or
`faiss-cpu`. `sqlite3` is standard library — no install.

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
