# RhinoSecure

RhinoSecure turns raw vulnerability scanner output into a ranked, explainable remediation
plan for a Windows enterprise. Its thesis: **CVSS severity alone isn't enough to prioritize
patching.** A critical CVE on an internet-facing production server and the same CVE on an
isolated dev box are different problems, and a plan that can't tell them apart isn't
actionable. RhinoSecure scores each finding as `Risk = Threat × Impact`, where Threat comes
from live sources (NVD, CISA KEV, FIRST EPSS, MITRE ATT&CK) and Impact comes from business
context declared in the asset inventory (criticality, internet exposure, environment, data
sensitivity, operational patching constraints). The same CVE on three different hosts lands
in three different remediation buckets, and every verdict comes with cited evidence for why.

**Actively in development, not a finished product** — see [Status](#status) near the bottom for
what's solid today and what's still rough.

Scoring is deterministic and LLM-free. An optional agent layer (CrewAI, Claude) wraps it to
produce cited narrative rationale, escalate genuinely contested findings to a Tree-of-Thought
search over remediation strategies, and accept human operational constraints in plain English
("the payroll server only reboots on Sundays") and re-plan around them. See
[CLAUDE.md](CLAUDE.md) for the full design spec and [PROGRESS.md](PROGRESS.md) for build
history — this file is just enough to get it running.

## Setup

Requires **Python 3.12**. The deterministic scoring path itself only needs `>=3.11`, but the
agent layer's dependency, CrewAI, transitively imports `chromadb` on module load regardless of
whether this project touches CrewAI's own memory subsystem — and `chromadb`'s `pydantic.v1`
settings shim fails to construct on Python 3.14. 3.12 is the version confirmed to work end to
end, so it's what every path here assumes.

```bash
python3.12 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate (cmd) or Activate.ps1 (PowerShell)
pip install -e ".[agents,dev]"   # deterministic path + agents/LLM path + pytest
cp .env.example .env             # then fill in ANTHROPIC_API_KEY (agent path only)
```

`NVD_API_KEY` in `.env` is optional — it raises NVD's rate limit but every CVE in the demo
fixture already has a committed snapshot, so `--offline` never touches the network for it.
Run `pytest` to confirm the install (1,433 tests, no network or API key required).

Everything below runs against data checked into the repo: `data/demo/` (the frozen
24-finding fixture), `data/demo-anchor/` (three of those findings, for a cheap agent-path
demo), and `data/defender-sample/` (a synthetic Microsoft Defender export). `--offline` means
every command runs from committed snapshots — no network calls except the two examples that
make real Claude API calls, noted where they do.

## The deterministic path

No LLM, no network. CSVs in, a ranked and bucketed plan out — reproducible and free.

```bash
rhino run --data demo --seed 42 --offline
```

```
finding_id  cve_id          hostname   bucket            risk_score
----------  --------------  ---------  ----------------  ----------
F01         CVE-2021-26855  EXCH01     patch_now         85.5
F04         CVE-2020-1472   DC01       next_window       46.6
F09         CVE-2022-21907  WEB01      next_window       43.8
F02         CVE-2021-26855  EXCH02     next_window       36.0
...                                                        (24 rows total)
F24         CVE-2020-16938  DEVBOX01   accept            1.0

Contested: 3/24 (12.5%) of scored findings
```

`F01`/`F02`/`F03` are the same CVE (ProxyLogon) on three Exchange hosts — the headline
result: identical technical severity, three different verdicts, driven entirely by exposure,
criticality, and controls. `contested` means the scorer found no honest bucket among the four
real ones (today: a KEV-confirmed finding with no known control or patch window) and refuses
to guess — that's what the agent path's Tree-of-Thought search and constraint submission
(below) are for. Add `--explain` for cited, per-finding rationale.

## The agent path

Wraps the same scoring in four agents (Coordinator, Vulnerability Research, Environment
Analysis, Risk & Recommendation) that produce cited narrative rationale on top of the identical
deterministic verdict — makes real Claude
API calls (a few cents, well under a minute for a handful of findings). Requires
`ANTHROPIC_API_KEY` in `.env`. `data/demo-anchor/` is the same three ProxyLogon hosts pulled
out of the full fixture, kept small so this is cheap and fast to actually run rather than
just read about.

```bash
rhino run --agents --quiet --data demo-anchor --offline --explain
```

```
finding_id  cve_id          hostname   bucket            risk_score
----------  --------------  ---------  ----------------  ----------
F01         CVE-2021-26855  EXCH01     patch_now         85.5
F02         CVE-2021-26855  EXCH02     next_window       36.0
F03         CVE-2021-26855  EXCHDEV01  mitigate_monitor  16.3

Contested: 0/3 (0.0%) of scored findings

F01 (CVE-2021-26855 on EXCH01) -> patch_now

  This finding lands in the patch_now bucket with a risk score of 85.5/100. The single biggest
  driver is that CVE-2021-26855 is a CISA KEV-listed, near-certain-to-be-exploited (EPSS
  0.99996) critical flaw (CVSS 9.8) sitting on an internet-facing, production Exchange server
  with no compensating controls.
  - epss=1.000, is_kev=True -> EPSS already clears the KEV floor -> x1.600 likelihood multiplier
  - ATT&CK: confirmed via procedure example -- T1190 (Exploit Public-Facing Application)
  - criticality=5/5, environment=prod, data_sensitivity=confidential, role=exchange
  - patch_window='Sun 02:00-06:00' declared -> defer to this window
```

Same risk scores as the deterministic table (85.5 / 36.0 / 16.3) — the agent layer never
overrides `scoring.py`'s arithmetic, it's checked against it (`verify_scoring_matches_tool`).
`EXCH02` and `EXCHDEV01` get their own full rationale the same way, differing only on
exposure, criticality, and the isolated dev box's compensating control.

## The Defender adapter

Ingest adapters translate a real scanner export into the same schema the deterministic and
agent paths already consume — no changes to scoring, enrichment, or agents. `defender` is the
first one, reading Microsoft Defender Vulnerability Management's own exported tables:

```bash
rhino run --format defender --data defender-sample --offline
```

```
finding_id             cve_id          hostname                    bucket       risk_score
---------------------  --------------  --------------------------  -----------  ----------
MDVM-F59E5560181150D0  CVE-2022-21907  web01.corp.example.com      next_window  50.6
MDVM-F5A5FC8781563B20  CVE-2021-34527  web01.corp.example.com      contested    42.7
MDVM-F3537E29A8CD2380  CVE-2020-1472   dc01.corp.example.com       contested    35.5
...                                                                              (9 rows total)

Contested: 6/9 (66.7%) of scored findings

Data gaps (--format defender): fields this export has no concept of, or left blank.
  assets   5/5  business_function, compensating_controls, data_sensitivity, environment,
                owner, patch_restrictions, patch_window, role
  assets   1/5  criticality
  findings 9/9  detected_date, port, service
  The bucket rules read a blank patch_window as "no declared restriction" and blank
  compensating_controls as "none"; for these assets both mean "not collected". Supply the
  real ones per asset with `rhino constraint add`.
```

Defender exports no maintenance window, compensating controls, or business role — a real
scanner carries technical facts, not organizational context. RhinoSecure tracks exactly which
fields are missing rather than guessing (`Asset.not_collected`), which is why six of nine
findings land `contested` here: with no known window or control anywhere in the fleet, that's
the honest verdict, not a bug. `rhino constraint add` (next) is how the gaps get filled in.

## Constraint submission

A human states an operational fact in plain English; the Constraint Interpreter agent
resolves it to an asset and a re-plan, scoped to just the findings it affects — not the whole
fleet. Also makes real Claude API calls.

```bash
rhino constraint add "WKS-FIN12 can only be patched during the Friday afternoon \
maintenance slot, 13:00-15:00" --data demo --offline
```

```
Interpreting constraint...
  asset: A09
  effect: patch_window = 'Friday afternoon maintenance slot, 13:00-15:00'
  affects: F07, F14, F22

Constraint #1 persisted. Re-planned 3 finding(s).

Diff (2/3 finding(s) changed):

  F07 (CVE-2022-30190 on WKS-FIN12): contested (18.7) -> next_window (18.7)
    + patch_window='Friday afternoon maintenance slot, 13:00-15:00' declared -> defer to this window
    - bucket=contested: is_kev=True with no compensating control and no patch window -- ...

  F14 (CVE-2023-23397 on WKS-FIN12): contested (25.5) -> next_window (25.5)
    + patch_window='Friday afternoon maintenance slot, 13:00-15:00' declared -> defer to this window
    - bucket=contested: is_kev=True with no compensating control and no patch window -- ...
```

Two findings that had no honest bucket now do — `risk_score` is unchanged in both cases,
because the constraint changed what's *known* about the asset, not how risky the finding is.
The constraint persists in `rhinosecure.db` (SQLite, gitignored) and is picked up
automatically by every later `--agents` run, no need to restate it.

## Web UI

`rhino web` serves a browser UI over a plan: pipeline status (Ingest / Enrichment / Scoring /
Agents / Tree-of-Thought), the ranked findings table with cited rationale, contested findings
and their ToT branches, data gaps, and a constraint form.

```bash
rhino web --data demo --offline
```

On Windows, Smart App Control blocks the unsigned `rhino.exe` console shim — run
`python -m rhinosecure.cli web --data demo --offline` instead.

With `--enable-jobs`, it also accepts CSV uploads and dispatches ingest, scoring, and the agent
crew itself as background jobs from the browser — no CLI needed at all, including against a
mapping nobody's confirmed yet (see Status).

## Status

Actively in development — built as a Carnegie Mellon Agentic AI capstone project, not a
finished product. The deterministic path, the four-agent crew, Tree-of-Thought, and constraint
intake described above all work end to end and are exercised by the test suite. Also built
since: LLM-assisted adapter generation (`rhino adapt propose`/`confirm`) that maps an arbitrary
CSV onto the scoring schema behind a human attestation gate, a schema target registry backing
that generation, a provisional run path that scores an unconfirmed mapping anyway — drop a CSV,
get a scored plan, no signature required — remediation tracking (`rhino remediation
mark`/`log`), and the web UI above.

Known rough edges, named rather than hidden: ingesting an unfamiliar CSV format can still fail
in specific, sometimes hard-to-predict ways depending on how far its shape diverges from what
the schema-inference model expects; and Tree-of-Thought currently reports a near-tie on
essentially every contested finding it runs against, surfacing both branches to a human rather
than the ranking it actually computed. See [CLAUDE.md](CLAUDE.md) for the full spec, scoring
model, and open items.
