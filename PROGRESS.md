# RhinoSecure — Progress Log

Factual, dated record of what changed and why. Not a design doc — see CLAUDE.md for the
current spec and rationale; this file is the history of how it got there.

## 2026-08-27

**KEV + EPSS wired into the threat term.** KEV and EPSS are treated as different kinds of
claim: EPSS is a model's probability estimate, KEV is CISA's record of confirmed exploitation.
EPSS sets the likelihood multiplier (`0.6 + epss`, range 0.6–1.6); KEV sets a **floor** under
it (`max(epss_multiplier, 1.5)`) instead of multiplying on top of it, so an observation can't
be diluted by — or compounded with — a prediction that disagrees with it. A KEV CVE the model
underrates gets pulled up to the floor; a KEV CVE the model already rates highly is left alone.

**Fixture repair: KEV and EPSS were both non-discriminating.** The original 15-finding fixture
was built from famous anchor CVEs (ProxyLogon, ZeroLogon, PrintNightmare, etc.). Checked
against the live feeds: 13/15 (87%) were KEV-listed and 14/15 (93%) had EPSS above 0.92 — both
signals near-saturated, so wiring them in would have added almost no spread. Added 9 real,
verified mundane Windows CVEs (outdated/superseded components, info disclosure, local privesc
requiring prior access), each checked live and kept only if EPSS < 0.05 and not KEV-listed.
Fixture is now 24 findings across 12 assets.

**Bucket rule: KEV disqualifies `accept`.** A KEV-listed finding can no longer land in
`accept` — confirmed exploitation and "we are fine with this" are incompatible. `is_kev` forces
at least the actionable tier; the existing compensating-control/patch-window logic still picks
`mitigate_monitor` vs `next_window` within it, unchanged. The one combination that logic can't
resolve honestly — KEV-listed, no compensating control, no patch window — has no truthful
bucket among the four remediation categories, so it's marked `contested` instead of forced into
one. Added as `Bucket.CONTESTED`, documented as the first concrete trigger for Slice 4's
Tree-of-Thought gate (not yet built).

**The contested rule found more than it was built for.** It was scoped against 4 findings that
were sitting in `accept`. Applied, it also caught `F11` (WKS-IT05, SMBGhost) and `F07`
(WKS-FIN12, Follina) — both already in `next_window`, both KEV-listed, both with no
compensating control and no patch window. `next_window` was silently implying they were
scheduled when nothing was. Neither finding was in the discussion that produced the rule; the
rule caught them anyway because the condition it checks (`is_kev` + no control + no window) is
what mattered, not the bucket a finding happened to start in.

**Live instance of why snapshotting matters.** `CVE-2019-1068` (on the fixture's `F15`, added
last session specifically to exercise `mitigate_monitor`) entered the CISA KEV catalog on
2026-08-26 — one day before this session — with a due date of 2026-08-29, a three-day window.
Mid-project, a fixture CVE picked for an unrelated reason became actively exploited with an
active remediation deadline. `data/snapshots/kev.json` is pinned to the version fetched this
session; without that, a rerun next week would silently produce different KEV/EPSS numbers for
the same fixture, breaking the reproducibility CLAUDE.md Section 4 requires.

**NVD wired: authoritative CVSS overrides scanner_severity.** `enrich/nvd.py` queries the v2.0
API per CVE with retry-with-backoff on 403/429 (real NVD throttling hit repeatedly while
fetching the fixture's 20 CVEs unauthenticated, and recovered every time). NVD's base_score
overrides the scanner's severity tier on disagreement, and provenance (which source, and
whether they disagreed) is recorded on every finding's rationale. 10 of 24 findings disagree.
`F14`'s risk climbs 1.99 → 30.62 (15.4x) once applied — the correction the earlier F14 decision
named. Bug caught along the way: NVD's metric arrays can hold two scorers (vendor CNA + NVD
itself) and aren't reliably ordered NVD-first; a naive `entries[0]` silently took Microsoft's
5.5/medium for ZeroLogon over NVD's own 10.0/critical. Caught by inspection, not by a test:
5.5/medium contradicted ZeroLogon's well-known real-world severity (an unauthenticated
domain-controller takeover), which is what prompted checking the raw response instead of
trusting the parsed value. Fixed to select by NVD's `"Primary"` tag instead of position.
Also corrected the risk-normalization ceiling (`MAX_SEVERITY_BASE`), which still assumed
severity topped out at 9.5 (the old scanner-tier proxy) even though NVD's real scores can
reach 10.0 — no finding was close enough to the old ceiling to have visibly clipped,
but it would have.

**Fixture correction: 10/24 scanner/NVD disagreements was too many to be deliberate.** `F16`-
`F24`'s `scanner_severity` values were assigned by hand for narrative variety when those rows
were added, not derived from anything real. 7 of the 9 turned out to disagree with NVD, all in
the same direction (NVD higher) — unexamined placeholder data, not a realistic scanner failure
mode. Corrected those 7 to match NVD. Left exactly three deliberate disagreements, each with a
specific reason: `F12` (under-called), `F14` (under-called, the designated bad-data case),
`F15` (over-called — the opposite direction, enrichment pulling a score down instead of up).
3/24 (12.5%) reads as a realistic scanner; 10/24 (42%) read as a broken one. No scoring output
changed — `_resolve_severity` was already using NVD's real score for all 7 regardless of what
the CSV said — confirmed the bucket distribution and every finding's risk score are unchanged.

**The thesis demonstrating itself.** Seven of those nine mundane findings (`F17`-`F23`) had
`scanner_severity` corrected up to 7.8/high once matched to NVD, and their risk scores rose
with it — up to roughly 10x (e.g. `F17`: 0.95 → 9.26). None crossed `ACTIONABLE_THRESHOLD`
(18); the highest landed at 10.32. Their EPSS stayed under 0.05 throughout, so the threat term
never moved enough to matter, regardless of how technically severe NVD rated them. This is
CLAUDE.md Section 1's thesis — "CVSS alone is an insufficient prioritization signal" — playing
out on real data rather than being asserted: a high-severity, low-exploitation-probability
finding correctly stays low priority, because Risk = Threat × Impact means a strong score on
one axis can't rescue a weak one on the other.

## 2026-09-01

**ATT&CK wired in, two-tier: confirmed feeds the score, candidate stays informational.**
`enrich/attack.py` fetches the Enterprise STIX bundle and filters to Windows-platform
techniques, but there is no direct CVE → technique edge anywhere in ATT&CK's own data — that
bridge normally runs through CAPEC/CWE, which CLAUDE.md Section 11 does not name as a source
for this project. Two tiers instead: **confirmed**, when a CVE is explicitly named in an
ATT&CK "uses" relationship's procedure-example text (a tracked group or malware/tool STIX
object documented exploiting it — e.g. HAFNIUM's relationship to T1190 cites CVE-2021-26855 by
name), and **candidate**, IDF-weighted keyword overlap between the finding's product/evidence
text and technique name+description, for CVEs no procedure example happens to mention. Only
confirmed matches feed `ThreatInputs.attack_prevalence`; candidates are attached to the finding
and shown in rationale but never move a score. Candidate matching is a hand-tuned stand-in for
the MMR-reranked vector retrieval CLAUDE.md Section 4 actually specifies for ATT&CK prose —
`retrieval/vector.py`/`mmr.py` don't exist yet — and lexical overlap can't reliably distinguish
"rare because specific" from "rare because unusual phrasing," so it isn't confident enough
evidence for a deterministic score the way an explicit procedure-example citation is.

**Bundle filtered before it touches disk, not after.** The raw Enterprise bundle is 53,835,637
bytes (~51MB) and covers every platform (macOS, Linux, cloud, network devices, PRE) and STIX
object type (mitigations, campaigns, data sources) this project has no use for. Committing it
verbatim, the way kev.py/epss.py/nvd.py cache their raw responses, would have bloated the repo
with data nothing here reads. `_fetch_and_filter` does the filtering inline — Windows platform,
not revoked, not deprecated — before anything is written, so only the reduced structure is
persisted: `data/snapshots/attack/enterprise-windows.json`, 765,060 bytes (~747KB), 474 of the
bundle's 858 total techniques, plus a 161-entry CVE-mention index built by regex-scanning kept
relationships' descriptions. ~70x smaller than the source, and the only artifact this project
ever reads back.

**Real split: 7 confirmed / 14 candidate / 3 none, across the 24-finding fixture.** Three
techniques got confirmed matches, each because a famous, heavily-tracked anchor CVE is
well-documented enough for ATT&CK's own procedure examples to name it: T1190 Exploit
Public-Facing Application (`CVE-2021-26855`/`CVE-2021-31207`, ProxyLogon/ProxyShell — `F01`,
`F02`, `F03`, `F13`), T1210 Exploitation of Remote Services (`CVE-2020-1472`, ZeroLogon —
`F04`), and T1203 Exploitation for Client Execution (`CVE-2022-30190`, Follina — `F07`, `F08`).
The remaining 14 findings got only unconfirmed keyword candidates, and 3 (`F10`, `F23`, `F24`)
got nothing above the candidate-tier confidence bar at all. Bucket distribution is unchanged
from before this session (`patch_now=1, next_window=8, contested=3, mitigate_monitor=3,
accept=9`) — ATT&CK prevalence is refining risk scores within buckets, not reshuffling them.

**Limitation: the confirmed tier mostly re-confirms what KEV/EPSS already said.** Checked the
four distinct CVEs behind the 7 confirmed matches against the fixture's own KEV/EPSS snapshots:
all four are KEV-listed, and all four carry EPSS ≥ 0.992 — the same near-saturated territory
the 2026-08-27 entry above already documented for the fixture's famous anchors ("13/15 KEV,
14/15 EPSS > 0.92"). ATT&CK's confirmed tier is not surfacing new information about which
findings matter; it is re-deriving, from a third independent-in-principle source, the same
"this one is famous" signal KEV and EPSS were already saturated on. That is a real property of
public threat-intel sources, not a mapping bug: KEV, EPSS, and ATT&CK procedure-example
documentation all preferentially track whichever CVEs are well-documented, so three sources
that each individually look independent correlate heavily in practice once a CVE is famous
enough for all three to have noticed it. It is also, after the fact, a second reason the
confirmed/candidate split was the right call beyond the CAPEC/CWE-bridge argument above: on this
fixture, confirmed-tier ATT&CK data added least exactly where the score already had the most
reason to be high, and the candidate tier — informational rather than score-moving — is where
the mundane, non-KEV, low-EPSS findings' only ATT&CK context actually shows up.

**The candidate tier's keyword heuristic replaced with real vector retrieval + MMR.**
CLAUDE.md Section 11 names chromadb for this; it fails outright on Python 3.14 — its `Settings`
class subclasses `pydantic.v1.BaseSettings`, and pydantic's v1-compat shim does not support
3.14, raising `ConfigError: unable to infer type for attribute "chroma_server_nofile"` before a
single document is ever embedded. Confirmed by actually running it, not assumed. faiss-cpu
installs cleanly but only indexes vectors someone else generates — it doesn't solve the "where
do the vectors come from" problem, and at ~500 short documents a nearest-neighbor index buys
nothing over brute force anyway. Built `retrieval/vector.py` (TF-IDF + cosine similarity) and
`retrieval/mmr.py` (Carbonell & Goldstein reranking) instead: no new dependency, fully local and
deterministic — the same offline/reproducibility bar as the rest of Slice 2, which a neural
embedding model would not clear as cleanly — and not a fallback in the pejorative sense, since
TF-IDF vector space is the actual substrate the original 1998 MMR paper was built and evaluated
on, predating neural embeddings by over a decade. `enrich/attack.py`'s candidate tier now
retrieves a 20-wide pool by cosine similarity and reranks to 5 with MMR; the old hand-curated
CVE-advisory-boilerplate stopword list is gone, since IDF weighting down-weights common corpus
terms in proportion to how common they actually are, rather than by a hand-picked list tuned
against one fixture's wording.

**MMR's own effect, isolated from the vector-vs-keyword swap: F14 (Outlook, CVE-2023-23397).**
Before reranking, the top-5 candidate pool by cosine similarity alone was dominated by a
redundant cluster — Outlook Forms (0.301), Outlook Rules (0.260), Local Email Collection
(0.228), and Outlook Home Page (0.212) are 0.36–0.59 pairwise-similar to each other, all
restating "Outlook abuse" rather than adding distinct evidence. MMR at λ=0.5 kept Outlook Forms
(still the most relevant single match) but broke up the rest of the cluster, surfacing Pass the
Hash (T1550.002) instead — which is arguably the mechanistically correct technique for this
specific CVE (an NTLM hash leak) and which plain top-5 relevance ranking had buried outside the
returned set entirely. This is CLAUDE.md Section 4's literal argument playing out on real data:
"rather than eight restatements of the same CVSS score."

**Limitation: TF-IDF can still produce a confident coincidence, and no threshold fixes that.**
`F12` (MSMQ, `CVE-2023-21554`/QueueJumper) matches the credential-attack family — Credential
Stuffing, Password Spraying, AS-REP Roasting — at cosine similarity 0.26–0.29, purely on
"listener"/"accepts"-type vocabulary overlap with no real topical connection to message queuing.
That score is *higher* than several genuinely correct matches elsewhere in the fixture (e.g.
`F19`'s OLE-DB-to-SQL-Stored-Procedures match at 0.177), so `MIN_CANDIDATE_SIMILARITY` cannot be
tuned to separate true from coincidental matches by magnitude alone — some false positives
outscore true positives. This is a real, disclosed property of lexical/statistical similarity
generally (see `retrieval/vector.py`'s and `enrich/attack.py`'s docstrings), not a bug to chase
with a different cutoff. It doesn't matter for scoring: candidates stay informational regardless
of how confident-looking their similarity score is, and only confirmed CVE-mention matches ever
feed `attack_prevalence` — bucket distribution and every finding's risk score are byte-identical
before and after this change.

## 2026-09-02

**CrewAI hard-imports chromadb; chromadb doesn't run on Python 3.14.** Installing CrewAI and
langchain-anthropic into the existing `.venv` (Python 3.14) and running the full suite showed
nothing wrong — all 93 tests passed, because no code anywhere imports `crewai` yet
(`src/rhinosecure/agents/` is still empty; Slice 3 hasn't started). A separate throwaway runtime
check (`from crewai import Agent`) caught what the test suite structurally couldn't: `import
crewai` itself raises before any of this project's code or `langchain_anthropic` is even
reached. CrewAI's own `__init__` chain pulls in its memory subsystem unconditionally —
`crewai` → `crewai.memory.unified_memory` → `crewai.rag.chromadb.config` → `chromadb.config
.Settings` — and `Settings` subclasses `pydantic.v1.BaseSettings`, whose v1-compat shim cannot
construct on Python 3.14: `pydantic.v1.errors.ConfigError: unable to infer type for attribute
"chroma_server_nofile"`. This is one step worse than the 2026-09-01 finding that chromadb fails
when *this project* constructs it — CrewAI can't even be imported, independent of anything
RhinoSecure does.

**Confirmed there's no newer CrewAI release to fix it.** `pip index versions crewai` reported
`LATEST: 0.11.2`, which looked like a viable downgrade-and-retry path until checked against
PyPI's JSON API directly: `info.version` is `1.15.18` — the version already installed — and
`pip`'s answer was wrong because it string-sorted version numbers lexicographically
(`"1.15.18" < "1.9.3"` as strings, so `1.15.x` releases sorted before and were dropped from its
notion of "latest"). Enumerating all 1.15.x releases by parsed version confirms 1.15.18 is the
newest non-yanked build. The chromadb hard-import isn't a regression an upgrade fixes; it's the
current shipped state of CrewAI's dependency tree.

**No Python 3.11–3.13 was installed on this machine.** Only 3.14 (`AppData\Local\Programs
\Python\Python314`, what `.venv` was built from). `uv` was already present in `.venv/Scripts`
as a transitive CrewAI-CLI dependency; used `uv python install 3.12` to fetch a standalone
build directly (~20.9MiB, from the same `python-build-standalone` project uv's own Python
management is built on) rather than a system-wide installer. Its convenience symlink step
errored (`Missing expected target directory for Python minor version link`) but the interpreter
itself downloaded and runs fine — verified by invoking it directly before trusting it. Chose
3.12 over 3.11/3.13 as the most mature match for this exact dependency stack (chromadb's
`pydantic.v1` shim, crewai, langchain-anthropic); 3.11 and 3.13 were not tested.

**`.venv312` built alongside `.venv`, not in place of it.** `uv venv --python <3.12 interpreter
path> .venv312`. uv-created venvs ship without pip, so installs went through `uv pip install
--python .venv312/Scripts/python.exe -e ".[agents,dev]"` rather than `pip install -e` directly.
All 93 tests pass under 3.12, same as under 3.14 — expected, since the suite doesn't touch
CrewAI either way. `import crewai` succeeds under 3.12 with no chromadb error, confirming the
Python version, not this project's code, was the actual variable. `.venv` (3.14) was left
completely untouched throughout — never reinstalled into, never deleted.

**CrewAI's `Agent.llm` rejects a raw `langchain_anthropic.ChatAnthropic` instance.** Constructing
`Agent(role=..., goal=..., backstory=..., llm=ChatAnthropic(...))` under 3.12 raised a pydantic
validation error: CrewAI's `llm` field accepts a plain model string or an instance of CrewAI's
own `BaseLLM` wrapper, not a langchain object — `ChatAnthropic` itself imported and constructed
cleanly standalone, so this is CrewAI's API surface, not a Python-version or langchain-anthropic
problem. Passing `llm="anthropic/claude-sonnet-5"` (litellm-style provider/model string)
constructed the `Agent` cleanly and printed its role with no API call made. This is the form
Slice 3's agent wiring needs to use — CrewAI is not a langchain-object consumer here despite
`langchain-anthropic` being one of CLAUDE.md's named packages.

**Switched the working environment to `.venv312`.** CLAUDE.md Section 11 now pins Python 3.12
exactly (was "3.11+") with this episode's reasoning, and drops chromadb/faiss-cpu from the
packages this project itself installs — Slice 2's TF-IDF + MMR retrieval (2026-09-01, above)
already replaced chromadb before this session, so **no RhinoSecure code needed to change** to
fix the CrewAI import; the fix was entirely at the interpreter level. `.gitignore` now covers
both `.venv/` and `.venv312/`.

**Slice 3 complete: all four CrewAI roles built, chained, and verified against the deterministic
pipeline.** `agents/research.py`, `environment.py`, `risk.py`, `coordinator.py` — every role
CLAUDE.md Section 5 names now exists. Research wraps NVD/KEV/EPSS/ATT&CK as four tools bound to
one `SnapshotCache`; Environment wraps a local asset-inventory lookup as one tool (OS build,
exposure, controls, and patch constraints are facets of one Asset record, unlike Research's four
independent sources, so one tool covers all of it); Risk wraps `scoring.score_finding` as one
tool and is structurally barred from computing a score or bucket any other way (see below);
Coordinator dispatches all three in sequence and owns the shared state threading their structured
payloads together. Every tool call is logged (name, args, result) independent of CrewAI's own
execution tracing, and every agent's output is locked to a pydantic schema via `output_pydantic`
— CVE ID, severity, exploitation status, ATT&CK techniques (Research); OS/build consistency,
exposure, controls, patch constraints (Environment); risk_score, bucket, rationale, narrative
(Risk). No agent anywhere computes a risk score or bucket except by calling the one tool built
for that purpose.

**Coordinator is plain Python, not a CrewAI `Agent` — a deliberate, scope-bound choice.** Section
5 lists it in the same responsibility table as the three LLM-backed roles ("Plans the run,
dispatches work, owns shared state, owns every re-plan loop"), which reads as if it should be
symmetric with them. It isn't, on purpose: none of those four responsibilities needs model
reasoning at the scope built so far. The primary path's sequencing is fixed (`Research ->
Environment -> Risk`, not model-decided), and "re-plan" as built today —
`Coordinator.replan(finding_ids)` — is a mechanical re-dispatch of Environment and Risk for given
finding_ids, reusing Research's already-cached output, since Research is CVE-keyed and doesn't
depend on operational constraints. Interpreting free-form human constraint text into which
finding_ids need re-planning is genuinely LLM-shaped work — that's Slice 4 (constraint intake,
ToT, `tot.py`), not built yet, and it slots in ahead of `replan`'s argument, not inside Coordinator
itself. If Slice 4 changes that calculus, Coordinator becoming an actual `Agent` is the natural
next step; this is a decision scoped to what's built today, not a permanent architectural stance.
`RunState` holds everything Coordinator owns: per-stage results by finding_id, per-stage call
logs, and per-stage `crewai` `UsageMetrics` for cost visibility — CP4's "MCP correction"
(Section 1): agent state lives in the Coordinator, not passed through MCP or left implicit in a
crew's internal history.

**`verify_scoring_matches_tool`: grounding validation gets a first real enforcement check,
narrowly scoped.** Risk's task prompt tells the model to copy `score_finding`'s
risk_score/bucket/rationale verbatim, but a prompt instruction isn't a guarantee — the model's
final `output_pydantic` pass is itself an LLM call that could in principle round a number, swap a
bucket, or paraphrase a rationale line. `verify_scoring_matches_tool` (`agents/risk.py`) checks
the agent's final answer against the actual tool-call log entry for that finding_id and raises
`ScoringMismatchError` on any mismatch; `Coordinator._dispatch_risk` calls it after every Risk
task and propagates the exception rather than silently accepting drift. This is real, tested
enforcement — not the general "does every agent's rationale cite the evidence it was actually
given" checker CLAUDE.md's "Grounding validation" open item still asks for (that would also need
to check Research's and Environment's own outputs against their own call logs, which nothing does
yet). CLAUDE.md's open item is updated to reflect exactly this distinction rather than marked
done.

**Found a real gap while wiring Risk: `ResearchFinding` was missing ATT&CK prevalence.**
`AttackTechniqueSummary` carried `technique_id`/`name`/`confidence` but not `prevalence`
(enrich/attack.py's percentile-rank field) — without it, Risk's reconstruction of
`attack_prevalence` (a real threat-term input) had nothing to compute from. Added the field and
threaded it through `lookup_attack_techniques`'s tool JSON. Caught by writing a test that compared
the tool's reconstructed score against calling `scoring.score_finding` directly on equivalent
inputs — the two didn't agree until the fix, confirming it wasn't just a schema gap but an actual
scoring input gap.

**`rhino run --agents` wired into the CLI; the deterministic path's Python 3.14 compatibility
protected by a lazy import.** `cli.py` has no top-level import of anything crewai-shaped —
`agents.coordinator` is imported inside `run_agents()` and inside `main()`'s `--agents` branch
only, so plain `rhino run` keeps working on `.venv` (3.14), where `import crewai` itself fails
(this date, above). Confirmed by an AST-based test that parses `cli.py`'s source and asserts
nothing crewai/agents-shaped appears in its module-level import statements, and separately by
actually running `rhino run --data demo --seed 42 --offline` under `.venv` after the change —
unaffected, full 24-finding table, no import error.

**Verified: the agent crew reproduces the deterministic pipeline exactly.** Ran the full crew
(`Coordinator` dispatching Research → Environment → Risk) against F01 (ProxyLogon, patch_now),
F14 (the scanner/NVD severity-disagreement case, contested), and F19 (mundane/non-KEV, accept) —
both via `Coordinator` directly and via `rhino run --agents --explain` against a 3-finding subset.
Agent-produced risk_score/bucket matched the deterministic `cli.run()` output exactly for all
three (85.5/patch_now, 25.5/contested, 8.6/accept), `verify_scoring_matches_tool` passed silently
throughout, and the narratives correctly explain the non-obvious cases in plain language — e.g.
F14's narrative states why `contested` is the honest bucket rather than treating it as a scoring
quirk, and F19's separates "high severity" from "low priority" via the compensating-control
discount. 27 LLM requests (9 per stage) for the 3-finding run, ~130K tokens, **≈$0.41** at Sonnet
5 pricing ($2/$10 per MTok, cache write ≈1.25x, cache read ≈0.1x) — extrapolating linearly, a full
24-finding run would be on the order of $3-4, not yet run.

**Incident: the extrapolation above was optimistic. A real 24-finding `--agents` run hung on the
first finding, retrying an identical failure indefinitely.** `agentrun.txt` (the user's captured
run output, UTF-16-encoded) showed steady progress through 15 findings' worth of Research tool
calls, then nothing further — no traceback, no new activity, consistent with an internal retry
loop that stops producing any new visible output rather than a clean crash. Root cause, traced in
the installed `crewai` package (`crewai/utilities/converter.py`), not guessed: the model's final
answer for the stuck finding was syntactically valid JSON but shaped as `{"finding": {...fields}}`
instead of the fields directly. `Task._export_output` routes that through `convert_to_model`,
which catches the resulting `pydantic.ValidationError` and retries once via `handle_partial_json`
— but that function's own retry (`model.model_validate(parsed)`) fails identically and **re-raises
the `ValidationError` uncaught** (`except ValidationError: raise`, converter.py:317-318), with no
enclosing handler anywhere in that call chain. That exception then escapes `Task._export_output`
and `crew.kickoff()` entirely, into whatever retry logic sits above it in CrewAI's own execution
loop — which kept reproducing the same malformed shape rather than converging, and had no visible
bound.

**Fix: stop depending on CrewAI's own structured-output conversion for correctness at all.** Three
changes, all in service of that one decision:

1. **`agents/parsing.py`** (new) — `parse_structured_output(raw, model)` parses an agent's raw
   final-answer text into the target pydantic schema itself, tolerating exactly one shape beyond a
   direct match: a single top-level key wrapping the real fields (`{"finding": {...}}`,
   `{"result": {...}}` — any one key, not hardcoded to `"finding"`). Anything else (two-plus keys,
   non-JSON text, a wrapper whose inner value still doesn't validate) raises
   `AgentOutputParseError` rather than guessing further. 8 tests, all offline.
2. **No Task built by `research.py`/`environment.py`/`risk.py` sets `output_pydantic` any more.**
   Each task's raw text (`TaskOutput.raw`, always populated regardless of whether any conversion
   succeeds or even runs) is what gets parsed, by code this project owns instead of CrewAI's
   converter. `expected_output` on all three was rewritten to explicitly say "not wrapped in any
   container key" and spell out every top-level field name, since removing `output_pydantic` also
   removes whatever schema-injection prompting CrewAI was doing automatically.
3. **`Coordinator._resolve_output`** (new) is this project's own retry loop, capped at
   `max_parse_attempts` (default 3, configurable) fresh single-task re-dispatches — not CrewAI's.
   A finding that still won't parse (or, for Risk, still fails `verify_scoring_matches_tool` —
   folded into the same retry-then-skip loop, since a scoring mismatch is the same kind of
   untrustworthy-answer problem as a parse failure) after the cap is recorded into
   `RunState.research_failures`/`environment_failures`/`risk_failures` (finding_id -> reason) and
   excluded from that stage's `*_by_id` — never raised. A finding missing from an upstream stage
   because it failed there is skipped at every stage after that, recorded again at each one
   ("skipped: no ResearchFinding (Research failed for this finding)"), rather than the old
   behavior of `_dispatch_environment`/`_dispatch_risk` raising `CoordinatorError` and aborting
   every other finding along with it. `CoordinatorError` is now reserved for actual Coordinator
   misuse (`replan` before any `run`, `replan` naming an unknown finding_id) — provably nothing in
   `run()`'s own call path can raise it any more, so `cli.py`'s `--agents` branch no longer catches
   it or `ScoringMismatchError` (dead code otherwise); `rhino run --agents` now prints a `finding
   failed and were skipped` summary to stderr when `coordinator.state.*_failures` is non-empty.

**Verified two ways.** `tests/test_coordinator.py`'s fake `Crew` now feeds raw JSON text strings
(including a deliberately `{"finding": {...}}`-wrapped one) through the real
`parse_structured_output` path instead of injecting pre-built pydantic objects, so these tests
exercise the actual fix, not an assumption it works: a wrapped response resolves on the first
attempt with zero extra dispatches; a persistently-unparseable finding is retried exactly
`max_parse_attempts` times (counted precisely via Crew-instantiation count) then recorded and
skipped, without blocking a second, healthy finding in the same run; a Risk scoring mismatch is
recorded and skipped rather than raised. Separately, live: re-ran the same F01/F14/F19 trio from
the entry above end to end with the redesigned (no-`output_pydantic`) agents — identical results
(85.52/patch_now, 25.52/contested, 8.60/accept), zero recorded failures, and the console output
showed the model wrapping one answer in markdown code fences this run, which
`parse_structured_output`'s regex-based extraction handled transparently — a live example of the
defensive parsing already pulling its weight, not just passing synthetic tests.

**Slice 3 exit criteria confirmed on the full demo fixture: `rhino run --agents --data demo
--explain`, all 24 findings, zero failures.** Checked against Section 10's exit criteria
programmatically, not by eyeballing the transcript:

- **Ranking match.** Parsed the agent-produced table and diffed it row-by-row against a fresh
  `rhino run --data demo --seed 42 --offline` (the deterministic pipeline) for all 24
  finding_ids: 0 mismatches, exact rank order match, every bucket and risk_score (to the
  printed 0.1 precision) identical — `patch_now=1, next_window=8, contested=3,
  mitigate_monitor=3, accept=9`, unchanged from every deterministic run logged above. Section
  10's "any delta traceable to a named reasoning step" clause is vacuously satisfied: there is
  no delta to trace.
- **Rationale cites sources, on all 24, not a sample.** Every finding's `scoring_rationale`
  carries an explicit `source=nvd` or `source=scanner` tag, and every narrative explicitly
  names both "Research" and "Environment" by role when citing the facts that came from each —
  confirmed by parsing all 24 narrative blocks out of the transcript and checking every one,
  not spot-checking a few and assuming the rest match. Spot-read F01's block in full for prose
  quality: it correctly separates what NVD/KEV/EPSS/ATT&CK (Research) established from what the
  asset record (Environment) established, and ties both to the specific rationale line each
  fact drove (the KEV floor, the ATT&CK prevalence multiplier, the internet-exposure
  multiplier) rather than a generic restatement.
- **The four roles are doing genuinely distinct work, not overlapping.** Tool-call tally across
  the whole run: `lookup_nvd`, `lookup_kev`, `lookup_epss`, `lookup_attack_techniques` (Research)
  each called exactly 24 times; `lookup_asset_context` (Environment) exactly 24 times;
  `score_finding` (Risk) exactly 24 times — 144 total, 24 × 6, with zero overlap between the
  three tool sets and zero calls attributable to Coordinator (confirmed structurally in the
  2026-09-02 Coordinator entry above: it is plain Python, no LLM calls of its own). Every tool
  called exactly once per finding, no more, is itself a second confirmation of zero failures:
  a retried finding would have shown up as extra calls to whichever tool its retried stage uses.
- **Zero failures, independently confirmed.** No `ValidationError`, `ConverterError`,
  `Traceback`, `AgentOutputParseError`, `ScoringMismatchError`, or "gave up after" text anywhere
  in the 819-line transcript — the incident this session's previous entry fixed does not
  recur at 8x the finding count that originally triggered it.

**Cost.** The transcript doesn't carry token counts — `rhino run --agents` doesn't print
`usage_metrics` the way the ad hoc verification scripts earlier in this session did, a real
gap worth closing later but not done here. Extrapolating from the 3-finding run's measured rate
(≈$0.41 for 9 finding-stage units, i.e. ≈$0.046/finding-stage) rather than re-running the job a
second time just to meter it: **≈$3.3** for the full 24-finding, 3-stage, 72-task run — in line
with the "$3-4" estimate the earlier entry projected before this run existed to confirm it.

**`tot.py` built: Slice 4's beam search over remediation strategies, wired to the `contested`
gate.** `Bucket.CONTESTED` findings (Section 6's "First concrete gate," Section 3) now route into
`tot.run_tree_of_thought` via a new `Coordinator._dispatch_tot`, called after `_dispatch_risk` in
both `run` and `replan`. `tot.py` lives at the repository-layout-specified top level (CLAUDE.md
Section 9), not under `agents/`, though it imports crewai and the other agents' output types the
same way they import each other.

**The canonical three branches don't apply to the only gate that exists — replaced, not
patched.** Section 6 already flagged this as unresolved: "accept and monitor" is invalid for a
KEV-disqualified finding, and "compensating control + defer" presupposes a control that, for this
gate, by construction doesn't exist (that absence is *why* the finding is contested). Rather than
bolt a fourth branch onto the old three, `tot.py` uses a different fixed three, each viable
regardless of whether a control or window currently exists: `emergency_change` (patch now,
outside any window, via an expedited change process), `establish_window` (formally schedule one
going forward), `build_control` (implement a real control before the next cycle). CLAUDE.md
Section 6 records the full reasoning inline (a "Decided" note, matching the file's own
convention) rather than only here, since it changes what the spec itself commits to.

**Depth is refinement, not new branches — a design decision CLAUDE.md didn't fully specify.**
Section 6 says "beam width 2, max depth 3" and "~3 initial branches" but doesn't say what depth
*means* for a strategy space this small. Read literally as breadth-first branching, three fixed
branches have nowhere to branch to past depth 1. Implemented instead as refinement-in-place: the
beam's survivors (top 2 of the initial 3, by critic score) get the SAME strategy strengthened
round over round against the critic's own prior feedback, never swapped for a different one. This
is also what makes "exhausted evidence" (Section 6's third termination condition, alongside clear
winner and depth limit) a coherent thing for the strategist to report — a strategy can run out of
runway to improve; a branch identity can't.

**A real bug the test suite caught, not just a spec gap: an exhausted strategy was being
re-dispatched for refinement anyway.** First implementation tracked "did every active beam member
just report exhausted" only within the current round, so a thought that went exhausted at depth 2
was still handed a fresh refine task at depth 3 — wasted LLM calls, and a strategist re-asked a
question it already answered. `tests/test_tot.py`'s
`test_partial_exhaustion_only_recritiques_the_still_active_thought` was written to exercise
exactly the "one exhausted, one not" case and failed against a hand-queued fake `Crew` with an
`IndexError: pop from empty list` — the depth-3 round tried to dispatch a refine task for BOTH
beam members when only one should have been re-queued, one queue item short by construction (the
test deliberately queues nothing past the point where a correct implementation would stop
needing input). Fixed by tracking each beam member's `exhausted` flag as sticky: once set, that
member is skipped in `active_idx` for every subsequent round and carried forward unchanged (same
`Thought`, same score, zero new dispatches) rather than re-refined. Confirms the value of writing
the queue-exhaustion test tight enough to fail loudly on an under-consumption bug, not just a
parse-shape one.

**Critic scoring is a deterministic aggregation over LLM-assessed axes, never an LLM-computed
number.** `CritiqueOutput` (the parsed schema) has no total/aggregate field at all — the model is
asked for five 0–10 scores (risk_reduction, operational_cost, constraint_compliance,
evidence_strength, contradicting_evidence) and nothing else; `CriticScores.aggregate`, ordinary
Python arithmetic against a documented fixed weight table (`AGGREGATE_WEIGHTS`), is the only
thing that ever combines them. Same shape as why `RiskRecommendation.risk_score` can only ever be
a verbatim copy of `score_finding`'s answer (`agents/risk.py`) — there's structurally nothing for
the model to mis-add, because it's never asked to add. Weights: risk_reduction highest (0.35 —
the reason a strategy exists at all is reducing risk on a confirmed-exploited finding),
contradicting_evidence second and as a penalty (0.25 — evidence against a strategy should be able
to overrule an appealing one, the same argument behind the KEV floor in `scoring.py`, applied to
a strategy instead of a CVE), constraint_compliance (0.20), evidence_strength (0.15),
operational_cost lowest and deliberately capped (0.05 — cost is real, it's why branches besides
"always emergency patch" exist, but must not be able to outweigh confirmed exploitation on its
own, the same reason `is_kev` disqualifies `accept` regardless of convenience).

**Contested-rate reporting lives in `scoring.py`, not `tot.py` — an import-boundary constraint,
not a style choice.** `cli.py`'s deterministic path has a hard, tested requirement (this
PROGRESS.md, 2026-09-02, above; `test_cli_module_does_not_import_crewai_at_module_level`) to stay
import-clean of crewai so `rhino run` (no `--agents`) keeps working on Python 3.14. `tot.py`
imports `crewai.Agent`/`Task`/`Crew` at module level, same as `agents/research.py` etc. — so
`contested_rate` (a pure count of `Bucket.CONTESTED` occurrences, nothing about beam search)
could not live in `tot.py` without dragging crewai into the deterministic path the moment either
CLI branch imported it. Added to `scoring.py` instead (already crewai-free, already the sole
owner of `Bucket`), with a docstring explaining why it isn't with the rest of ToT. Both CLI paths
now print `Contested: n/total (pct%) of scored findings`; confirmed against the real fixture
(`rhino run --data demo --seed 42 --offline`, both `.venv` (3.14) and `.venv312`): `3/24 (12.5%)`,
matching `F07`/`F11`/`F14`.

**`--agents --explain` prints each contested finding's ToT outcome** — the winning strategy and
its score, or every near-tied final-beam candidate with neither picked (Section 6: "surface both
branches to the human. Do not force a single answer") — right after its narrative, or a `Tree-of-
Thought: failed` line with the reason if `tot.ToTDispatchError` was raised for it. `_print_failures`
grew a fourth stage (`"tot"`) alongside research/environment/risk, listing the same reason to
stderr. A ToT failure does not remove the finding from the ranked table: unlike a
Research/Environment/Risk failure, Risk already succeeded for a contested finding (that's *why*
it reached the ToT gate at all) — `_dispatch_tot` catches `ToTDispatchError` per finding, records
it into `RunState.tot_failures`, and leaves `risk_by_id` untouched.

**Verification.** 34 new tests (198 total, up from 164): `tests/test_tot.py` (21 — critic
aggregation arithmetic against hand-computed examples, the substituted `Strategy` enum, task/agent
construction, and the full beam search via a hand-queued fake `Crew` covering clear-winner,
depth-limit-near-tie, all-exhausted, partial-exhausted, a persistently unparseable response, and a
wrong-echoed-strategy retry), `tests/test_scoring.py` (+3, `contested_rate`, including the real
fixture's 3/24), `tests/test_coordinator.py` (+4, the gate itself: a contested finding routes into
ToT while a non-contested one never touches its `Crew`; a ToT failure is recorded without
disturbing `risk_by_id`; `replan` dispatches ToT too), `tests/test_cli.py` (+6, contested-rate
printing on both paths, winner/near-tie/failure explain output, and that none of it prints without
`--explain`). Constraint intake — turning free-form human text into which `finding_ids` `replan`
should re-dispatch — and `memory.py` (SQLite persistence) remain the two unbuilt pieces of Slice 4;
neither was touched here.

## 2026-09-03

**First real (non-fake) ToT run: `F07`/`F11`/`F14`, the demo fixture's three contested findings,
scoped past the CLI (no `--findings` flag exists) by constructing a filtered `EnrichedFinding`
list and calling `Coordinator.run` directly.** `offline=True` — every CVE the three needed
(`CVE-2022-30190`, `CVE-2020-0796`, `CVE-2023-23397`) already had committed NVD/EPSS/KEV/ATT&CK
snapshots, so the only live network calls were the LLM requests themselves, which `--offline`
doesn't and can't gate. Zero failures at any of the four stages, all three.

**`establish_window` was pruned after the first round in all three findings, unprompted.** Every
run's depth-1 critique scored `establish_window` below both `emergency_change` and `build_control`
— nothing in the fixture, the prompts, or `tot.py`'s code favors two of the three branches over
the third; this fell out of the critic's own scoring given each finding's actual evidence, not
anything engineered. Only `emergency_change` and `build_control` ever reached depth 2 in any of
the three searches.

**The critic caught two KEV due dates that had already passed — a fact `scoring.py` never
encodes.** `F11`'s `CVE-2020-0796` (SMBGhost) has a KEV due date of 2022-08-10; `F14`'s
`CVE-2023-23397` has one of 2023-04-04. Both are years in the past relative to the fixture's
`detected_date`s. `scoring.py`'s `ThreatInputs`/`_likelihood_multiplier` use `is_kev` as a
boolean floor (Section 3) and never read `kev_date_added`/a due date at all — that field exists on
`ResearchFinding` (`kev_date_added`) but the deterministic score has no notion of "overdue."
Both critics used the overdue date directly in `risk_reduction`'s justification (`F11`: "the KEV
entry's own remediation due date of 2022-08-10 has already passed... this fix is not merely
urgent but already delinquent"), and the winning `F14` proposal built the entire remediation
timeline around it. This is exactly the kind of business-context reasoning the deterministic
model structurally can't do — not a gap to fix in `scoring.py` (Section 8 rule 2: no LLM calls in
the scoring path, and "overdue by how much" is not a clean multiplicative factor the way
KEV-membership-as-floor is) but a concrete demonstration of why Section 6 routes contested
findings to an LLM at all instead of forcing a deterministic guess.

**All three proposals addressed `internet_exposed=False` head-on instead of leaning on it.**
Every one of the six critiqued branches across the three findings is on an asset with
`internet_exposed=False` — the fact that drove each finding's `x0.7` threat discount and kept
`risk_score` in the 18–26 range despite KEV+near-maximal EPSS. Every proposal (not just the
winners) explained specifically why that discount doesn't reduce *this* CVE's real exploitability:
Follina's CVSS vector is `AV:L`/`UI:R` (local, phishing-delivered, not network-reachable) so
"not internet-exposed" doesn't block the actual delivery path; SMBGhost is "network-adjacent/
LAN-based... not one whose primary risk stems from direct internet exposure"; the Outlook NTLM
leak is client-initiated outbound, so the host's own inbound exposure is irrelevant. None of the
three treated the lower deterministic score as license to relax — each explicitly argued the
discount doesn't apply to its finding's actual attack mechanism, using the CVSS vector string
and the CVE's own description already sitting in the evidence, not new facts.

**Two near-ties surfaced rather than forced; one resolved to a clear winner, but only by using
the full depth budget.** `F07` (Follina, risk 18.7): `emergency_change` 8.60 vs `build_control`
8.15 — gap 0.45, near-tie, `emergency_change` exhausted at depth 2 while `build_control` kept
refining to depth 3. `F11` (SMBGhost, risk 25.9): `emergency_change` 8.50 vs `build_control` 7.75
— gap 0.75, near-tie, neither exhausted, both went the full 3 rounds. `F14` (Outlook NTLM leak,
risk 25.5): `emergency_change` 8.75, `build_control` 6.25 — gap 2.50, clear winner, but the gap
only cleared `CLEAR_WINNER_MARGIN` (2.0) at the depth-3 critique; at depth 1 and depth 2 it was
still ambiguous. All three needed `depth_reached=3` — none resolved at depth 1 the way the
synthetic clear-winner test does — consistent with real critiqued strategies converging more
slowly than hand-picked test numbers, not a sign the margin or the search is miscalibrated.

**ToT usage tracking added — the cost-visibility gap CLAUDE.md's open item 4 named, extended to
the one stage that didn't have it.** `research_usage`/`environment_usage`/`risk_usage` existed
since Slice 3 (each stage dispatches exactly one `Crew` per run, so `crew.usage_metrics` is the
whole stage's cost); ToT never had an equivalent, because one finding's search can dispatch
anywhere from 2 Crews (clear winner at depth 1) to many more, and nothing summed them. Fixed by
threading a single `UsageMetrics` accumulator (crewai's own `add_usage_metrics`) through
`tot.py`'s `_dispatch_batch`/`_resolve` — every Crew this module ever constructs, initial batches
and per-task retries alike, adds itself to it — and returning it on `ToTResult.usage`.
`agents/coordinator.py`'s `_dispatch_tot` sums every contested finding's usage in one dispatch
into the new `RunState.tot_usage`, mirroring the other three fields' shape (most-recent-dispatch,
not a running session total).

**Partial spend on a failed search is not dropped.** A finding whose strategist/critic responses
never parse still made real, billed API calls before `tot.py` gave up — silently excluding that
from `tot_usage` would make "cost visibility" undercount actual spend exactly in the failure case
someone auditing cost would most want to see. `ToTDispatchError` now takes an optional `usage`
parameter and `_resolve`'s final raise passes the same live accumulator it had been mutating all
along; `_dispatch_tot`'s `except` clause adds `exc.usage` into the running total the same way it
adds a successful result's. No CLI printing was added for any of this (`rhino run --agents`
still prints nothing about cost, matching all three of the older usage fields) — that remains
CLAUDE.md's still-open item 4, a separate, larger piece (pricing table, dollar computation) than
"does the number exist to print."

**Verification.** 200 tests (+2 net over the prior entry's 198 — several existing tests gained
inline usage assertions rather than becoming new tests). `tests/test_tot.py`'s fake `Crew` now
reports `usage_metrics` scaled to task count (1 "request" per task), so accumulation across
multiple Crew instantiations is asserted on exact numbers, not just "is non-null": the clear-winner
test checks `successful_requests == 6` (3 propose + 3 critique tasks); the depth-limit test checks
`== 14` across all three rounds; a new pair of direct tests confirms `ToTDispatchError()` defaults
to an empty `UsageMetrics()` (not `None`) and preserves whatever instance it's given.
`tests/test_coordinator.py` gained the same fake-crew usage scaling plus two assertions:
`tot_usage.successful_requests == 6` on the happy path, and `== 3` on the failure path (the
batched 3-task propose crew's spend, with `max_parse_attempts=1` so no retry crew runs) —
confirming a failed contested finding's real spend still lands in `RunState.tot_usage`.
`tests/test_cli.py`'s `_fake_tot_result` helper needed a `usage=UsageMetrics()` argument added
now that the field is required on `ToTResult`; no behavior there changed.

**`memory.py` built: the four Section 7 tables, persistence only.** `sqlite3` from the standard
library, one local file (`rhinosecure.db` at the repo root by default — `.gitignore` already had
`*.db` from before this session, evidently anticipating this). Zero dependency on `crewai` or
anything under `agents/` — deliberately, so this module stays importable from both the
deterministic and agents paths without repeating the exact problem `scoring.contested_rate` was
moved out of `tot.py` to avoid. Record types (`RunRecord`, `Decision`, etc.) take and return plain
JSON-serializable values rather than importing `UsageMetrics`/`ContestedRate`/`ToTResult` — a
future caller extracts primitive fields before calling in.

**Schema decisions, each traced to something already in the codebase rather than invented:**
`constraints` is asset-scoped free text (`asset_id`, `constraint_text`) with a soft-delete
`active` flag — `deactivate_constraint`, not an UPDATE-in-place, so a retracted constraint stays
in the historical record, the same append-only instinct this project's own PROGRESS.md already
follows. `runs` stores exactly the four things asked for (seed, snapshot versions, contested
rate, usage) plus the minimum bookkeeping needed for a row to be identifiable at all
(`started_at`, `data_dir`, `total_findings`, `offline`, `agents`) — `snapshot_versions` is a
single JSON object keyed `"source"` or `"source:key"` (mirroring `enrich/cache.py`'s
`SnapshotEntry.source`/`.key`/`.version` exactly) rather than a normalized child table, since nothing
needs to query across runs by individual snapshot version, only read one run's provenance back out
whole; the four `*_usage` columns are nullable JSON blobs of whatever `UsageMetrics`-shaped dict a
caller passes, since the deterministic path has none at all and a `--agents` run with nothing
contested never touches `tot_usage`. `decisions` is one row per finding per run, foreign-keyed to
`runs` (`PRAGMA foreign_keys = ON`, enforced by SQLite itself, not re-checked in Python) — the
`RiskRecommendation` fields that are the actual verdict, plus nullable `tot_winner_strategy`/
`tot_near_tie`/`tot_termination_reason`, because a decision record for a contested finding that
omitted what ToT recommended wouldn't capture what was actually decided for exactly the subset of
findings where the historical record matters most. `feedback` is raw input plus what it changed,
per Section 7's own description verbatim, `run_id` nullable since feedback can be recorded before
or without a resulting replan.

**Deliberately not built: constraint intake, and reading constraints back into a run.** Two gaps,
both named explicitly in this session's instructions and now also in CLAUDE.md Section 7 itself so
they don't get silently marked done. First, nothing turns free-form human text ("the payroll
server only reboots on Sundays") into the `(asset_id, constraint_text)` pair `add_constraint`
takes — `agents/coordinator.py`'s docstring already names this exact interpretation step
("constraint intake") as the one unbuilt piece of its own wiring, unchanged by this session.
Second, nothing calls `constraints_for_asset` from anywhere in the run pipeline — Environment
Analysis's `has_patch_window`/`compensating_controls` still come only from the asset CSV, never
from stored constraints. Both are real, working, tested query paths with no caller yet, which is
the literal difference between "persistence layer" (this session's scope) and "the worked example
actually happening automatically" (CLAUDE.md Section 7's own text, still describing target
behavior, not current behavior).

**Verification.** 24 new tests (224 total), all in `tests/test_memory.py`, no changes needed
anywhere else — a genuinely standalone module. Confirmed importable and functional under both
`.venv` (3.14) and `.venv312`, unlike every agents-touching module so far, since it has no crewai
dependency to trip on. The one test written to match Section 7's worked example precisely
(`test_the_claude_md_worked_example_survives_a_new_session`) closes one `Memory` instance and
opens a brand new one against the same file before reading the constraint back, rather than reusing
the same connection — the concrete difference between "this variable is still in scope" and
"persists across sessions." Also covered: schema creation is safe to run twice against the same
file (exercised the same way, not as a separate code path); constraints don't leak across assets
and come back oldest-first; retracted constraints are excluded from `active_only` queries but stay
queryable with `active_only=False`; every `runs`/`decisions`/`feedback` field round-trips through
JSON correctly including `None` for absent usage data; `contested_pct` (a computed property,
mirroring `scoring.ContestedRate.pct`, never stored) handles a zero-total run without dividing by
zero; an unknown `run_id` on `record_decision`/`record_feedback` raises `sqlite3.IntegrityError`
from the foreign key constraint itself; `decisions_for_finding` correctly spans multiple runs for
the same finding, oldest first, with `latest_decision_for_finding` picking the most recent.

**Constraint intake and re-plan-with-diff built: the last piece of Slice 4.** `agents/
constraint_intake.py` (new) is the Constraint Interpreter agent CLAUDE.md and every prior session
named as the one unbuilt piece; `agents/coordinator.py`'s new `submit_constraint` wires interpret
→ persist → targeted re-plan → diff end to end; `cli.py` exposes it as `rhino constraint add
"<text>"`. Scoped deliberately to asset-scoped operational constraints — Section 7's worked
example ("the payroll server only reboots on Sundays") — not Section 10's "only five patches fit
this window," a fleet-wide capacity statement with no single asset to resolve to and no
representation in `memory.py`'s `constraints` table (`asset_id NOT NULL`). CLAUDE.md Section 10
now carries a "Decided" note saying so plainly rather than implying that example is handled.

**Three effect kinds, chosen to match what Environment/scoring already read, not invented.**
`patch_window`, `compensating_control`, `patch_restriction` — the same three `Asset` fields
Environment Analysis already surfaces and `scoring.bucket_for`/`score_impact` already consume.
The Interpreter is instructed to refuse (`asset_id`/`effect_kind`/`effect_value` all `None`)
rather than force a constraint that doesn't clearly name one asset or describe one of the three —
this is the concrete mechanism that keeps "only five patches fit this window" from being silently
mishandled: it isn't caught by a special case, it just never matches any of the three, and the
Interpreter says so in `rationale`.

**Overlay, not mutation — `apply_constraints` (`agents/constraint_intake.py`), the actual
mechanism the whole feature exists to build correctly.** Takes an `Asset` and active
`memory.Constraint` rows, returns a *new* `Asset` via `model_copy` with their effects folded in;
never mutates its input. `agents/risk.py`'s `score_finding` tool is where this reaches scoring:
when given a `Memory`, it builds the overlaid asset fresh on every call from the ground-truth
`Asset` plus whatever `constraints_for_asset` currently returns, scores *that*, and never writes
the result back to `enriched_by_id` — every other finding on the same asset, and every future call
without this constraint, sees `assets.csv`'s asset exactly as declared. Verified directly:
`test_the_overlay_never_mutates_the_ground_truth_asset` re-reads `enriched_by_id["F01"].asset
.compensating_controls` after a constrained `score_finding` call and confirms it's still `""`.

**Provenance stays distinguishable by staying in separate fields, never by scoring.py learning a
new concept.** `scoring.py` has no notion of "who declared this patch_window" and Section 8 rule 2
(deterministic, LLM-free) argues against giving it one. Instead: `agents/environment.py`'s
`lookup_asset_context` tool reports active constraints as a `human_constraints` list *alongside*
`patch_window`/`compensating_controls`/`patch_restrictions`, which always report only what the
asset record itself says regardless of any constraint on file — `EnvironmentAssessment` carries
the same field, and the task prompt tells the agent to mention it distinctly in
`applicability_summary`, never blended into the inventory's own facts. `agents/risk.py`'s
`score_finding` tool reports which constraints it actually applied as `constraints_applied`, a
field *separate from* `rationale`; `RiskRecommendation.constraints_applied` carries that into the
agent's narrative, and `verify_scoring_matches_tool` now checks it verbatim the same way
`risk_score`/`bucket`/`scoring_rationale` already are. This is how "human input stays
distinguishable from scanner input for provenance" actually surfaces in what a person reads.

**A real gap the test suite caught, not a hypothetical one: the fake Crew's risk-stage simulation
didn't echo `constraints_applied`, which would have made `verify_scoring_matches_tool`'s new check
spuriously fail the moment any test exercised an actual constraint.** `tests/test_coordinator.py`'s
`_QueuedFakeCrew.kickoff()` calls the *real* `score_finding` tool (by design — deterministic,
not an LLM call, so `verify_scoring_matches_tool` has a genuine call to check) and constructs a
fake "LLM answer" JSON around the real tool's result. That construction listed `risk_score`/
`bucket`/`scoring_rationale` but not `constraints_applied` — meaning the fake's simulated answer
would silently disagree with the real tool's output the instant a constraint made
`constraints_applied` non-empty, exactly the kind of drift `verify_scoring_matches_tool` exists to
catch, except the "drift" here would have been the test double lying, not the agent. Caught before
it caused a false failure (added the missing field to the fake's constructed JSON) because the
constraint-overlay tests were written to actually exercise a real active constraint through the
whole stack, not just call `apply_constraints` in isolation.

**A real test-isolation bug, caught before it could pollute the actual repo: `run_agents`/
`submit_constraint` construct a real `memory.Memory` — creating a real SQLite file — *before* the
`Coordinator` they hand it to is even constructed, so monkeypatching `Coordinator` alone in
`tests/test_cli.py` doesn't stop a real file from being created at `memory.DEFAULT_DB_PATH` (the
actual repo-root `rhinosecure.db`).** First run of the updated `tests/test_cli.py` (before this was
noticed) left a real `rhinosecure.db` sitting in the repo root, gitignored but still not something
that belongs there. Fixed with a session-wide autouse fixture that monkeypatches `rhinosecure
.memory.DEFAULT_DB_PATH` to a `tmp_path` location for the whole test file — both call sites import
`DEFAULT_DB_PATH` lazily (inside the function, at call time), so the patch is picked up correctly
rather than cached stale. The stray file was deleted; a version of it existing at all was the
signal something needed fixing, not just a cleanup step.

**Automatic pickup, not just at submission time.** `cli.py`'s `run_agents()` now always constructs
a `Memory` (default `memory.DEFAULT_DB_PATH`, overridable with `--db`) and passes it to
`Coordinator` — so a plain `rhino run --agents`, with no constraint just submitted in the same
invocation, still applies whatever's on file. This is what actually satisfies CLAUDE.md Section
7's worked-example phrase "applied automatically on the next run without being restated" — it was
entirely possible to build `submit_constraint` without this and only apply a constraint within the
same process that just created it, which would not have satisfied "next run."

**`rhino constraint add` output: interpretation, persistence confirmation, and the diff with
why.** Prints what the Interpreter resolved (asset, effect, affected findings, rationale) before
anything is persisted; on decline (`asset_id=None`), prints the rationale and exits 1 without
touching `memory.py` at all. On success, prints which findings actually changed bucket or risk
score (not the full set re-planned, if some didn't move) with the rationale lines added/removed
by the constraint and the agent's own `verdict_summary` as the "why" — satisfying CLAUDE.md's
"the agent explains the delta" in the agent's own words, not a mechanically-generated sentence
this module writes on its behalf. A finding_id the Interpreter named that doesn't actually belong
to the resolved asset (hallucination or cross-asset mistake) is filtered out of the re-plan and
reported to stderr as `unresolved_finding_ids`, without blocking the findings that did resolve.

**Verification.** 44 new tests (268 total, up from 224): `tests/test_constraint_intake.py` (17 —
`apply_constraints` against hand-built `Constraint` rows, including that it never mutates its
input and that a later same-kind constraint wins over an earlier one; `search_assets`/
`list_findings_for_asset` tool behavior; agent/task construction), `tests/test_environment_agent.py`
(+4, `human_constraints` present/absent/excluded-when-retracted, and that it's never merged into
the asset's own fields), `tests/test_risk_agent.py` (+4, the overlay changing a real risk_score,
never mutating ground truth, `verify_scoring_matches_tool`'s new check), `tests/test_coordinator.py`
(+6, `interpret_constraint`'s parse-retry-then-raise, and `submit_constraint`'s full happy path —
persistence, targeted replan, a real risk_score delta, all four `memory.py` tables populated —
plus the decline and hallucinated-finding-id cases), `tests/test_cli.py` (+11, argument wiring,
output formatting, all four error-to-exit-code mappings, `--quiet`). All 268 pass; the
deterministic path (`.venv`, Python 3.14) is unaffected and confirmed separately, since none of
this touches it — `memory.py` stays crewai-free but this session's new code that *uses* it
(`constraint_intake.py`, the `Coordinator`/`risk.py`/`environment.py` changes) is agents-only,
same as everything built since Slice 3.

**Fleet-wide capacity constraint built: CLAUDE.md Section 10's "only five patches fit this
window" exit-criteria sentence, exercised literally for the first time rather than only proving
the asset-scoped case.** The design decisions were the user's, given explicitly rather than left
to this session to guess: global scope for the limit (no per-window-name matching), `patch_now`
and a ToT-recommended `emergency_change` both exempt from competing (too urgent to schedule
either way), capacity constraints cycle-scoped to one run rather than standing like asset
constraints, a new `deferred_capacity` bucket following the `contested` precedent, the allocation
itself kept deterministic and in the scoring path rather than an agent, the existing Constraint
Interpreter extended with a third classification rather than a new agent, and the diff framed as
"risk_score unchanged, lost a rank-position race" rather than a before/after score pair.

**`scoring.py`: `Bucket.DEFERRED_CAPACITY`, `RankableFinding`, `CapacityAllocation`,
`apply_capacity_limit`.** `apply_capacity_limit(findings, limit)` filters its input to
`Bucket.NEXT_WINDOW` only — the entire exemption mechanism for `patch_now` and a
`emergency_change`-bound `contested` finding, and deliberately not an explicit exemption list:
neither is ever `Bucket.NEXT_WINDOW` in the first place, so restricting the competing pool to
that one bucket excludes both by construction. Sorts by `(-risk_score, finding_id)` — the same
tie-break `scoring.rank` already uses — and assigns `NEXT_WINDOW` for rank ≤ limit,
`DEFERRED_CAPACITY` past it. `RankableFinding` is a minimal three-field shape (`finding_id`,
`risk_score`, `bucket`) so a caller isn't forced to fabricate irrelevant fields from either
`ScoredFinding` (deterministic path) or `RiskRecommendation` (agents path, which has no
`threat_score`/`impact_score` at all).

**`memory.py`: a fifth table, `capacity_constraints`, plus three nullable `decisions` columns.**
`capacity_constraints` (`run_id`, `raw_text`, `patch_limit`, `pool_size`, `deferred_count`,
`created_at`) has no active/deactivate lifecycle, unlike `constraints`' soft-delete — a capacity
limit describes exactly one cycle's bandwidth and is foreign-keyed to the one `runs` row it
applied within; there is nothing later to retract it from. `decisions` gained
`capacity_rank`/`capacity_pool_size`/`capacity_limit` (all nullable, same pattern as the existing
`tot_*` columns) so a decision produced by this path records why it landed where it did.
`record_decision`'s new kwargs are fully backward compatible; `Decision`'s new fields had to be
placed after `decided_at` specifically, since Python dataclasses require defaulted fields to
follow non-defaulted ones.

**`agents/constraint_intake.py`: a third classification, not a second agent.**
`ConstraintKind.CAPACITY` alongside the existing `ASSET` (and the null refusal).
`ConstraintInterpretation` gained `constraint_kind` and `patch_limit`. The task prompt now leads
with the three-way decision before anything else, gives three example capacity phrasings, and
explicitly forbids the model from calling `search_assets`/`list_findings_for_asset` or
populating `affected_finding_ids` for a capacity statement — which findings a limit actually
constrains (every current `next_window` finding) is computed deterministically elsewhere, never
by the model. `apply_constraints` (the asset-overlay function) is untouched.

**`agents/coordinator.py`: `_submit_capacity_constraint`, entirely LLM-free past the one
interpretation call.** The hard design question was where the competing pool's real, live
buckets come from without either (a) a full Research/Environment/Risk/ToT dispatch over the
whole fleet (expensive, and the user's instruction was explicit that the allocation itself must
stay out of an agent) or (b) trusting stale, unenriched scanner-only scores. Resolved by reusing
`rhino run`'s own deterministic enrichment: `attach_threat_signals` (KEV/EPSS/NVD/ATT&CK, via
`SnapshotCache`) was pulled out of `cli.py`, where it was private, into `ingest.py`, public and
unchanged in behavior — `cli.run()` and `_submit_capacity_constraint` now share the exact same
call, so "who's in `next_window`" reflects real enrichment, not a guess, while still making zero
LLM calls. `coordinator.py` importing from `cli.py` directly would have been backwards (the
entry-point module reaching down into a lower one); `ingest.py` already sits below both and was
the natural shared home. `_submit_capacity_constraint` then re-scores every finding through that
pipeline, builds `RankableFinding`s, calls `scoring.apply_capacity_limit`, and records a decision
for every pool member — both the ones that fit and the ones deferred, not just the deferred ones
— so `decisions_for_run` reflects the whole competing pool, not only what changed.
`CapacityDelta` is deliberately not a `FindingDelta`: nothing about a finding's own risk_score or
evidence changed, only its rank position did, so framing it as a risk_score before/after (like
the asset-scoped `FindingDelta`) would misrepresent what happened — `risk_score` here is a single
value, not a pair.

**`cli.py`: a second interpretation printer and diff printer, dispatched by result type.**
`asset_id is None` stopped uniquely meaning "declined" the moment a capacity statement also
resolves with no asset — `_print_constraint_interpretation` now branches on
`interpretation.constraint_kind` explicitly (`"capacity"` / `"asset"` / anything else, treated as
refusal) rather than trusting `asset_id`'s nullness alone. `main()`'s `constraint add` dispatch
now checks `isinstance(result, CapacitySubmissionResult)` and calls `_print_capacity_result`
instead of `_print_constraint_result` for that case — printing the pool (rank, finding, hostname,
risk_score, fits/deferred) and, for anything deferred, "risk_score unchanged at X — ranked N of
M, exceeding this cycle's limit of L. This finding lost a rank-position race, not a change in
risk," the framing given explicitly rather than the asset-scoped diff's bucket-and-score-pair
format.

**Real end-to-end smoke test against the actual 24-finding demo fixture, not just the fake-Crew
unit tests.** `rhino constraint add "only three patches fit this window" --data demo --offline`
made one real LLM call (the Constraint Interpreter) and correctly classified it as
`constraint_kind="capacity"`, `patch_limit=3`; the deterministic allocation then found 8 real
`next_window` findings in the fixture, ranked them by `risk_score` (46.6 down to 16.3), kept the
top 3 (`F04`/`F09`/`F02`), and deferred the other 5 with the rank-position framing above. Only one
LLM call total for the whole operation, confirming the "LLM-free past interpretation" design
actually holds against real data, not just mocked Crews.

**Verification.** 24 new tests (292 total, up from 268): `tests/test_scoring.py` (+6 —
`apply_capacity_limit` against an empty pool, `limit=0`, `limit` ≥ pool size, the exact rank
boundary, the tie-break, and the structural proof that `patch_now`/`mitigate_monitor`/`accept`/
`contested` findings never enter the pool regardless of `risk_score`), `tests/test_memory.py`
(+5 — `record_capacity_constraint`/`capacity_constraints_for_run` round-trip,
`record_decision`'s three new optional columns, cross-session persistence for the new table),
`tests/test_constraint_intake.py` (+5 — the three-way `ConstraintInterpretation` shape validates
for each kind, the task description/expected_output mention the new capacity fields and an
example phrasing), `tests/test_coordinator.py` (+4 — a capacity-kind interpretation dispatches no
Research/Environment/Risk Crew at all, a real 4-finding pool ranks and defers correctly against a
limit with every `memory.py` write checked, a limit that covers the whole pool defers nothing,
and a recognized-but-unextractable-limit persists nothing), `tests/test_cli.py` (+4 — the
capacity result routes through the capacity printer and never the asset-scoped one, the diff uses
rank/bucket framing and never a risk_score-pair, an all-fits pool reports no changes, a missing
limit exits 1). All 292 pass; the deterministic path (`.venv`, Python 3.14) still imports cleanly,
confirmed directly (`ingest.py`'s `attach_threat_signals` move touched the module `cli.run()`
depends on) since none of this feature's own code — `constraint_intake.py`,
`coordinator.py`'s new method, `cli.py`'s new printers — is on that path.

**Adversarial review (3 dimensions, each finding independently re-verified before counting)
caught a real bug: the capacity pool skipped the constraint overlay `agents/risk.py` already
applies.** Ran a 9-agent review/verify workflow against the whole feature -- correctness, spec
compliance against CLAUDE.md's own new claims, and test coverage -- with every candidate finding
handed to a separate agent instructed to try to refute it, not just rubber-stamp it. Spec
compliance came back clean (0 findings). Correctness and test coverage surfaced 5 candidates that
survived adversarial re-verification, one refuted (a claimed vacuous test assertion that turned
out not to matter in practice).

The one worth fixing immediately: `_submit_capacity_constraint` (`agents/coordinator.py`)
re-scored every finding straight from ground-truth `assets.csv` via `attach_threat_signals` +
`score_finding`, never consulting `self.memory.constraints_for_asset` the way
`agents/risk.py`'s `score_finding_tool` already does. Concretely reproduced: an active
`compensating_control` constraint on an asset with no declared `patch_window` should move a
finding from `next_window` to `mitigate_monitor` (`bucket_for`'s own rule) -- but the capacity
path, computing straight from raw CSV, would still see it as `next_window` and wrongly let it
compete for capacity (or, the mirror case, wrongly exclude a finding a constraint had moved
*into* `next_window` from `contested`). `ingest.py`'s own docstring claim that this path computes
"the real bucket a finding is in" was accurate for enrichment freshness but overstated for
constraint state. Fixed by folding in `constraint_intake.apply_constraints` per finding before
scoring, mirroring `agents/risk.py`'s pattern exactly (`self.memory` is guaranteed non-None here
already -- `submit_constraint` raises before this method is ever reached otherwise). Verified with
a new regression test (`test_submit_capacity_constraint_applies_an_active_asset_constraint_before_ranking`)
built specifically to fail without the fix: a no-window, no-control asset defaults to
`next_window` (risk=31.73); the same asset with an active `compensating_control` constraint on
file scores `mitigate_monitor` (risk=26.97) -- the finding must be entirely absent from the
capacity pool once the constraint is applied, not merely deprioritized within it.

Three more confirmed test-gap findings, each closed with a real test rather than noted and
skipped: no coordinator-level test exercised `patch_limit=0` specifically (0 is a legitimate
"zero patches fit this window" answer, and is falsy in Python -- `if interpretation.patch_limit is
None` is one accidental rewrite away from silently misrouting a real 0 into the decline branch);
`capacity_constraints` had no cross-session (close-then-reopen) persistence test, unlike the
`constraints` table's own dedicated one, despite depending on the same easy-to-regress
`self._conn.commit()` discipline; and `_print_capacity_result`'s `persisted=True, deltas=()`
branch (a real, reachable state -- the limit was extracted and recorded, but zero `next_window`
findings exist in the fleet right now) had no test, leaving both its message text and its
ordering relative to the `result.deltas[0]` indexing right after it unverified.

One confirmed-but-low-severity finding deliberately left unfixed here and flagged as a separate
follow-up instead: `finding_id`-keyed dicts inside `_submit_capacity_constraint`
(`scored_by_id`/`asset_id_by_finding_id`) would silently collapse and misattribute a
`CapacityDelta`'s fields if `findings.csv` ever contained two rows sharing a `finding_id` --
reproduced end-to-end, including a wrong persisted `decisions` row. Real, but requires a primary-
key violation nothing in `ingest.py` currently guards against, and the same finding_id-keyed-dict
assumption appears throughout `agents/coordinator.py`'s `RunState` (`research_by_id`,
`environment_by_id`, `risk_by_id`) -- a one-off patch here would be inconsistent and wouldn't fix
the root cause. Belongs at the ingest layer instead; spawned as its own follow-up task rather than
folded into this change.

**Verification.** 4 more tests (296 total, up from 292): the constraint-overlay regression above,
`patch_limit=0` through the real `Coordinator`, `capacity_constraints`' cross-session test
(`tests/test_memory.py`), and the empty-pool CLI print case (`tests/test_cli.py`). All 296 pass.

**`rhino constraint add` now suppresses CrewAI's console output by default, inverted from `rhino
run --agents`'s polarity.** Reported directly: the command was printing the full agent task
prompt and reasoning (CrewAI's "Agent Started"/"Agent Final Answer" boxes) to the terminal.
`--quiet` already existed for `constraint add` and, verified directly, already fully suppressed
this via the same `set_suppress_console_output` mechanism `run --agents` uses -- so the flag
itself was not broken. The actual ask, once clarified: `run --agents` is an exploratory command
where per-stage agent activity is often exactly what's wanted, so verbose-by-default with opt-in
`--quiet` fits it; `constraint add` is a single-decision command where the interpretation, the
pool ranking, and the diff already say everything a person needs, so it should default to quiet
instead. Replaced `--quiet` on `constraint add` with `--verbose` (opts back into CrewAI's console
output); the underlying mechanism (`set_suppress_console_output`) is unchanged, just called by
default now instead of behind a flag. `run --agents`'s own `--quiet` is untouched -- this only
changes `constraint add`. Verified against the real 24-finding demo fixture with a real LLM call:
no flag prints only the interpretation, pool ranking, and diff; `--verbose` prints CrewAI's full
console output on top of that.

**Verification.** 1 test replaced with 2 (297 total, up from 296):
`test_constraint_add_suppresses_console_output_by_default` and
`test_constraint_add_verbose_flag_disables_suppression`, mirroring the existing
`run --agents` quiet-flag test pair's structure. All 297 pass.

**Full Slice 4 live demonstration against the real 24-finding demo fixture: ToT on all three
contested findings, an asset-scoped constraint, a capacity constraint layered on top of it.**
Requested directly, not a unit test -- real LLM calls throughout (`--offline` only gates
enrichment, not the LLM). Surfaced a real, previously-undetected bug along the way:
`memory.py`'s `Memory` opened its SQLite connection with `check_same_thread=True` (the default),
but `agents/environment.py`'s `lookup_asset_context` and `agents/risk.py`'s `score_finding_tool`
call `memory.constraints_for_asset` unconditionally whenever `memory is not None` -- not only
when a constraint exists -- and CrewAI executes tool calls from a worker thread, not the thread
that constructed the `Memory`. A real (non-mocked-Crew) asset-scoped constraint submission failed
on every `lookup_asset_context` call with `sqlite3.ProgrammingError: SQLite objects created in a
thread can only be used in that same thread`, cascading into the whole Environment task
exhausting its retries and the constraint resolving to "0 finding(s) re-planned" with no visible
error (`cli.py`'s `_print_constraint_result` never surfaces per-finding failures for this path).
This had been latent since the constraint-intake feature was built: `run_agents()`/
`submit_constraint()` always construct and pass a real `Memory`, but the only real (non-mocked)
agents smoke test since then was the capacity path, which never touches `memory` from inside a
CrewAI tool thread. Fixed: `sqlite3.connect(..., check_same_thread=False)` plus a
`threading.Lock` around every method body (cross-thread access alone isn't enough -- one shared
connection still isn't safe for genuinely concurrent use). New regression test
(`test_reads_and_writes_from_a_different_thread_than_construction_do_not_raise`) does real work
from a `threading.Thread` against a live `Memory`; confirmed directly that it fails with the exact
production error when temporarily reverted, so it isn't vacuous. 298 tests total (was 297).

With the fix, all three pieces ran clean end to end:
- **ToT**: `F07`/`F11`/`F14` (all KEV-listed, no compensating control, no patch window) each ran
  the full 3-branch beam search to depth 3 and landed near-tied (`emergency_change` vs. either
  `build_control` or `establish_window`, gaps of 0.65/1.20/1.80 -- all under the 2.0 clear-winner
  margin), surfacing both candidates rather than forcing a winner. `establish_window` was pruned
  after round 1 for F07 and F11 (consistent with the earlier documented run) but survived to the
  final beam for F14 this time -- real LLM variance across runs, not a bug. F11's strategist
  independently caught that CVE-2020-0796's vulnerable SMBv3 code path is specific to Windows 10
  builds 1903/1909 while `WKS-IT05` reports build 19045, and built every proposal around
  verifying that mismatch before spending remediation effort -- reasoning `scoring.py` has no way
  to perform. Total ToT spend: 823,223 tokens, 194 requests across the three findings.
- **Asset-scoped constraint**: "SQL02's vendor has certified a quarterly emergency patch window..."
  correctly resolved to `A12`, `effect_kind=patch_window`, `affects: F15` -- moving `F15` from
  `mitigate_monitor` to `next_window` with `risk_score` unchanged (20.7 -> 20.7), the exact
  CLAUDE.md Section 3 case this asset/finding pair was added to demonstrate.
- **Capacity constraint, layered on the same memory DB**: "only three patches fit this window"
  found 9 `next_window` candidates -- 8 from the fixture plus `F15`, freshly moved there by the
  constraint just above -- ranked them, kept the top 3, deferred the other 6, each framed as
  "risk_score unchanged... lost a rank-position race." `F15`'s presence in the pool is a live
  demonstration of the constraint-overlay fix from earlier this session: the capacity computation
  correctly reflected the asset-scoped constraint's effect rather than the fleet's raw CSV state.

Scratch memory DBs used for this run were not the repo's `rhinosecure.db` and are not part of any
commit.

**Microsoft Defender Vulnerability Management adapter; `rhino run --format`.** CLAUDE.md
Section 1's contract ("swapping in a real scanner export should require a new ingest adapter
and nothing else") now has its first real adapter and the seam to plug it into. New
`adapters/` package: `base.py` (the `IngestAdapter` contract, `AdapterError`, and the
`not_collected` representation below), `native.py` (the existing assets.csv/findings.csv
loaders, wrapped so "native" is a format like any other rather than the one everything
silently assumes), `defender.py`. `ingest.py` gained the loader-agnostic `join` (the old
`join_findings` delegates to it, behavior unchanged), `load_batch`, and `IngestStats`/
`IngestReport`/`GapTally`; `cli.py` gained `--format {defender,native}` (default native),
`run_with_report` (same pipeline as `run`, which keeps its list return -- test_scoring.py
calls it), a data-gap summary after the table, and a per-finding `! not collected:` note under
`--explain`. scoring.py, enrich/, and agents/ are untouched, as required. Confirmed the native
demo output is byte-identical to HEAD (full `--explain` run diffed against a temporary
worktree of the previous commit: 432 lines, no difference), not just "tests still pass".

**Column vocabulary is Microsoft's, verified, not remembered.** The adapter reads two CSVs
shaped like the advanced-hunting tables Microsoft documents: `devices.csv` <- `DeviceInfo`
(DeviceId, DeviceName, OSPlatform, OSBuild, IsInternetFacing, AssetValue; Timestamp
optional) and `vulnerabilities.csv` <- `DeviceTvmSoftwareVulnerabilities` (DeviceId, CveId,
VulnerabilitySeverityLevel, SoftwareName, SoftwareVersion; SoftwareVendor,
RecommendedSecurityUpdate(Id) optional). Checked both Learn pages today rather than trusting
memory, which paid off twice: the hunting table has *no* timestamp column at all (so
`detected_date` is not collected unless the file came from the per-device assessment API,
whose `FirstSeenTimestamp` the adapter accepts as optional), and the API doc states the
uniqueness key of a per-device vulnerability record is (DeviceId, SoftwareVendor,
SoftwareName, SoftwareVersion, CveId) -- SoftwareVendor included, which the first draft of the
dedup key had left out. `finding_id` is `MDVM-` plus 16 hex of a sha256 over exactly that key:
Defender exports no stable per-finding id, and a content-addressed one gives the same finding
the same id across exports, which memory.py's `decisions` table needs. The 64-bit prefix keeps
accidental collisions negligible at fleet scale and the validation pass still checks for one.

**The representation of fields the source has no concept of -- the decision this feature was
gated on.** Defender exports no maintenance window, compensating controls, patch restrictions,
environment tier, data-sensitivity classification, role, business function, or owner. Every
Defender asset therefore arrives with a blank `patch_window`, and the schema already gives that
blank a meaning -- "no declared scheduling restriction", read by `bucket_for` as "may be patched
any time" -- when here it means "nobody asked". This was Section 3's open item, now bitten by the
first real format. Decided: separate the *value* from the *claim*. The value stays the schema's
own absent encoding ("" for free text), so `bucket_for`, `has_patch_window`,
`compensating_control_list`, and the constraint overlay read it exactly as before and nothing
downstream changes; the claim moves into a new machine-readable field on the record,
`Asset.not_collected` / `Finding.not_collected` -- the set of schema field names the source
had no concept of, or left blank on that row. A blank `patch_window` with `"patch_window" in
not_collected` means "unknown"; without it, "none declared". A pydantic validator refuses
names that aren't real fields and refuses the primary keys (a record without identity is
unmappable input, not a record with a gap). Rejected alternatives, recorded so they don't come
back: a sentinel value in the field (any non-blank `patch_window` flips `has_patch_window`
and any non-blank `compensating_controls` manufactures a control, so it would change verdicts
and force every consumer to learn to skip it); `None` vs `""` (a CSV cell can't tell them
apart, so the native loader would have had to decide what a blank means, reintroducing the
ambiguity one layer down). The enumerated Impact inputs (`role`, `environment`,
`data_sensitivity`, `criticality`) have no absent encoding -- scoring indexes weight tables by
them -- so `NOT_COLLECTED_DEFAULTS` (adapters/base.py) fixes one value per field for every
adapter: the modal enterprise value (prod, internal, criticality 3), deliberately neither the
worst case (every unknown server a DC in a regulated prod environment floods `patch_now`
uniformly and teaches the reader to distrust the ranking) nor the best case (hides risk).
Because the default is the same for every record of a format, it shifts every finding's
Impact by a constant instead of reordering them. `role` is defaulted by OS class --
`workstation` for a client OS (nearly a fact), `file` for a server OS (the most generic server
role, mid-table blast radius) -- and marked not collected either way. A dedicated `server`
role would be cleaner but needs a `ROLE_BLAST_RADIUS` entry, a scoring change, so it was not
made. Values are still visible everywhere: `rhino run` prints per-field counts and, under
`--explain`, each finding's defaulted fields with the value in effect.

**Messy realities, each with one defined behavior (adapters/defender.py's docstring is the
reference).** Missing column: refused at the header, listing missing and found (a portal-grid
export with display names fails as "not a DeviceInfo export", not as forty rows of blank
identity). Blank cell: fatal for identity columns; otherwise the field's default plus a
per-row `not_collected` entry. Non-Windows OSPlatform: refused, every offender listed --
Section 2 scopes the fleet to Windows, and dropping a macOS box silently would hide that part
of the fleet went unscored. Orphaned findings (DeviceId not in the inventory): refused, every
device listed with its finding count, because a plan that quietly omits findings is the thing
this project refuses to produce. Repeated device rows (DeviceInfo is per-report): identical
rows collapse; differing rows collapse to the latest `Timestamp` (Microsoft's own sample query
is `arg_max(Timestamp, *) by DeviceId`); differing rows with no Timestamp are refused.
Duplicate findings: same uniqueness key plus same severity and first-seen date collapse
(evidence-only differences included, first row's evidence kept, count reported); a different
severity or date is a conflict and refused. Non-CVE advisory ids: refused (enrichment is
CVE-keyed). UTF-8 BOM: tolerated. `load_findings` reads the file twice -- a yield-nothing
validation pass that collects every problem (bounded memory: one digest per distinct
finding, never a row), then the yielding pass -- so the operator sees all problems in one
message and no NVD/EPSS lookup is spent on a batch about to abort.

**What the sample run shows.** `data/defender-sample/` (synthetic, 6 device rows / 10
vulnerability rows, CVEs chosen from the committed snapshots so `--offline` works, one repeated
device row and one exact-duplicate finding row on purpose): `rhino run --format defender
--data defender-sample --offline` scores 9 findings on 5 devices, reports 5/5 assets missing
the eight never-exported fields and 1/5 missing criticality (a blank AssetValue), 9/9 findings
missing detected_date/port/service, and `Contested: 6/9 (66.7%)`. That last number is the
representation decision showing its teeth, not a bug: every KEV-listed finding on a Defender
asset is contested, because no window and no control are *known* for any asset, and
`bucket_for` refuses to call such a finding "on schedule". It is the honest verdict on an
export that carries no business context, and it is exactly why `rhino constraint add` --
which persists a per-asset window or control and overlays it on the next agents run -- is the
fill-in path the summary points to. The two non-KEV findings land where their risk puts them
(next_window at 50.6, accept below 18).

**Left open, stated rather than hidden.** (1) `--format` is deterministic-path only:
`Coordinator.__init__` builds its own asset index from `<data>/assets.csv`, so `--agents` and
`rhino constraint add` with a non-native format are refused up front with a message saying so
(exit 2) rather than reading a file that isn't there. Lifting it means the Coordinator accepts
an inventory instead of a path -- an agents change deliberately not made under this feature's
"no changes to scoring, enrichment, or agents" rule. Until then the constraint fill-in path
the gap summary recommends is usable only for native data. (2) scoring.py's rationale still
prints "no patch_window declared -> no scheduling restriction" for a not-collected window,
and `lookup_asset_context` still hands agents `patch_window: ""` with no marker; the CLI's
gap note corrects the reading for a human, nothing corrects it for an agent. One line each in
`scoring._rationale` and `agents/environment.py` would close that; both are outside this
feature's remit. (3) Role, environment, and data sensitivity have no fill-in path at all --
constraints cover only window/restriction/control. `DeviceInfo.DeviceRoles` (JSON, undocumented
vocabulary) and `DeviceManualTags` are the natural Defender-side sources; a CMDB/context sidecar
keyed by DeviceId is the general one. 347 tests total, up from 298; the fixture-coupling guard
now scans `adapters/*.py` too.

**`rhino constraint add` accepts `--format`; the not-collected marker reaches every consumer.**
The adapter commit left `--format` deterministic-path only, because `Coordinator.__init__` built
its own asset index by reading `<data_dir>/assets.csv` -- a filename a Defender export does not
have. That was backwards: an export carrying no patch window, no compensating control and no role
is exactly the input a human has to fill in by hand, so the fill-in command is the one that has to
accept it. `Coordinator` now takes the already-loaded, already-validated inventory as `assets=`
(falling back to the native load when omitted, so every existing native caller and all ~20
`Coordinator(data_dir)` test constructions are unchanged), plus `ingest_format=` for the run
record. `cli.py`'s `run_agents` and `submit_constraint` both go through `ingest.load_batch` now,
the refusal branch is gone, and `constraint add` gained its own `--format`.

**The scoring rationale stops overclaiming.** `scoring._rationale` said "no patch_window declared
-> no scheduling restriction, may be patched at any time" for an asset whose source never exports
the field -- a claim the data does not support. It now reads `Asset.not_collected`: "patch window
not collected -- this source exports none, so when this asset may be patched is unknown, not
unrestricted". Not-collected compensating controls get a named line instead of silence (the
native path only ever printed a line when controls existed, so a gap was invisible), and the
`contested` explanation says "no patch window collected" rather than "no patch window" when the
field is a gap. The marker is read for **wording only, never arithmetic** -- a dedicated test
asserts risk_score/threat_score/impact_score/bucket are identical with and without it, so this
stays inside Section 8 rule 2. `agents/environment.py`'s `lookup_asset_context` and
`agents/constraint_intake.py`'s `search_assets` also carry the marker now, so it reaches a model's
reasoning and not just the CLI's output.

**Two correctness problems found while wiring this, neither of which unit tests would have
surfaced on their own.** First: `apply_constraints` overlaid a constraint's value but left the
field marked not-collected, so an asset would keep reporting a data gap for a fact a human had
just supplied. Fixed -- a supplied field is removed from `not_collected`, and only that field, so
one constraint never launders an asset's other gaps. Second, and worse: `search_assets` matched a
free-text query against `role`, `business_function`, and `owner` without checking whether those
values were real. Every Defender server carries the same defaulted `role="file"`, so "the file
server can only be patched on Saturdays" would have matched all three servers in the sample and
invited the Interpreter to pick one -- landing a human's constraint on a domain controller.
`_matches` now skips any field in `not_collected`; identity fields (hostname, asset_id) are never
marked, so assets stay resolvable. Resolving off a placeholder is the same guess the ingest layer
refuses to make, one layer up.

**`runs.ingest_format`, and the first schema migration.** A run record said which `data_dir` it
read but not which adapter read it. Added as a nullable column -- nullable because a row written
before `--format` existed has no truthful answer, and backfilling "native" would assert one.
`CREATE TABLE IF NOT EXISTS` is a no-op on an existing file, so the column would never have
reached a database anyone already had and the next INSERT would have failed with "no such column"
against their real history; `Memory._migrate` applies idempotent `ALTER TABLE`s guarded by
`PRAGMA table_info`. Tested by hand-building the pre-migration schema, inserting a row, and
confirming the reopen preserves it, leaves its `ingest_format` NULL, and accepts new writes.

**Verified end to end with real LLM calls** (`data/defender-sample`, `--offline`, scratch DB, not
the repo's `rhinosecure.db`). `rhino constraint add "dc01.corp.example.com can only be rebooted on
Sundays between 02:00 and 06:00" --format defender` resolved the host by hostname, persisted an
asset-scoped `patch_window`, and moved `CVE-2020-1472` on that host from `contested` (35.5) to
`next_window` (35.5) -- `risk_score` unchanged, which is the point: the constraint changed which
bucket is honest, not how risky the finding is. The removed rationale lines in the diff are the
two new not-collected strings, so the wording fix and the constraint path are visible in one
output. The Interpreter's own rationale volunteered that it relied on the hostname match and not
on the asset's `patch_window` "since it appears in not_collected" -- the marker reaching a model's
reasoning unprompted by that specific case. The refusal path was exercised too: "the file server
can only be patched on Saturdays" returned zero candidates and refused. One honest imperfection
there -- the prompt asks the Interpreter to name the missing field so the human can restate by
hostname, and this run did not; the refusal was correct, the explanation less helpful than
intended. `runs.ingest_format='defender'` confirmed in the scratch database.

**One deliberate change to native output**, the first since the fixture was frozen: the
`contested` rationale said ToT was "(Slice 4, not yet built)", which stopped being true when
`tot.py` landed. It is a false statement shipped in the deliverable's own output, in the exact
string being edited for the not-collected wording, so it was corrected rather than left. Diffed
the full `rhino run --data demo --seed 42 --offline --explain` against the prior commit through a
temporary worktree: 18 changed lines, all of them that one phrase on the three contested findings,
with every score and bucket identical. 374 tests, up from 348.

**Fixed: `--format`/`--data` mismatch crashed instead of erroring.** Reported: `rhino constraint
add --format defender` with `--data` left at its default (`demo`, the native fixture) raised a raw
`FileNotFoundError` traceback -- `devices.csv` doesn't exist under `data/demo`. Same crash on
`rhino run --format defender` with no `--data`. Root cause: all three CLI paths (`run`,
`run --agents`, `constraint add`) share `ingest.load_batch`, which never checked that `--data`'s
resolved directory had the files the chosen `--format` expects before an adapter tried to open
them -- `native.py`'s `_rows` and `defender.py`'s `_open_csv` both call `path.open()` unguarded.
`ingest._require_adapter_files`, called first inside `load_batch`, now checks with `Path.is_file()`
before either file is opened and raises `IngestError` -- already caught by name in every "ingest
error: ..." / exit 1 handler in `cli.py` for all three commands, so no `cli.py` change was needed.
One check in the one function all three paths already call is what makes them behave identically:
the second half of the ask ("make --data and --format consistent between run and constraint add")
turned out to be the *same* fix as the first half ("catch missing input files"), not a separate
change.

**An adversarial review of the first version found four real bugs in the fix itself.** Given the
diff was small and already manually verified against every scenario tested by hand, a 3-reviewer
workflow (completeness, edge-cases, test-and-requirements lenses) was run before committing, each
finding adversarially re-verified by two more independent agents. All five findings the reviewers
raised survived unanimous re-verification. Four were fixed:

1. `_require_adapter_files`'s own "list what's present" branch called `Path.iterdir()`, which --
   unlike `.is_file()`/`.is_dir()`/`.exists()` -- does not swallow a genuine `OSError`. A directory
   the process can stat but not list (a realistic locked-down deployment share) crashed the
   precheck with an unhandled `PermissionError` -- reintroducing, in the fix's own new code, the
   exact bug class it exists to close. Now every filesystem check in the function is wrapped in one
   `try/except OSError`, converted to a clean `IngestError` naming what couldn't be checked and why.
2. The "contains:" listing filtered to `is_file()` only, so a same-named directory (e.g. a stray
   `mkdir devices.csv`) was silently excluded while `_require_adapter_files` still called that name
   "missing" -- a visible contradiction a user could see was false just by running `ls`/`dir`
   themselves. Directories are now listed too, suffixed `(not a file)`.
3. The missing-file list wasn't deduplicated: a hypothetical future adapter reusing one filename
   for both `assets_filename` and `findings_filename` would have produced a message repeating that
   name on both sides ("needs data.csv, data.csv, but data.csv, data.csv are missing"). Not
   exploitable by either currently-registered adapter, but cheap to close now via
   `dict.fromkeys` -- fixed on both the "needs" and "missing" clauses, not just one.
4. The "likely cause" was unconditionally "this is almost always a --format/--data mismatch," even
   when only ONE of the two expected files was missing -- exactly the case where a format swap is
   the *least* likely explanation (the correct-format file is right there) and an incomplete or
   corrupted export is the more likely story. The test added for this exact scenario in the first
   version of the fix even said so in its own docstring ("a genuinely broken export, not
   necessarily a format swap") without the production message matching it. The explanation now
   branches: format/data mismatch only when every expected file is absent; "incomplete or
   corrupted export" language when some are present.

One finding was surfaced but deliberately not fixed here: `agents/coordinator.py`'s
`Coordinator.__init__` has its own separate native-only fallback file load
(`ingest.load_asset_index`, used only when a caller omits `assets=`) that still raises a bare
`FileNotFoundError` with no path or cause named -- the same defect class, a different code path.
Confirmed unreachable from any of the three CLI commands today (`run_agents`/`submit_constraint`
always pass `assets=` from `load_batch`'s own result before constructing `Coordinator`), and
pinned as intentional behavior by an existing test
(`test_without_an_inventory_and_without_assets_csv_it_fails_loudly`,
`tests/test_coordinator.py:1004`). Fixing it means deliberately reversing a pinned test's contract
in a code path the reported bug never touched -- a separate decision, flagged rather than made
unilaterally.

All four fixes verified by hand (a monkeypatched `Path.iterdir` raising `PermissionError` for the
exact directory under test; a real same-named directory; a stub adapter reusing one filename; a
real partial-file directory) before writing the covering tests. 389 tests, up from 374.

## 2026-09-04

**Local-model swap tested: the seam works, the model didn't.** CLAUDE.md's trust-boundary section
commits to a provider swap via `.env`, not code -- verified against a real local model instead of
taken on faith. `RHINO_LLM_MODEL=ollama/llama3.1:8b` plus `RHINO_LLM_BASE_URL=http://localhost:11434`,
no change to `llm.py` or any agent: `crewai.LLM` auto-detected the `ollama/` prefix and routed to
Ollama's OpenAI-compatible endpoint (`http://localhost:11434/v1`); a direct `get_llm().call(...)`
round-tripped correctly. Then ran the real pipeline against it: `rhino run --data demo-anchor
--agents` (the 3-finding ProxyLogon anchor fixture -- one CVE, three hosts).

**0/3 findings scored, two distinct failure modes, both caught rather than shipped.**
- F02 and F03 failed at Research: `attack_techniques[].prevalence` came back as `"Common"` /
  `"Likely"` -- free-text labels where `ResearchFinding` requires a float. Failed Pydantic
  validation on all 3 structured-output retry attempts, then gave up.
- F01 passed Research and Environment, then failed at Risk: its self-reported
  `recommendation.risk_score` was 9.8; the `score_finding` tool it had just called actually
  returned 85.52377816714133. `verify_scoring_matches_tool` (CLAUDE.md Section 8's
  grounding-validation item) caught the mismatch and refused rather than ship the fabricated
  number -- the first real case of that check firing on a genuine disagreement rather than a
  synthetic test.

Tool-calling itself wasn't the failure -- F01 really did call `score_finding` and get the real
value back. The model just didn't faithfully report what the tool told it, and separately didn't
respect a field's declared type. Both are model-capability gaps against a schema/grounding
contract written and tuned against claude-sonnet-5, not a defect in the seam.

**Side-by-side on the identical fixture.** Ran the same `demo-anchor` data through the default
config immediately after, same command, no other change: 3/3 findings scored in 2m04s,
reproducing the anchor demonstration exactly (`patch_now`/`next_window`/`mitigate_monitor` across
EXCH01/EXCH02/EXCHDEV01), rationale correctly citing NVD CVSS 9.8, EPSS 1.000 clearing the KEV
floor, ATT&CK T1190, and per-asset impact composites (0.925/0.750/0.400). The Ollama run took
17m38s and produced nothing usable.

**Caveats -- not tested here.** One quantized model (llama3.1:8b, Q4_K_M) against one 3-finding
fixture; the prompts are the ones written and tuned against claude-sonnet-5, with no adaptation
attempted for a weaker instruction-follower. A larger local model, a different quantization, or
loosened schema/grounding requirements might behave differently -- none of that was tried.

**docs/adapter-generation.md Slice 6 built: `adapters/probe.py`, `rhino adapt probe`/`list`.** The
next unbuilt piece behind that design's own build-order table -- Slices 1-4 (contract model,
`ConfiguredAdapter` engine, confirmation digests, CLI read path) and Slice 5 (source enrichment)
were already complete; this is the first thing a human runs against a source nobody has written a
mapping for yet, ahead of Slice 8's not-yet-built phase-1 inference agent. No LLM, no API key, no
network, writes nothing -- pure local file profiling.

**Built exactly the two things the design doc named, nothing more.** `NonRaisingProblemCollector`
(a `ProblemCollector` whose `raise_if_fatal` never raises) is not new invention -- `configured.py`'s
`ConfiguredAdapter` docstring already named this exact class ahead of time: "`collector_factory`
defaults to the real `ProblemCollector`; a probe (a later slice) passes a non-raising recording
subclass instead." Built now, in the slice the design document assigns it to; not yet wired as
anyone's `collector_factory` -- that is Slice 7's re-probe-and-refuse-while-fatal step, still open.
`profile_csv`/`profile_source` are the bounded full-file column profiler: every row is read exactly
once (CLAUDE.md Section 1's "nothing may assume the dataset is small enough to hold in memory or
fetch in one pass," which a first-N-rows peek would have violated outright), but each column's
retained state is capped (`MAX_DISTINCT_TRACKED=500` distinct values tracked, `MAX_SAMPLE_VALUES=8`
samples kept) so memory stays bounded independent of row count. Past the cap, `distinct_overflow`
marks the count as a verified lower bound, never a guess presented as exact -- and the same
discipline extends to `looks_like`'s `identity_candidate` tag, which a dedicated test confirms
never fires once a column has overflowed, even though every value really was distinct before the
cap was reached.

**`looks_like` reuses `configured.py`'s own code-owned pattern definitions, but is explicitly not
authoritative over them.** `_CVE_ID_PATTERN`, the ISO/US-slash/EU-slash date checks, and the
timestamp check are duplicated as small private constants in `probe.py` rather than imported --
matching this codebase's own established precedent (`_BLANK_BEARING_KINDS` already lives
independently in both `config_model.py` and `configured.py`) rather than inventing a new shared
module, and the stakes of drift are much lower here: a wrong hint costs nothing, since nothing
downstream trusts it automatically. Every tag requires EVERY non-blank value in the column to
match, computed exactly over the whole file via a per-value "still true" flag, never approximated
from a sample. Two honestly-disclosed limitations, not bugs: a column can get both
`date_us_slash` and `date_eu_slash` at once when every day-of-month value seen is <=12 (neither
reading is contradicted, so neither is silently dropped); and there is no `bool` tag at all, since
unlike a CVE id or an ISO date, a boolean vocabulary is not fixed across sources (`True/False`,
`Y/N`, `1/0` all appear in real exports) -- a column with exactly two distinct values is tagged
`binary` instead, a weaker, honest claim a human confirms by reading the two actual values in
`sample_values`.

**Duplicate header names and ragged rows are recorded, never raised -- the opposite posture from
every other adapter in this package, deliberately.** `native.py`/`defender.py`/`bluepeak.py`/
`configured.py` all refuse loudly the moment a value doesn't fit an already-decided mapping; this
module runs BEFORE any mapping exists, so there is nothing yet to be unfaithful to, and refusing on
a messy real-world file would defeat the entire point of looking at one. A repeated header name
is accumulated last-occurrence-wins, verified against a test that gives the two occurrences
genuinely different values and confirms only the LAST one's values survive -- matching
`ingest.open_csv`'s own documented `csv.DictReader` behavior exactly, so the profile shows what a
real mapping would actually read, not an average of two columns that don't exist. A short row's
missing trailing column is not counted as blank -- mirrors `ingest.iter_csv_rows`'s own documented
distinction ("a truncated row is not a row with blank cells") for the real engine, verified with a
dedicated test. A mid-file decode error stops the scan and sets `truncated=True` rather than
raising, so a caller sees real partial results plus a `problems` entry instead of nothing at all.

**CLI: `rhino adapt list` and `rhino adapt probe <name>` (cli.py).** `list` scans `data/` for
subdirectories containing at least one `.csv` file and, for each one, names every registered
`--format` whose expected filenames are already present (a subset check, so unrelated extra CSVs
alongside a full native or Defender file set don't disqualify a match) -- pure directory listing,
no file content read, so a user isn't pointed at probing a source that already has a working,
reviewed built-in adapter. `probe <name>` resolves `<name>` exactly like `--data`
(`_resolve_data_dir`, reused verbatim) and prints, per file, a column table (blank rate, distinct
count, value length range, `looks_like` tags, bounded samples) via the same `_print_rows` helper
`_print_table` already uses, followed by every recorded observation or "No observations." A
duplicate header name is de-duplicated in the printed table itself (iterating
`dict.fromkeys(profile.header)`) even though `FileProfile.header` keeps the raw, duplicate-bearing
list -- the `problems` section already explains the duplication, so showing the same resolved
column twice would only be confusing, not more informative.

**Verified against the real committed sample files, not just synthetic tmp_path CSVs.** `rhino
adapt probe defender-sample` correctly reproduces facts already documented elsewhere in this file:
`devices.csv`'s `DeviceId` shows 6 rows but only 5 distinct values (the one repeated device row
built into that sample on purpose), and `vulnerabilities.csv`'s `CveId` shows 10 rows but 9
distinct values (the one duplicate finding row). `rhino adapt probe bluepeak` correctly tags
`CVE_ID` as `cve_id` and `Company`/`Data_Source` as `constant` on the real 50-row file. `rhino
adapt list` against the real `data/` directory correctly surfaces `demo`/`demo-anchor` as `native`,
`defender-sample` as `defender`, `bluepeak` as `bluepeak`, and excludes `data/adapters/` (JSON
contracts, no CSVs) and `data/snapshots/` (nested JSON) entirely.

**Verification.** 57 new tests: `tests/test_adapters_probe.py` (39 -- every `looks_like` tag
individually, the distinct-value cap and its interaction with `identity_candidate`, duplicate-
header last-wins accumulation, ragged-row short/long handling and its message cap, encoding
detection reuse, both failure modes (`ProbeError` on an unreadable/empty file, on a directory with
no CSVs), and smoke tests against the real `demo`/`bluepeak`/`defender-sample` files asserting only
column names and structural facts, never a specific fixture VALUE, since `test_no_fixture_coupling
.py` already enforces exactly that discipline for `adapters/*.py` and this module is now inside its
glob), `tests/test_cli_adapt.py` (18 -- argument wiring, directory discovery including the subset-
match check and the no-`data/`-directory case, output formatting, the header-deduplication display
fix, and every exit code). All 719 tests pass under `.venv312`; confirmed separately under `.venv`
(Python 3.14, excluding the modules that already couldn't collect there before this session) that
`test_adapters_probe.py` and `test_cli_adapt.py` both pass cleanly -- `probe.py` has no `crewai`
dependency, so it needed no lazy-import treatment the way `agents.*`/`memory` do.

**docs/adapter-generation.md Slice 7 built: `adapters/review.py`, `rhino adapt confirm`/`rereview`.**
The slice was already "partially built" on paper -- V18 validated attestations (Slice 1),
`confirm_contract` stamped digests (Slice 3), and Slice 6 had just added the non-raising collector
the re-probe needed. What was missing was the part that makes a human confirmation mean anything:
the verbs, the re-probe, and the merge-by-slot-digest logic.

**Designed by panel before any code was written, because the decisions interact.** Four independent
designs (framed around gate integrity, reviewer UX, codebase convention, and failure modes) judged
by three adversarial lenses (correctness, convention fit, whether the review is real). Two judges
independently ranked the same design first and converged on nearly every question, and the judges
verified their claims by running code rather than reading it -- which is where several of the
decisions below come from.

**The chicken-and-egg, and why the fix is the boring one.** `ConfiguredAdapter.__init__` calls
`assert_confirmed` before it sets a single attribute, so the one object that must measure an
UNCONFIRMED contract is the one object that refuses to exist for it. Confirmed by running it, not
assumed. Resolved by SATISFYING the gate rather than routing around it: `_provisional` stamps an
in-memory copy through the ordinary `confirm_contract` with a sentinel identity, and that copy is
function-local -- never returned by a public name, never written, never handed to scoring. The
rejected alternative was extracting the engine's constructor body so a review could call it on an
`__new__`'d instance; that adds a second supported construction path around a gate whose entire
value is being the only one, then guards it with naming discipline -- the class of protection
`config_model.py`'s own docstring refuses to rely on when it argues against an `on_unmapped` key.
Two details of `_provisional` are load-bearing rather than cosmetic, and both were found by running
the thing: clearing `review` first (so `confirm_contract` recomputes digests over CURRENT content,
which is what keeps a DRIFTED contract measurable at all -- `rereview` is the only command left
that can inspect one), and clearing `observed` (because `load_assets` runs `validate_contract` on
every load and V18 reads the stored exclusion count, so a stale measurement makes the fresh
measurement refuse itself).

**The order is not negotiable, and validating in the wrong place produces a spurious failure.**
measure -> build `observed` -> merge attestations -> `confirm_contract` (stamp) -> `validate_contract`
LAST -> in-memory round-trip verify -> single write. Validating before stamping reports a
`review.content_digest` mismatch on every already-confirmed contract, because `observed` has moved
while `review` still carries the old digest. And the validation has to use the engine's own
`_filtered_for_validation` header view, not a freshly read raw header -- otherwise a vendor's new
column, which `header.mode="declared"` deliberately tolerates as a notice, comes back as a V08
"neither mapped nor in unmapped_columns" refusal at the very last step, in precisely the drift case
a re-review exists to report. `ConfiguredAdapter` now records that view as `self.headers` for this
reason.

**`rereview` cannot write, structurally.** Not "does not by default" -- there is no code path from
`sign=False` to `overwrite_contract`. One verb reports, one verb signs, and only the signing verb
takes an identity, so a CI drift check can never produce a confirmed contract nobody read.
`confirm` refuses an already-confirmed contract without `--reconfirm`, which is also the mechanical
guard on CLAUDE.md Section 8 rule 1: both committed contracts are confirmed with matching digests,
so no bare invocation can rewrite `bluepeak-gen.json` or `mdvm-gen.json` and break the two pinned
differential tests. Demonstrated the write path on scratch copies throughout; a test asserts the
committed files are byte-identical after both verbs run against them.

**The attestation gate is a two-shot loop, not a prompt** (this codebase has no interactive input
anywhere). `--attest ITEM=TEXT`, repeatable, split on the first `=` so the text may contain one,
validated against `ATTESTATION_ITEMS` -- which turns out to be that constant's first consumer:
`Attestation.item` is a bare `str`, so before this a typo (`exclusion` for `exclusions`)
constructed happily and V18 then refused for a missing item while the file visibly contained an
attestation. The C3 ordering hazard -- the measurement DISCOVERS exclusions, so V18 then demands an
`exclusions` attestation that does not exist yet -- resolves by order: shot one measures, refuses,
writes nothing, and prints the exclusions with their reasons; shot two supplies the sentence.
Exercised end to end against a real BluePeak file with one row's `Asset_Type` set to an unmappable
value: 1 excluded asset + 1 cascaded finding, refusal naming `['exclusions']`, then a clean sign.
Nothing is ever auto-generated -- synthesizing the sentence that sanctions a measurement is the
silent absorption the whole design exists to prevent. An attestation for a condition that does NOT
hold is refused too: a signed acknowledgment of something that never happened reads later as
evidence someone looked.

**V18's policy is now extracted rather than duplicated.** `required_attestations`/
`missing_attestations` (`config_model.py`) are the single definition behind both the validator's
refusal and `review.py`'s need to PREDICT it before signing -- the same anti-drift move the module
already makes deriving `GAP_LEGAL_TARGETS` from `NOT_COLLECTED_DEFAULTS`. `validate_contract` still
emits byte-identical problem strings (insertion order is V18's own emission order). While extracting
it, closed a live crash: `observed` is `dict[str, Any]`, so a hand-edited contract storing the
`id -> reason` DICT that `IngestStats` carries under the identical names made V18 add two dicts and
raise a bare `TypeError` out of the validator instead of refusing. `_observed_exclusion_count` now
refuses.

**Merge-by-slot-digest does both halves.** The partition (unchanged / changed / new / orphaned) is
what `compute_slot_digests`' own docstring says it exists for -- a reviewer re-reads one line
instead of the whole contract, confirmed live: edit one mapping's `case` and the re-review reports
`23 unchanged, 1 changed` and names it. The report also states plainly that a digest cannot
reconstruct what it hashed, so it prints the CURRENT node and points at `git show HEAD:<path>` for
the previous one. The second half is which of the reviewer's prior CLAIMS survive: everything
carries while `decision_digest` is unchanged; once a decision moves, `finding_id.synthesized`
carries only while `finding.finding_id`'s own slot is unchanged. `exclusions` never carries on
digest grounds -- it describes a measurement, not a mapping. **C5, the no-`slot_digests` fallback,
is the state both committed contracts are actually in**, not a hypothetical; it is announced loudly
and self-heals, since confirming records them.

**A bug the tests caught, in the carry-forward gate itself.** The first implementation refused
whenever an attestation was dropped by drift -- including when the reviewer had just supplied a
fresh sentence for that exact item in the same invocation. `still_missing` is the real gate (a
dropped item that was not re-supplied lands there anyway), so the drop is now context printed for
the reader, not a refusal. Caught by `test_a_changed_finding_id_recipe_is_refused_without_reset_identity`,
which exercised `--reset-identity` with a re-supplied attestation and got a refusal it should not
have.

**What the reviewer actually sees, which is the point of the whole feature.** The report leads with
the measurement -- assets/findings loaded, what collapsed, what was excluded and why -- before any
of the contract's own claims about itself, so an impression forms from measurements rather than
assurances (a test pins that ordering). Then two sections that exist because a claim-only review
cannot produce them. First, the values the mapping actually produced for the enumerated Impact
inputs beside how many are documented defaults: on `mdvm-gen`/`defender-sample` that reads
`environment prod x5 -- 5/5 not collected`, `data_sensitivity internal x5 -- 5/5`, `role file x3,
workstation x2 -- 5/5` -- a mapping that runs perfectly clean while three of the four Impact inputs
are fabricated, which is exactly the failure a signature over a hash cannot catch. Only enumerated
targets are tallied; free text (`hostname`, `owner`, `business_function`, `product`, `evidence`) is
never counted and never persisted. Second, every column the contract declares it deliberately does
not read, with its stated prose reason beside its MEASURED shape from Slice 6's profiler --
`unmapped_columns` is a signed claim that nothing otherwise checks, and this is where a mapping
hides the patch-window column somebody dismissed as operational metadata.

**`observed` is written for the first time, and what is NOT in it was decided deliberately.** Flat,
because V18 reads `excluded_assets`/`excluded_findings` at the top level and adds them, so both are
plain ints there. Asset-side exclusion reasons are recorded (they carry the source's own vocabulary
token and the known vocabulary -- schema information) keyed by reason text with a count, never by
record. Finding-side reasons are NOT: a cascaded reason embeds its asset's id, which on a real
export is a device identifier, and a contract is committed to git. No cell value, no record id, ever.
All of it prints to the terminal, which is not committed.

**Closed the gap that made a signature mean less than it looks.** Nothing in the codebase read
`observed` except V18, so a contract confirmed against a friendly six-row sample and then run
against a six-million-row export was completely undetectable -- and the re-probe's own cost is
exactly what pushes an operator toward the small sample. `_print_adapter_config_banner` now compares
the counts the confirmation measured against the counts this run loaded and prints a notice when
they differ. Stated as a notice, not enforced: there is no defensible threshold yet, and the point
is to put the mismatch in front of a person at the moment it matters. Silent for a contract with no
measurement, which is both committed contracts today -- so no existing output changes, and a test
pins that.

**Two latent defects surfaced, both reachable only now.** `config_io` wrote `"from_"` instead of the
documented `"from"` for `derived`/`default_by` mappings, because `model_dump()` emits the field name
rather than the alias -- latent since Slice 3 because nothing had ever written a contract containing
a `derived` block back to disk, and `confirm` is that something. Fixed with `by_alias=True`, verified
digest-neutral (digests hash the non-aliased dump, so both committed contracts' stored digests still
verify), and pinned by tests that fail without the fix -- the pre-existing serialization test could
not catch it, since it uses the one contract with no `derived` block. And `configured.load_findings`'
`assert mapped is not None` fired as a message-less `AssertionError` under a non-raising collector --
not an `IngestError`, so it escaped every `except IngestError` in cli.py as a traceback, and vanished
under `python -O`, leaving a `TypeError` on the tuple unpack instead. Now `if mapped is None:
continue`, provably behavior-identical on every production path.

**Adversarial review caught two more defects, both of which the tests written for this slice had
missed for the same reason: the fixtures were too healthy.** A 5-dimension review (gate integrity,
correctness, privacy, regression, test quality) with two independent skeptics per finding, each
instructed to refute rather than confirm. The run was cut short by a session limit -- the regression
and test-quality reviewers and most verifiers never completed -- so this is a partial review, and
the remaining dimensions are still open. Of what did complete: the one privacy finding
(`observed.excluded_asset_reasons` persisting source vocabulary tokens) was refuted unanimously,
both skeptics noting it is documented, pinned by a test, and gated behind an `exclusions`
attestation a human must write after seeing every reason on screen. Two survived, both real, both
reproduced before fixing:

1. **A contract that did not already carry its shape-required attestations could never be
   confirmed.** `validate_contract` runs inside `ConfiguredAdapter.load_assets`, so V18's structural
   requirements (`enrichment`, `union`, `finding_id.synthesized`) fired during the MEASUREMENT --
   before `--attest` was merged. The pass halted with 0 rows and the refusal blamed the source, so
   supplying the attestation could never help. That is the normal state of a freshly proposed
   contract, so it would have blocked the entire propose -> confirm flow Slice 8 exists to produce.
   Both committed fixtures already carry their attestations, which is exactly why every test passed.
   Fixed by merging attestations BEFORE measuring, and by listing the missing-attestation refusal
   ahead of the generic fatal-problems line, since the former is often the CAUSE of the latter.
2. **The identity freeze could be walked past three different ways.** It was keyed on
   `finding.finding_id in slots.changed`, but `review` sits outside both digests, so `slot_digests`
   is unsigned evidence that can be absent (the state of BOTH committed contracts), partially
   deleted (`partition_slots` then classifies the slot as `new`, not `changed`), or removed whole.
   In each case a changed content-address recipe was re-signed in silence, re-keying every
   `memory.decisions` row for the format -- confirmed by loading before and after and observing two
   disjoint `finding_id` sets. Fixed by inverting the gate to "refuse unless the identity slot is
   PROVABLY unchanged", which closes all three at once, with wording that distinguishes "known to
   have changed" from "cannot be determined from this file".

**The review finished in a second pass, and the dimensions that had been cut short found four more
defects.** The first run lost its regression and test-quality reviewers, and most verifiers, to a
session limit; those were completed afterwards. Four more real defects, all fixed:

3. **`rereview` reported "No drift and no problems." and exited 0 on exactly the drift it exists to
   catch.** A requirement can appear without the contract changing at all: the source starts
   excluding records, so V18 demands `exclusions` where it did not before. Every digest still
   matched and the measurement was clean, so the summary went green while `confirm --reconfirm`
   refused the identical input -- a CI drift check passing on a contract that can no longer be
   signed. `still_missing` was computed and never printed, either. Both now flow from one
   `ReviewOutcome.rereview_clean` property, so the printed line and the exit code cannot disagree
   (they briefly did, mid-fix, which is why it is one property rather than two expressions). It also
   now covers a moved slot, which had the same print-says-NEEDS-REVIEW / summary-says-clean split.
4. **The "columns this contract does not read" section vanished in silence for any source with a
   non-comma delimiter or a banner row**, because `_unmapped_profiles` re-read the file through
   `probe.profile_csv`, which knows nothing of `Source.delimiter`/`quotechar`/`encoding`/
   `first_data_row`. The file parsed as one giant column, every declared name missed, and the
   section simply disappeared -- the worst failure mode for the part of the report whose job is to
   show what a mapping ignores. `profile_csv` now takes those four as optional arguments defaulting
   to today's behavior, and the review passes the contract's own.
5. **`_print_contract_state` raised `IndexError` on a slot-digest key with no `.` in it.**
   `slot_digests` lives under `review`, which sits outside both digests, so its keys are unsigned
   and a hand-edited file can carry any shape. A printer must not raise on one.
6. **The value distribution silently truncated to four values per field**, with no ellipsis and no
   count, so the numbers shown simply did not add up to `assets_loaded` and a reader had no way to
   know the list was partial. Now says `+N more`.

**Regression checked by byte-diffing against the previous commit, after the first attempt at it was
itself wrong.** Running the old code from a `git worktree` looked convincing and proved nothing: the
editable install shadows the worktree, so both sides imported the same current source. With
`PYTHONPATH` actually pinned, `run` on the demo fixture, `--format bluepeak`, `--format defender`,
`--adapter-config`, and `adapt list` are byte-identical pre- and post-slice, and `adapt probe`
differs only in the absolute path of the worktree it ran from. V18's attestation messages are
byte-identical across the extraction, checked branch by branch; the only deliberate difference is
the non-int exclusion count, where the old code raised `TypeError: unsupported operand type(s) for
+: 'dict' and 'int'` out of the validator and the new one refuses -- reproduced against the real
pre-slice code rather than argued.

**Mutation testing on the new tests, which found one vacuous claim and one hazard.** Eight
load-bearing behaviors were each broken in turn to confirm a test caught it. Seven did. The
survivor was `_provisional` clearing `observed` -- a property this module's own docstring calls
"load-bearing, not cosmetic" and which nothing tested, because every fixture either had no
`observed` or had one with a matching attestation; now covered by a test built on the real case (a
previous run's exclusion counts with no `exclusions` sentence on file). The hazard was worse and
was found by the mutation rather than by the test: with the `--reconfirm` guard removed,
`test_the_committed_contracts_are_never_written_by_a_review` -- the one test that deliberately
points the WRITING verb at a real committed artifact -- rewrote `data/adapters/bluepeak-gen.json`
and took the pinned differential test down with it. The guard regressing should produce a red test,
not a corrupted repository, so that test now restores the bytes in a `finally`. Both mutations are
caught now, and the repository is verified clean afterwards.

**Verification.** 68 new tests (791 total, up from 723): `tests/test_adapters_review.py` (46 -- the
measurement against real committed data including that its numbers equal what `rhino run` reports,
every refusal path, the C3 two-shot loop, carry-forward under three drift shapes, `--attest`
parsing, all six review findings above, and that the committed contracts are byte-identical after
both verbs run) and a confirm/rereview section in `tests/test_cli_adapt.py` (21 -- flag wiring, exit
codes, output ordering, and the banner notice). Plus 4 in `tests/test_adapters_config_io.py` for the
alias fix and 3 in `tests/test_adapters_probe.py` for the dialect arguments. All 791 pass; the two pinned differential tests and every `rhino run` byte-identical test are
untouched, and `git status data/adapters/` is clean after the whole suite.

**CLAUDE.md gained an adapter-generation section (commit `ebd1273`), which surfaced that
docs/adapter-generation.md itself had drifted from what the hardening round actually shipped.**
CLAUDE.md had no mention of the LLM-assisted contract-authoring subsystem at all despite it being
seven slices deep -- added a standalone section stating the two-phase split and why it exists
(the same discipline Section 8 rules 2-3 already require of scoring), current slice status, and
both design rules in full inline rather than only by reference (exclude is legal only for a check
feeding `Asset.role`, forward-traced by the validator; every pattern a contract can invoke is a
closed, code-owned catalog, never model-authored). Checking the "current status" sentence against
`git log --follow -- docs/adapter-generation.md` found it was wrong: the design doc was never
touched by `309b9a1` at all, and two of the six hardening defects (the attestation-merge ordering,
the identity-freeze bypass) were found and fixed *before* `48ac821` was committed, not by it --
"an adversarial review round (commit `309b9a1`)" attributed all six to the wrong commit. Corrected
to name both commits.

**The design doc's "Order, which is not negotiable" paragraph was never accurate, not merely
stale.** `git show 48ac821:docs/adapter-generation.md` already carries the wrong text at the
moment of that commit -- "measure -> build `observed` -> merge attestations" -- while `48ac821`'s
own `review.py`, in the SAME commit, already merges attestations before measuring (the fix for
defect 1, above). The prose was never updated to match a fix already made before the commit
landed; there is no historical window in which this paragraph was true of the code it sat next
to. Fixed to state the real order and, briefly, why attestations move first.

**Checked directly whether the "Known limitation" (enrichment/union attestations can't provably
carry forward) survived the six-defect hardening, since asked.** It does, unaffected: read
`carried_attestations()`'s current source against the design doc's own prose line for line --
identical for those two items, and none of the six defects touch that branch. They hardened a
related but distinct mechanism instead, the `finding.finding_id` identity freeze, which lives in
`review_contract` itself, not in `carried_attestations`. Added a sentence to the design doc saying
so explicitly, since it's a reasonable thing to wonder from the outside and was previously
unanswered either way.

**docs/adapter-generation.md now also documents the identity freeze's real mechanism and the
unmapped-column profile, neither of which had prose before.** The identity freeze
(`--reset-identity`'s actual trigger -- refuse unless the slot is *provably* unchanged, never
merely "not known to have changed," closing the three ways `slot_digests` being absent, missing
one entry, or removed entirely used to let a changed recipe through in silence) had no
description at all despite `--reset-identity` already appearing in the CLI usage block. And
"every column the contract declares it deliberately does not read, profiled beside its stated
reason" -- built in the initial `48ac821`, never mentioned anywhere in the design doc -- is now
described, since defect 4 (`profile_csv` blind to the contract's own delimiter/encoding/banner
row) was a correctness bug in exactly that feature, and Slice 8's own reporting posture is
expected to inherit it: an LLM proposal's own low-confidence column is the same shape of thing as
a declared-ignored one.

**Slice 8 built: `agents/schema_inference.py`, the phase-1 inference agent, and `rhino adapt
propose`.** The model's structured output is `AdapterProposal`, not a `Contract` -- `Contract`
requires every `asset`/`finding` slot mapped to something, which would force a guessed mapping for
any field the model isn't confident about. Every target is `SlotMapped` (a real `config_model
.Mapping` node -- the identical 9-kind discriminated union `configured.py` executes, imported not
restated, so an LLM can only *select* a kind/parser from the closed catalog, never author one) or
`SlotUnresolved` (an honest non-answer, never auto-filled -- not even into a legal `not_collected`,
since "the source has no such column" and "I'm not confident" are different claims and conflating
them would itself be a guess). No `output_pydantic`: the same `expected_output`-JSON-plus-
`parsing.parse_structured_output` convention `agents/constraint_intake.py` already established
for the identical reason, with a bounded retry loop (`max_attempts`) on a parse failure or a
proposal that disagrees with the source facts it was actually handed.

`check_grounding` is the LLM-free gate that decides whether a proposal is trustworthy enough to
assemble: every cited column must be real; a `vocabulary`/`derived` table's keys must be among a
column's actually measured values (`probe.ColumnProfile.distinct_values` -- Slice 6's profiler
already tracked this internally, capped at `MAX_DISTINCT_TRACKED`, but only exposed 8 truncated
samples; now exposed in full, no new scan); a `literal` must cite a column the profiler tagged
`constant` and match its one observed value. `assemble_contract` refuses (never raises --
`ProposeResult.contract is None`, a normal reportable outcome) unless every slot is mapped and
grounding reports zero failures, then builds a real `Contract` (`review.state="proposed"`).
`rhino adapt propose` always saves the raw proposal (`out/propose_<name>.json`, paired with its
`Generator` provenance) regardless of completeness, so an incomplete one can be hand-corrected and
resumed via `--from-proposal` without re-spending an LLM call.

**An adversarial review of the first version (8 parallel finder angles, the same discipline as
Slice 7's hardening round) found and fixed eight real defects before this slice's first commit --
none of them shipped.** Two were found independently by more than one angle, and one was confirmed
by the shipped test suite itself asserting the wrong thing:

1. **Grounding ignored the mapping's own `case` transform.** A vocabulary/derived table's keys were
   checked against the RAW, un-cased measured values, but `configured.py`'s real engine applies
   `_apply_case(raw, mapping.case)` before ever consulting the table. A correct, working
   `case:"lower"` mapping over a column containing `"SRV"`/`"WKS"` was reported as a hard grounding
   failure -- confirmed by two independent review angles, one of which reproduced it directly.
   Fixed: `_ground_table` now cases the observed values the same way before comparing.
2. **`assemble_contract` never ran `validate_contract`.** Grounding only checks that a table's
   KEYS were observed and that cited columns exist -- it has no opinion on whether a table's VALUE
   is legal for its target's own vocabulary, or on `asset_grouping.union_fields`/`finding_dedup
   .content_targets`' own structural legality, both real checks `validate_contract` already
   performs. A proposal mapping `asset.environment` to `"cloud"` (not a legal value) passed
   grounding cleanly and would have assembled and been reported "every slot mapped and grounded,
   every column accounted for" -- confirmed by reproducing exactly that. Fixed: `assemble_contract`
   now runs the real, already-exhaustive `validate_contract` before ever returning, and a failure
   there refuses assembly the same way an unresolved slot does.
3. **A `literal` mapping's value was never checked against the column it cited.** `_ground_literal`
   confirmed only that SOME cited column was tagged `constant`, never that the literal's declared
   value matched that column's one true observed value -- confirmed by the shipped test suite
   itself, which had a passing test asserting a `literal(value="prod")` citing a column whose only
   observed value was `"srv"` was correctly grounded. Fixed: the cited column's actual value must
   now match.
4. **`optional` columns were treated as hard failures when absent.** `_check_column_exists` had no
   `optional` parameter, so a slot legitimately marked optional for a column this export doesn't
   have (`config_model._compute_not_collected`'s own documented escape hatch) was blocked exactly
   like a hallucinated column. Fixed: an absent optional column is no longer a grounding failure.
5. **`check_grounding` never touched `proposal.enrichment` at all.** A hallucinated
   `enrichment.severity_score.column` sailed through unreported on a BluePeak-shaped proposal.
   Fixed: enrichment's three column-reading sub-mappings are now grounded explicitly (on top of the
   `validate_contract` safety net from defect 2, which would also have caught this).
6. **`composed`/`content_address` grounding hardcoded the findings file regardless of which side a
   slot was on, and didn't distinguish a placeholder absent from both files (legal -- it simply
   never contributes) from one that exists only in the OTHER file (the real, no-cross-file-join
   mistake `validate_contract` itself flags).** Fixed both: an asset-side `composed`/
   `content_address` proposal is now refused directly rather than checked against the wrong file,
   and a composed placeholder is only a failure when it exists in the other file.
7. **The retry loop under-reported cost.** `Generator.prompt_tokens`/`completion_tokens`/
   `estimated_cost_usd` were read only from the FINAL (successful) dispatch's `usage_metrics`,
   silently dropping every earlier failed attempt's real, billed spend from the audit trail. Fixed:
   usage now accumulates across every attempt via `UsageMetrics.add_usage_metrics`, and
   `call_log_digest` hashes every attempt's prompt+response, not just the last.
8. **A hand-edited `--from-proposal` file with a schema typo crashed instead of refusing cleanly.**
   `load_saved_proposal` let a raw `pydantic.ValidationError` escape, and `cli.py`'s dispatch only
   caught `SchemaInferenceError` -- the exact pattern the block already guards against ten lines
   above, for `read_contract`, just not applied here too. Fixed: wrapped into `SchemaInferenceError`.

**Verification.** 68 new tests (862 total, up from 794): 55 in `tests/test_schema_inference.py`
(new), 10 in `tests/test_cli_adapt_propose.py` (new), 3 added to `tests/test_adapters_probe.py`
for `distinct_values`. Coverage added specifically to close what the review's own test-coverage
angle found missing: a genuine two-file layout exercised end to end through `check_grounding`/
`assemble_contract` (every prior fixture used `single_file`, where `assets_profile is
findings_profile`, unable to prove `is_asset` selects the right side at all), `derived`/
`default_by`/`composed`/`content_address` mapping-kind grounding, and `assemble_contract`'s new
`validate_contract` safety net against an illegal vocabulary value and an illegal `union_fields`
entry. Full suite: 861 passed, 1 skipped. `git status` confirmed clean of any stray write outside
the intended files throughout.

**Differential check, for real: `rhino adapt propose` against the committed Defender fixture,
confirmed, run, and diffed against the hand-written `defender.py` adapter on the same data.** This
is the first real (non-mocked-Crew) exercise of the whole propose -> confirm -> run pipeline, and
it surfaced two more real defects no unit test had a chance to catch, because a hand-crafted test
fixture always already matches the schema the test author had in mind.

1. **The prompt never actually stated `ProposalMeta`'s field names.** All 3 attempts failed to
   parse: the model produced `meta.name` instead of `meta.format`, and omitted `description`/
   `reasoning_summary` entirely -- reasonable inferences from context (the CLI's own positional
   argument is literally called `name`), but `_build_task_description` never gave the model an
   explicit key-name list for `meta`, only prose describing the four echoed facts. Fixed: the task
   description now opens with a literal, exact top-level JSON skeleton naming all six `meta` keys.
   Second attempt with the fix: parsed clean on attempt 1.
2. **`assemble_contract`'s new `validate_contract` safety net (added by the adversarial review
   above) unconditionally refused any proposal using `content_address` for `finding_id`** -- V18
   requires a `finding_id.synthesized` attestation, but attestations are a confirm-time human act
   (`config_io`'s own "attestations merge in, THEN validate_contract runs" ordering); a freshly
   assembled proposal can never carry one yet. Since `content_address` exists specifically for a
   source with no natural finding-id column -- exactly Defender's `vulnerabilities.csv` -- this
   meant the safety net, meant to catch real defects, instead made an entire legitimate class of
   proposal unassemblable. Fixed: `assemble_contract` validates against a COPY of the contract
   carrying placeholder attestations for whatever `missing_attestations` would demand, never the
   real one -- so the structural check still runs in full, but the contract actually returned and
   written carries zero attestations, and `rhino adapt confirm` still correctly demands the real
   one later. A related, smaller gap fixed alongside it: `propose_contract` was silently discarding
   the `ProposalIncompleteError` message whenever `assemble_contract`'s validator (not grounding)
   was what refused, so the CLI could print "0 unresolved, 0 grounding failures -- NOT written"
   with no way to tell why -- `ProposeResult.incomplete_reason` now carries it through.

**The differential result itself, once both fixes landed:** the model, unprompted, chose a
DIFFERENT derivation source than the hand-written adapter for `asset.role` (`MachineGroup`
Servers/Workstations, vs. `defender.py`'s own `OSPlatform`-keyed `OS_PLATFORMS` table) -- both
correct, because `MachineGroup` happens to correlate perfectly with OS class in this fixture --
and correctly left `asset.criticality` UNRESOLVED rather than guess between `AssetValue` and
`ExposureLevel` (two candidate columns, no way to know which one the target's 1-5 scale intends,
or that `AssetValue`'s Low/Normal/High needs the exact numeric mapping `defender.py` hand-encodes).
Hand-completed `criticality` the same way `defender.py` does (`AssetValue` -> 1/3/5) to finish the
check -- with `"Low"` correctly OMITTED from the table, since this fixture never exercises it and
grounding refused a value it can't verify (a real, structural difference from the hand-written
adapter's table, which encodes all three documented tiers regardless of any one sample: a
confirmed contract's vocabulary coverage is bounded by what its reviewed sample actually contained
in a way a general-purpose Python table isn't).

**The scored, ranked, bucketed output is BYTE-IDENTICAL to `defender.py`'s own** across all 9
findings: same risk_score, same bucket, same 6/9 (66.7%) contested rate, same Impact-axis values
(role, environment, data_sensitivity, criticality, internet_exposed), same not_collected gaps.
The only real differences: `finding_id` values themselves (a different, but equally valid,
content_address recipe -- `defender.py` additionally hashes `SoftwareVendor` and uses uppercase
hex; `memory.decisions` rows will not be shared between the two formats, an accepted tradeoff
recorded in the confirm attestation), and the ATT&CK "unconfirmed candidate" technique lists for
5 of 9 findings -- traced to `enrich/attack.match`'s query text being `f"{product} {evidence}"`:
the propose-generated contract's composed `evidence` (remediation trail only) differs from
`defender.py`'s own (which restates vendor/product/version first), so semantic retrieval over a
genuinely different query string surfaces a different candidate set. Neither difference touches
scoring -- unconfirmed ATT&CK candidates are never used in it.

`data/adapters/defender-propose-check.json` (confirmed, signed by an automated identity for this
check, not a named human maintainer) is left uncommitted pending a decision on whether to keep it
as a third example contract or discard it -- unlike `bluepeak-gen.json`/`mdvm-gen.json`, it is the
first ever produced by the actual phase-1 agent rather than hand-authored.

## 2026-09-05

**Chat layer for the web UI: read-only Q&A over one run's export file, proposed and approved
before any code was written, then built.** Not a CLAUDE.md-numbered slice -- a web UI addition
scoped in conversation: "reads the plan and changes nothing. Mutation comes later through the
existing job substrate." The design was written up and agreed first (context-fitting strategy,
citation mechanism, grounding enforcement, UI placement, and whether the job substrate applies),
matching this project's own "propose representation before building" discipline, then implemented
against that agreed shape rather than improvised during the build.

**`agents/chat.py`, a new, deliberately toolless agent.** Every other agent in this codebase
(`research.py`/`environment.py`/`risk.py`/`constraint_intake.py`) gets tools because its job is to
gather or act on evidence beyond one prompt. Chat gets none: the entire export JSON is serialized
into the task prompt every turn (full-context-stuffing, no retrieval, no chunking), which at this
fixture's scale (~13.5K tokens deterministic, measured; ~34K extrapolated agents-path) fits a
context window with wide margin. A tool that could fetch anything else -- even something already
in this codebase, like `lookup_nvd` -- would be exactly the escape hatch "no enrichment lookups, no
outside CVE knowledge" is supposed to close. `ChatAnswer`'s `insufficient_data`/`insufficient_reason`
pair (a `model_validator` requires a non-empty reason whenever `insufficient_data` is true) makes
"not in this plan" a legal, structured answer rather than something the model has to improvise
honestly on its own. `build_chat_task` also wraps the export JSON in explicit data-not-instructions
delimiters -- CLAUDE.md's still-open prompt-injection item names scanner/NVD-derived free text as a
risk, and chat is the first place that text reaches an LLM prompt a human actively reads answers
from; the delimiter is a stated mitigation, not a claim that item is now closed.

**Citations are code-verified, never model-trusted -- the same discipline `risk_score` and
`tot.CriticScores.aggregate` already enforce elsewhere in this codebase, applied to chat.**
`ChatCitation` carries only `finding_id`/`fields_used`; the model is never asked for, and never
supplies, a cited finding's score or bucket. `_validate_citations` checks every cited `finding_id`
against the export's real `findings[]` (the same shape of check as `agents/risk.py`'s
`verify_scoring_matches_tool` and `agents/schema_inference.py`'s `check_grounding` -- ground truth
from data, not from the model's retelling) and fails the response, bounded-retrying up to
`DEFAULT_MAX_ATTEMPTS=3` fresh dispatches, on any citation that doesn't exist. `enrich_citations`
then attaches the REAL `risk_score`/`bucket`/`cve_id`/`hostname` server-side, from the export, after
grounding passes -- so a citation the UI shows can never be a number the model was in a position to
misreport. This directly answers a requirement stated when the design was approved: citation chips
show the cited finding's real score and bucket inline, not just its id, so a wrong claim is visible
without clicking through. What this checks and what it can't: real finding_id membership is a
mechanical, code-enforced fact; the truth of the surrounding prose is not (no tool-call log to check
it against, unlike `score_finding`) -- named as a limitation chat inherits, not one it solves,
matching CLAUDE.md Safety and guardrails' still-open general "grounding validation" item.

**`web/chat.py`, mounted only by `rhino web --enable-chat` -- independent of `--enable-jobs`, on
purpose.** `web/jobs.py`'s `JobRegistry`/`PlanState`/single-job-at-a-time lock exist to serialize
access to shared mutable state (`Coordinator.state`, `memory.py`'s SQLite) that a constraint
submission actually writes to. Chat writes to neither: every request is a pure function of (the
export file's current contents, the question), so it needs none of that -- no `--data`/`--format`/
`--seed`/`--db`, no lock, no `PlanState`. `create_app()`'s existing import-boundary discipline
(`web/jobs.py` imported only inside `create_app`'s body, only when enabled) is extended the same way
for `web/chat.py`; `/api/health` gained `chat_enabled` alongside `jobs_enabled`. Confirmed nowhere
else in this codebase either: no auth, no rate limiting, no request-size limit on any existing
route -- `--enable-chat` is the only gate this route ever exists at all, and `ChatRequest.message`'s
`max_length=2000` (plus a 20-turn cap on client-supplied history) is the only per-request cost
control, since unlike every other LLM path here, chat has no `--offline` equivalent: every request
calls the seam for real. `web/server.py`'s `_load_export` was renamed to `load_export` (unprefixed)
specifically so `web/chat.py` reads through the exact same function `GET /api/export` does, rather
than a second, independently-loaded copy of the file.

**Persistent right-hand panel, not a fifth tab -- the UX call made when the design was approved.**
A tab would hide the Findings/Contested table exactly when a citation chip's whole value is
glancing at the row it names. `index.html` gained `#chat-panel` as a third flex child of `.layout`
(sibling to `.sidebar`/`.main`), toggled by a topbar button that only appears once `/api/health`
reports `chat_enabled` -- same `jobsEnabled`-gates-optional-UI convention `renderConstraints`
already uses for the constraint form. Real bug caught testing this in a browser, not by any test:
`.chat-panel`'s own `display: flex` beat the browser's native `[hidden] { display: none }` UA rule
at equal specificity by cascade order, so the panel rendered OPEN on first load regardless of the
`hidden` attribute in the HTML -- fixed with an explicit `.chat-panel[hidden] { display: none; }`
override. `app.js` deliberately breaks its own "never cache the export payload" convention in
exactly one place (`lastExportData`, set in `renderAll`) so a citation chip's click can jump to and
open the exact Findings-tab row it names (`jumpToFinding`) -- the same cross-link idiom
`findingDetailHtml`'s existing `jump-to-contested` link already established, extended to a second
purpose. At <=900px the existing responsive breakpoint now also collapses the chat panel to full
width below the main content instead of a fixed 360px column.

**Verified against a real, live LLM call in the browser, not just mocked tests.** `rhino web
--export out/export_demo.json --enable-chat` (real `ANTHROPIC_API_KEY`, `.venv312`), asked "what
should i do about the 3 that are contested?" against the 24-finding deterministic fixture. The
model correctly refused to invent a remediation recommendation (`insufficient_data=true`) because
this export's `pipeline.tot.status` is `"not_run"` and every finding's `has_tot` is `false` -- a
deterministic-path export has no ToT branches to recommend from, and the model said exactly that,
naming which pipeline fields told it so, rather than fabricating a plausible-sounding action. It
correctly cited F11/F14/F07 (the fixture's actual three contested findings) with their real
risk_scores (25.9/25.5/18.7) -- server-injected, not model-reported. Citation-chip click-through
confirmed switching to the Findings tab and opening the named row's detail accordion. Toggle
open/close and the <=900px responsive stack were also confirmed in-browser. New test coverage:
`tests/test_agents_chat.py` (parsing/grounding/retry/enrichment, `_FakeCrew`-faked LLM dispatch,
same convention as `test_coordinator.py`/`test_web_jobs.py`) and `tests/test_web_chat.py`
(HTTP-level: route gating, `chat_enabled` health field, request validation, reads the live export
off disk). Full suite: 905 passed, 1 skipped (was 861/1 skipped before this addition).

**A local-model swap test against the chat layer specifically (`qwen2.5:14b`, via Ollama) surfaced
a failure mode `_validate_citations` cannot catch -- fabricated prose anchored to a real
citation.** This is a different probe than 2026-09-04's local-model test, which exercised
`llama3.1:8b` against the Research/Environment/Risk agent pipeline and found outright structured-
output/grounding failures (0/3 findings scored) -- a failure the existing machinery already catches
and reports as a failure. `qwen2.5:14b` against `agents/chat.py` did not fail that way: asked about
`F14`, it returned schema-valid `ChatAnswer` JSON citing `finding_id="F14"` -- a real finding_id,
so `_validate_citations` passed it, the response was accepted on the first attempt, and it was
returned to the caller as a grounded answer. The prose itself was not grounded: it stated F14 is
contested "due to incomplete data collection on a scoped asset." The export's real rationale for
`F14` says nothing of the kind -- `bucket=contested: is_kev=True with no compensating control and
no patch window -- not accept (confirmed exploitation), not mitigate_monitor (no control to point
to), not next_window (nothing scheduled)`. `not_collected`/`asset_not_collected` are both empty for
this finding (native fixture, no data gaps at all per this run's own `summary.data_gaps`) -- the
model didn't misread a real gap, it invented one that isn't in the export.

This is exactly the limitation `agents/chat.py`'s own module docstring already names rather than
claims to solve ("What this checks, and what it can't... It does NOT verify that every sentence of
prose is true -- there is no ground-truth log to check free text against"), and the concrete case
CLAUDE.md Safety and guardrails' still-open "Grounding validation" item is about -- now with a real,
reproduced instance against this specific agent rather than only a theoretical gap. It's a more
dangerous failure than `llama3.1:8b`'s: a schema/grounding failure is loud -- `ChatAnswerError`,
a 502, nothing shown to the user as an answer. This one is quiet -- a real finding_id, a plausible-
sounding sentence, a citation chip that renders normally with F14's real score/bucket next to a
claim about F14 that is simply false, indistinguishable in the UI from a correct answer without a
human separately knowing the real rationale. Not yet fixed or mitigated beyond what's already
documented; recorded here so the gap is measured, not just asserted.
