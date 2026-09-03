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
