# RhinoSecure — Handoff

*Written 9 Sept 2026, at the transition from capstone deadline to open development.*

---

## 0. How to use this document

Paste this into a new chat to seed the context. It is written for **architecture and design review**, not implementation — Claude Code implements, this chat pushes back. If a proposal in here looks wrong on contact with the code, the code wins; say so and update this document rather than defending it.

Ground rules that have earned their place:

- Push back when I'm wrong. "That's the fast version and it isn't defensible" is more useful than agreement.
- Flag scope creep. This has bitten the project before and a spec reset is what fixed it.
- One command or prompt at a time, not a list.
- When Claude Code returns something, say whether it's actually *good*, not just whether it ran.
- Windows, PowerShell, Python 3.12 in `.venv312`. The `rhino.exe` shim is blocked by Smart App Control — always `python -m rhinosecure.cli`.
- Solo, direct to `main`, no PRs.

Repo: `C:\Users\akops\rhinosecure` · `github.com/andrew-kopshin/rhinosecure` (public). `CLAUDE.md`, `PROGRESS.md`, and `docs/adapter-generation.md` are the in-repo sources of truth; **read them before trusting anything in this file.**

---

## 1. What RhinoSecure is

A scan comes back with thousands of findings, most rated Critical. Nobody can patch them all. CVSS says how bad a vulnerability is in the abstract; it does not say how bad it is *here*. RhinoSecure scores each finding as **Risk = Threat × Impact**, where Threat comes from public sources (CVSS, CISA KEV, FIRST EPSS, MITRE ATT&CK) and Impact comes from business context (criticality, environment, data sensitivity, role), and produces a ranked, explainable remediation plan.

The same CVE on three hosts lands in three buckets — `patch_now`, `next_window`, `mitigate_monitor`, `accept`, or `contested` — and every verdict decomposes into the factors that produced it.

**It is no longer a course project.** The capstone was submitted 8 Sept 2026. From here it is being built as a real application for real fleets, which changes the standard: things that were acceptable as "demonstrates the concept" are now defects.

---

## 2. Where we are

**Built and working:**

- Deterministic ingest → enrich → score → bucket. Multiplicative between Threat and Impact, weighted-additive within Impact. No LLM anywhere in the scoring path.
- Enrichment from NVD / CISA KEV / FIRST EPSS / MITRE ATT&CK, snapshotted locally so runs are reproducible offline.
- Hand-built TF-IDF + MMR retrieval. No vector DB — the corpus is small enough that one would have been infrastructure without a payoff.
- Four CrewAI agents (Coordinator, Vulnerability Research, Environment Analysis, Risk & Recommendation) that reproduce the deterministic ranking exactly and add reasoning and citations. Checked programmatically against `scoring.py`, not by eye.
- Tree-of-Thought on contested findings only. Strategist proposes, critic scores on risk reduction / operational cost / constraint compliance / evidence strength / contradicting evidence, beam search at depth ~3.
- SQLite memory for constraints and prior human decisions; asset-scoped and fleet-wide capacity constraints with re-plan diffs.
- Hand-written adapters (`native`, `defender`, `bluepeak`) plus LLM-assisted adapter generation: `adapt propose` infers a mapping from an unfamiliar CSV, a human confirms with written attestations, and later runs read a hashed JSON contract with no LLM involved. Verified byte-identical against the hand-written Defender adapter.
- Web UI, read-only by default, with opt-in `--enable-jobs` and `--enable-chat`. Chat is grounded and toolless; citations carry only `finding_id` with scores injected server-side.
- Append-only `remediation_events`. Contradictions (marked remediated, still appearing in a scan) are reported, never auto-resolved.
- ~1,400 tests.

**Evidence that the central claim holds:** one CVE on three hosts with identical CVSS, KEV status and exploit availability scored 31.37 / 24.05 / 8.37, differing only in asset context — and the middle row is a *production workstation*, so role is observable independently of environment. On a 24-finding fleet: 1 patch_now, 8 next_window, 3 mitigate_monitor, 3 contested, 9 accept. ToT decided F11 (7.3 vs 5.25) and escalated F14 (8.0 tie). That full run cost 2.77M tokens.

---

## 3. Design principles that are load-bearing

Do not let these erode. Each one exists because something went wrong without it.

1. **Scoring is deterministic and LLM-free.** The model explains the number, never produces it. This is what makes the system testable and is the reason the agent layer can be trusted at all.
2. **Refuse rather than guess.** If a scoring input cannot be determined, the axis is *dropped and the score renormalized*, and the output says so. A plausible default is never quietly substituted. (Note: this is stated backwards in some older writing — the design neutralizes the axis; it does not substitute a default.)
3. **Confirming a scanner mapping is a signed human act.** `INGEST_CONFIRM` is deliberately absent from the Router's operation enum so it can never be automated. This is not a UX inconvenience to be optimized away.
4. **Amend is selection among pre-vetted options, never free-form.**
5. **`LOW_CONFIDENCE_THRESHOLD = 0.70`** and the `low_confidence_mappings` attestation exist because `check_grounding` verifies that cited tokens are *real*, not that the target-side mapping *means the right thing*.
6. **Provisional provenance, not "nothing escapes."** A provisional run records `(finding_id, format)` pairs in `provisional_provenance`, written before results become visible to a human and before the job can report success — a failed write fails the job. `remediation mark` (CLI and the Router's job) refuses a finding whose recorded format is still unconfirmed, re-resolved fresh against the live contract on every check, never cached. It fails open when no record exists, and cannot support "not recorded, therefore safe" — a mitigation, not a guarantee.

---

## 4. What needs work

### 4.1 The structural problem underneath most of it

Six separate bugs were diagnosed in the last build push, and they share one property worth stating plainly, because fixing them one at a time will keep regenerating them:

> **The system distributes knowledge about its own rules across components that do not share it, and it encodes absence as a plausible value plus a flag rather than as absence.**

The slot-resolution widget offered a correction that `validate_contract` always refuses, because the widget does not know the grammar the validator enforces. The other two examples are now fixed, and the fixes are the diagnosis's own proof: `_provisional()` used to stamp `confirmed` with a sentinel, so every downstream `state == "confirmed"` check passed — absence encoded as a plausible value — until `ConfiguredAdapter.unconfirmed_preview()` replaced the stamp with an honest bypass that never fakes state, and `is_provisional()` went back to reading `state` directly. `remediation mark` used to have no contract awareness at all, so "nothing provisional writes `remediation_events`" held only on the `--track-remediation` path — until `provisional_provenance` gave the provisional-run path its own record, re-checked live at mark time (principle 6). Both fixes single-sourced a fact that was previously guessable instead of adding a check bolted onto the symptom.

**The right first move is not a bug list, it is making legality and provenance single-sourced.** One grammar object that the generator, the widget and the validator all consult. One representation of "not known" that cannot be mistaken for a value. Then the six symptoms become one fix each, or disappear.

### 4.2 The concrete parked items

| Item | What's wrong | Priority |
|---|---|---|
| Resolve-slots form | Unestablished, needs re-surveying. "The form never completes" is not blanket true — on-disk evidence (`upload-6f1bbcfe`) shows it assembling cleanly with two human checkbox edits. Whether it's reliably broken, reliably works, or fails only in specific cases isn't known yet. | **High** |
| `remediation mark` has no per-finding provenance | The provisional-run gap is closed (principle 6: `provisional_provenance`, checked live at mark time). What remains: a `Finding`/`ScoredFinding` carries no reference to the contract that produced it, confirmed or not — so even a mark against a finding from a fully signed contract can't be verified against that specific contract/revision, only trusted because the format name currently resolves to something confirmed. | Medium |
| Enrichment on the upload path | Only partially attaches — `epss: null` even when the CVE *is* in the snapshot cache. Fifth instance of the fetched-then-discarded pattern. | Medium |
| Grounding vs paraphrase | `check_grounding` catches a placeholder restated literally, not one that is paraphrased. Known limit, not a quick fix. | Medium |
| Compound `Asset Tags` parser | Pipe-delimited key-value tags in scanner exports were never parsed. | Low |
| Chat box intercepts operations | Once a plan is loaded, the chat box swallows operation requests, so there is no UI path to dispatch `run_agents`. | Low |

### 4.3 Known cost mechanics

`crew.usage_metrics` reads cumulative lifetime counters off the shared LLM instance, not a per-call delta — this bug was found twice. Fixed in `schema_inference.py` and `tot.py` via delta snapshotting; **Router, constraint intake, and `_resolve_output`'s retry still count no usage.** Proposal cost measured $1.58 while inflated, $0.58 after a 24,000 `max_tokens` cap and feeding the previous attempt's error into retries.

---

## 5. The ultimate plan

The end state: **drop a CSV, get a defensible remediation plan back** — one step, the way dropping a file into Claude Code returns results — for real fleets, at a cost that makes sense to run weekly, with remediation that actually reaches the systems that own the machines.

Five phases, in this order and for these reasons.

### Phase 0 prerequisite — source intake

Phase 0 asks whether an unfamiliar CSV produces a signable contract or an honest, specific refusal. That question presupposes the file can be read at all — decoded, split into rows and columns — before there's a mapping to accept or refuse in the first place. This sits underneath Phase 0 rather than inside it.

**CSV half: closed, 2026-09-14.** Six fixes landed this week, verified against real producer output, not synthetic re-encodes:

- `cp1252` is now declarable in `Source.encoding` (cp1252 only — not `latin-1`; the two aren't the same encoding and conflating them would misdecode real bytes). Reasoning is in the field's own docstring.
- `configured.py`'s `_open_csv` now forces and wraps the header read, so a mis-declared encoding is caught and reported by the one function that knows the path and the codec — the discipline `ingest.open_csv` already held, now held on the confirmed-contract read path too.
- Three real-producer fixtures — PowerShell writing cp1252, Excel's COM `xlCSVUTF8` export (UTF-8 with BOM), PowerShell writing UTF-16 — each with non-ASCII verified at the codepoint level, not just "the file opens."
- Delimiter detection (`probe.detect_delimiter`) switched from character-frequency counting to row-shape consistency: a candidate delimiter is accepted only if it splits the header and every sampled row into the identical field count throughout. Wired into `Source` and rendered at confirm time so a human signer can actually see what was detected.
- A cross-file encoding or delimiter mismatch between the assets and findings files now refuses assembly outright, instead of silently preferring the assets file's profile.
- Non-text input (a `.xlsx`/`.docx`/`.pptx` dropped where a CSV was expected) is now named by its real container format via ZIP magic bytes, instead of suggesting a "re-export as UTF-8" fix that can't help a binary file.
- A failed unmapped-columns profile — the confirm-review's supplementary display, which re-reads the same file a second time after `load_batch` has already succeeded or failed — now degrades into its own `Measurement.unmapped_profile_problems` field instead of raising `ProbeError` uncaught. This was a real, unhandled 500 on the web confirm path, reachable with the committed `bluepeak-gen.json`.

**Still open:** all six fixes above landed on the confirmed/configured read path (`configured.py`, `probe.detect_delimiter`, `review.py`). `probe.profile_csv` — the propose-path profiler, the one an unfamiliar CSV actually hits first — still carries its own inline decode-error strings and never calls `ingest._decode_error_message`, so the message-quality fixes exist but aren't reachable from the path a new user meets first.

### XLSX intake — a separate phase, not started

Not a remaining item of the CSV work above — a phase of its own, filed here so it isn't assumed folded into source intake by omission. Constraints established in discussion; nothing built or decided yet:

- **Typed cells break every parser that assumes `str`.** openpyxl returns real Python types for numeric, date, and boolean cells, not strings — every parser downstream of a row (`ParsedMapping`, `_apply_case`, the delimiter/row-shape logic) assumes string input throughout the ingest layer today.
- **Sheet selection has no home in the current schema.** `Source.layout` is a two-member `Literal["single_file", "two_file"]` — it has no dimension for "which sheet," a question a CSV never has to answer.
- **Ragged-row protection can't transfer as-is.** The CSV-side protections (row-shape consistency, ragged-row reporting) depend on line-oriented reading; XLSX has no equivalent concept to detect the same failure mode against, so this needs a different mechanism, not a port of the existing one.
- **Merge detection and memory-bounded streaming are in direct tension in openpyxl's own API.** `read_only=True` streaming mode gives up the ability to detect merged cells; detecting merges means loading the full worksheet into memory — which conflicts with the "must not assume input fits in memory" rule (CLAUDE.md Section 1).
- **openpyxl's dependency boundary is unresolved, and currently inconsistent with `pyproject.toml`.** It isn't declared anywhere there — not core, not `agents`, not `dev` — yet it's installed in `.venv312` and imported unconditionally (no guard) by `tests/test_adapters_probe.py`, today only to construct a real `.xlsx` binary for the non-text-refusal test, never to parse XLSX content. The real design question — whether XLSX support is core, gated behind `agents`, or its own extra, given the deterministic path must keep working without it — is still open; the current ambient install isn't an answer to it, just an untracked gap.

### Phase 0 — Single-source the rules *(do this first)*

Make grammar legality and "not known" single-sourced, per 4.1. Then clear the High-priority items in 4.2. Nothing else is worth building on the current foundation, because every new surface will re-derive the same rules and drift from them again.

Exit condition: an unfamiliar CSV either produces a signable contract or an honest, specific refusal — never a contract the validator will reject, and never a plan that claims a confirmation it doesn't have.

### Phase 1 — The one-step flow

The current path is propose → resolve slots → confirm → run. The target is drop → results, with confirmation moved to where it belongs rather than removed. **This is the open architectural question and it should be argued out before it is built:** the human signature is load-bearing (principle 3) and cannot be deleted to make the flow shorter.

The most promising shape so far is that the gate moves from *input* to *output* — run immediately, return a plan marked provisional with its axes honestly neutralized, and ask for the signature at the moment the user wants to *act* on it. That change already unblocked a path that had failed for three sessions. Whether it generalizes to the whole flow is the thing to design.

Exit condition: a user who has never seen the tool drops a scanner export and gets a ranked plan without reading documentation, and cannot mistake a provisional plan for a signed one.

### Phase 2 — Fleet scale

The 24-finding fixture is not a fleet. On a thousand findings, three hundred contested is not three hundred decisions — it traces back to a much smaller set of assets missing the same operational fact. **Cluster contested findings by cause and rank the clusters by how many findings a single answer would resolve**, so a human answers five questions instead of forty. Today it's a flat list.

This is also where the contested rate becomes meaningful: `CLAUDE.md` targets ~1% at fleet scale, and fixture-sized runs read far higher (50% on the 14-finding upload). That gap needs real data behind it, which means finding or building a fixture at fleet scale.

Exit condition: a thousand-finding run produces a bounded question list, not a wall.

### Phase 3 — Local-model economics

2.77M tokens for 24 findings does not survive contact with a real fleet. The plan: point schema inference and CSV analysis at the local model, and spend API credits only when genuinely new information has to be fetched or reasoned about.

Evidence so far: llama3.1:8b failed the schema outright (a safe failure). qwen2.5:14b produced schema-valid but **fabricated** content that passed grounding — the single most important result in the project. qwen2.5:32b invented a CVE with full context but answered correctly once the pre-filter narrowed to 7KB, at ~10 min/answer on CPU. **GPU is untested and is the open question for self-hosted viability.**

Note the dependency: the 14B result means local models cannot be trusted on the narrative path without stronger verification than `check_grounding` currently provides. So Phase 3's ceiling is set by the paraphrase-detection gap in 4.2.

Exit condition: a fleet-scale run at a cost that would be approved as a recurring line item.

### Phase 4 — Remediation execution

Recorded but not built: remediation as **change requests to the system that owns the machines** (WSUS / Intune / SCCM) rather than direct execution. Accept / amend / reject gate per recommendation, amend being selection among pre-vetted options. Outcomes write `remediation_events` rows with `source="execution"`.

This is last deliberately. It is the only phase where the system touches production, and it should not be built on a foundation that can silently claim a confirmation it doesn't have.

---

## 6. Watch-outs

- **Claude Code fabricates GitHub commit URLs.** Verify before trusting one.
- **Multi-agent design panels are expensive** — one burned 1.6M tokens for output that a single careful pass would have produced.
- **Real runs find what tests can't.** ~1,400 tests passed while the upload path silently dropped EPSS.
- **Commit at checkpoints, not just slice ends.**
- **Recurring pattern: data fetched, then discarded before it reaches the structured layer.** Five instances so far — ATT&CK prevalence, `is_kev`, KEV `due_date`, mapping confidence, EPSS on the upload path. When something is missing downstream, suspect this before suspecting the fetch.
- **Do not delete files in `out\`** or in any Downloads folder. Claude Code once removed a test fixture as "agent scratch."
- **Do not rewrite git history.** A security scan confirmed it isn't needed; `.env` is gitignored and was never committed.
- **Don't disable Smart App Control** to get the `rhino.exe` shim working. Use the module invocation.

---

## 7. Where to start

Read `CLAUDE.md` and `PROGRESS.md` first — this document is a summary and they are the source of truth.

Then the first real conversation to have is **Phase 0's design**: what the single-sourced grammar object looks like, and what representation of "not known" cannot be mistaken for a value. That decision constrains everything in Phases 1 through 4, and it is the one place where getting the abstraction right saves the most rework.

Do not open with a bug list. Open with that.
