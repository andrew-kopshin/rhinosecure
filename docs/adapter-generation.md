# LLM-assisted adapter generation

Point RhinoSecure at an arbitrary vulnerability CSV and have it work without a
hand-written Python adapter. Two phases, and the split is the whole design:

- **Phase 1** (`rhino adapt propose`, not yet built — Slice 8): an LLM inspects
  the source's headers and a sample of rows, proposes a mapping onto
  `Asset`/`Finding`, and a human confirms or corrects it. This runs **once**
  per source, ever (again only if the source's shape changes).
- **Phase 2** (`ConfiguredAdapter`, built — Slices 1–4): every subsequent run
  reads the confirmed mapping — a JSON **contract** — with **zero LLM
  involvement**. Deterministic, free, reproducible, exactly like every
  hand-written adapter (CLAUDE.md Section 8, rules 2–3). If the mapping were
  re-derived per run, the same file could score differently on different
  days.

A contract is resolved the same way a built-in `--format` is:
`rhino run --adapter-config <name>` and `rhino constraint add ... --adapter-config
<name>` both hand a `ConfiguredAdapter` to the same `ingest.load_batch` every
other adapter goes through. Scoring, enrichment, and the agents never know the
difference.

## Build order

| Slice | Scope | Status |
|---|---|---|
| 1 | Contract model + validator (`config_model.py`) — pydantic tree, the nine mapping kinds, `validate_contract`. No engine, no CLI, no LLM. | **Complete** — `8817e0f` |
| 2 | `ConfiguredAdapter`, the phase-2 engine (`configured.py`) — proven by a *differential* test: field-for-field identical output (`not_collected` included) to the hand-written BluePeak and Defender adapters on the real committed samples. | **Complete** — `aeac1bf` |
| 3 | Confirmation gate: canonical-JSON digests (`content_digest`/`decision_digest`/`slot_digests`), atomic write with version bump, header-mode enforcement, identity-recipe freeze, `assert_confirmed` refusing construction on an unconfirmed or tampered contract. | **Complete** — `e4b07f0` |
| 4 | CLI read path — `--adapter-config` on `rhino run` / `rhino constraint add`, mutually exclusive with `--format`; provenance banner. End to end with hand-written contracts, no LLM anywhere. | **Complete** — `b8cae6f` |
| 5 | `provides_enrichment` / `SourceEnrichment` for config-driven sources, so a pre-enriched export (BluePeak-shaped) skips live NVD/KEV/EPSS/ATT&CK the way the hand-written BluePeak adapter already does. | **Complete** — no dedicated commit; pulled forward into 1/2/4 (`Enrichment`, `provides_enrichment`, `_resolve_enrichment`) because Slice 2's differential test against `BluePeakAdapter` couldn't pass without it. `data/adapters/bluepeak-gen.json` exercises it end to end. |
| 6 | `adapters/probe.py`: a non-raising collector plus a bounded full-file column profiler. `rhino adapt probe <name>` / `list`. Still no LLM, no key, writes nothing. | **Complete.** `NonRaisingProblemCollector` is the exact class `configured.py`'s `ConfiguredAdapter` docstring already named ahead of time as a future `collector_factory` — built now, not yet wired anywhere (Slice 7's job). `profile_csv`/`profile_source` stream a whole file once, bounding only what they *retain* per column (`MAX_DISTINCT_TRACKED`, `MAX_SAMPLE_VALUES`), never how much they *read* — CLAUDE.md Section 1's "nothing may assume the dataset is small enough to hold in memory or fetch in one pass," applied to the tool that runs before any format-specific code exists. `rhino adapt list` scans `data/` for subdirectories with a `.csv` file and flags which already match a registered `--format`; `rhino adapt probe <name>` resolves `<name>` exactly like `--data` and reports, per column: blank rate, distinct-value count (honestly capped, never a guess dressed up as exact), min/max length, sample values, and `looks_like` tags (`cve_id`, `int`, `float`, `date_iso`, `timestamp`, `date_us_slash`/`date_eu_slash`, `constant`, `binary`, `identity_candidate`) computed from the SAME code-owned pattern definitions `configured.py` uses for real parsing — but never fed back into a contract automatically; a tag is a hint for a human or Slice 8's future inference agent, and an ambiguous slash-date column honestly gets both `date_us_slash` and `date_eu_slash` rather than one guessed and the other hidden. |
| 7 | `rhino adapt confirm` / `rereview` and the attestation gate. | **Complete** — `adapters/review.py`. `confirm` measures, gates, and signs; `rereview` measures and reports and *cannot* write (no code path from it to `overwrite_contract`), so a CI drift check can never produce a confirmed contract nobody read. The re-probe is a real `ingest.load_batch` through a real `ConfiguredAdapter` with `probe.py`'s `NonRaisingProblemCollector`, so the artifact a human signs is produced by the code that executes the mapping. See "The review" below. |
| 8 | Phase 1 itself: the inference agent (`agents/schema_inference.py`) and `rhino adapt propose`. | Not started |
| 9 | Provenance surfaced in `export.py` / `rhino web`. | Not started |

## The contract

`config_model.Contract` (`extra="forbid"`) has 21 top-level fields:
`config_schema_version`, `version`, `format`, `description`, `generated_at`,
`generator`, `source`, `header`, `derived`, `asset`, `finding`, `enrichment`,
`asset_grouping`, `finding_dedup`, `unmapped_columns`, `not_collected`,
`validator_overrides`, `observed`, `divergences`, `attestations`, `review`.

Notable shape:

- `format` must match `^[a-z0-9][a-z0-9-]{0,31}$`, can't collide with a
  built-in `FORMATS` name, and can't be a `RESERVED_PROVENANCE_LABELS` value
  (`nvd`, `nist`, `cvss`, `scanner`, `source`) — a config's severity source is
  always labeled by its own format name, never mistaken for NVD's.
- `asset`/`finding` are dicts whose keys must equal `ASSET_SLOTS`/
  `FINDING_SLOTS` **exactly** — every real `Asset`/`Finding` field, no more,
  no fewer. Nothing can be silently left unmapped.
- `source.assets_filename`/`findings_filename` must match
  `_FILENAME_PATTERN` (`^[A-Za-z0-9._-]{1,128}$`) — no path separators.
  **Known gap, not yet fixed:** the pattern's own comment states the intent
  is "no `..`" too, but the character class allows a filename made entirely
  of dots, so `".."` itself still matches and `data_dir / ".."` would walk
  up a directory; flagged separately, not fixed here. `layout="single_file"`
  requires the two names to be equal (BluePeak's shape); `"two_file"`
  requires them to differ.
- `header.mode` is `"declared"` (default: tolerates new columns as a notice,
  ignores reorder, refuses on missing/renamed) or `"frozen"` (exact ordered
  match required).
- `enrichment` presence alone sets `provides_enrichment` — there's no
  separate boolean, and no `severity_label` field: the label is
  `contract.format` itself, so a config-driven score can never be
  misattributed to NVD.
- `review` is the confirmation gate: `state` (`proposed`/`confirmed`/
  `stale`), `confirmed_at`, `confirmed_by`, `confirmed_version`,
  `content_digest`, `decision_digest`, optional `slot_digests`. A pydantic
  validator requires `confirmed_at`/`confirmed_by`/`content_digest`/
  `decision_digest` to all be set whenever `state=="confirmed"`.

**Digests.** `content_digest` hashes the whole contract except `review`
itself (a signature can't include what it signs); `decision_digest` hashes
only nine subtrees — `source`, `header`, `derived`, `asset`, `finding`,
`enrichment`, `asset_grouping`, `finding_dedup`, `unmapped_columns` — so a
re-probe can touch `observed` without voiding a human's confirmation.
`slot_digests` is one hash per `asset.<field>`/`finding.<field>` mapping
node, for a future proportional re-review. `ConfiguredAdapter.__init__` calls
`assert_confirmed(contract)` before opening any file: refuses unless
`state=="confirmed"`, then recomputes and compares both digests, naming the
exact slot(s) that drifted if `slot_digests` is present.

## Mapping-node grammar

Nine kinds, a discriminated union on `kind`:

| Kind | Purpose |
|---|---|
| `column` | Read a named column, strip it, apply case, write verbatim. |
| `vocabulary` | Closed source-token → target-value lookup table. A miss is never snapped to a neighbor — only excluded or refused (see Rule 1). |
| `derived` | Pull one named output of a module-level `derived[name]` block. |
| `parsed` | Parse via a fixed, code-owned parser (see Rule 2). A parse failure is always fatal. |
| `literal` | A constant, never read from a column. |
| `composed` | Build free text from template/join parts — legal only for `finding.evidence`, never a scoring input. |
| `not_collected` | The source has no such column; the value comes from code (`NOT_COLLECTED_DEFAULTS[target]`), never the contract. |
| `default_by` | Look a value up in a registered code table (today only `ROLE_DEFAULT_BY_OS_CLASS`), keyed by one output of a named derivation. |
| `content_address` | Synthesize `finding.finding_id` by SHA-256 over ordered raw columns — legal only there; the recipe freezes once confirmed since `memory.decisions` keys on the rendered id. |

`column`/`vocabulary`/`parsed` each carry a mandatory `blank: "gap" |
"absent_fact" | "fatal"` — no default; guessing one would assert something no
one has stated. `"gap"` means not collected (legal only for
`GAP_LEGAL_TARGETS`, i.e. `NOT_COLLECTED_DEFAULTS`'s keys); `"absent_fact"`
means the blank *is* the fact (legal only for fields whose schema default is
already `""`); `"fatal"` is always legal and refuses the whole batch (not
just the offending row — problems accumulate over the full pass and
`raise_if_fatal` refuses the file once, at the end). The two legal
sets overlap on 9 fields (an author picks either), diverge on 6
enumerated/typed fields that can only be `"gap"` (no blank member exists,
e.g. `criticality`), and 2 free-text fields that can only be `"absent_fact"`
(no `NOT_COLLECTED_DEFAULTS` entry exists, e.g. `evidence`).

## The review (`rhino adapt confirm` / `rereview`)

```
rhino adapt confirm  NAME_OR_PATH --data DIR --by IDENTITY
                     [--attest ITEM=TEXT]... [--reconfirm] [--reset-identity]
rhino adapt rereview NAME_OR_PATH --data DIR [--attest ITEM=TEXT]...
```

`--data` is required and never defaulted: a signature covers specific bytes
and cannot inherit which ones. `--by` is required and never inferred from
`$USER` or git config — an inferred signature is a fabricated one. The
timestamp comes from `cli.py`, the only place that reads the clock
(`config_io.py`'s docstring reserves it there), so `review.py` is testable
with a literal.

**Measuring a contract the engine refuses to construct.**
`ConfiguredAdapter.__init__` calls `assert_confirmed` before it sets an
attribute, so the object that must measure an *unconfirmed* contract is the
one object that refuses to exist for it. Resolved by satisfying the gate,
not routing around it: `_provisional` stamps an in-memory copy through the
ordinary `confirm_contract` with a sentinel identity, and that copy is
function-local — never returned by a public name, never written. Rejected:
extracting the constructor body to call it on an `__new__`'d instance (a
second construction path around a gate whose value is being the only one),
and a `review_only=` flag on the constructor the ingest path itself calls.
`_provisional` clears `review` (so a *drifted* contract is still
measurable — `rereview` is the only command left that can inspect one) and
clears `observed` (or V18 reads a stale exclusion count and the fresh
measurement refuses itself).

**Order, which is not negotiable.** merge attestations (carried-forward plus
`--attest`) → measure → build `observed` → `confirm_contract` (stamp) →
`validate_contract` **last** → round-trip verify → write. Attestations merge
*before* the measurement, not after: `ConfiguredAdapter.load_assets` runs
`validate_contract` on every load, and V18's structural requirements
(`enrichment`/`union`/`finding_id.synthesized`) depend only on the contract's
shape — so measuring the pre-merge contract made `--attest` unable to ever
help a freshly proposed contract, which doesn't yet carry them (the
hardening round below). Validating before stamping reports a spurious
`content_digest` mismatch, because `observed` moved while `review` still
carries the old digest. The validation uses `adapter.headers` — the engine's
own post-`_filtered_for_validation` view — because validating against the raw
header turns a vendor's new column, which `header.mode="declared"`
deliberately tolerates as a notice, into a V08 refusal at the last step, in
exactly the drift case a re-review exists for.

**What `observed` holds:** `measured_at`/`measured_by`/`measured_by_command`,
`contract_version`, `assets_loaded`, `findings_loaded`, the two
`duplicate_*_collapsed` counters, `excluded_assets`/`excluded_findings` as
plain **ints** (V18 reads those two at the top level and adds them),
`excluded_asset_reasons` (reason text → count), `not_collected_assets`/
`not_collected_findings`, and `header_notices`. Deliberately absent: any cell
value, any record id, and the *finding*-side exclusion reasons — a cascaded
reason embeds its asset's id, and a contract is committed to git. All of that
prints to the terminal, which is not.

**What prints but is never persisted: every column the contract declares it
deliberately does not read, its stated reason beside its measured shape.**
`unmapped_columns` carries a human- or model-authored prose reason per
column, and it sits inside a decision subtree — a signed claim nothing
otherwise checks. The review re-profiles each declared-ignored column with
Slice 6's `probe.profile_csv` (blank rate, distinct count, `looks_like`
tags, samples) and prints it directly beside the stated reason, so a column
dismissed as "operational metadata, not needed" that is actually 0% blank
with a handful of distinct values reading like a maintenance window is
visible at review time, not discovered later. This is why `profile_csv`
takes the contract's own `delimiter`/`quotechar`/`encoding`/`first_data_row`
rather than assuming a bare CSV (the hardening round below, defect 4) — a
wrong dialect used to make the whole section disappear in silence, the
worst failure mode for the one part of the report whose job is to show what
a mapping ignores. Slice 8's own reporting posture inherits this: a
proposal an LLM cannot confidently map to a schema slot is exactly a
declared-ignored column, and it should be reviewable the same way.

**The attestation gate is a two-shot loop, not a prompt.** `--attest
ITEM=TEXT` (repeatable, split on the first `=`, validated against
`ATTESTATION_ITEMS` — its first consumer). Nothing is ever auto-generated:
synthesizing the sentence that sanctions a measurement is the silent
absorption the whole design exists to prevent. The C3 ordering hazard —
the measurement *discovers* exclusions, so V18 then demands an `exclusions`
attestation that does not exist yet — resolves by order: shot one measures,
refuses, writes nothing, and prints the exclusions **with their reasons**;
shot two supplies the text. An attestation for a condition that does not
hold is also refused: a signed acknowledgment of something that never
happened reads later as evidence someone looked.

**Merge-by-slot-digest** partitions the 24 slots into unchanged / changed /
new / orphaned, so a reviewer re-reads one line instead of the whole
contract, and drives which prior *claims* survive: everything carries while
`decision_digest` is unchanged; once a decision moves,
`finding_id.synthesized` carries only while `finding.finding_id`'s own slot
is unchanged. A digest cannot reconstruct what it hashed, so the report names
which slot moved and prints its current node — the previous one is in git.
Both committed contracts recorded **no** `slot_digests` (legal), so the
coarse fallback is a live path, announced loudly; confirming records them, so
a contract passes through it at most once.

**The identity freeze refuses unless the identity slot is *provably*
unchanged, never merely "not known to have changed."** `--reset-identity` is
required whenever a mapping decision has moved and `finding.finding_id`'s own
slot cannot be shown to have held still — `review` sits outside both
digests, so `slot_digests` is unsigned evidence that can be absent (the
state of both committed contracts today), missing just that one entry, or
removed entirely, and each of those used to let a changed content-address
recipe through in silence, re-keying every `memory.decisions` row for the
format (the hardening round below). `config_io.check_identity_recipe_unchanged`
(Slice 3) isn't used here — it needs both the old and new contract, and both
verbs read one file; comparing against the committed history (`git show
HEAD:<path>`) is on the human.

**Known limitation, flagged not fixed:** `enrichment` and `union`
attestations cannot carry forward once any decision moves, because no stored
digest covers those subtrees individually — so an unrelated one-word edit
makes a reviewer retype them, and prose retyped under duress reads like a
fresh judgment without being one. The fix is to have `compute_slot_digests`
also emit entries for the `enrichment` and `asset_grouping` subtrees; that
changes what `confirm_contract` stamps and what `assert_confirmed` compares
(Slice 3 machinery and one of its pinned tests), so it is a digest-format
decision rather than a CLI one. Unaffected by the hardening round below —
none of those six defects touched attestation carry-forward for these two
items; this remains open.

**Two defects this slice surfaced**, both latent since Slice 3 and both
reachable only now that something actually writes contracts and measures with
a non-raising collector: `config_io` wrote `"from_"` instead of the
documented `"from"` for `derived`/`default_by` mappings (`dump_for_disk` now
uses `by_alias=True`; digest-neutral, since digests hash the non-aliased
dump), and `configured.load_findings`' `assert mapped is not None` fired as
a message-less `AssertionError` under a non-raising collector — not an
`IngestError`, so it escaped every `except IngestError` as a traceback, and
vanished entirely under `python -O`.

**A subsequent adversarial review round found and fixed six more defects**
(commits `48ac821`/`309b9a1`; PROGRESS.md is authoritative for how each was
found and verified). Two reshaped mechanisms already described above: the
attestation-merge ordering, and the identity freeze. Four more, all
reachable only once something actually drove a real measurement through a
real CLI: `rereview` could report a contract clean and exit 0 on exactly the
drift `confirm` refuses (a fresh exclusion can make a new attestation
required with no digest moving at all); the "columns this contract does not
read" profile silently vanished for a non-comma delimiter or a banner row,
since it read the file with the profiler's own defaults rather than the
contract's declared dialect; a slot-digest key with no `.` in it crashed a
printer; and the value-distribution report truncated to four values per
field with no indication it had.

## Rule 1: fatal-vs-exclude forward-traces to `role`, not a config key

There is deliberately **no `on_unmapped` field anywhere in the grammar**.
Making disposition configurable would let either the model or a human
classify an inconvenient refusal as "exclude" to make it go away — exactly
the failure mode the whole not-collected/refuse-rather-than-guess discipline
exists to prevent (`config_model.py`'s own module docstring).

Instead, the engine decides structurally. `ConfiguredAdapter._role_reference()`
inspects how `contract.asset["role"]` is itself mapped and returns what would
have to miss for the exclusion path to be legitimate:

- `asset["role"]` is a `VocabularyMapping` → `("vocabulary", "role")`
- `asset["role"]` is a `DefaultByMapping` → `("derivation", <the derivation
  feeding it>)`
- anything else → `("none", "")` — an invalid role value fails at
  `Asset(...)` construction as an ordinary pydantic error, never through
  `ProblemCollector`.

At the two places a vocabulary or derivation-table *lookup* can miss
(`_resolve_target`'s vocabulary branch, `_resolve_derivation`), a miss is
compared against that tuple. Only a miss that *is* the thing feeding `role`
becomes `problems.exclude(...)` — a scope-boundary skip, reported but not
fatal (BluePeak's Kubernetes cluster, firewall, etc. are this case). Every
other vocabulary or derivation miss, anywhere else in the contract, is
always `problems.add(...)` — a fatal, whole-batch refusal. A third,
separate `exclude` call exists in `_validate_findings`: once an asset is
excluded, every finding on it is excluded too, cascading rather than
raising a second, confusing "orphan" error for the same root cause — that
site doesn't re-run the role trace itself, it just inherits whatever reason
its asset was already excluded for. `EXCLUDING_TARGETS = frozenset({"role"})`
exists in `config_model.py` purely as a documented decision; it is not read
by any runtime code — `_role_reference()`'s live structural trace is the
actual mechanism, computed fresh on every miss rather than looked up from a
stored set.

## Rule 2: patterns are code-owned, never model-authored

Nothing in `config_model.py`, `configured.py`, or `config_io.py` lets an LLM
author or select a regex at runtime. Every pattern a contract can invoke is a
closed, code-owned catalog:

- `ParsedMapping.parser` is `Literal["bool", "float", "date", "timestamp",
  "cve_id"]` — pydantic itself rejects anything else. The actual regexes
  (`_ISO_DATE_PREFIX`, `_US_EU_SLASH`, `_FRACTIONAL_SECONDS`,
  `_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")`) are hard-coded
  module constants in `configured.py`, never built from contract text.
- The one "degrade" field, `EnrichmentAttackTechnique.pattern`, is a
  single-valued `Literal["attack_technique"]` — a contract can only *select*
  this one pre-existing pattern by name. The regex it names
  (`_ATTACK_TECHNIQUE_PATTERN`) is likewise a hard-coded constant.
- `VocabularyMapping.table` / `Derivation.table` are plain JSON dicts, read
  only via `dict.get(...)` — never `eval`, never `re.compile` on contract
  data, no code generation at any point.
- `Contract.generator` records that an LLM authored the *contract itself* in
  the not-yet-built phase 1 — `tool`, `model`, token counts, cost, a
  `call_log_digest`. Its own docstring: "Never read by phase 2 — this is
  audit trail, not input to any decision the engine makes." None of the
  three modules above import an LLM client or call a network API; their only
  external interactions are `csv.DictReader`, file I/O, `hashlib.sha256`, and
  pydantic validation.

Together, Rules 1 and 2 are what make the "confirmed once, deterministic
forever" claim actually true rather than aspirational: the engine's every
runtime decision — including the one qualitative judgment call it makes
(fatal vs. exclude) — resolves against fixed code and a frozen, hashed
contract, never a live model call or a pattern the model chose on this run.

## Where to look

`src/rhinosecure/adapters/config_model.py` (schema + validation + digests),
`configured.py` (the engine), `config_io.py` (read/write/confirm),
`base.py` (`not_collected`, `ProblemCollector`), `__init__.py`
(`load_config_adapter`). Example confirmed contracts:
`data/adapters/bluepeak-gen.json`, `data/adapters/mdvm-gen.json`.
