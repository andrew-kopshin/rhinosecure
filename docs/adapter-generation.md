# LLM-assisted adapter generation

Point RhinoSecure at an arbitrary vulnerability CSV and have it work without a
hand-written Python adapter. Two phases, and the split is the whole design:

- **Phase 1** (`rhino adapt propose`, built — Slice 8): an LLM inspects
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
| 6 | `adapters/probe.py`: a non-raising collector plus a bounded full-file column profiler. `rhino adapt probe <name>` / `list`. Still no LLM, no key, writes nothing. | **Complete.** `NonRaisingProblemCollector` is the exact class `configured.py`'s `ConfiguredAdapter` docstring already named ahead of time as a future `collector_factory` — built now, not yet wired anywhere (Slice 7's job). `profile_csv`/`profile_source` stream a whole file once, bounding only what they *retain* per column (`MAX_DISTINCT_TRACKED`, `MAX_SAMPLE_VALUES`), never how much they *read* — CLAUDE.md Section 1's "nothing may assume the dataset is small enough to hold in memory or fetch in one pass," applied to the tool that runs before any format-specific code exists. `rhino adapt list` scans `data/` for subdirectories with a `.csv` file and flags which already match a registered `--format`; `rhino adapt probe <name>` resolves `<name>` exactly like `--data` and reports, per column: blank rate, distinct-value count (honestly capped, never a guess dressed up as exact), min/max length, sample values, and `looks_like` tags (`cve_id`, `int`, `float`, `date_iso`, `timestamp`, `date_us_slash`/`date_eu_slash`, `constant`, `binary`, `identity_candidate`) computed from the SAME code-owned pattern definitions `configured.py` uses for real parsing — but never fed back into a contract automatically; a tag is a hint for a human or Slice 8's inference agent, and an ambiguous slash-date column honestly gets both `date_us_slash` and `date_eu_slash` rather than one guessed and the other hidden. |
| 7 | `rhino adapt confirm` / `rereview` and the attestation gate. | **Complete** — `adapters/review.py`. `confirm` measures, gates, and signs; `rereview` measures and reports and *cannot* write (no code path from it to `overwrite_contract`), so a CI drift check can never produce a confirmed contract nobody read. The re-probe is a real `ingest.load_batch` through a real `ConfiguredAdapter` with `probe.py`'s `NonRaisingProblemCollector`, so the artifact a human signs is produced by the code that executes the mapping. See "The review" below. |
| 8 | Phase 1 itself: the inference agent (`agents/schema_inference.py`) and `rhino adapt propose`. | **Complete.** The model's structured output, `AdapterProposal`, is not a `Contract` — every target is `SlotMapped` (a real `config_model.Mapping` node, imported not restated) or `SlotUnresolved` (honest, never auto-filled, not even into a legal `not_collected`). `check_grounding` is the LLM-free gate: cited columns must exist; a vocabulary/derived table's keys must be among the column's actually measured values (`probe.ColumnProfile.distinct_values`, now exposed in full rather than truncated to 8 samples), through the same case transform `configured._apply_case` applies before its own lookup; a `literal` must cite a column tagged `constant` AND match its one observed value. A `distinct_overflow` column is a `"caveat"` (reported prominently, never blocking) not a `"fail"`. `assemble_contract` refuses (never raises — `ProposeResult.contract is None`) unless every slot is mapped and grounded, then runs the real `validate_contract` before ever calling the result assembled — closing the gap where grounding alone can't see an illegal vocabulary *value* or a structural mistake outside the mapped slots. An adversarial review of the first version found and fixed eight defects, including the case-transform gap and the missing `validate_contract` call themselves. |
| 9 | Provenance surfaced in `export.py` / `rhino web`. | **Complete.** New top-level `provenance` key on both export builders: `format`/`version`/`confirmed_at`/`confirmed_by`/`content_digest`/`decision_digest`, plus `scale_drift` (non-`null` only when a confirmed-time `observed` measurement disagrees with what this run actually loaded). `null` for a built-in `--format` run. Mirrors exactly what `cli._print_adapter_config_banner` (Slice 4) already prints to a terminal -- no new facts, just a new surface. Deliberately excludes `Contract.generator` (model/token/cost): two of the three committed contracts carry identical, hand-authored placeholder generator blocks, and surfacing that here would present fabricated numbers as real audit trail. `rhino web`'s Overview tab renders a "Mapping provenance" card, including an explanatory note (not just two bare numbers) when `scale_drift` is present, pointing at `rhino adapt rereview`. Also fixed three adjacent defects the same bare-format-vs-revisioned-label gap produced: `export._capacity_history` comparing a historical run's versioned `ingest_format` against this run's bare `fmt` (every config-driven run's own capacity constraints rendered a false "stale" pill); `--format X` wording hardcoded into ingest-report/exclusion prose on a config-driven run, where the real flag is `--adapter-config`; and `rhino web --enable-jobs --adapter-config X` printing its own default `format: native` instead of the resolved adapter. `EXPORT_SCHEMA_VERSION` 1.1.0 -> 1.2.0. |

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
format (the hardening round below). An equivalent two-contract check was once
drafted as `config_io.check_identity_recipe_unchanged`, but neither verb here
ever had both an old and a new contract in hand at once (each reads a single
file), so it had no real caller and was deleted; comparing against the
committed history (`git show HEAD:<path>`) is on the human.

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

## Rule 1: fatal-vs-exclude is a flat membership check, not a config key

There is deliberately **no `on_unmapped` field anywhere in the grammar**.
Making disposition configurable would let either the model or a human
classify an inconvenient refusal as "exclude" to make it go away — exactly
the failure mode the whole not-collected/refuse-rather-than-guess discipline
exists to prevent (`config_model.py`'s own module docstring).

Instead, the engine decides with a flat set-membership check, not a
structural trace. `config_model.EXCLUDING_TARGETS = frozenset({"role"})` is
read by runtime code: it's the default value of `ConfiguredAdapter.__init__`'s
`excluding_targets` parameter, stored as `self.excluding_targets`. At the two
places a vocabulary or derivation-table *lookup* can miss (`_resolve_target`'s
vocabulary branch, `_resolve_derivation`), the resolver already knows which
target is asking — `target` is threaded through as a plain parameter from
whichever `asset.*`/`finding.*` slot triggered the resolution (directly for a
`VocabularyMapping`, or as the *outer* target for a `DefaultByMapping`/
`DerivedMapping` that consults a `derived` table on that target's behalf) — so
the miss handler just checks `target in self.excluding_targets`. No separate
inspection of *how* `role` itself is mapped ever runs; the outcome matches
"only a miss that is the thing feeding `role` becomes exclude" purely because
every call site is already scoped to the target it's resolving for, and
`role` is the only member of the set today. A miss on any other target is
always `problems.add(...)` — a fatal, whole-batch refusal. A third, separate
`exclude` call exists in `_validate_findings`: once an asset is excluded,
every finding on it is excluded too, cascading rather than raising a second,
confusing "orphan" error for the same root cause — that site doesn't
re-check `excluding_targets` at all, it just inherits whatever reason its
asset was already excluded for. `self.excluding_targets` is also the one
place this decision can be widened per-run without touching the contract
(the provisional-run path, `web/jobs.py`, passes every `SCORING_ENUM_TARGETS`
member instead of just `{"role"}`) — the contract itself carries no such
knob; only the caller constructing `ConfiguredAdapter` does.

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

## Schema registry: what the target schema *means*

`config_model.py`'s grammar names which `asset.*`/`finding.*` slots exist and,
for a handful of them, which bare token strings a source may use — but a bare
legal token (`"dc"`) has no stated meaning and no known real-world spelling
attached to it. That gap was found, not theorized: a real upload
(`northgate_flat_2.csv` — one domain controller, one dev workstation, the same
CVE) produced a proposal where the model correctly *refused to guess* rather
than fabricate an answer — `asset.role`'s table covered "Workstation" but left
"Domain Controller" out ("no verified target token"), and `asset.criticality`
went `unresolved` entirely ("the target's own numeric scale is not specified
here") — and both hosts were scored with their criticality/role axes
*neutralized*, flattening a domain controller and a dev workstation to the
same placeholder despite the model having a real column and real values to
work from. It had nothing to ground a judgment call in.

`src/rhinosecure/adapters/schema_registry.py` is that missing half: `TARGET_
REGISTRY` (`dict[str, TargetSpec]`) is the single published source of truth
for every `asset.*`/`finding.*` slot's accepted Python type and legal blank
policies, and — for `role`, `environment`, `data_sensitivity`, and
`criticality` — each legal value's real meaning and the real-world source
spellings this project has already confirmed map to it. `config_model.py`'s
`GAP_LEGAL_TARGETS`, `ABSENT_FACT_LEGAL_TARGETS`, `_target_vocabulary`,
`describe_target_vocabulary`, and `_check_parser_placement` all now *read*
this registry (and its sibling `PARSER_POSITIONS` dict) instead of deriving
their answers independently — a pure relocation: every existing target
produces byte-identical results, proven by the same hardcoded-partition tests
(`test_gap_legal_targets_match_the_three_verified_partitions`,
`test_absent_fact_legal_targets_match_the_three_verified_partitions`) that
existed before this module did, left unmodified.

**No I/O, no LLM, no `crewai` import** — the same deterministic-path
discipline `config_model.py` itself holds to, and structurally required here:
this module is one of `config_model.py`'s own dependencies.

**Three mechanisms close the northgate gap, none of them guesses:**

1. **Prompt enrichment.** `agents/schema_inference.py`'s grammar reference now
   renders, for the four registry-backed targets, every legal value's
   published meaning and known aliases — so the model has something concrete
   to ground a mapping in instead of a bare token list. `criticality` gets a
   structurally different treatment (below) since it's a number, not a closed
   string vocabulary.
2. **`_apply_registry_aliases`** — a deterministic, LLM-free pass, called
   exactly once inside `propose_contract`, immediately before
   `check_grounding` (the one call site that reaches both `rhino adapt
   propose`/`--from-proposal` *and*, via `web/jobs.py`'s `_run_ingest_propose`
   reusing the identical `propose_contract` call, the provisional
   drop-a-CSV path too). Two mechanisms, scoped to only the four
   registry-backed targets:
   - **Table augmentation** — an already-`SlotMapped` `VocabularyMapping` (or
     single-output `Derivation`) whose table is missing entries the cited
     column's *observed* distinct values would resolve gets those entries
     *added*. An existing entry is never overwritten, even when it disagrees
     with the registry — that's a contradiction (mechanism 3), not something
     to silently paper over.
   - **Slot promotion** — a `SlotUnresolved` target is promoted to
     `SlotMapped` only when `full_alias_coverage` finds a *complete* table
     (every observed value resolves) for exactly one candidate column. More
     than one candidate independently achieving full coverage is ambiguous —
     neither is promoted. A promoted mapping's `evidence.note` says
     `"resolved via schema registry alias table, no model judgment"` and
     carries `confidence=1.0`, so a code-verified fact never trips the
     `low_confidence_mappings` attestation gate.
3. **`check_grounding`'s new alias-contradiction check.** A table entry whose
   key case-normalizes to a known registry alias but whose *value* disagrees
   with what that alias resolves to is a real contradiction — flagged as a
   grounding `"fail"`, never silently corrected. This lives in
   `check_grounding` (`schema_inference.py`), **not** in `validate_contract`
   (`config_model.py`): `check_grounding` runs only during `rhino adapt
   propose`, against a fresh-or-reloaded `AdapterProposal`, never against an
   already-confirmed `Contract` — so this check can never reach, and so can
   never affect, `bluepeak-gen.json` or `mdvm-gen.json` (both already
   confirmed, never re-proposed), even in principle.

**The criticality anchor-only scope decision.** `CriticalityScale.anchors`
covers *only* the two unambiguous ends of the 1–5 scale — never a middle word
like "High"/"Medium"/"Normal"/"Low"/"Moderate". This is a safety boundary, not
an oversight, and the evidence is sitting in this repository's own two
confirmed, human-reviewed contracts: `data/adapters/bluepeak-gen.json` maps
its four-tier scale `critical`→5, `high`→4, `medium`→3, `low`→2 (its own
`table_notes`: *"low is deliberately 2, not 1 — this source's four tiers do
not reach the schema's floor"*), while `data/adapters/mdvm-gen.json` maps its
three-tier scale `high`→5, `normal`→3, `low`→1. Two real, careful reviewers
made *different, both-correct* judgment calls for the identical words,
because the right number for a middle tier depends on how many other tiers
the source's own scale has — there is no universal mapping to encode. A
deterministic alias table that resolved "Low" to a fixed number would
silently assert one source's judgment as fact for every future source, which
is exactly the wrong-but-plausible-number failure the whole
not-collected/refuse-rather-than-guess discipline exists to prevent. "Critical"
and "Informational"/"Minimal"/"Negligible" carry no such ambiguity — they mean
the same absolute thing regardless of how many tiers a scale has — so, and
only so, they resolve deterministically (`resolve_criticality_anchor`).
Every middle word stays the model's own judgment call, now *informed* (the
enriched prompt cites both real contracts above as worked precedent) rather
than blind. Confirmed as a real consequence, not just a design intent: run
against the actual `northgate_flat_2.csv` proposal, `asset.role`'s table
correctly gains `"Domain Controller"` → `"dc"` (a real anchor), while
`asset.criticality` correctly *stays unresolved* — its only candidate column
has exactly two observed values, `"Critical"` and `"Low"`, and `"Low"` is
deliberately not an anchor, so `full_alias_coverage` can never return a
complete table for it. Promoting the slot anyway with a partial table would
have been a *worse* outcome than staying unresolved: at real ingest time, a
non-`role` vocabulary miss is a fatal, whole-batch refusal, not a per-record
exclusion — the very first `"Low"` row would have taken down the entire plan.
`tests/test_adapters_schema_registry.py` asserts this boundary directly and
explicitly, as a safety property: `"High"`/`"Medium"`/`"Normal"`/`"Low"` must
never be resolvable via `resolve_criticality_anchor`, in any case fold.

## A `column` mapping's raw value must actually be legal, not merely cited

A `ColumnMapping` reads a named column, strips it, applies its declared
`case`, and writes the result to the target *verbatim* — no translation, no
vocabulary lookup. That's fine for a free-text target (`business_function`,
`owner`), but for a target with a **closed vocabulary** (`role`,
`environment`, `data_sensitivity`, `scanner_severity`) nothing previously
checked that the column's real, cased values actually equal one of that
target's legal members. `check_grounding` verified only that the *cited
column exists* — never that a `"column"` mapping's *observed* values were
legal for where they were being written. The gap was structural, not a
missed edge case: `check_slot_mapping_legality` had conditions for a
mapping's blank policy and parser placement, but none for this at all, so a
proposal built entirely from legal, well-formed pieces could still be
guaranteed to fail at real ingest.

**Found live, not theorized.** A real upload, `northgate_flat_2.csv` (the
same file the schema registry section above uses), has a `Risk` column whose
only observed value is `"Critical"` — title case. `schema.ScannerSeverity`
is `Literal["critical", "high", "medium", "low", "informational"]`, lowercase
only. A proposal mapping `finding.scanner_severity` as
`{kind: "column", column: "Risk", case: "exact"}` is structurally legal by
every check that existed: the column is real, the mapping shape is valid,
`check_grounding` passes cleanly. The contract assembles, gets confirmed,
and looks complete. Only at real ingest — `adapters/configured.py` handing
the raw `"Critical"` string straight to `Finding(scanner_severity=...)` —
does pydantic raise a generic `literal_error`
(`"Input should be 'critical', 'high', 'medium', 'low' or 'informational'"`),
with no hint that the fix is `case="lower"` or a `"vocabulary"` mapping, and
no indication of which slot is actually at fault.

**Two checks close this, one static and one data-dependent, matching the
same split the rest of this document already draws between what a mapping's
*shape* can prove and what only *real profiled data* can prove.**

- **`config_model._check_column_mapping_type`** (static, zero-cost, needs no
  data): a `ColumnMapping` always produces a string, so a target whose
  declared Python type is genuinely non-string — `criticality` (`int`),
  `internet_exposed` (`bool`) — can *never* legally be fed by one, regardless
  of what the source data contains. Wired into
  `check_slot_mapping_legality` alongside the existing blank-policy and
  parser-placement checks, so it runs at both proposal-generation time and
  real `validate_contract` time, for every adapter path, not just LLM-
  generated ones.
- **`schema_inference.check_column_mapping_legal_values`** (data-dependent):
  the other half of the same problem class — a *string-shaped* closed
  vocabulary (`role`, `environment`, `data_sensitivity`, `scanner_severity`,
  or any future closed `Literal[str, ...]` target) is only actually illegal
  for a `"column"` mapping when the column's real, case-transformed observed
  values (`probe.ColumnProfile.distinct_values`) fall outside that
  vocabulary — something only real profiled data can answer. Reads
  `schema_registry.TARGET_REGISTRY` for each target's legal value set, and
  applies the mapping's own `case` through `configured._apply_case` (the
  identical transform the real engine applies) before comparing, so a
  `case="lower"` mapping over the same `"Critical"` column is correctly
  never flagged. Wired at two points: `_ground_slot`, so the terminal
  `check_grounding` report fails a `"column"` mapping the same way it fails
  any other grounding problem, naming the actual illegal value(s) and
  suggesting `case="lower"`/`"upper"` or a `"vocabulary"` mapping instead;
  and `_check_mapped_slots_legal`, so the same problem is caught during
  `propose_contract`'s own generation-time retry loop, not only at the
  end — `_check_mapped_slots_legal` now takes the same `profiles` dict
  `check_grounding` does for exactly this reason.

**Confirmed against the real fixture, not just synthetic data.** Loaded
`northgate_flat_2.csv`'s real profile and built the exact buggy proposal
above: both `check_grounding` and `_check_mapped_slots_legal` reject
`finding.scanner_severity`'s `"column"`/`case="exact"` mapping over `Risk`,
naming `"Critical"` as the illegal observed value. Switching to
`case="lower"` — the fix the message itself suggests — makes both checks
pass cleanly, proving the suggested remedy actually works. A `"vocabulary"`
mapping over the identical column and value (`{"Critical": "critical"}`) is
untouched by this new check either way, since it's grounded by its own,
pre-existing key-matching path (`_ground_table`). `tests/test_adapters_config_model.py`
gained 3 new test functions (6 collected cases, one parametrized across
`role`/`environment`/`scanner_severity`/`hostname`) covering the static
non-string-type check; `tests/test_schema_inference.py` gained 5 new test
functions covering the data-dependent check end to end, all built directly
against `northgate_flat_2.csv`'s own profile rather than synthetic
stand-ins. Full suite after this fix: 1354 passed, 1 skipped (up from 1343,
this document's own schema-registry milestone above) — 11 new tests, zero
regressions.

## Where to look

`src/rhinosecure/adapters/config_model.py` (schema + validation + digests),
`configured.py` (the engine), `config_io.py` (read/write/confirm),
`base.py` (`not_collected`, `ProblemCollector`), `__init__.py`
(`load_config_adapter`), `probe.py` (the column profiler phase 1 reads),
`schema_registry.py` (published target meaning + alias data — see above).
`src/rhinosecure/agents/schema_inference.py` is phase 1 itself
(`AdapterProposal`, `check_grounding`, `assemble_contract`,
`propose_contract`, `_apply_registry_aliases`,
`check_column_mapping_legal_values` — see "A `column` mapping's raw value
must actually be legal" above) — `rhino adapt propose` in `cli.py` is its
only caller. Example confirmed contracts:
`data/adapters/bluepeak-gen.json`, `data/adapters/mdvm-gen.json`.
