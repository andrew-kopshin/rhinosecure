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
| 7 | `rhino adapt confirm` / `rereview` and the attestation gate. | **Partially built.** The library pieces already exist and would be reused: attestation validation is `validate_contract`'s V18 (Slice 1), digest stamping is `confirm_contract` (Slice 3) — and confirming deliberately does *not* bump version (`overwrite_contract`'s whole reason for existing: a bump would invalidate the digest it just signed). Slice 6 adds a third: `probe.py`'s `NonRaisingProblemCollector`, ready to pass as `ConfiguredAdapter`'s `collector_factory` for the re-probe-and-refuse-while-fatal step. What's genuinely missing is the CLI verb itself and `rereview`'s merge-by-slot-digest logic. |
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
