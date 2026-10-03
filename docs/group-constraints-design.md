# Group constraints — design (read-only; nothing in this entry is built)

Date: 2026-10-02. Branch `main`, HEAD `975e30f` ("Agents path reports constraint application
honestly; provisional plans never apply"). This document is the full design asked for before any
code is written. Nothing in the repository was edited to produce it — no table, no function, no
test. It follows the convention CLAUDE.md's own "Future direction" sections already establish
(remediation execution, the conversational front end): a design agreed in discussion, recorded in
full, built later against this record rather than from memory of the conversation.

Three storage/precedence/digest decisions arrived already fixed, and are **not relitigated
here** — restated in one place so the rest of the document can cite them by name:

1. **Shape**: a stored predicate (`group_field`, `group_value`), matched at read time against
   the current asset, in a new `group_constraints` table with the same soft-delete `active` flag
   `constraints` already uses. A third skip reason, `not_collected`, parallels `legacy`/
   `identity_mismatch` and is checked against the asset's own `not_collected` set at match time,
   never stored on the row. One value per row for v1 (`role in {workstation, dev}` would be two
   submissions, not one row with a list).
2. **Precedence**: when an asset constraint and a group constraint both set the same
   replace-kind field (`patch_window`, `patch_restriction`), the asset constraint wins outright,
   and the overridden group value is reported in the run summary and the export.
   `compensating_control` stays additive across both. This must be an explicit, type-based rule
   in the merge logic, never a position in a combined list.
3. **Digest**: covers the per-asset facts scoring actually read — `(asset_id, hostname, origin,
   effect_kind, effect_value)`, `origin` literally `"asset:<id>"` or `"group:<id>"`. It must
   change when a new asset joins a group. With zero group constraints on file, it must stay
   byte-identical to today's digest for the same applied asset constraints.

Everything below is the mechanism that satisfies these three, the parts the three decisions
don't by themselves specify (storage schema, matching code, intake, the review gate, every
consumer site), and the v1 field-scope recommendation asked for separately.

This design builds on, and does not relitigate, `out/constraint-source-scoping-survey.md` (why
machine identity, not source, scopes an asset constraint — unaffected by this work) and
`out/contested-clustering-survey.md` (Q3/Q4, the measurement and the two storage shapes this
document's decision 1 already resolved one of).

**Provenance of this document, stated plainly.** A first draft of everything below was produced
during an investigation pass that was asked only to verify current-code facts across six areas
(every consumer of `constraints`, the v1 field-scope measurement, the intake/`CAPACITY` precedent,
provisional-inertness, the precedence/digest mechanics, and a test plan) and report back — not to
write this file. One of those six investigations wrote a complete first draft of this design
unprompted, during that same pass. Rather than discard that work or accept it uncritically, every
claim in it was checked against five independently-run investigations that verified the same
ground (consumer sites, field scope, intake, provisional-inertness, precedence/digest) by reopening
the actual code themselves, without reading each other's output first. Four categories of outcome
came out of that cross-check, each called out at the relevant section rather than smoothed over:
(1) the overwhelming majority of claims were independently confirmed, often with additional
file:line precision; (2) one real, useful disagreement surfaced on the digest design (Section 8.5),
presented here as a genuinely open choice, not resolved by fiat; (3) one mechanism (the intake tool
question, Section 6) turned out to have a sharper justification than the first draft gave it,
folded in; (4) one subtlety about the preview step's data source (Section 7.1) needed an explicit
tie-back to an existing, already-accepted CLAUDE.md precedent that the first draft's reasoning was
consistent with but never cited. Section 11 (tests) is a merged, substantially expanded version of
the first draft's own test list, produced by a sixth investigation that took the design as given
and built out full coverage against this codebase's real test conventions.

---

## 1. Storage

### 1.1 `group_constraints` — a new table, not a repurposed `constraints`

```sql
CREATE TABLE IF NOT EXISTS group_constraints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_field TEXT NOT NULL,
    group_value TEXT NOT NULL,
    constraint_text TEXT NOT NULL,
    effect_kind TEXT,
    effect_value TEXT,
    created_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_group_constraints_field_value ON group_constraints (group_field, group_value);
```

No `asset_id` column — a group constraint is not about one asset, the same reason
`capacity_constraints` has no `asset_id` either. `effect_kind`/`effect_value` are nullable for
the identical reason `constraints.effect_kind`/`effect_value` are: `Memory.add_group_constraint`
does not itself require an interpreted effect, even though the Interpreter (Section 6, below)
is instructed to refuse a group statement that doesn't resolve to one, mirroring the asset
path's existing refusal rule exactly. This is schema-level defense in depth, not a new case v1
has to build for.

This is a **new table added straight into `_SCHEMA_SQL`**, not a `_migrate()` entry —
`_migrate()` exists only for `ALTER TABLE ADD COLUMN` against a table that already exists on
disk; a brand-new table reaches an existing database the same way `capacity_constraints`,
`remediation_events`, and `provisional_provenance` already did: `CREATE TABLE IF NOT EXISTS` is
idempotent, so opening an older `rhinosecure.db` with this code picks up the new, empty table on
next construction with nothing to migrate. Zero risk to an existing deployment's data.

`Memory` gains:

```python
@dataclass(frozen=True)
class GroupConstraint:
    id: int
    group_field: str
    group_value: str
    constraint_text: str
    created_at: str
    active: bool
    effect_kind: str | None = None
    effect_value: str | None = None

def add_group_constraint(self, group_field: str, group_value: str, constraint_text: str, *,
                          effect_kind: str | None = None, effect_value: str | None = None) -> int: ...
def deactivate_group_constraint(self, group_constraint_id: int) -> None: ...
def all_active_group_constraints(self) -> list[GroupConstraint]: ...
```

`all_active_group_constraints` returns the **whole** table (there is no `asset_id` to filter a
`WHERE` clause on) — the same shape `all_active_constraints` already has, and the same shape
`capacity_constraints` reads with (a small, fleet-wide table, read in full and filtered in
application code). `add_group_constraint` validates `group_field` against
`constraint_apply.GROUP_FIELD_CHOICES` (Section 3) defensively, even though every real caller
(the confirm step, Section 7) already goes through a `Literal`-typed model that can't produce an
illegal value — the same belt-and-suspenders posture `Asset._validate_not_collected` already
takes for a field that can't legally appear in `not_collected` either.

### 1.2 `pending_group_constraints` — the review gate's own durable state

The preview/confirm gate (decision 2, Section 7) cannot be held only in server memory: the CLI
runs propose and confirm as two **separate process invocations**, so whatever the human is
confirming against has to survive between them. A second small table, append-mostly (one write
at propose, one write at confirm):

```sql
CREATE TABLE IF NOT EXISTS pending_group_constraints (
    token TEXT PRIMARY KEY,
    group_field TEXT NOT NULL,
    group_value TEXT NOT NULL,
    constraint_text TEXT NOT NULL,
    effect_kind TEXT,
    effect_value TEXT,
    matched_asset_ids TEXT NOT NULL,     -- JSON list
    excluded_asset_ids TEXT NOT NULL,    -- JSON list (not_collected)
    preview_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    consumed_at TEXT                     -- set once confirmed (or explicitly discarded); NULL = still pending
);
```

`token` is `uuid.uuid4().hex` — the identical shape `upload_id`/`Job.id` already use, so every
existing "looks like a real id" regex (`router.py`'s `_UPLOAD_ID_PATTERN`) is reusable without a
new pattern. `consumed_at` makes a token one-shot: a confirm call against an already-consumed
token is refused ("already confirmed or discarded — propose again"), closing a double-apply
replay. Nothing here ever deletes a row — matching every other table in this module's own
append-only convention — so an old, never-confirmed preview just sits inert forever. **Decided:
previews do not expire.** The digest re-check at confirm time (Section 7.3) is the real safety
net — it refuses the moment the reviewed matched/excluded set no longer reflects current data,
regardless of how much wall-clock time has passed — so an old-but-still-accurate preview confirms
exactly as validly as a fresh one, and a clock-based TTL would only ever force a redundant re-review
of a fleet that hasn't actually changed. `created_at` is kept on the row for one purpose only:
`confirm_group_constraint`'s own output states the preview's age, purely informationally, never as
a gate (Section 7.3, test A54).

**Why this needs to be a durable row, not a re-derivation from the raw text.** Re-running
`interpret_constraint` a second time at confirm time, from the same text, is not safe: it is a
fresh LLM call, and nothing guarantees it produces the identical `group_field`/`group_value`/
`effect_kind`/`effect_value` the human actually reviewed in the preview. The human confirms
*what they saw*, not *whatever the model says if asked again*. The interpretation happens
exactly once, at propose time; confirm only ever re-validates the **match** against current
data (Section 7.3) and then writes.

---

## 2. Matching: `match_group_constraints`

Next to `match_constraints` in `constraint_apply.py`, same file, same "one matcher" discipline:

```python
GROUP_FIELD_CHOICES: frozenset[str] = frozenset({"role"})  # v1 — see Section 4

@dataclass(frozen=True)
class GroupConstraintMatch:
    applied: tuple[GroupConstraint, ...] = ()
    skipped_not_collected: tuple[GroupConstraint, ...] = ()

def match_group_constraints(group_constraints: list[GroupConstraint], asset: Asset) -> GroupConstraintMatch:
    applied: list[GroupConstraint] = []
    skipped: list[GroupConstraint] = []
    for gc in group_constraints:
        if gc.group_field in asset.not_collected:
            skipped.append(gc)
        elif str(getattr(asset, gc.group_field, None)) == gc.group_value:
            applied.append(gc)
        # else: this asset's real value for group_field simply isn't gc.group_value —
        # not a skip, not reported, exactly like an asset constraint whose asset_id
        # isn't this asset's id. Silence here is "not relevant," not "a problem."
    return GroupConstraintMatch(applied=tuple(applied), skipped_not_collected=tuple(skipped))
```

Three outcomes per `(group constraint, asset)` pair, deliberately asymmetric in how loudly each
is reported:

- **Applies** — the field is collected and equals the group's value. Folded into scoring
  (Section 5), counted in `applied`, hashed into the digest (Section 5.3).
- **Not collected** — the field is a placeholder on this asset (`adapters/base.py`'s
  `NOT_COLLECTED_DEFAULTS`, or any adapter's own not-collected marking). This is the live
  analogue of `constraint_intake._matches`' existing skip ("the file server" must not match
  every Defender-sourced server sharing one defaulted `role`), moved from "a human's own asset
  *resolution*" (today, single-asset) to "a stored rule's *membership* test" (here, group-wide).
  Reported, never silently applied and never silently dropped — the same posture `legacy`/
  `identity_mismatch` already have for asset constraints.
- **Doesn't match** — the field is real and simply isn't the group's value. Not reported at all,
  by design: enumerating every asset that *isn't* in a group would be noise at any real fleet
  size, and it carries no honesty concern the way a placeholder match does — "this machine isn't
  a workstation" is not a gap in the data, it's the data.

This is why `GroupConstraintMatch` has no third field for "didn't match" — there is nothing to
report there, mirroring exactly how `match_constraints` never reports "this constraint's
asset_id is a different asset."

**`getattr(asset, gc.group_field, None)` is intentionally defensive**, not merely convenient:
`group_field` is restricted to a closed `Literal` at every writer (Section 4, Section 6), so a
genuinely illegal value should never reach a stored row — but a row written by a future version
of this code with a wider `GROUP_FIELD_CHOICES` than an older reader knows about (a rolling
deploy, or a database shared across versions) must not crash matching; `getattr(..., None)`
degrades to "doesn't match" rather than raising, the same forward-compatible posture
`Asset.not_collected`'s own "absence means no signal" convention already takes elsewhere.

**`has_usable_effect` generalizes by structural typing, not by importing `GroupConstraint` into
a `Constraint`-shaped signature:**

```python
class _EffectBearing(Protocol):
    effect_kind: str | None
    effect_value: str | None

def has_usable_effect(c: _EffectBearing) -> bool:
    return c.effect_kind in _RECOGNIZED_EFFECT_KINDS and bool(c.effect_value)
```

`Constraint` and `GroupConstraint` both satisfy this `Protocol` with no change to either
dataclass and no import of one module into the other — the exact same filter, unmodified
semantics, now shared by both effect-bearing row types.

---

## 3. Fleet-scale reading: fetch the group table once, not per asset or per finding

`all_active_group_constraints()` reads the *whole* table, unlike `constraints_for_asset(asset_id)`,
which is already indexed per-asset. Every new call site must read it **once per run** (or once
per Crew-tool construction on the agents path) and pass the list down, never re-querying inside a
per-finding or per-asset loop — the identical lesson "Fleet-scale audit, part 2" already drew for
`SnapshotCache`/`TechniqueIndex`: a defect that is invisible at the 24-finding fixture (a handful
of extra queries against a local SQLite file) becomes a real, measurable defect at thousands of
findings. Concretely, every consumer in Section 8 either:

- reads the group table once at tool-build time (agents path: `build_risk_tools`/
  `build_environment_tools` already close over inputs computed once per Coordinator dispatch
  stage, not per finding — the group list joins that same one-time closure), or
- reads it once per `rhino run`/export-build invocation (deterministic path/export.py: the exact
  shape `cli.run_with_report`'s own `kev_catalog`/`attack_index` already use — one load, reused
  across the whole scored list).

No new per-finding SQL read is introduced anywhere by this feature.

---

## 4. v1 field scope: `role` alone, nothing else justified yet

**Recommendation: `GROUP_FIELD_CHOICES = {"role"}` for v1.** `out/contested-clustering-survey.md`
Part A measured `role` covering 77 of 96 contested findings (80.2%) on a realistic-KEV-share,
5,000-finding fleet — by a wide margin the dominant cluster key, and the only one with a measured
case behind it at all. Nothing else is added because nothing else has an equivalent measurement
justifying it, and this project's own discipline (CLAUDE.md's repeated "asked, not assumed"
decisions; "no interface may assume demo scale," applied here to "no field joins the vocabulary on
the strength of looking easy to add") argues for recommending exactly what's measured, not what's
merely cheap.

**Candidates considered and explicitly declined for v1, each with the reason:**

- **`environment`, `internet_exposed`** — mechanically as easy as `role` (already export-visible
  via `_asset_summary`, already closed-vocabulary/boolean, already carry a `not_collected` marker
  the identical way `role` does). Declined anyway: neither has a measured case. The 19 contested
  findings `role` doesn't cover (`file` 7, `dev` 6, `sql` 3, `exchange` 1, `dc` 1, `iis_web` 1,
  per the survey) are split across *roles*, not across environments or exposure — adding either
  field would not close that residual, and no other operational need for them was named. If a
  real one surfaces, extending `GROUP_FIELD_CHOICES` is a one-line `Literal` widening plus one
  `GROUP_FIELD_CHOICES` entry (Section 6's `group_value` typing already anticipates a
  discriminated per-field union for exactly this reason) — cheap to add later, so there is no
  cost to deferring.
- **`data_sensitivity`** — same reasoning as the two above: easy, unmeasured, declined for now.
- **`business_function`** — not a storage question at all yet: it is absent from `_asset_summary`,
  `RiskRecommendation`, `scoring.py`, `cli.py`, `app.js`, and `agents/chat.py` (confirmed by the
  clustering survey's own direct greps, zero matches). It would need export wiring before it could
  even be *displayed* as a group's matched/excluded population, which is a separate, smaller piece
  of work this document does not fold in.
- **`criticality` — comparators explicitly out of v1, per instruction.** `criticality` is numeric
  (1–5); a group rule keyed on it almost certainly wants a comparator (`>= 4`), not plain equality
  ("criticality equals exactly 3" is a far less natural fleet-wide statement than "critical or
  above"). A comparator is a predicate-language decision — do group rules gain an operator field,
  is it restricted to a closed set (`>=`, `<=`, `==`), how does the digest/precedence/not_collected
  machinery read it — and that decision is explicitly deferred, not folded into this document.
  `criticality` is left out of `GROUP_FIELD_CHOICES` entirely for v1, not included with
  equality-only semantics as a half-measure, since "criticality equals 3" is unlikely to be the
  statement anyone actually wants to make.

`GROUP_FIELD_CHOICES` is a `frozenset[str]`, but the **type-safety enforcement lives in the
Interpreter's own schema** (Section 6): `group_field: Literal["role"] | None`. Adding a field to
v2 is: widen that `Literal`, widen `GROUP_FIELD_CHOICES` to match (single source of truth,
`constraint_apply.py`, imported by both `memory.py`'s defensive check and
`agents/constraint_intake.py`'s schema), and add that field's own value vocabulary to the glossary
the Interpreter's task prompt gives the model (Section 6). No match-time code changes
(`match_group_constraints` already reads `group_field` generically via `getattr`).

---

## 5. Precedence and the merge: `fold_constraints`

### 5.1 The mechanism

`apply_constraints(asset, constraints) -> Asset` keeps its exact current signature and exact
current behavior — every existing call site (there are several across `agents/risk.py`,
`agents/environment.py`, `agents/coordinator.py`, `cli.py`, `export.py`) continues to compile and
run unchanged until each is deliberately rewired to also pass group constraints. It becomes a
one-line wrapper around a new function that does the real work:

```python
@dataclass(frozen=True)
class OverriddenGroupEffect:
    """One replace-kind field a group constraint would have set, on one
    asset, that an asset-level constraint overrode instead -- CLAUDE.md's
    decision 1 ("the overridden group value is reported in the run
    summary and the export")."""
    asset_id: str
    field: str                      # "patch_window" | "patch_restrictions"
    overriding_constraint_id: int    # the asset constraint that won
    group_constraint_id: int         # the group constraint that was overridden
    group_value_would_have_set: str

@dataclass(frozen=True)
class FoldResult:
    asset: Asset
    overridden_group_effects: tuple[OverriddenGroupEffect, ...] = ()

def fold_constraints(asset: Asset, *, constraints: list[Constraint] = (),
                      group_constraints: list[GroupConstraint] = ()) -> FoldResult:
    patch_window = asset.patch_window
    patch_restrictions = asset.patch_restrictions
    added_controls: list[str] = []
    supplied: set[str] = set()
    origin_by_field: dict[str, tuple[str, str]] = {}   # field -> ("group"|"asset", value)
    overridden: list[OverriddenGroupEffect] = []

    # Pass 1 -- GROUP constraints establish a baseline. Among themselves,
    # the identical "oldest-first, later supersedes earlier" rule the
    # asset pass already uses (group_constraints is expected oldest-first,
    # the same ORDER BY convention constraints_for_asset already uses).
    for gc in group_constraints:
        if not gc.effect_value:
            continue
        if gc.effect_kind == ConstraintEffectKind.PATCH_WINDOW.value:
            patch_window = gc.effect_value
            supplied.add("patch_window")
            origin_by_field["patch_window"] = ("group", gc.effect_value)
        elif gc.effect_kind == ConstraintEffectKind.PATCH_RESTRICTION.value:
            patch_restrictions = gc.effect_value
            supplied.add("patch_restrictions")
            origin_by_field["patch_restrictions"] = ("group", gc.effect_value)
        elif gc.effect_kind == ConstraintEffectKind.COMPENSATING_CONTROL.value:
            added_controls.append(gc.effect_value)
            supplied.add("compensating_controls")

    # Pass 2 -- ASSET constraints. For a replace-kind field, this
    # UNCONDITIONALLY overwrites whatever pass 1 set, regardless of either
    # side's created_at -- precedence is which PASS you're in, never list
    # position. If pass 1 already set the field from a group constraint,
    # record the override before overwriting it.
    for c in constraints:
        if not c.effect_value:
            continue
        if c.effect_kind == ConstraintEffectKind.PATCH_WINDOW.value:
            prior = origin_by_field.get("patch_window")
            if prior is not None and prior[0] == "group":
                overridden.append(OverriddenGroupEffect(
                    asset_id=asset.asset_id, field="patch_window",
                    overriding_constraint_id=c.id,
                    group_constraint_id=_group_id_for(gc_list=group_constraints, value=prior[1], kind="patch_window"),
                    group_value_would_have_set=prior[1],
                ))
            patch_window = c.effect_value
            supplied.add("patch_window")
            origin_by_field["patch_window"] = ("asset", c.effect_value)
        elif c.effect_kind == ConstraintEffectKind.PATCH_RESTRICTION.value:
            # identical shape, omitted for brevity
            ...
        elif c.effect_kind == ConstraintEffectKind.COMPENSATING_CONTROL.value:
            added_controls.append(c.effect_value)   # additive, both passes contribute
            supplied.add("compensating_controls")

    if added_controls:
        compensating_controls = (
            f"{asset.compensating_controls}, {', '.join(added_controls)}"
            if asset.compensating_controls else ", ".join(added_controls)
        )
    else:
        compensating_controls = asset.compensating_controls

    new_asset = asset.model_copy(update={
        "patch_window": patch_window,
        "patch_restrictions": patch_restrictions,
        "compensating_controls": compensating_controls,
        "not_collected": asset.not_collected - supplied,
    })
    return FoldResult(asset=new_asset, overridden_group_effects=tuple(overridden))

def apply_constraints(asset: Asset, constraints: list[Constraint]) -> Asset:
    return fold_constraints(asset, constraints=constraints).asset
```

(`_group_id_for` above is sketch-level plumbing — the real implementation tracks the originating
`GroupConstraint` object directly in `origin_by_field`, e.g. `("group", gc.effect_value, gc.id)`,
rather than re-deriving it by value; shown as a lookup only to keep the snippet readable.)

### 5.2 Why this satisfies "explicit, type-based, never positional"

The two inputs are never concatenated into one orderable sequence at all. `constraints` and
`group_constraints` stay two separate parameters through the whole function; precedence is
"whichever pass runs second always wins for a replace-kind field," which is a property of the
*code*, not of either list's *contents* or *order*. Reordering `group_constraints` can change
which group constraint wins *among groups* (unaffected, pre-existing "oldest-first, last wins"
semantics, scoped only to the group pass) but can never make a group constraint outrank an asset
constraint — there is no code path that compares a group constraint's `created_at` against an
asset constraint's at all.

### 5.3 Reporting an override

`overridden_group_effects` surfaces through the exact same channel `ConstraintApplicationSummary`
already uses for applied/skipped records (Section 8.6): a new field,
`overridden_group_effects: tuple[OverriddenGroupEffect, ...] = ()` (additive — every existing
construction of `ConstraintApplicationSummary` keeps working with the new field defaulting to
empty), populated by whichever caller actually calls `fold_constraints` with both lists populated
(`cli.ConstraintApplicator`, `agents/risk.py`'s `score_finding_tool`, `_submit_capacity_constraint`'s
fold, `export.py`'s `_agents_decomposition`). `cli._print_constraint_application_summary` gains one
more conditional line ("overridden: N group effect(s) -- see --export for detail") when the tuple
is non-empty; the export's `constraint_application` block gains an `overridden_group_effects`
array with the full detail (asset_id, field, which group constraint, what value it would have
set, which asset constraint won).

---

## 6. Intake: `ConstraintKind.GROUP`, extraction, and ambiguity

### 6.1 The third member, mirroring the capacity precedent exactly

```python
class ConstraintKind(str, Enum):
    ASSET = "asset"
    CAPACITY = "capacity"
    GROUP = "group"
```

`ConstraintInterpretation` gains two fields, populated only when `constraint_kind == "group"`:

```python
from rhinosecure.schema import AssetRole  # the one source of this vocabulary

group_field: Literal["role"] | None = None
group_value: AssetRole | None = None
```

`group_value`'s type is `schema.AssetRole` **imported directly**, not a hand-copied list of its 15
literals — `schema.py` already defines `AssetRole = Literal["dc", "exchange", ..., "printer"]` as
the one place this vocabulary is declared (CLAUDE.md Section 2/3's own role table is prose
*describing* that same code-level list, not a second source of it). Importing the type alias
means a future 16th role (CLAUDE.md Section 3 already names a still-open `server` role as a
candidate) is picked up automatically the moment `schema.AssetRole` changes — nothing in
`constraint_intake.py` needs editing in lockstep, closing the exact hand-maintained-duplicate risk
a literal copy would have created. (The prompt's own role glossary — Section 6.4 — is prose the
model reads, not a type; keeping that list in sync with `AssetRole` by eye is a much smaller,
one-line-per-role maintenance cost than a second schema declaration would have been, and is already
covered by test A39's substring check.)

`group_field`'s `Literal` **is** the v1 field-scope decision, enforced the same way
`ConstraintKind`/`effect_kind` already enforce their own closed vocabularies: an out-of-vocabulary
value is a `pydantic.ValidationError`, which feeds the exact same retry-then-`ConstraintInterpretationError`
path a malformed JSON blob already takes (`agents/parsing.py`) — no new failure mode, no new
exception type. `group_value`'s type is scoped to `role`'s own vocabulary for v1 only because
`role` is the only legal `group_field` today; when a second field is added later, this becomes a
discriminated union keyed by `group_field` (a `model_validator` cross-check) — a real, named
extension point, not built speculatively now.

`effect_kind`/`effect_value` are **reused unchanged** for a group statement — the same three-kind
vocabulary (`patch_window`/`compensating_control`/`patch_restriction`), populated the identical way
an asset statement's are. `patch_limit`/`affected_finding_ids`/`asset_id` all stay `None`/empty for
a group interpretation, mirroring exactly how `capacity` already leaves `asset_id`/`effect_kind`/
`effect_value` empty and `asset` leaves `patch_limit` empty. A `model_validator(mode="after")`
enforces "exactly one shape populates" across all four (`asset`, `capacity`, `group`, refusal) —
today's docstring already states this rule in prose ("In every case exactly one shape applies --
never a partial mix across shapes"); this is the one place it becomes a real, code-enforced check
rather than only prompt-level discipline, closing a gap that existed even before group constraints
(nothing today stops a malformed `asset_id`-plus-`patch_limit`-both-populated response from passing
validation).

### 6.2 No new tool — the model never resolves group membership

A group statement calls **neither** `search_assets` **nor** `list_findings_for_asset`, exactly
mirroring the existing instruction for a capacity statement ("Do NOT call search_assets... for a
capacity statement -- it names no asset to look up"). The Interpreter's only job for a
group-shaped statement is extracting `(group_field, group_value, effect_kind, effect_value)` from
the text — it never sees or touches the real asset population, the same "the model interprets,
code allocates" split capacity already proved. The actual matching (which real assets qualify, how
many are excluded as `not_collected`) is computed by code, after interpretation, in the preview
step (Section 7) — never by the model, and never checked against a tool call log, because there is
no tool call to check against (the same reason `effect_value`/`patch_limit` are already excluded
from `verify_constraint_matches_tool`: this is extraction from prose, not a verbatim copy of a
tool's own result).

### 6.3 Ambiguity: asset vs. group, never guessed

The task prompt's existing three-way framing (capacity / asset / refusal) becomes four-way. The
new first-order question, stated before any tool call: **does this statement name one specific
machine, or a category of machines?**

- A **singular, definite** reference — a hostname, "the payroll server," "WKS-FIN12" — is
  asset-shaped, exactly as today. The model proceeds to `search_assets` as before.
- A **collective or categorical** reference — "all workstations," "every file server," "any
  domain-joined dev box," a bare plural role noun with no article pointing at one machine — is
  group-shaped. The model extracts `group_field`/`group_value` from a supplied glossary (the
  prompt lists the real 15 `AssetRole` values with a one-line gloss each, mirrored from CLAUDE.md
  Section 2/3's own role table, so "domain controllers" reliably maps to the code token `"dc"`,
  "file servers" to `"file"`, and so on) and does **not** call either tool.
- **Genuinely ambiguous — refuse, don't guess.** Two sub-cases, both already partially covered by
  today's refusal logic and now stated explicitly for the new axis:
  - A **singular-looking** phrase that resolves to **two or more** real candidates with nothing in
    the text to narrow it ("the file server," three file servers in the fleet) was already a
    refusal before group constraints existed (zero-or-2+-candidates). The rationale now explicitly
    suggests the group alternative when it applies: *"'the file server' matched 3 assets with
    nothing to distinguish them — if you meant all of them, try 'all file servers...' instead."*
    This is a wording change to the refusal's own rationale text, not a new code path.
  - A statement that gestures at a category **and** a specific exception in the same sentence
    ("all workstations except the finance ones") is refused outright for v1 — `group_value` is a
    single scalar (decision 1's "one value per row"), so there is no honest single-row
    representation of an exclusion, and silently dropping the exception to approximate the
    statement would be exactly the guess this project's discipline forbids. The rationale says so
    plainly and asks the human to submit it as two statements if that's genuinely what's meant
    (the group rule, then a separate, narrower asset-scoped override — which decision 1's own
    precedence rule already handles correctly: an asset-level override always wins).

No code-level tool-result check is added for `group_field`/`group_value` beyond the `Literal`
typing already described — there is nothing to verify against a call log, the same reason
`effect_value` isn't checked that way today.

### 6.4 Why no tool call is needed for v1, and what that depends on

An independent investigation of this design proposed a different mechanism for grounding
`group_value`: a new tool, `list_field_values(field)`, that scans the live asset population
(skipping any asset where `field in asset.not_collected`, the exact analog of `_matches`'s own
skip), returns the distinct real values actually observed, and lets the model self-refuse before
committing — plus a code-level backstop checking `group_value` against that tool's own call log,
architecturally identical in shape to `verify_constraint_matches_tool`'s existing two checks.

That mechanism is real, well-justified, and **is the correct design the moment `GROUPABLE_FIELDS`
ever grows to include a field whose legal values are not a fixed code enum** — `business_function`
is the concrete future case: its values are whatever free text a given fleet's CSV happens to
contain, genuinely data-dependent, and there is no `Literal` that could enumerate them in advance.

It is **not needed for v1** specifically because `role` is a closed, code-owned enum
(`schema.AssetRole`, 15 fixed values) that doesn't vary per fleet — the same reason `effect_kind`
is already a `Literal` rather than a tool-verified string. A `Literal["dc", "exchange", ...]`
schema field makes an illegal `group_value` a `pydantic.ValidationError` at parse time,
structurally — stronger than "the model forgot to call the tool" or "the model called the tool
but asserted something it didn't return," which is what a tool-plus-call-log check would instead
guard against. For v1's one legal field, the `Literal` already closes the gap the tool exists to
close; the tool would be solving a problem v1 doesn't have yet. **When `GROUPABLE_FIELDS` grows to
include a free-text or fleet-dependent field, `list_field_values` plus a
`verify_constraint_matches_tool`-style backstop is the mechanism to add at that point** — recorded
here as the named extension, not built speculatively now (the identical posture Section 4 already
takes toward widening `GROUPABLE_FIELDS` itself).

**An adjacent, pre-existing gap, found while investigating this, out of scope for this feature.**
The existing ASSET-case refusal-on-genuine-ambiguity ("the file server" resolving to two or more
real candidates with nothing to narrow it) is enforced **only** by the prompt instruction today —
there is no code-level check that the model actually refused when `search_assets` returned more
than one plausible match; `verify_constraint_matches_tool`'s existing two checks are copy-fidelity
checks against the model's own tool-call log (did it assert an id the tool actually returned),
never a check that it was right to assert one at all when the tool returned several. This predates
group constraints, is unaffected by them, and is not fixed here — flagged because the hard case
below turns on the identical kind of ambiguity, one level up.

**The hard case, worth stating precisely rather than only by example.** A statement combining an
unambiguous single-asset reference with a cohort reference that needs more than one field to pin
down safely — "WKS-FIN12 and the other finance workstations" — cannot be represented by one
`group_field`/`group_value` pair (it would need `role="workstation"` **and**
`business_function≈"finance"` together, a conjunction decision 1's single-value-per-row schema
doesn't support). Three shortcuts are available and all are wrong: resolving only on
`business_function` risks sweeping in a far more sensitive asset that merely shares the department
tag (e.g. a Finance-tagged SQL Server); resolving only on `role` silently drops the "finance"
qualifier and applies fleet-wide; treating `WKS-FIN12` as the whole of it silently discards the
cohort reference. The system's own existing rule already settles this without a new one: *"Never
guess a partial answer across shapes: constraint_kind, and only the fields that shape uses, are
populated together, or nothing is"* (`constraint_intake.py`'s own docstring). A statement that would
require combining an ASSET reference and a GROUP predicate in one call is, by that rule, a refusal
— never a best-effort pick of one half. The rationale should name the compound nature explicitly
and ask for two separate statements (or a hostname-level restatement of the cohort), the identical
recourse the ASSET case already gives for an unresolvable role/function. A genuine conjunctive
GROUP predicate (`role` **and** `business_function` together) is a real, separate future extension,
named here and not built — the same deliberate deferral this codebase already applies to a
`criticality` comparator (Section 4) and the still-open `server` role (CLAUDE.md Section 3).

---

## 7. The review gate: preview, then a separate, explicit confirm

Decision 2's four requirements, restated as the four things this section has to deliver: (a) the
human sees field, value, match count, exclusion count, and the list before anything is stored;
(b) nothing is written until confirmation; (c) this works identically in spirit on the CLI, the
web Constraints form, and a Router-dispatched `constraint_submit`; (d) confirm is a separate,
explicit step everywhere, never an "are you sure" folded into one call.

**A fifth requirement, added on review, now governs the shape of everything below: the group path
is LLM-free except for the one Interpreter call.** The first version of this section reused
`submit_constraint`'s existing asset-scoped mechanism verbatim — "re-plans using the asset-scoped
flow's exact mechanism," meaning `Coordinator.replan`/`.run()`. That is wrong for a group
constraint specifically, not merely suboptimal: `role=workstation` matches roughly 700 assets on
the 5,000-finding measured fleet (Section 4), so `replan`/`run()` over "every finding on a matched
asset" means dispatching Research/Environment/Risk agents across thousands of findings just to
*confirm* a group rule — exactly the fleet-scale cost this whole feature exists to avoid paying per
human answer (the clustering survey's own premise, restated in this document's opening). PREVIEW
has the identical problem one layer up: on the CLI, a fresh `Coordinator` has `self.state is None`,
so `submit_constraint`'s existing asset branch falls through to `self.run(affected, ...)`, a full
agents pass, the moment it's asked to resolve `affected` for hundreds of assets. On the web path,
`_run_constraint_submit` calls `plan_state.seed()` first, which — when no plan is current yet —
dispatches a full agents run over the **entire fleet** just to obtain a `Coordinator`/`findings`
pair to interpret against. Neither of these is something a group-constraint PREVIEW should ever
have to pay for.

**Redesigned mechanism, below.** PREVIEW interprets the text once (the only LLM call in this whole
path) and matches directly against a deterministically-loaded asset inventory — no seeded, no
agents-run `Coordinator` required. CONFIRM writes the row and computes deltas through the
deterministic pipeline — the exact one `_submit_capacity_constraint` already uses
(`ingest.attach_threat_signals` + `scoring.score_finding`, no Crew dispatch at all) and the one
`--apply-constraints`'s `ConstraintApplicator` already uses to fold a constraint and recompute a
before/after score. Neither step calls `Coordinator.run()` or `Coordinator.replan()`.
**Asset-scoped `rhino constraint add` is explicitly NOT touched by this redesign** — its own
full-fleet-agents-seed cost (the web path's `plan_state.seed()`, and the CLI path's reliance on
`self.run(affected, ...)` when nothing has been seeded) is a real, separate fleet-scale defect,
recorded in Section 12 as its own open item, out of this design's scope.

### 7.1 Preview: interpret once, match against a freshly-loaded inventory

```python
def preview_group_constraint(
    self, text: str, findings: list[EnrichedFinding]
) -> GroupConstraintPreview | ConstraintSubmissionResult:
```

Reached from `submit_constraint` exactly the way `_submit_capacity_constraint` already is —
branching on `interpretation.constraint_kind` — but note the signature above is **not**
`_preview_group_constraint(self, text, interpretation)`: it still takes `text`/`findings` and calls
`interpret_constraint` itself (one Crew dispatch, same as today), the only difference from the old
design is everything AFTER interpretation.

1. Calls `self.interpret_constraint(text, findings)` — the one Interpreter dispatch. Requires
   `self.memory is not None` (the existing guard, unchanged).
2. If the interpretation isn't group-shaped, or is group-shaped but `effect_kind`/`effect_value`
   never resolved, returns the existing no-op refusal shape — unchanged from today.
3. Matches `interpretation.group_field`/`group_value` against `self._asset_index.values()` — **the
   inventory this `Coordinator` was constructed with**, which per `Coordinator.__init__`'s own
   existing contract is passed in via `assets=` or, when omitted, loaded from `data_dir/assets.csv`
   directly (`load_asset_index`) — **neither path ever requires `.run()` to have been called.**
   This is the load-bearing fact that makes the whole redesign work: `self._asset_index` is
   populated at `__init__` time, before any agent has ever been dispatched, exactly the same
   inventory `search_assets`/`list_field_values`-style tools already read from for the SAME
   Interpreter call in step 1. Matching reuses the real matcher (one throwaway
   `GroupConstraint(id=-1, ...)` run through `match_group_constraints`, so there is exactly one
   implementation of the match predicate, never two), over the **full fleet inventory**, not just
   assets with findings in `findings` — a human reviewing "how many assets match" should see the
   real fleet-wide count, the same reason `search_assets` searches the same full inventory.
4. Computes `preview_digest` and writes one row to `pending_group_constraints` (token,
   group_field/group_value/effect_kind/effect_value, matched/excluded lists, `created_at`,
   `consumed_at=NULL`) — unchanged from the first draft.
5. Returns `GroupConstraintPreview` (same shape as before: `persisted` reads `False` by
   construction).

**What loading `findings`/`self._asset_index` actually costs, stated precisely.** `findings` here
is whatever `ingest.load_batch(data_dir, adapter)` returns — the deterministic join of finding+asset
(CSV parse, format/contract resolution, zero network calls, zero threat-signal attachment) — **not**
an `EnrichedFinding` with real NVD/KEV/EPSS data attached. `interpret_constraint`'s own docstring
already states its `score_finding(e)` calls are "context for the model's own reasoning, not an
authoritative verdict" — it was already designed to tolerate this lower-fidelity input, so handing
it un-enriched findings is not a degradation introduced by this redesign; it is exactly what the
function already promised to accept. Constructing a `Coordinator` itself does no agent dispatch
(`__init__` only assigns attributes and loads the asset index) — the ONE thing that was ever
expensive is calling `.run()`/`.replan()`, and this design never does either for a group statement.

**Where `findings`/the inventory come from, per surface.**

- **CLI**: `rhino constraint group add "<text>" --data ... --format ... --adapter-config ...` —
  the identical three flags `rhino constraint add`/`rhino run` already take, resolved the identical
  way: `adapter = load_config_adapter(adapter_config) if adapter_config else get_adapter(fmt)`,
  then `assets, enriched = load_batch(data_dir, adapter)`. No `coordinator.run(findings)` anywhere
  in this path, at any fleet size.
- **Web**: a new, deterministic-only resolution step, independent of `plan_state.seed()`/
  `run_agents_pipeline` entirely. If `plan_state.active_source` is set (a prior confirmed
  `run_agents`/`run_deterministic` job), load from it directly via `ingest.load_batch(resolved
  .data_dir, adapter)` — the exact same one-line call `_build_and_run_coordinator` already makes,
  minus the `coordinator.run(findings)` call right after it. If `active_source` is `None` but the
  server has a startup default (`plan_state.config.data_dir`/`.fmt`/`.adapter_config`), build a
  `ResolvedSource` from those three the same way `seed()`'s own fallback does, and load from
  *that* — still no agents run. If neither is set (a genuinely empty workspace), PREVIEW refuses
  cleanly, mirroring `seed()`'s own `PlanNotSeededError` for the identical reason: there is nothing
  honest to preview against. This means a web PREVIEW never touches `plan_state.coordinator`/
  `.findings`/`.memory` at all — it builds its own short-lived `Coordinator` from whichever source
  resolves, exactly mirroring the CLI's own mechanism, so the two surfaces share one real
  implementation (a free function or a `Coordinator` classmethod that both call), not two
  independently-written ones.

**Does this change anything about which source a confirmed-vs-provisional contract resolves to?**
No, and this is simpler than the first draft's own reasoning here, not more complex: because
PREVIEW never reads `plan_state.coordinator` (the object that could, in principle, be stale
relative to what's on screen during the known provisional-run-vs-export.json discrepancy, Section
9), there is no staleness question to resolve at all. PREVIEW always reflects whatever is on disk
at the resolved `data_dir` *right now* — the freshest possible read, not a cached one. The one
thing PREVIEW still inherits unchanged from the asset-scoped case is the provisional-contract
refusal itself (Section 9): constructing the short-lived `Coordinator` with a real `Memory` against
a contract `is_provisional()` reports `True` for still raises at `Coordinator.__init__`, the
identical structural guard every other path relies on.

### 7.2 Fleet-scale-safe reporting

`matched_asset_ids`/`excluded_not_collected_asset_ids` are capped for **display** at a fixed,
documented limit (e.g. 50, matching `SCENARIO_PAGE_SIZE`'s own existing precedent) with the real
total count always shown honestly alongside a truncated sample — "77 matched (showing 50); 12
excluded as not_collected (showing 12)" — never a silent truncation with no count. The **stored**
`pending_group_constraints` row keeps the **full** untruncated lists (needed for a byte-accurate
re-validation at confirm time, Section 7.3) — only the human-facing rendering caps. This mirrors
the Fleet-scale audit's own repeated finding that an interface rendering every row unpaginated is
fine at 24 findings and a defect at thousands; a group preview against a 1,000-asset fleet must not
dump 1,000 ids into a CLI print or a chat card by default.

### 7.3 Confirm: re-validate against *current* data, re-score deterministically, never dispatch an agent

```python
def confirm_group_constraint(
    self, token: str, findings: list[EnrichedFinding], *, seed: int = 42,
    on_stage: Callable[[str], None] | None = None,
) -> GroupConstraintSubmissionResult:
```

1. Loads the `pending_group_constraints` row by `token`. Missing or `consumed_at` already set:
   refuse — "no such pending group constraint, or it was already confirmed/discarded; propose
   again."
2. **Re-runs the match** (Section 7.1, step 3) against the asset index **as it stands right now**
   (loaded fresh, the identical way PREVIEW loaded it — never cached from the preview call), and
   recomputes the digest the identical way.
3. If the recomputed digest **disagrees** with the stored `preview_digest`: refuse — "the fleet
   changed since this preview was generated (an asset's role changed, or the inventory was
   re-ingested); the matched/excluded set you reviewed no longer reflects current data. Propose
   again to review the current set before confirming." This is the direct analogue of
   `adapters/review.py`'s own drift check on re-confirming an ingest contract — a human's approval
   is of *specific, reviewed content*, not of "whatever this rule happens to mean by the time
   someone clicks confirm." **Previews never expire on their own** — there is no TTL, and an old,
   unconfirmed preview against an unchanged fleet confirms just as validly as a fresh one; the
   digest re-check above is the entire safety net, not a clock. The one thing CONFIRM's output
   states, purely informationally, is the preview's own age (`now - pending.created_at`, e.g.
   "confirming a preview generated 14 minutes ago") — never a gate, never a reason to refuse on its
   own.
4. If it agrees: marks `consumed_at`, writes the real `group_constraints` row
   (`Memory.add_group_constraint`), and **re-scores deterministically — no `replan`, no `run`, no
   agent dispatch of any kind.** For every finding whose `asset_id` is in the row's own stored
   `matched_asset_ids` (re-read from the row, not re-derived from the fresh match in step 2 — the
   row's own stored list is what was reviewed and is what gets applied, not a third,
   independently-recomputed set at write time):
   - Load `kev_catalog`/`attack_index` once (`load_kev_catalog(self.cache)`/
     `load_attack_index(self.cache)`), exactly as `_submit_capacity_constraint` already does.
   - Compute a **before** score: fold in whatever is *already* active for this asset today (any
     active asset-scoped constraint via `match_constraints`/`fold_constraints`, and any
     *other, already-confirmed* group constraint that also matches) via
     `attach_threat_signals` + `score_finding` — the honest baseline this new constraint is being
     added on top of, the same baseline `cli.ConstraintApplicator`'s own before/after pattern
     already establishes for the asset case.
   - Compute an **after** score: the identical fold, with the newly-confirmed group constraint's
     effect added via `fold_constraints`, respecting Section 5's precedence rule (an active asset
     constraint on the same replace-kind field still wins; the override is reported the same way
     Section 5.3 already specifies).
   - Build a `FindingDelta` from before/after, the same shape `submit_constraint`'s asset path
     already builds.
   - An asset that matched but has zero findings produces no delta (nothing to rescore) — not a
     refusal; the constraint still applies to that asset's role, it simply has nothing to show yet.
5. Records `runs` (with `agents=False`, matching `_submit_capacity_constraint`'s own reasoning —
   "this run made no LLM calls beyond the one Interpreter call already dispatched"),
   `decisions` (one per finding with a delta), and `feedback` the same way an asset-scoped
   submission already does — `feedback.raw_input` is the original constraint text (carried on the
   pending row), so a group constraint's provenance reads the same way in `rhino constraint list`'s
   own audit trail as any other submission's does.

**Verifying "LLM-free except the one Interpreter call" is a testable claim, not a narrative one.**
Section 11 states this as two concrete, instrumented assertions: a mocked/counted
`Coordinator.run`/`Coordinator.replan` (or the underlying `Crew.kickoff` these call) is invoked
**zero times** across a full preview-then-confirm cycle for a group statement matching hundreds of
assets, and `interpret_constraint` (or the `Crew.kickoff` it wraps) is invoked **exactly once** per
preview call. These are the executable form of this section's own fifth requirement, not merely an
architectural intention.

### 7.4 Three surfaces, one job handler — no Router-side token plumbing

All three paths funnel into the **same** `_run_constraint_submit` job handler and the same
`preview_group_constraint`/`confirm_group_constraint` pair — not a new job kind. This mirrors the
handler's own existing docstring ("a human's free text doesn't pre-declare its kind, so this isn't
two job kinds"), extended from two branches to three.

- **CLI**: `rhino constraint group add "<text>"` calls `preview_group_constraint`, prints the
  preview (field, value, counts, capped list) and a ready-to-run next command with the real token —
  `rhino constraint group confirm <token>` — the identical "prints the exact next command"
  convention `rhino adapt propose`'s own output already uses. `rhino constraint group confirm
  <token>` calls `confirm_group_constraint` and prints the diff via a renderer shaped like the
  existing `_print_constraint_result`. A separate, sibling subcommand tree (`rhino constraint group
  {add,list,retract,confirm}`), not reusing `rhino constraint {list,retract}`'s bare integer
  `--constraint-id` — see Section 8.2 for why the two id spaces must never be merged under one
  argument.
- **Web Constraints form**: `POST /api/jobs {kind: "constraint_submit", input: {raw_text}}`
  (unchanged call) now may return `result.kind == "group"`, `result.persisted == False`, and a
  `result.preview` block. `app.js`'s `handleJobSucceeded` gains a branch: render the preview as a
  card (field/value, matched/excluded counts and a capped sample) with a **Confirm** button.
  Clicking it posts a **second**, explicit job: `POST /api/jobs {kind: "constraint_submit", input:
  {confirm_token: <token from the in-memory preview result>}}`, whose own result reports the
  preview's age (Section 7.3) alongside the real deltas. The human never types the token — the browser already holds it from the
  first job's own result — but the confirm is still a distinct click on a distinct button, never
  folded into the first response rendering itself as an auto-apply. (Slice B, Section 7's web-side
  wiring; Section 11 assigns every test by slice.)
- **Router-dispatched `constraint_submit`**: **no change to `ConstraintSubmitParams` at all** —
  it stays bare `{raw_text: str}`, exactly as it is today. When the Interpreter resolves a
  Router-dispatched statement to a group preview, the step's own result carries the identical
  `result.preview` block the web form gets, and the **chat UI renders the identical preview card**
  — not the Router, not `web/route.py`'s dispatcher — with its own Confirm button. Clicking it
  posts the confirm job **directly** (`POST /api/jobs {kind: "constraint_submit", input:
  {confirm_token: ...}}`), exactly the way the chat's existing route-step follow-up buttons already
  work for `ingest_propose`'s own resolve/confirm panels (`openResolvePanel`/`openConfirmPanel`,
  reached from a completed step's own card via `card.conv`/`card.dataset.name`, never re-entering
  `/api/route`). No model ever sees, carries, or infers the token — it lives only in the browser's
  own rendered card, read directly by its Confirm button's click handler. This closes the question
  the first draft's design opened (whether `route.py` needs a new cross-step value-injection
  mechanism): it does not, because there is no cross-step injection here at all — confirm is a
  same-turn, browser-side follow-up on an already-completed step's own card, the identical shape
  `ingest_propose`'s resolve/confirm panels already use, not a second Router-dispatched step.

**Asset-scoped and capacity submissions are unaffected by any of this.** Decision 2 scopes the
gate to group constraints only; `submit_constraint`'s existing `asset`/`capacity` branches persist
immediately, exactly as they do today, with zero new confirmation step. This is a deliberate,
explicit non-change, not an oversight — restated here because it's the kind of thing an
implementation could accidentally over-generalize into "every constraint now needs confirmation."

---

## 8. Every consumer of the constraints table, and what it does with group constraints

The survey's own Q2 inventory, walked one at a time. "Never invisible or unremovable anywhere" is
the governing requirement — each entry below says where a group constraint's effect, and its own
retraction, becomes visible.

### 8.1 Constraints tab (web) and its Remove button — Slice B

A **third** section, "Group constraints," alongside the existing "Asset-scoped constraints"/
"Capacity constraints" — not merged into either. Each card shows `group_field`/`group_value`,
`effect_kind`/`effect_value`, matched/excluded counts (live, recomputed against the current
export's own asset population — not the stale preview-time counts), and a deltas table identical
in shape to `assetConstraintHtml`'s. Its own **Remove** button posts to a **new**, separate route,
`POST /api/group-constraints/{id}/retract` (mirroring `POST /api/constraints/{id}/retract`
exactly: soft-delete only, synchronous, no job, no LLM) — a distinct URL path, not the existing
route with a type discriminator, because the two tables' integer ids are independent and **will**
collide (constraint #3 and group constraint #3 can both exist at once); a shared endpoint taking a
bare id would be genuinely ambiguous about which table it means.

### 8.2 `rhino constraint list` / `retract` — Slice A

**Unchanged** — continues to operate only on `constraints` (asset-scoped), exactly as today. A
sibling command tree, `rhino constraint group list` / `rhino constraint group retract <id>`,
is added for the new table — never merged into the existing bare-integer argument, for the
identical id-collision reason as 8.1: `constraints.id` and `group_constraints.id` are independent
`AUTOINCREMENT` sequences, each starting at 1, so a bare shared integer argument is genuinely
ambiguous the moment both tables have an active row 3. **Live match counts in `rhino constraint
group list`, decided, not an open question**: each row additionally prints its current matched-asset
count against the current `--data`, recomputed fresh on every `list` invocation (cheap — `O(assets)`,
not `O(findings)` — matching the same inventory load PREVIEW/CONFIRM already use), so a human
retracting one sees its current blast radius before doing so, not just its stored text.

### 8.3 The export's constraints section — Slice A

`_constraints_section` gains a third key, `group_scoped`, alongside `asset_scoped`/`capacity`:

```python
{
  "asset_scoped": [...],   # unchanged
  "capacity": [...],       # unchanged
  "group_scoped": [
    {
      "group_constraint_id": 7,
      "group_field": "role",
      "group_value": "workstation",
      "constraint_text": "...",
      "effect_kind": "patch_window",
      "effect_value": "...",
      "created_at": "...",
      "active": true,
      "matched_asset_count": 212,
      "matched_asset_ids": ["A014", "A033", ...],          # capped, same convention as 7.2
      "excluded_not_collected_asset_count": 9,
      "excluded_not_collected_asset_ids": ["A101", ...],    # capped
      "deltas": [...]        # same per-finding before/after shape as asset_scoped, when live
    }
  ]
}
```

`live`/`not_live_note` plumbing is **reused verbatim** — a group-scoped constraint needs the
identical three-way honesty (`_DETERMINISTIC_NOTE` when `--apply-constraints` wasn't given,
`_PROVISIONAL_*_NOTE` when the plan is provisional, a real delta otherwise) the asset-scoped
section already has, computed by the same `live: bool` parameter already threaded through
`_constraints_section`/`_asset_scoped_constraints`.

### 8.4 `_constraint_application_dict` (the top-level `constraint_application` block) — Slice A

Additive fields, preserving every existing one byte-for-byte when no group constraint ever
applies:

```python
{
  "applied": True,
  "reason": None,
  "digest": "sha256:...",
  "applied_constraint_ids": [1, 2],       # unchanged meaning: asset-origin ids only
  "applied_group_constraint_ids": [],     # NEW -- group-origin ids, empty when none applied
  "overridden_group_effects": [],         # NEW -- Section 5.3's OverriddenGroupEffect list
  "skipped": {
    "legacy": [...], "identity_mismatch": [...],
    "not_collected": []                   # NEW -- Section 8.5's capped-summary shape
  }
}
```

No `digest_covers_groups` field — decided against (see Section 8.5): the digest formula below
never has a run-wide "mode" for a reader to need a flag for in the first place.

### 8.5 `all_active_constraints` and the digest — Slice A

`all_active_constraints` (asset-scoped) is **untouched** — it was never going to read a different
table. `ConstraintAccumulator` gains a parallel method:

```python
def record_group(self, asset: Asset) -> tuple[GroupConstraint, ...]:
    """Mirrors record(), for the group table. Caches the group-constraint
    LIST once (fetched by the constructor or on first call, never per
    asset -- Section 3), matches per asset via match_group_constraints,
    records not_collected skips (capped per Section 7.2's own convention
    for the SUMMARY shape, never the underlying count), and returns the
    usable-effect subset the caller folds in via fold_constraints."""
```

`not_collected` skip records are **summarized**, not enumerated per `(group_constraint, asset)`
pair, in any human-facing output — unlike `legacy`/`identity_mismatch`, which can only ever name
exactly *one* asset (an asset constraint belongs to exactly one asset by construction), a single
group constraint can be skipped against an unbounded number of assets. The summary shape:

```python
@dataclass(frozen=True)
class SkippedGroupConstraintSummary:
    group_constraint_id: int
    group_field: str
    group_value: str
    skipped_asset_count: int
    sample_asset_ids: tuple[str, ...]   # capped (Section 7.2's limit), never the full list in a print/summary line
```

The **full** list remains available on request (the export's `group_scoped[].excluded_not_collected_asset_ids`,
itself capped per 7.2 with an honest total count) — this summary is specifically for the one-line
CLI/digest-adjacent reporting (`_print_constraint_application_summary`'s new "excluded: N
not_collected" clause), where dumping every id would repeat the exact unpaginated-dump defect the
Fleet-scale audit already found and fixed elsewhere.

**The digest — decided, neither of the two previously-weighed options.** The first draft presented
two alternatives: (A) one digest whose tuple SHAPE switches, run-wide, from 4-tuple to 5-tuple the
instant any group-origin record exists anywhere in the applied set; (B) two permanently-separate
fields, `digest` (asset-only, forever 4-tuple) and `group_digest` (group-only, forever 5-tuple). Both
are rejected. The actual design: **one digest, one sorted list, where each record's own tuple shape
depends only on that record's own origin — never on what else applied this run:**

```python
def compute_constraint_digest(
    applied: tuple[AppliedConstraintRecord, ...],
    group_applied: tuple[AppliedGroupConstraintRecord, ...] = (),
) -> str:
    tuples = [(r.asset_id, r.hostname, r.effect_kind, r.effect_value) for r in applied]
    tuples += [
        (g.asset_id, g.hostname, f"group:{g.group_constraint_id}", g.effect_kind, g.effect_value)
        for g in group_applied
    ]
    tuples.sort(key=lambda t: tuple((x is None, x) for x in t))
    blob = json.dumps([list(t) for t in tuples], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()
```

No conditional branch at all — asset-origin records are **always** built as the plain 4-tuple
(`asset_id, hostname, effect_kind, effect_value`), exactly the existing function's own literal line,
unchanged; group-origin records are **always** built as the 5-tuple with `"group:<id>"` injected as
the third element. There is no "asset-origin record gets an `'asset:<id>'` tag once a group record
exists anywhere" rule, because there is no run-wide switch to trigger it — each record's shape is a
pure function of which list it came from, nothing else. `AppliedGroupConstraintRecord` is its own
dataclass (not a reuse of `AppliedConstraintRecord` with an overloaded `constraint_id`), with its
own `group_constraint_id: int` field, so the `"group:<id>"` string is unambiguous about which table
the id names — the export's `applied_constraint_ids` (asset-origin) and
`applied_group_constraint_ids` (group-origin) stay two separate lists for the same reason.

Python's tuple comparison handles the mixed-length sort safely: comparing a 4-element and a
5-element tuple, each already wrapped per-position as `(x is None, x)`, compares positions 0–3
first (lexicographically, no incompatible-type comparison possible — the wrapping already forces
every position to be a `(bool, value)` pair) and only falls back to tuple length if every shared
position compared equal, which is the standard, safe Python rule for comparing a prefix against a
longer sequence. No `TypeError` risk, no special-casing needed in the sort key itself.

**Walked through, precisely, the three required scenarios — and why this formula satisfies both
halves (i) and (ii) simultaneously, by construction, not by a conditional that has to be gotten
right:**

1. **Zero group constraints ever exist.** `group_applied` is the empty tuple, always, since there is
   nothing in `group_constraints` to match against. `tuples` is built from `applied` alone, under
   the literal 4-tuple expression — not "the formula happens to degenerate here," the **only** code
   path that ever executes when `group_applied` is empty, because the list concatenation
   (`tuples += [...]`) appends nothing. Byte-identical to today's digest for the identical `applied`
   set, by construction, for every possible asset-only run, not merely the ones a test happens to
   check.
2. **One group constraint matches one asset.** `record_group` produces one
   `AppliedGroupConstraintRecord` with `group_constraint_id` set, appended to `group_applied`. The
   digest now sorts a mixed list — every asset-origin record's tuple is **still** the plain 4-tuple,
   completely unaffected by the group record's presence; the one group-origin record contributes its
   own 5-tuple. The digest differs from before, correctly: a new fact (this group constraint applying
   to this asset) entered the picture.
3. **A second asset later joins that group.** `record_group` is called for this asset too (every
   asset actually scored is visited, Section 3), it now matches (`match_group_constraints` is a
   live, read-time check — there is no stale membership to update), and a **second**
   `AppliedGroupConstraintRecord` enters `group_applied`. The sorted list gains one more 5-tuple
   entry → a different, larger blob → a different digest. This is decision 3's requirement (i): the
   digest changes "because the plan changed," specifically because membership grew. The symmetric
   case — an asset leaving a group — works identically in reverse: the record disappears from
   `group_applied`, the digest changes again. Neither direction needs separate handling; both are
   ordinary membership changes to the same list.

**Why this is better than both of the previously-weighed options, not merely a compromise between
them.** Option A's cost was a run-wide "mode" (`digest_covers_groups`) a reader needed to check to
know which formula produced a given digest string — a real gap, since two digest strings are
indistinguishable in shape regardless of which formula made them. Option B's cost was two
permanently-separate fields a consumer must both check to detect any drift. This design has
neither problem: there is only one field, so there is only one thing to check for "did anything
change"; and there is no run-wide mode at all, since an individual record's tuple shape is legible
from the record's own origin, not from some global condition — `digest_covers_groups` is simply
unnecessary, not merely removed. Neither investigation that weighed Options A and B anticipated this
third shape; it closes the actual disagreement between them rather than picking a side.

### 8.6 The agents-path read sites — Slice A

- **`agents/risk.py`'s `score_finding_tool`**: fetches `memory.all_active_group_constraints()`
  once at `build_risk_tools` call time (Section 3), closes over it; per finding, calls
  `match_group_constraints(group_list, enriched.asset)` alongside the existing
  `match_constraints(...)` call, then `fold_constraints(asset, constraints=asset_applied,
  group_constraints=group_applied)` in place of today's bare `apply_constraints(...)` call. A new
  result field, `group_constraints_applied: list[str]` (parallel to the existing
  `constraints_applied: list[str]`, same plain-text-list shape so nothing downstream that
  verbatim-checks `constraints_applied` needs to change) carries which group constraints' own text
  applied. `neutralized_axes`/the five raw axis values are unaffected — a group constraint can
  clear `asset.not_collected`'s `role` entry only if it ever *writes* `role` (it doesn't; it reads
  `role` to decide membership, and its effect is always one of the three operational fields, never
  `role` itself) — so this feature never interacts with Impact-axis neutralization at all, worth
  stating explicitly since it's exactly the kind of cross-feature interaction CLAUDE.md's own
  "Provisional scoring reaches run_agents" entry had to reason carefully about for a different
  pairing.
- **`agents/environment.py`'s `lookup_asset_context`**: identical shape — fetch once, match per
  asset, fold, and a new `group_human_constraints: list[str]` result field alongside the existing
  `human_constraints`. Left unfenced in the prompt for the identical reason the existing six fields
  already are (Section 8's own "Prompt-injection isolation" entry): this is meant to be copied
  verbatim into `EnvironmentAssessment`, not read as an instruction.
- **`agents/coordinator.py`'s `_submit_capacity_constraint`**: its existing per-finding fold
  (`candidates = self.memory.constraints_for_asset(...)`) gains a **sibling**, fetched **once**
  before the loop (`group_candidates = self.memory.all_active_group_constraints()`), matched per
  asset inside the loop exactly like the asset-scoped read already is, and combined via
  `fold_constraints` instead of the bare `apply_constraints` call — otherwise "the real, current
  bucket" this function computes before reallocating capacity would quietly ignore a group rule
  that's actively changing `has_patch_window`/`has_compensating_controls` for dozens of assets at
  once, which is a worse version of the exact gap this function's own docstring already describes
  fixing for the asset-scoped case ("otherwise... a lie whenever an asset has a constraint").
- **`export.py`'s `_agents_decomposition`**: the fourth site the earlier machine-identity-scoping
  entry found that the original survey's Q2 inventory didn't separately name — the identical
  pattern applies again here: fetch `coordinator.memory.all_active_group_constraints()` once per
  export build (not per finding), fold alongside the existing asset-scoped read, so this live
  recompute never disagrees with what `score_finding_tool` actually used for the real
  `risk_score`/`bucket` a reader sees.

### 8.7 The deterministic path: `cli.ConstraintApplicator` — Slice A

`ConstraintApplicator.__init__` fetches `self._group_constraints = memory.all_active_group_constraints()`
once; `.apply(enriched)` calls `self._engine.record(asset)` and `self._engine.record_group(asset)`
and folds both via `fold_constraints` in place of today's bare `apply_constraints`. Unreached unless
`--apply-constraints` is given, exactly as today — a plain `rhino run` still never touches
`memory.py` at all, group constraints included (confirmed by the identical "`Memory.__init__`
monkeypatched to raise, never fires" test convention the machine-identity scoping work already
used).

### 8.8 Housekeeping, done during Slice A, not a new feature

**Single-source the "findings that reached Risk" filter.** Confirmed by direct grep: the exact same
generator-expression pattern — `(e.asset for e in <state>.enriched_by_id.values() if
e.finding.finding_id in <state>.risk_by_id)` — appears independently, written three separate times,
in `export.py` (feeding `_build_agents_export`'s own `summarize_for_assets` call),
`cli.py`'s `_agents_constraint_application_summary` (`scored_ids = coordinator.state.risk_by_id`),
and `web/jobs.py` (the `_run_run_agents` job's own mirrored call) — each with its own copy of the
same reasoning in its own comment ("a finding whose Research/Environment/Risk dispatch failed... is
never pruned... filtering to `risk_by_id` membership is the honest population"). This is exactly
the kind of duplicated-rule risk CLAUDE.md's own structural-problem framing warns about
("distributes knowledge about its own rules across components that do not share it") — a future
change to what "actually scored" means would need to be found and fixed in three places, and two of
those three both already needed this exact filter fixed once, independently, for the group feature's
own new `summarize_for_assets(memory, assets)` call sites (`cli._agents_constraint_application_summary`
and `export._build_agents_export`'s own `agents_capp` computation) to stay correct. Extracted into
one crewai-free helper — `constraint_apply.scored_assets(enriched_by_id, risk_by_id) ->
Iterator[Asset]` is the natural home (the file already hosts `summarize_for_assets`, the one real
consumer of this exact filtered iterable, and `constraint_apply.py`'s own crewai-free discipline
means `export.py`/`cli.py`/`web/jobs.py` can all import it without pulling `crewai` into any of
their import graphs — the same reason `apply_constraints`/`ConstraintEffectKind` were extracted out
of `agents/constraint_intake.py` in the first place). All three call sites are rewired to call it;
behavior is unchanged (same filter, same inputs, same outputs) — this is a pure refactor with no
externally-visible effect, confirmed by the existing test suite passing unmodified before any group
constraint code is added.

**Correct `compute_constraint_digest`'s existing docstring.** Section 11's own incidental finding
(carried over from the first draft): the function's current docstring claims its sort key "treats
`None` as sorting before any string," when the actual behavior (via `tuple((x is None, x) for x in
t)`, `False < True`) sorts `None` *after* every string. Not a correctness bug — the branch is
unreachable in practice, since no field of a genuine `AppliedConstraintRecord`/
`AppliedGroupConstraintRecord` is ever `None` — but a confirmed, pre-existing inaccuracy, fixed as a
one-line docstring edit alongside the digest work in Slice A, not bundled into any new behavior.

---

## 9. Provisional plans stay constraint-free — confirmed, not merely inherited

**Claim: a provisional (unconfirmed-contract) run never applies a group constraint, for the
identical structural reason it never applies an asset-scoped one — `memory=None`, not a new
check.** Walked through against every backstop that already exists, to confirm rather than assume:

- `web/jobs.py`'s `_resolve_provisional`-branch `Coordinator` is constructed with `memory=None`
  (the "Provisional scoring reaches `run_agents`" entry, and its "provisional plans never apply"
  follow-up). `agents/risk.py`'s `score_finding_tool`, `agents/environment.py`'s
  `lookup_asset_context`, and `_submit_capacity_constraint`'s fold are all gated on `if memory is
  not None`. A `None` memory means **neither** `memory.constraints_for_asset(...)` **nor** the new
  `memory.all_active_group_constraints()` is ever called — there is no code path by which a
  provisional `Coordinator` can reach the group table at all, because there is no `Memory` object
  through which to reach it. This requires no new guard; it falls out of every new read site being
  written the same `if memory is not None:` shape every existing one already uses.
- `Coordinator.__init__`'s own structural refusal (`if memory is not None and is_provisional(contract):
  raise CoordinatorError(...)`) is unaffected and unextended — it was never about *which* table a
  `Memory` might read, only about whether a real `Memory` may be paired with an unconfirmed
  contract at all. A `Memory` that would read the group table is exactly as forbidden here as one
  that would read the asset-scoped table; the same single check covers both, since it fires on the
  *pairing*, not on which methods get called afterward.
- `cli._run_run_deterministic`'s `memory=None if provisional_adapter is not None else job_memory`
  line (the "provisional plans never apply constraints" fix) governs the **scoring input** to
  `run_with_report`/`ConstraintApplicator` as a whole — a provisional deterministic run passes
  `memory=None` into `run_with_report` regardless of `--apply-constraints`, so
  `ConstraintApplicator` (Section 8.7) is never even constructed, group-aware or not.
- The **preview/confirm gate itself requires a real `Memory`** (`pending_group_constraints` is a
  table in it) — so the question "can a provisional Coordinator even *propose* a group constraint"
  has the same answer as "can it submit an asset-scoped one": `submit_constraint`'s own existing
  `if self.memory is None: raise CoordinatorError(...)` guard fires first, before interpretation
  ever runs, for a provisional Coordinator attempting **any** constraint submission, group included.

No new code is needed to make this true; it is a corollary of every new consumer reusing the
identical `memory is not None` gate every existing one already has, checked explicitly here rather
than left as an unstated assumption, per CLAUDE.md's own "distributes knowledge about its own
rules across components that don't share it" lesson (the `_provisional()` sentinel postmortem).

---

## 10. Byte-identical with no group constraints: the acceptance test

`rhino run --data demo --seed 42 --offline` (no `--apply-constraints`) must print
`Contested: 3/24 (12.5%)` and produce byte-identical scored output to `975e30f`, for the
same reason it already must today — this feature adds no call on the plain path at all
(Section 8.7, unreached without `--apply-constraints`).

`rhino run --data demo --seed 42 --offline --apply-constraints` against the **real**,
`975e30f`-era `rhinosecure.db` (confirmed to hold zero active constraints — the "Two fixes" entry's
own read-only query) must also print an identical bucket distribution and an **identical digest**
to what the pre-this-feature `--apply-constraints` code already produces for the same database —
guaranteed by Section 8.5's formula walk-through (scenario 1): zero rows in the new
`group_constraints` table collapses the new digest function to the literal old one. This is the
sharpest, most direct form of the "byte-identical to 975e30f" requirement: not merely "the demo
fixture looks the same," but "the digest — the one value whose whole job is detecting a change in
what applied — provably cannot differ when the new table is empty," proven by construction in
Section 8.5 rather than only by running the comparison once and hoping it holds.

---

## 11. Test plan, split into Slice A and Slice B

Every test below states its intent and its own break/fix check — reverting the one fix it covers
must turn it red; this project's own convention (every prior constraint-scoping entry) is to
actually perform that revert → confirm red → restore → confirm green cycle before trusting a test,
not merely assert that one exists. Every test is tagged **A** or **B**: Slice A is storage, the
matcher, fold/precedence, the digest, intake, the CLI (`rhino constraint group
add/confirm/list/retract`), the deterministic path (including its existing web entry point,
`_run_run_deterministic`), all four agents-path read sites plus capacity's fold, the export, and
both provisional guards. Slice B is the web Constraints tab's new UI section, its retract route,
and the preview card with a Confirm button (both the direct web form and the chat/Router path).
Nothing in Slice B is reachable without Slice A merged first; Slice A is fully usable (CLI-only) on
its own.

Baseline at HEAD `975e30f`: **1,742 passed**, `rhino run --data demo --seed 42 --offline` reads
`Contested: 3/24 (12.5%)` — re-confirm this literal figure at implementation time rather than
trusting it as written here, since it is itself a snapshot.

### 11.1 — A — Schema / migration — `tests/test_memory.py`

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A1 | `test_a_fresh_database_gets_the_group_constraints_table` | A brand-new `Memory(db_path)` creates `group_constraints` with the documented columns, readable via `PRAGMA table_info`. | Remove the `CREATE TABLE IF NOT EXISTS group_constraints` block from `_SCHEMA_SQL` → `PRAGMA table_info` returns empty, test fails. |
| A2 | `test_a_fresh_database_gets_the_pending_group_constraints_table` | Same, for the preview/confirm table (`token, group_field, group_value, constraint_text, effect_kind, effect_value, matched_asset_ids, excluded_asset_ids, preview_digest, created_at, consumed_at`). | Same mechanism as A1, against the second table. |
| A3 | `test_a_database_created_before_group_constraints_existed_gets_the_tables_idempotently` | Mirrors `test_a_database_created_before_hostname_existed_is_migrated` line-for-line: hand-build the pre-feature schema, insert one pre-existing `constraints` row and one `runs` row, reopen with the new `Memory`, assert old rows are untouched and the two new tables now exist, empty. Confirms this reaches an existing DB via plain `CREATE TABLE IF NOT EXISTS`, **not** `_migrate()` (a brand-new table, not an `ALTER TABLE` on one that already exists). | Delete the `CREATE TABLE IF NOT EXISTS group_constraints` statement → reopening the hand-built old DB raises `sqlite3.OperationalError: no such table` on the first `add_group_constraint` call, instead of the table silently appearing. |
| A4 | `test_group_constraints_table_addition_adds_no_migrate_entries` | Opening a pre-feature DB produces **zero** new `_migrate()`-reported `ALTER TABLE` additions — distinguishing this from the `hostname`/`ingest_format` cases, which genuinely are column migrations. | If a future implementer mistakenly routes this through `_migrate()` instead of `_SCHEMA_SQL`, the migrate-entries list picks up an unexpected new entry, catching an architecture drift even though the functional behavior would otherwise look identical. |
| A5 | `test_migration_is_idempotent_across_reopens_for_group_constraints` | Open/close the same db 3 times, calling `add_group_constraint` each time; all 3 rows survive, no duplicate-table error. | Change `CREATE TABLE IF NOT EXISTS` to plain `CREATE TABLE` → the second open raises `table group_constraints already exists`. |

### 11.2 — A — Storage CRUD — `tests/test_memory.py`

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A6 | `test_add_group_constraint_returns_an_id_and_is_retrievable` | `add_group_constraint("role", "workstation", "text", effect_kind=..., effect_value=...)` returns an int id; `all_active_group_constraints()` contains exactly one matching `GroupConstraint`, `active=True`. | Comment out the `INSERT` body → readback returns `[]`. |
| A7 | `test_add_group_constraint_with_no_effect_defaults_both_to_none` | Mirrors `add_constraint`'s own precedent (an uninterpreted constraint is a legitimate row shape) — omitting `effect_kind`/`effect_value` stores `None`, not `""`. | Default them to `""` in the signature → the `is None` assertion fails. |
| A8 | `test_deactivate_group_constraint_is_a_soft_delete` | `deactivate_group_constraint(id)` flips `active` to `False`; the row still appears via a full read with its text intact — never deleted. | Implement it as `DELETE` instead of `UPDATE ... SET active=0` → the row vanishes entirely. |
| A9 | `test_all_active_group_constraints_excludes_deactivated_rows_by_default` | After deactivating one of two rows, the active-only (default) read returns only the still-active one — the whole-table read, since there's no `asset_id` to filter a `WHERE` on. | Drop the `WHERE active = 1` clause → the deactivated row still appears. |
| A10 | `test_deactivating_an_already_inactive_group_constraint_a_second_time_is_refused` | Mirrors `test_web_constraints.py`'s existing `test_retract_an_already_retracted_id_is_refused_the_second_time` for the asset table — the group route refuses identically, not a silent second success. | Remove whatever "already inactive" guard the chosen implementation uses → a second deactivate that should 404/raise instead returns success. |
| A11 | `test_group_constraints_survive_across_sessions` | Add, close, reopen the same db file, confirm the row is still there with the same fields. | N/A as a single line to revert — guards against a future accidental in-memory-only cache substituting for a real write. |
| A12 | `test_pending_group_constraint_save_load_and_one_shot_consume` | Save a `pending_group_constraints` row, load it by token, mark it consumed; loading the same token again still returns the row (for the age/audit display) but the confirm path's own "already consumed" check (A32) is what refuses a second write — this test only pins the storage layer's own round-trip, not the refusal. | Comment out the `consumed_at` `UPDATE` → a second confirm attempt's own refusal check (A32) can never fire, since `consumed_at` never actually gets set. |

### 11.3 — A — Matching — `tests/test_constraint_apply.py`

Mirrors the exact `_constraint()`-factory-plus-dataclass-equality style of the existing
`match_constraints` suite.

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A13 | `test_match_group_constraints_applies_when_the_field_value_matches` | `GroupConstraint(group_field="role", group_value="workstation")` against `Asset(role="workstation", not_collected=frozenset())` → `GroupConstraintMatch(applied=(gc,))`. | Invert the equality check → the matching case reports no match. |
| A14 | `test_match_group_constraints_does_not_apply_on_a_different_value` | Same constraint against `Asset(role="sql", ...)` → `GroupConstraintMatch()` — empty, **not reported at all**, per the design's explicit "silence here is 'not relevant,' not 'a problem'" decision. | Add an `else:` branch appending to a third "didn't match" list → the "no such field, or empty" assertion fails. |
| A15 | `test_match_group_constraints_skips_as_not_collected_when_the_field_is_a_placeholder` | Same constraint against `Asset(role="workstation", not_collected=frozenset({"role"}))` (the Defender-defaulted-role case) → `skipped_not_collected=(gc,)`, **never** `applied`, even though the raw value happens to equal `group_value`. | Check `not_collected` membership *after* the equality branch (or drop it) → a Defender-sourced server defaulted to `role="file"` wrongly matches a `"file"`-role rule. |
| A16 | `test_match_group_constraints_mixed_population_sorts_each_asset_correctly` | Three assets (matches / wrong value / not_collected) against one group constraint in one call → each lands in exactly the right bucket. | Swap the not_collected and equality checks' order → the not_collected asset false-matches. |
| A17 | `test_match_group_constraints_getattr_degrades_gracefully_for_an_unknown_field` | A `GroupConstraint` with a `group_field` this code version doesn't recognize (a forward-compat row from a newer version) degrades to "doesn't match," never raises. | Replace `getattr(asset, gc.group_field, None)` with plain attribute access → the crafted case raises `AttributeError` instead of degrading. |
| A18 | `test_has_usable_effect_accepts_a_group_constraint_identically_to_an_asset_constraint` | `has_usable_effect(GroupConstraint(effect_kind="patch_window", effect_value="..."))` → `True`; with `effect_kind=None` → `False` — the identical two assertions the existing `Constraint`-only tests already make, now against the new type. | Revert the `Protocol` back to a concrete `Constraint` type hint — the sharper signal is a static-type-checker catch; the runtime assertion is a weaker but real regression guard either way. |

### 11.4 — A — Precedence — `tests/test_constraint_apply.py`

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A19 | `test_asset_patch_window_overrides_group_patch_window_on_the_same_asset` | `fold_constraints(asset, constraints=[asset_pw], group_constraints=[group_pw])` → the asset's value wins; `overridden_group_effects` names the group constraint, its value, and the winning asset constraint's id. | Reorder pass 1/pass 2 (asset first, group second) → the group value wins instead. |
| A20 | `test_group_patch_window_alone_applies_and_clears_not_collected` | No asset-level override present → the group's value is used, `"patch_window"` clears from `not_collected`, `overridden_group_effects` is empty. | Skip the group pass entirely when no asset constraint exists → `patch_window` stays blank. |
| A21 | `test_compensating_control_accumulates_from_both_asset_and_group_constraints` | An asset-level and a group-level compensating-control constraint on the same asset → **both** strings appear in the result (additive, never override). | Route `compensating_control` through the same single-winner branch as the replace-kind fields → only one value survives. |
| A22 | `test_precedence_is_independent_of_which_constraint_was_created_more_recently` | Construct the group constraint with a **later** `created_at` than the asset constraint — the asset constraint still wins; precedence is "which pass," never timestamp or list position. | The named regression target: merge both inputs into one timestamp-sorted list internally and take "last wins" → this test flips (the newer, group value now wins). |
| A23 | `test_group_vs_group_precedence_is_oldest_first_last_writer_wins` | **New, per the accepted group-vs-group precedence decision** (Section 5.1's own flagged assumption, now settled): two group constraints on the same `(group_field, group_value)` both setting `patch_window` on an asset both match — the one with the **later** `created_at` wins, mirroring the asset-only case's own existing within-type rule exactly, scoped only to the group pass. | Sort the group list by `id` instead of `created_at` → a group constraint inserted earlier but assigned a higher id (e.g. after a retract-and-reinsert) wins instead of the chronologically later one. |
| A24 | `test_patch_restriction_precedence_mirrors_patch_window_precedence` | Same shape as A19/A20 but for `patch_restriction` — exists specifically because an implementation might elide this branch as "identical, omitted for brevity" and get it subtly wrong. | Implement pass 2's `patch_restriction` branch without the override-detection block `patch_window`'s branch has → the value is still correctly overwritten but `overridden_group_effects` silently misses recording it. |
| A25 | `test_fold_constraints_never_mutates_the_input_asset` | Mirrors the existing `apply_constraints` mutation guard — `fold_constraints` returns a new `Asset` via `model_copy`, the original frozen instance is untouched. | Have the function return the same object reference → an identity check (`result.asset is not asset`) fails. |
| A26 | `test_apply_constraints_still_behaves_identically_when_no_group_constraints_are_passed` | `apply_constraints(asset, constraints)` (now a thin wrapper) produces byte-identical output to `fold_constraints(asset, constraints=constraints, group_constraints=()).asset` — a direct regression guard that the refactor changed nothing for existing callers. | Have the wrapper silently also consult a module-level "all active group constraints" global → the "identical to an empty group list" comparison fails because the wrapper now does more than its signature promises. |

### 11.5 — A — Digest (Option C) — `tests/test_constraint_apply.py`

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A27 | `test_compute_constraint_digest_is_byte_identical_to_pre_feature_output_when_no_group_constraints_exist` | `group_applied=()` (the only value it can ever be when the table is empty) → the digest equals a captured, hardcoded expected digest produced by the actual pre-feature `compute_constraint_digest` for the identical `applied` input — a literal before/after byte comparison. | Build asset-origin tuples with a 5th, injected `"asset:<id>"` origin element regardless of `group_applied` → the hardcoded expected string (computed under the plain 4-tuple) no longer matches. |
| A28 | `test_asset_origin_tuples_stay_4_tuples_even_when_a_group_origin_record_is_also_present` | **The Option-C-specific invariant**: one asset-origin record and one group-origin record in the same `applied`/`group_applied` pair → the digest's hashed blob contains the asset record as a 4-element array and the group record as a 5-element array, never both widened to 5. | Add a run-wide `if group_applied: tag every asset tuple with "asset:<id>" too` branch (reintroducing Option A's rejected mechanism) → this test's shape assertion on the asset tuple's length fails. |
| A29 | `test_digest_changes_when_a_second_asset_joins_an_existing_group` | Digest for `{group record for asset A}` vs. `{group record for asset A, group record for asset B}` (same group constraint) → the two differ. | Dedupe by `group_constraint_id` alone instead of `(group_constraint_id, asset_id)` → asset B's record is silently collapsed into asset A's. |
| A30 | `test_digest_changes_when_an_asset_leaves_a_group` | The symmetric case to A29: start with two records, remove one, the digest changes again — and equals what A29's single-asset digest was, proving the digest is a pure function of the current applied set, not of history. | N/A as a distinct line to revert — a symmetry/determinism pin; would only fail from a future regression making the computation order- or history-dependent. |
| A31 | `test_digest_is_insertion_order_independent_with_mixed_asset_and_group_origins_of_different_tuple_lengths` | Mirrors the existing `test_apply_constraints_digest_is_independent_of_insertion_order`, extended to a mixed 4-tuple/5-tuple record set constructed in two different orders → identical digest both ways, confirming Python's lexicographic prefix comparison (a 4-tuple vs. a 5-tuple sharing the same first four positions) sorts safely with no `TypeError`. | Sort by `(group_field, group_value)` instead of the documented key → two differently-ordered constructions of the same set stop matching. |
| A32 | `test_digest_does_not_change_on_an_unrelated_free_text_edit` | Editing a group constraint's `constraint_text` only (not `effect_kind`/`effect_value`) produces an identical digest, since `constraint_text` was never part of either tuple shape. | Add `constraint_text` into the hashed tuple → a cosmetic edit now churns the digest. |

### 11.6 — A — Intake — `tests/test_constraint_intake.py`

Via a fake `Agent`/`Task`/LLM response, the same way every existing Interpreter test already
injects one — no real LLM call. Mirrors this codebase's **actual** existing shapes of
"refusal-on-ambiguity" coverage: schema validation, closed-vocabulary rejection, and
prompt-substring checks — there is no test anywhere in this codebase that feeds natural language to
a real LLM and checks it refuses; that reasoning is prompt-level and untestable without a live
model call.

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A33 | `test_a_group_shaped_interpretation_parses_with_asset_id_and_patch_limit_null` | `ConstraintInterpretation(constraint_kind="group", group_field="role", group_value="workstation", ..., asset_id=None, patch_limit=None)` validates cleanly. | Don't add `group_field`/`group_value` to the model → construction raises `TypeError`. |
| A34 | `test_group_value_type_is_imported_from_schema_assetrole_not_a_second_declaration` | **New, per the single-sourcing fix**: `ConstraintInterpretation.model_fields["group_value"].annotation` is (or resolves to) `schema.AssetRole | None`, confirmed by identity/equality against the imported type, not by re-deriving a parallel list of 15 strings in the test itself. | Replace the import with a hand-copied `Literal[...]` duplicate → the test's identity/equality check against `schema.AssetRole` fails even though the two lists currently contain the same values, catching the drift risk before `AssetRole` actually grows a 16th value. |
| A35 | `test_an_out_of_vocabulary_group_field_is_rejected_at_parse_time` | `group_field="owner"` (a real `Asset` field, not in v1's `Literal["role"]` scope) raises `pydantic.ValidationError` — mirrors the existing unrecognized-`effect_kind` test exactly. | Widen the field to a bare `str` → the bad value now parses. |
| A36 | `test_an_out_of_vocabulary_group_value_is_rejected_at_parse_time` | `group_value="not-a-real-role"` raises `pydantic.ValidationError` (`AssetRole`'s own closed vocabulary). | Same mechanism as A35, applied to `group_value`'s type. |
| A37 | `test_a_response_with_both_asset_id_and_group_field_populated_is_rejected` | The new cross-shape `model_validator(mode="after")` ("exactly one shape populates") rejects a malformed response naming both. | Remove the new validator → the malformed, two-shape response parses successfully. |
| A38 | `test_a_response_with_group_field_but_no_effect_is_a_legitimate_uninterpreted_row_shape` | Mirrors `memory.py`'s own documented allowance (a constraint recorded before being interpreted into an effect): `group_field`/`group_value` populated, `effect_kind=None`/`effect_value=None` still validates — NOT a refusal, a real, legal partial shape. | Make the validator wrongly require `effect_kind` whenever `group_field` is set → this legitimate shape now raises. |
| A39 | `test_build_constraint_task_includes_the_full_role_glossary` | The task description text contains all 15 `AssetRole` values with their one-line glosses — the model's only way to map "domain controllers" → `"dc"` without a tool call. | Delete the glossary block → the substring assertion for e.g. `"dc"`/`"domain controller"` fails. |
| A40 | `test_build_constraint_task_instructs_not_to_call_tools_for_a_group_statement` | Mirrors the existing capacity-case instruction — the identical sentence exists for the group case. | Delete that clause → the substring assertion fails. |
| A41 | `test_build_constraint_task_states_the_singular_vs_categorical_distinction` | The prompt contains the first-order question ("does this statement name one specific machine, or a category of machines") — the only lever this codebase has for steering model behavior on this axis. | Delete that framing sentence → the substring assertion fails. |
| A42 | `test_build_constraint_task_instructs_refusal_on_a_category_plus_exception_statement` | Pins the "all workstations except the finance ones" refusal instruction text (Section 6.4's hard case). | Delete that clause → the substring assertion fails. |
| A43 | `test_build_constraint_task_instructs_refusal_on_a_compound_asset_plus_group_statement` | Pins the "WKS-FIN12 and the other finance workstations" refusal instruction (Section 6.4) — a statement combining an asset reference and a group predicate is a refusal, never a best-effort pick of one half. | Delete that clause → the substring assertion fails. |
| A44 | `test_refusal_interpretation_still_validates_with_group_fields_also_null` | Extends the existing refusal-validation test to also assert `group_field is None`/`group_value is None` on a refusal-shaped interpretation. | Make the new fields required (non-Optional) → a genuine refusal response that leaves them unset now fails validation. |

### 11.7 — A — Preview/confirm mechanism: zero agent dispatch, provisional guard, no expiry — `tests/test_coordinator.py`

This is the executable form of Section 7's own fifth requirement. Every test in this group
constructs a `Coordinator` directly (never via `plan_state`) and asserts against
`Coordinator.run`/`Coordinator.replan`/`Crew.kickoff` call counts, the same fake-Crew harness every
existing Interpreter/Coordinator test already uses — no real LLM call except where explicitly noted
for `interpret_constraint`'s own one dispatch (also faked).

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A45 | `test_preview_group_constraint_calls_interpret_constraint_exactly_once` | Call-count instrumentation on `Coordinator.interpret_constraint` (or the `Crew.kickoff` it wraps) asserts exactly one call for one `preview_group_constraint` invocation. | Have `preview_group_constraint` re-interpret on a transient parse hiccup outside `interpret_constraint`'s own existing retry loop → the count exceeds one. |
| A46 | `test_preview_group_constraint_never_calls_run_or_replan` | Against a fleet constructed so the group statement matches 50+ assets (large enough that a full agents pass would be an obvious, not incidental, cost): call-count instrumentation on `Coordinator.run`/`Coordinator.replan` asserts **zero** calls across a full `preview_group_constraint` invocation. | Fall through to `self.run(affected, ...)` for the group branch the way the asset branch already does when `self.state is None` → the call count becomes nonzero, and the test fails loudly rather than merely "running slow." |
| A47 | `test_confirm_group_constraint_never_calls_run_or_replan` | Same instrumentation, across a full `confirm_group_constraint` invocation against the same 50+-asset match. | Route confirm through `self.replan(affected_ids, ...)` to compute deltas instead of the deterministic `attach_threat_signals`/`score_finding` pair → the call count becomes nonzero. |
| A48 | `test_preview_group_constraint_works_without_any_prior_run_ever_being_called` | Construct a fresh `Coordinator` (`self.state is None`, confirmed) and call `preview_group_constraint` directly, with no `.run()` call anywhere beforehand — it returns correct `matched_asset_ids`/`excluded_not_collected_asset_ids` against `self._asset_index`. | Have `preview_group_constraint` read `self.state.enriched_by_id` instead of `self._asset_index` → raises `AttributeError` on a `Coordinator` that was never run, since `self.state` is `None`. |
| A49 | `test_a_provisional_coordinator_refuses_preview_group_constraint` | A `Coordinator` built with `memory=None` raises `CoordinatorError` on `preview_group_constraint` for a group-shaped interpretation, mirroring the existing provisional-refuses-asset-constraint test — confirms the pre-existing guard (fires inside `submit_constraint`, before `interpret_constraint` is even reached) applies identically to the group branch, with no special-cased bypass. | Add a `memory is None` bypass specifically inside the new group branch (e.g. "preview doesn't need memory") → `pytest.raises(CoordinatorError)` no longer fires. |
| A50 | `test_group_constraint_preview_never_writes_to_the_group_constraints_table` | `preview_group_constraint` (real `Memory`, non-provisional) returns a preview with `persisted=False`; `all_active_group_constraints()` is still empty afterward — only `pending_group_constraints` gained a row. | Call `add_group_constraint(...)` inside the preview path → the "table still empty" assertion fails. |
| A51 | `test_confirm_group_constraint_with_a_valid_unconsumed_token_writes_rescodes_deterministically_and_returns_deltas` | `confirm_group_constraint` with a valid token writes the `group_constraints` row, re-scores exactly the findings whose asset is in the stored `matched_asset_ids` via `attach_threat_signals`/`score_finding` (never `.run()`/`.replan()`), and returns correct before/after deltas that also honor Section 5's precedence rule when an asset-scoped constraint is already active on one of the matched assets. | Skip the `add_group_constraint` call → the subsequent readback check fails; separately, omit the asset-scoped overlay from the "before" computation → the delta's "before" picture wrongly looks unconstrained when an asset constraint was already active. |
| A52 | `test_confirm_group_constraint_refuses_when_the_fleet_changed_since_preview` | A token whose stored `matched_asset_ids` no longer match current data (simulate by mutating the asset index between preview and confirm) is refused with no write. | Skip the digest re-check → the stale preview silently applies. |
| A53 | `test_confirm_group_constraint_refuses_a_second_confirm_of_the_same_token` | Calling confirm twice with the same token: the second call is refused (`consumed_at` already set). | Remove the `consumed_at` guard → the second call succeeds and double-applies. |
| A54 | `test_confirm_group_constraint_succeeds_on_an_old_unchanged_preview_and_reports_its_age` | **Previews don't expire, decided.** A preview whose `created_at` is simulated as hours old, against an otherwise-unchanged fleet, still confirms successfully (the digest still matches) and the result's own age field reflects the real elapsed time — age is reported, never a gate. | Add a TTL check that refuses confirm past some age regardless of digest agreement → this test's "still succeeds" assertion fails. |
| A55 | `test_group_constraints_are_invisible_when_memory_is_none_structurally_not_by_a_new_check` | `score_finding_tool`/`lookup_asset_context` never call `all_active_group_constraints()` when `memory is None` — call-count instrumentation asserts zero calls, confirming this falls out of the existing `if memory is not None:` gate rather than needing a dedicated new guard. | Have the group-fetch line execute unconditionally before the `if memory is not None` check → the call-count mock registers a call even with `memory=None` (and would crash in practice). |

### 11.8 — A — CLI, deterministic path, export, agents-path read sites, digest parity

**CLI — `tests/test_cli.py`**

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A56 | `test_constraint_group_add_loads_the_inventory_via_load_batch_with_data_format_adapter_config` | `rhino constraint group add "<text>" --data ... --format ... --adapter-config ...` resolves the inventory the identical way `rhino run`/`rhino constraint add` already do, confirmed by a call-count/argument-capture spy on `load_batch` — and never constructs a `Coordinator` that has had `.run()` called on it. | Have the new subcommand's dispatch call `run_agents`'s own helper (which does call `coordinator.run(findings)` on the whole fleet) by mistake instead of the preview-only path → the spy sees a `.run()` call that shouldn't be there. |
| A57 | `test_constraint_list_shows_group_constraints_in_a_distinct_section_from_asset_constraints` | Output visibly separates group rows from asset rows — distinct section, never interleaved under one undifferentiated list. | Merge both reads into one combined, id-sorted list with no section header → the section-presence assertion fails. |
| A58 | `test_constraint_group_retract_removes_the_named_group_constraint_only` | `rhino constraint group retract <id>` soft-deletes exactly the named group constraint; a same-numbered **asset** constraint (a deliberately constructed id-collision scenario) is untouched — the decisive id-collision test. | Route group retract through the same deactivation call as asset retract (no table discriminator) → the asset constraint sharing that numeric id also gets deactivated. |
| A59 | `test_apply_constraints_flag_on_folds_a_matching_group_constraint_into_the_deterministic_score` | Seed a group constraint (`role=workstation`, `patch_window`) matching a currently-`contested` demo finding's asset, run with `--apply-constraints`, the finding moves bucket with `risk_score` unchanged. | Have `ConstraintApplicator.__init__` fetch the group list but never pass it into `fold_constraints` → the finding stays `contested`. |
| A60 | `test_constraint_applicator_fetches_group_constraints_exactly_once_per_invocation_not_per_finding` | A call-count mock on `all_active_group_constraints` asserts exactly one call across a whole `--apply-constraints` run over the 24-finding demo fixture, not 24 — the fleet-scale requirement made concrete. | Move the fetch inside the per-finding scoring loop → the call count becomes 24. |

**The deterministic path's existing web entry point — `tests/test_web_jobs_dispatcher.py`** (this is `_run_run_deterministic`'s own already-existing, always-on constraint fold gaining group-awareness — not new UI, so Slice A, not Slice B)

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A61 | `test_run_deterministic_job_reports_group_constraint_application_in_its_result_and_export` | Seed a matching group constraint, dispatch `run_deterministic`, assert `applied_group_constraint_ids` is non-empty in both the job result and the export. | Thread the group summary into the CLI path but not into `web/jobs.py`'s result dict (the exact asymmetry CLAUDE.md's own "Two fixes" entry already found and fixed once, for a different field pair) → the web job's result omits it while the CLI reports it. |
| A62 | `test_run_deterministic_job_never_applies_a_group_constraint_against_a_provisional_mapping` | Mirrors the existing asset-constraint provisional test exactly, substituting a seeded group constraint (`role=workstation`) matching several provisional-mapping assets: against the unconfirmed contract, the finding stays unconstrained and `applied_group_constraint_ids == []`; after confirming the same contract, the identical constraint now applies. | Change `memory=None if provisional_adapter is not None else job_memory` back to an unconditional `job_memory` → the provisional half of this test fails. |

**Export — `tests/test_export.py`**

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A63 | `test_constraints_section_gains_a_group_scoped_key_alongside_asset_scoped_and_capacity` | `_constraints_section(...)` returns all three top-level keys always present, `group_scoped` populated with the documented per-row shape. | Add the new key only when non-empty → a consumer reading `data.constraints.group_scoped` unconditionally on a plan with zero group constraints gets a missing-key error. |
| A64 | `test_constraint_application_block_reports_applied_group_constraint_ids_separately_from_asset_ids` | `applied_constraint_ids` (asset-origin) and `applied_group_constraint_ids` never share one combined list. | Merge both into one list with no origin tag → a reader can no longer tell a group id from an asset id when the two numeric spaces collide. |
| A65 | `test_agents_decomposition_reflects_a_live_group_constraint_identically_to_score_finding_tool` | Seed a group constraint, run the real agents pipeline (fake Crew), confirm the export's recomputed `risk_score`/`bucket` agrees with what `score_finding_tool` actually produced. | Have the export's recompute call bare `apply_constraints` (group-blind) instead of `fold_constraints` → the export's shown bucket disagrees with the real scored finding's — the identical bug class CLAUDE.md's "Two fixes" entry already found once for the asset-only case at this exact call site. |
| A66 | `test_zero_group_constraints_leaves_export_byte_identical_in_shape_to_pre_feature_except_the_new_empty_keys` | With zero rows in `group_constraints`, every existing export key/value is unchanged; the only diff from a pre-feature export is the presence of empty `group_scoped: []`/`applied_group_constraint_ids: []`/`overridden_group_effects: []`. | N/A as a single line — the export-level sibling of the Section 10 acceptance test. |

**Agents-path read sites — `tests/test_risk_agent.py`, `tests/test_environment_agent.py`, `tests/test_coordinator.py`**

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A67 | `test_score_finding_tool_folds_a_matching_group_constraint_into_the_real_score` | Seed a group-level compensating-control constraint matching the test asset's role, call `score_finding_tool`, assert the score/rationale reflects it and the new `group_constraints_applied` field names it. | Skip calling `match_group_constraints`/`fold_constraints`, keep the bare `apply_constraints` call → the seeded constraint has no effect. |
| A68 | `test_score_finding_tool_fetches_group_constraints_once_per_tool_build_not_per_finding` | Call-count instrumentation asserts exactly one call across a multi-finding dispatch — the fleet-scale requirement at the agents-path tool-build boundary. | Move the fetch inside the per-finding closure body → the call count equals the finding count. |
| A69 | `test_lookup_asset_context_surfaces_a_matching_group_constraint_as_group_human_constraints` | A new `group_human_constraints` field lists the matched group constraint's text, separate from `human_constraints`. | Fold the group text into the existing `human_constraints` list instead → a consumer that needs to tell the two origins apart can't. |
| A70 | `test_submit_capacity_constraint_applies_an_active_group_constraint_before_ranking` | A group-level compensating control changes a finding's "real, current bucket" before the capacity rank/cutoff is computed, exactly as an asset-level one already does. | Thread only `constraints_for_asset` into the capacity path's fold, leaving the group read unthreaded → the pre-ranking bucket ignores the group constraint. |

**CLI/agents digest parity — `tests/test_constraint_apply.py`**

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A71 | `test_summarize_for_assets_matches_cli_apply_constraints_on_the_real_demo_fixture_with_a_group_constraint` | Extends the existing identically-named test with a seeded group constraint matching several demo-fixture workstations — the deterministic and agents-path summaries still agree on digest, applied ids (both origins), and skip lists. | Have only one of the two paths call `record_group`, leaving the other group-blind → the two summaries' digests disagree. |

**Housekeeping (Section 8.8) — `tests/test_export.py`, `tests/test_cli.py`, `tests/test_web_jobs_dispatcher.py`**

| # | Test | Intent | Break/fix |
|---|---|---|---|
| A72 | `test_scored_assets_is_single_sourced_across_export_cli_and_web_jobs` | `export.py`/`cli.py`/`web/jobs.py` each call the same `constraint_apply.scored_assets(enriched_by_id, risk_by_id)` helper rather than each re-deriving the same filter — confirmed by a shared fixture exercising a finding that failed upstream (never reaches `risk_by_id`) and asserting all three call sites agree it's excluded. | Leave one of the three call sites with its own inline copy of the filter instead of calling the shared helper → a future change to the filter's logic (tested here by deliberately changing what "actually scored" means) is caught in two call sites and silently missed in the third. |

### 11.9 — B — Web Constraints tab UI + retract route — `tests/test_web_jobs_dispatcher.py` + a new `tests/test_web_group_constraints.py` + `tests/js/app_test.html`

| # | Test | Intent | Break/fix |
|---|---|---|---|
| B1 | `test_group_constraint_retract_route_deactivates_and_survives_as_a_soft_delete` | `POST /api/group-constraints/{id}/retract` (a distinct route, never a shared endpoint with the asset table) deactivates the row; it still appears via a full read with `active=False`. | Reuse `POST /api/constraints/{id}/retract` with a type query param instead of a distinct path → an id-collision scenario retracts the wrong row. |
| B2 | `test_group_constraint_retract_an_unknown_id_is_refused` | Mirrors the existing asset-route test — 404, clear message. | Drop the existence check → a bogus id returns 200. |
| B3 | `appjs: groupConstraintHtml renders field/value and a Remove button for an active group constraint` | The Constraints tab's third section renders `group_field`/`group_value`/matched-count and a `.group-constraint-retract-btn`. | Forget to add the new rendering function/section entirely → the DOM query for the group section finds nothing. Verified live in the browser pane (no Node in this environment), confirmed red before the fix and green after. |
| B4 | `appjs: retractGroupConstraint posts to /api/group-constraints/{id}/retract and removes the button in place` | Mirrors `retractConstraint`'s own fetch-spy test exactly, against the new distinct URL. | Point it at the shared `/api/constraints/{id}/retract` URL by mistake → the fetch-spy's URL assertion fails. |

### 11.10 — B — The preview card with Confirm, and the web-only resolution path — `tests/test_web_jobs_dispatcher.py` + `tests/js/app_test.html`

| # | Test | Intent | Break/fix |
|---|---|---|---|
| B5 | `test_web_preview_resolves_from_active_source_without_calling_run_agents_pipeline` | With `plan_state.active_source` already set (a prior confirmed `run_agents`/`run_deterministic` job), a `constraint_submit` job for a group-shaped statement resolves the inventory from `active_source` via `load_batch` directly — call-count instrumentation on `run_agents_pipeline`/`_build_and_run_coordinator` asserts **zero** calls. | Have the new preview path call `plan_state.seed()` first (the old, rejected design) → the call count becomes nonzero, and on a large fleet this is also an observable latency regression. |
| B6 | `test_web_preview_falls_back_to_server_startup_default_when_no_active_source` | With `plan_state.active_source is None` but `plan_state.config.data_dir` set (the server's startup default), preview resolves from that triple (`data_dir`/`fmt`/`adapter_config`) the same way `seed()`'s own fallback does — again with zero `run_agents_pipeline` calls. | Skip the fallback and require `active_source` to be set → a fresh server with only a startup `--data` fails to preview at all. |
| B7 | `test_web_preview_refuses_cleanly_in_a_genuinely_empty_workspace` | With both `active_source` and the startup default `None`, preview refuses with a clear message (mirroring `PlanNotSeededError`'s own wording) rather than crashing or guessing a source. | Let the resolution fall through to a bare `None`/`None` pair passed into `load_batch` → an unhandled `TypeError`/`AttributeError` instead of a clean refusal. |
| B8 | `test_constraint_submit_job_returns_a_preview_block_for_a_group_statement` | `POST /api/jobs {kind: "constraint_submit", input: {raw_text}}` for a group-shaped statement returns `result.kind == "group"`, `result.persisted == False`, and a `result.preview` block with field/value/counts/token. | Omit the `preview` block from the serialized result → the web form has nothing to render a card from. |
| B9 | `test_constraint_submit_job_with_confirm_token_writes_and_returns_deltas` | `POST /api/jobs {kind: "constraint_submit", input: {confirm_token}}` (no `raw_text` needed) calls `confirm_group_constraint`, persists, and returns deltas plus the preview's age. | Require `raw_text` to be re-sent alongside `confirm_token` and re-interpret it → a second, unnecessary LLM call fires on confirm, contradicting Section 7's own zero-extra-LLM-call requirement. |
| B10 | `appjs: a group preview card renders a Confirm button that posts confirm_token directly to /api/jobs` | The web form's rendering of `result.preview` includes a Confirm button; clicking it posts the second job with the token already held in the DOM/JS state — never re-prompting the human for it. | Render the preview with no actionable button (display-only) → the fetch-spy test finds no click handler to trigger the second job. |
| B11 | `appjs: a Router-dispatched constraint_submit step's group preview renders the identical preview card, reached via the step's own card, never through /api/route` | Mirrors the existing `ingest_propose`-step `openResolvePanel`/`openConfirmPanel` pattern: a completed `constraint_submit` route step whose result is a group preview gets a Confirm button wired via `card.conv`/`card.dataset`, posting directly to `/api/jobs` — a fetch-spy on `/api/route` during this click asserts **zero** calls. | Route the Confirm click back through `/api/route` as a second Router-dispatched step → the fetch-spy on `/api/route` registers a call, confirming the token would have had to round-trip through the Router after all. |
| B12 | `test_constraint_submit_params_still_has_no_confirm_field` | **A negative test, stated explicitly so a future PR can't quietly reintroduce it.** `agents.router.ConstraintSubmitParams` has exactly one field, `raw_text: str`, `extra="forbid"` — constructing it with a `confirm` kwarg raises `pydantic.ValidationError`. | Add `confirm: bool = False` back to the model (the first draft's rejected design) → this test's "exactly one field" assertion fails. |

### 11.11 Two acceptance procedures, one per slice

**Slice A's acceptance — the byte-identical-to-`975e30f` proof**, the exact method every prior
entry in CLAUDE.md's constraint-scoping work used (machine-identity scoping, the two-fixes
follow-up):

1. **Baseline capture, before any line of Slice A is written**, from a `git worktree` checkout of
   HEAD `975e30f`: capture `rhino run --data demo --seed 42 --offline` stdout (must read `Contested:
   3/24 (12.5%)`), capture `--export out/baseline-pre-group.json`, and capture the exact `pytest -q`
   pass count (re-confirm the literal number at capture time, not trusted from this document).
2. **Implement Slice A** against this design, adding tests A1–A72.
3. **Re-run the identical three commands** on the Slice A branch, with the real `rhinosecure.db`
   confirmed (read-only query, mirroring the prior two entries' own check) to hold **zero** rows in
   the new `group_constraints` table.
4. **Diff, not eyeball:** the two stdout captures byte-identical; the two export JSONs compared field
   by field excluding only `generated_at`, with every pre-existing field byte-identical and every new
   field (`group_scoped`, `applied_group_constraint_ids`, `overridden_group_effects`)
   empty/absent-equivalent; the full existing suite (every test that existed at `975e30f`) passing
   **unmodified**. The only acceptable count change is strictly additive: 1,742 plus every A-tagged
   test above, zero regressions, zero modifications to a pre-existing test's assertions.
5. **With `--apply-constraints` and the real, zero-group-row database**, re-run and re-diff against
   the pre-feature `--apply-constraints` output captured the same way in step 1 — confirming the new
   table's mere existence, even populated with nothing, doesn't perturb the already-shipped
   machine-identity constraint-scoping behavior at all.

**Expected post-Slice-A full-suite count: 1,742 + 72 = 1,814 passed.**

**Slice B's acceptance**, built and merged only after Slice A lands:

1. Re-confirm Slice A's own baseline still holds unmodified on the Slice B branch (the full A1–A72
   suite passes, the demo fixture's `Contested: 3/24 (12.5%)` is unchanged) — Slice B adds no scoring
   code, so this is a regression guard, not new verification.
2. Add tests B1–B12, each with its own break/fix cycle actually performed.
3. The JS harness (`tests/js/app_test.html`) verified live in the browser pane for every `appjs:`-
   labeled test (B3, B4, B10, B11) — no Node in this environment, so this is the established,
   load-bearing verification method for this codebase's own JS, not merely a nice-to-have.
4. A live, end-to-end click-through on a real seeded plan with a real (fake-Crew or, once confident,
   real-LLM) agents run: submit a group statement via the web form, confirm the preview card renders,
   click Confirm, confirm the Constraints tab's new section shows the persisted row with a working
   Remove button — mirroring this project's own repeated "verified live, not just in tests" discipline
   for web-UI work.

**Expected post-Slice-B full-suite count: 1,814 + 12 = 1,826 passed.**

Every break/fix check across both slices must be performed as an actual revert → confirm red →
restore → confirm green cycle before any single test is trusted — this project's own
repeatedly-stated discipline, not a formality.

---

## 12. Remaining decisions for a human

Everything the first draft listed here as open has since been decided, on review, except one item
— named and settled below for the record, followed by the one genuinely new item this revision
surfaced and explicitly keeps out of scope.

**Settled, not relitigated (restated briefly so this section still reads as a complete record):**

- **Digest shape** (was item 1): neither of the two previously-weighed options — Section 8.5's
  per-origin-tuple-shape design (Option C) closes the actual disagreement between them rather than
  picking a side.
- **Preview expiry** (was item 2): decided — no expiry. The digest re-check at confirm time is the
  entire safety net; confirm's own output states the preview's age, purely informationally
  (Section 7.3, test A54).
- **Router cross-step token injection** (was item 3): removed, not merely resolved — there is no
  cross-step value injection for this feature at all. `ConstraintSubmitParams` stays bare
  `{raw_text: str}`; a group preview's Confirm button is a same-turn, browser-side follow-up on an
  already-completed step's own card, the identical shape `ingest_propose`'s resolve/confirm panels
  already use (Section 7.4, tests B11–B12).
- **Live match counts in `rhino constraint group list`** (was item 4): accepted as designed — live,
  recomputed on every invocation, `O(assets)` not `O(findings)` (Section 8.2).
- **`group_value`'s vocabulary source** (was item 5): resolved by importing `schema.AssetRole`
  directly rather than hand-copying its 15 literals (Section 6.1, test A34) — the hand-maintained-
  duplicate risk the item named is closed; the residual, smaller question of registry-backed
  validation (`adapters/schema_registry.py`) instead of a fixed schema type was not asked for and
  is not pursued here.
- **Group-vs-group precedence** (was item 6): accepted as designed — oldest-first, last-writer-wins
  within the group pass only, the identical rule the asset-only case already has (Section 5.1, test
  A23).
- **The id-collision risk** (was item 7): resolved by construction — separate CLI subcommand tree,
  separate web route, never a shared bare-integer argument (Section 8.2, Section 8.1, test A58).

**One genuinely new item, recorded and explicitly out of scope for this design:**

1. **Asset-scoped `rhino constraint add`'s own full-fleet-agents-seed cost is a real, separate
   fleet-scale defect, not touched by this revision.** On the CLI, a fresh `Coordinator` constructed
   for `rhino constraint add` has `self.state is None`, so `submit_constraint`'s existing asset
   branch falls through to `self.run(affected, ...)` whenever nothing has been seeded — cheap for
   one asset's handful of findings, but the same shape of cost this design went to real lengths to
   avoid for the group case. On the web path, `_run_constraint_submit` calls `plan_state.seed()`
   first, which — when no plan is current yet — dispatches a full agents run over the **entire
   fleet** just to obtain a `Coordinator`/`findings` pair, before any constraint (asset, capacity,
   or group) can even be interpreted. This is real today, independent of group constraints
   entirely, and the group redesign above (Section 7) does not fix it for the asset case — it only
   ensures the group path never inherits it. Fixing the asset case the same way (interpret against a
   deterministically-loaded inventory; only `replan`/`run` when genuinely necessary, scoped to the
   one resolved asset's own findings) is a plausible, bounded follow-up, but it changes the
   behavior of an existing, shipped command and was not asked for here — recorded so it's found by
   design rather than by a future fleet-scale audit rediscovering it from scratch.
