"""A narrow, mechanical grounding check for free prose: does a field
mention a CVE ID that contradicts the one real CVE the finding it was
written about is actually for?

CLAUDE.md's Safety and guardrails "Grounding validation" open item names
free prose (`RiskRecommendation.verdict_summary`/`narrative`,
`ResearchFinding.exploitation_summary`, `EnvironmentAssessment
.applicability_summary`, `tot.py`'s `ProposalOutput.proposal`/
`CritiqueOutput.justification`) as the piece `verify_scoring_matches_tool`/
`verify_research_matches_tool`/`verify_environment_matches_tool`/
`verify_constraint_matches_tool` cannot reach -- those all check
verbatim-copyable numeric/categorical/list fields against a tool's own
call_log result. Free-synthesized prose has no single ground-truth string
to diff against byte-for-byte, and this codebase has no LLM-judge
precedent to reach for instead: an LLM checking another LLM's prose would
be a second unreliable opinion, not a fix -- see CLAUDE.md's repeatedly
stated "the model never computes the number, only cites it" discipline,
already applied to `tot.CriticScores.aggregate` and to a future
execution-proposal's citation of real evidence.

**What this narrow check actually catches, and does not.** Every one of
the prose fields above is written about exactly ONE finding, which has
exactly one real `cve_id`. A prose field that mentions a DIFFERENT CVE ID
is essentially always a hallucination -- a finding's own narrative has no
legitimate reason to cite a different CVE by ID (a reference to a related
vulnerability would say so in words, not swap the identifier it's
supposed to be about). This is narrow by design: it catches "wrong
specific identifier," not "unsupported claim," "wrong number," or
"invented detail" -- those remain open, exactly as CLAUDE.md records.

**`hostname`/`finding_id` mention-checking were considered and
deliberately deferred, not built badly.** Neither has a single universal
shape to regex for the way a CVE ID does: `finding_id` formats vary by
ingest adapter ("F01" natively, "MDVMC-..." for Defender-shaped sources,
"VULN-..." for BluePeak), and a hostname string has no fixed pattern at
all. Checking either correctly would require passing the WHOLE fleet's
real identifiers into every check (to tell "mentions a real but wrong
one" apart from "mentions something that merely looks like one"), not
just the one finding's own evidence this module's function actually
receives -- a materially bigger, riskier piece of engineering than the
check below.

No I/O, no LLM call -- a pure regex-and-compare function, the same
"no external dependency" discipline `agents/prompt_safety.py` and
`remediation.py` already hold themselves to. Deliberately returns a set
rather than raising: each calling agent module re-raises through its own
existing mismatch type (`ResearchMismatchError`, `EnvironmentMismatchError`,
`ScoringMismatchError`, or `tot.py`'s `AgentOutputParseError` reuse for
the strategy-echo check) rather than this module inventing a new
exception type every call site's own retry seam would need to learn
about.

**Track C -- `find_neutralized_axis_assertions`, added alongside the CVE
check above for a DIFFERENT grounding gap.** A provisional (unconfirmed
ingest contract) run can leave one or more scoring axes -- `criticality`,
`environment`, `data_sensitivity`, `role`, `internet_exposed` -- entirely
NEUTRALIZED: the source never determined them, so `Asset.<field>` holds an
inert placeholder value (`scoring.neutralized_axes_for`, `adapters/
base.py`'s `NOT_COLLECTED_DEFAULTS`) that must never be trusted as a real
fact. A live test showed a model confidently restating exactly such a
placeholder ("role: workstation") as though it were an observed fact,
because the prompt handed it the raw value with no caveat co-located at
the point the value is actually stated (fixed separately, at the prompt
template level, in `build_risk_task`/`tot._describe_root` -- this function
is the mechanical backstop for whatever gets through anyway).

**Why proximity-gated, not a flat presence scan.** The placeholder values
themselves are ordinary English words -- `"workstation"`, `"file"`,
`"internal"`, the bare digit `3` -- that collide constantly with entirely
legitimate prose (this project's own PROGRESS.md uses the literal phrase
"dev workstation" for this exact scenario). A false positive here is worse
than the bug it fixes: it burns a retry and then, if it survives every
retry, silently drops an honest finding out of the exported plan
(`Coordinator._resolve_output`'s failure path). So this checks two literal
conditions together, not one: the placeholder value token AND its own
axis-name anchor (`"role"`, `"sensitivity"`, `"environment"`,
`"criticality"`) must both appear within a small character window of each
other -- "the word happens to appear" and "the model is actually
discussing this axis" read very differently under that combined condition,
even though neither alone would.

**Adversarial-review hardening pass (4 independent reviewers, each finding
re-verified by an independent skeptic) found and fixed six real defects in
the version above -- recorded here so a future reader doesn't rediscover
them.**

1. **`internet_exposed` was directionally blind (critical).** The branch
   looked up `_EXPOSURE_CLAIM_PHRASES[bool(exposed)]` -- i.e. only the
   phrase list matching the CURRENT placeholder direction, which is always
   `False` (`adapters/base.py`'s `NOT_COLLECTED_DEFAULTS["internet_exposed"]
   = False`). A model confidently asserting the OPPOSITE of the placeholder
   ("this host is internet-facing" when exposure is genuinely unknown) was
   undetectable by construction -- exactly the direction that inflates
   apparent risk, the one a security tool can least afford to miss. Fixed:
   both direction phrase lists are now checked together, unconditionally,
   whenever the axis is neutralized -- asserting EITHER direction about an
   unknown value is equally dishonest, so which one the placeholder happens
   to hold no longer gates which phrases get checked.
2. **The same branch had no proximity or subject scoping at all (medium).**
   A flat whole-text substring scan meant a claim about a DIFFERENT,
   explicitly named asset ("the payroll server ... is not exposed to the
   internet") tripped a violation on THIS finding's asset. Fixed by giving
   `internet_exposed` the same anchor+value proximity gate every other axis
   already had, anchored on a small, self-referential subject pattern
   ("this asset/host/device/server/system/machine/endpoint") rather than an
   axis name -- boolean claims have no axis-name word of their own to
   anchor on, but they are always made in reference to a specific subject,
   and requiring that subject to be THIS finding's own asset is what a
   generic axis-name anchor does for the other four axes.
3. **Off-by-truncation bug in `_value_near_anchor` (medium).** The old
   implementation sliced `text[lo:hi]` to the window and searched inside
   the slice; when a value token's own span straddled the slice boundary
   `hi`, the slice truncated it mid-word (`"internal"` cut to `"intern"`),
   silently missing a value whose START was well within the stated window.
   Fixed by comparing match SPANS directly (`re.finditer` over the whole
   text for both patterns, then a plain integer gap between spans) instead
   of ever slicing and re-searching a substring -- there is no boundary left
   to truncate across.
4. **The 60-/20-char windows were narrower than ordinary two-sentence
   prose (high, tempered to medium given part 3's design intent).**
   Measured directly: a plain two-sentence restatement ("This host's role
   has already been confirmed ... It is a workstation used daily by finance
   staff.") puts the value only 64 characters past the anchor, 4 over the
   old 60-char window; a similarly plain criticality sentence needed only
   49 against a 20-char window. Both are ordinary prose, not adversarial
   phrasing. Widened to `_PROXIMITY_WINDOW = 150` / `_CRITICALITY_WINDOW =
   55` -- both values measured against the actual existing "must NOT fire"
   regression test (`test_criticality_anchor_far_from_its_value_does_not_
   fire`, real gap 69) to confirm the widened window still excludes it, not
   picked by feel.
5. **Ordinary paraphrase of a neutralized value defeated detection even
   with the axis name directly adjacent (high, tempered -- see below).**
   `_VALUE_ALIASES` covered exactly two hand-picked words (`prod`/`dev`);
   every other value (`workstation`, `file`, `dc`, `internal`, ...) had no
   alias at all, so an ordinary model paraphrase ("a managed corporate
   laptop" for `workstation`, "a network-attached storage node" for `file`,
   "a domain controller" for `dc`, "a live, customer-facing tier" for
   `prod`) evaded the check outright, axis name present and all. Extended
   to a curated, axis-scoped alias table (`_AXIS_VALUE_ALIASES`) covering
   the common paraphrases actually demonstrated. This is still NOT a
   semantic paraphrase detector, by design (see "What this does and does
   not catch" below) -- it is the same curated-closed-list mechanism
   `_EXPOSURE_CLAIM_PHRASES` already uses for booleans, extended to the
   role/environment values a reviewer showed a model actually produces.
6. **Negation-blind proximity matching produced a real, reproducible false
   positive (medium).** "Unlike the file share host discussed earlier,
   this asset's role is unrelated to storage" tripped `role` even though
   the sentence explicitly DENIES the placeholder value, not restates it.
   A minimal, narrow guard was added: a small, curated set of CONTRAST
   markers (`"unlike"`, `"in contrast to"`, `"as opposed to"`, `"distinct
   from"`, `"differs from"`) checked in the text immediately spanning an
   anchor/value match pair suppresses that specific match. This is
   deliberately NOT general negation or hedge detection -- "not", "isn't",
   "never" and similar are deliberately excluded from the list, because
   the module's own hedge-tolerance design (below) depends on those NOT
   suppressing a match ("role: workstation, though this was never actually
   collected" must keep firing). Contrast markers name a comparison to a
   DIFFERENT subject; hedges qualify confidence about the SAME subject --
   different things, and only the former is guarded against here.

**Two collision classes the hardening pass explicitly did NOT chase, left
open on purpose, matching this project's own "record what's still open,
don't overclaim" discipline (CLAUDE.md's Grounding validation Track A/B
"does not do" callouts are the same convention).** A reviewer also
demonstrated: (a) a polysemous anchor word colliding with an unrelated
sense of itself in the SAME window -- `"role"` also means RBAC/privilege
role ("reviewed role-based access control (RBAC) settings on the file
server"), `"environment"` also means an OS-level env var ("environment
variable configuration from a file named prod.env"); and (b) an unrelated
digit near `"criticality"` with no decimal point involved at all
("criticality aside, 3 of the servers ... were already patched last
week"). Both are real, but neither is a bounded, low-regression-risk fix
the way items 1-6 above were: (a) would need actual word-sense
disambiguation, and (b) has no mechanical signal (no negation, no decimal
point, no alias mismatch) to hang a narrow rule on without also
suppressing genuine "criticality ... 3" restatements the check exists to
catch. Left as an accepted false-positive risk, consistent with the
module's own stated tradeoff (an occasional extra retry, not a missed
violation, is the acceptable failure mode) rather than patched with a
rule likely to introduce a new false negative to fix an old false
positive.

**What this does and does not catch -- the same honest-scope convention
`find_wrong_cve_mentions` above uses.** This is a MECHANICAL, BINARY check
with no hedge detection: a properly-hedged restatement ("role: workstation,
though this was never actually collected") still trips it, exactly like an
unhedged one -- deliberately, since teaching the check to parse hedge
language would reopen the same "trust the model's own framing" problem
this whole mechanism exists to close, and the safe failure mode here is an
occasional extra retry, not a missed violation. It also cannot catch a
paraphrase that never puts the axis's own value (or one of its curated
aliases) near the axis's own name at all (e.g. "this looks like an
ordinary end-user machine" with no nearby mention of "role" and no
recognized alias phrase) -- the same class of gap `find_wrong_cve_mentions`
already admits for `hostname`/`finding_id`. `internet_exposed` is boolean,
so it has no single value token to anchor on -- it uses a curated,
already-multi-word phrase list (both directions, since either is an
equally invalid claim about an unknown value) anchored on a
self-referential subject pattern instead of an axis name.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

# The exact pattern this project's other CVE-recognizing code already
# uses (agents/chat.py's _CVE_MENTION_PATTERN, adapters/configured.py's
# _CVE_ID_PATTERN) -- unanchored and case-insensitive, to find a mention
# anywhere inside free-form prose rather than validate one whole field.
_CVE_MENTION_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def find_wrong_cve_mentions(text: str, real_cve_id: str) -> set[str]:
    """Returns every CVE ID `text` mentions OTHER than `real_cve_id` --
    an empty set if the only CVE ID mentioned (or none at all) is the
    real one. Case-insensitive on both sides, so a source that happens to
    store `real_cve_id` in a different case than the prose's own mention
    doesn't produce a false positive."""
    mentioned = {m.group(0).upper() for m in _CVE_MENTION_PATTERN.finditer(text)}
    return mentioned - {real_cve_id.upper()}


# axis name -> the anchor REGEX (not a literal string -- see below) its
# own name is checked for. "criticality" only -- never "critical" -- since
# "critical" is CVSS/NVD severity language that appears in essentially
# every Research/Risk/ToT prompt regardless of this axis (see module
# docstring).
#
# Each pattern covers the singular AND the plain plural ("role"/"roles",
# "environment"/"environments", "sensitivity"/"sensitivities") --
# NOT an afterthought: an adversarial review of this exact function found
# a real bypass in the singular-only version ("Roles: workstation" matched
# neither the old literal "role" anchor nor any value token, so it passed
# `find_neutralized_axis_assertions` clean despite confidently restating
# the placeholder). Deliberately still narrow -- no stemming beyond the
# plain plural, and still gated by proximity to a value token, so this
# stays a precision-biased check, not a broader one.
_AXIS_ANCHOR_PATTERNS: dict[str, str] = {
    "role": r"roles?",
    "data_sensitivity": r"sensitivit(?:y|ies)",
    "environment": r"environments?",
}

# Character window scanned on EACH side of an anchor match for the
# placeholder value token. Wide enough to cover ordinary two-sentence
# prose about the same asset ("This host's role has already been
# confirmed ... It is a workstation used daily by finance staff." --
# measured gap 64) without ballooning into a full-document scan. Measured,
# not guessed: see the module docstring's hardening-pass item 4 for the
# exact before/after numbers, including the existing regression test this
# was checked against to confirm it still excludes a genuinely distant
# mention.
_PROXIMITY_WINDOW = 150

# criticality's own window is deliberately tighter than the general one:
# a bare digit is a much shorter, much more common token than a
# role/environment/sensitivity word, so this stays narrower to keep the
# "actually talking about this axis's value" signal strong. Still widened
# from the original 20 (which a plain one-sentence restatement, gap 49,
# already exceeded) -- 55 sits between that measured "should fire" gap
# (49) and the measured gap of the existing "should NOT fire" regression
# test (69), calibrated against both rather than picked by feel.
_CRITICALITY_WINDOW = 55

# A model is far more likely to write a natural-English paraphrase of a
# schema value than the schema's own short code -- checked in ADDITION to
# the literal value, never instead of it. Axis-scoped (not one flat table)
# so a value string ambiguous across axes -- "dev" is both an Environment
# value and an AssetRole value -- gets the right alias set for whichever
# axis is actually being checked, rather than one shared guess.
#
# Curated and bounded, not a semantic paraphrase detector: each entry is a
# specific phrasing an adversarial review round actually demonstrated a
# model producing for that exact value (module docstring, hardening-pass
# item 5), not an attempt at exhaustive coverage of every way to describe
# a role or sensitivity tier in English.
_AXIS_VALUE_ALIASES: dict[str, dict[str, tuple[str, ...]]] = {
    "environment": {
        "prod": ("prod", "production", "customer-facing"),
        "dev": ("dev", "development"),
    },
    "role": {
        "workstation": (
            "workstation", "corporate laptop", "employee endpoint",
            "end-user endpoint", "end-user machine", "employee device",
        ),
        "file": (
            "file", "network-attached storage", "storage node",
        ),
        "dc": (
            "dc", "domain controller",
        ),
    },
}

# Small, curated CONTRAST markers -- a comparison to a DIFFERENT subject,
# not a hedge about confidence in THIS subject. Deliberately excludes
# "not"/"isn't"/"never" and similar: those are hedge/negation language
# that the module's own design intentionally does NOT let suppress a
# match (see module docstring's "What this does and does not catch").
# Only a marker that names an explicit comparison to something else
# suppresses the match it's found near -- see hardening-pass item 6.
_CONTRAST_MARKERS: tuple[str, ...] = (
    "unlike", "in contrast to", "as opposed to", "distinct from", "differs from",
)

# Margin added on each side of the checked anchor/value span when looking
# for a contrast marker -- wide enough to catch "Unlike the X ... this
# asset's role is Y" (the marker sits well before the value match) and
# "role is unrelated to Y" (a marker sitting just after the anchor) without
# scanning the whole proximity window, which would risk suppressing a
# genuine match over a contrast marker that belongs to an unrelated clause.
_CONTRAST_MARGIN = 30

# Self-referential subject anchor for the boolean internet_exposed axis,
# which has no axis-name word of its own to anchor on the way the other
# four axes do. Requires "this <noun>", optionally with up to two
# intervening words ("this specific host"), so a claim is only counted
# when it's plausibly about THIS finding's own asset -- not a claim about
# some other, differently-referenced host mentioned in the same message
# (hardening-pass item 2).
_SUBJECT_ANCHOR_PATTERN = (
    r"this\s+(?:\w+\s+){0,2}(?:asset|host|device|server|system|machine|endpoint)"
)

# Curated, already multi-word (so already proximity-safe on their own)
# claims about internet exposure -- internet_exposed has no single value
# token the way the other four axes do. BOTH directions are checked
# together whenever the axis is neutralized (hardening-pass item 1):
# asserting either direction about a value that is genuinely unknown is
# an equally invalid claim, so which one happens to match the current
# placeholder no longer decides which phrases get checked.
_EXPOSURE_CLAIM_PHRASES: dict[bool, tuple[str, ...]] = {
    True: (
        "internet-facing", "internet facing", "publicly accessible", "publicly-accessible",
        "exposed to the internet", "internet-exposed", "internet exposed",
        "accessible from the internet", "reachable from the internet",
    ),
    False: (
        "not internet-facing", "not internet facing", "internal-only", "internal only",
        "not exposed to the internet", "not publicly accessible", "isolated from the internet",
        "not reachable from the internet", "not accessible from the internet",
    ),
}
_ALL_EXPOSURE_CLAIM_PHRASES: tuple[str, ...] = _EXPOSURE_CLAIM_PHRASES[True] + _EXPOSURE_CLAIM_PHRASES[False]


def neutralized_axis_note(axis: str, neutralized_axes: Iterable[str]) -> str:
    """The inline caveat suffix for a possibly-placeholder axis value
    stated in a PROMPT TEMPLATE line -- e.g. `f"role {role}{note}"` -- so
    the caveat sits at the exact point the value is stated, not buried
    elsewhere in the same prompt (`agents/risk.py`'s `build_risk_task`,
    `tot.py`'s `_describe_root`).

    This is the actual root cause fix behind `find_neutralized_axis_
    assertions` above: a live test showed a model confidently restating a
    neutralized axis's placeholder value as fact, and the reason was that
    the template hands the model that raw value with no caveat co-located
    at the point it's stated -- the honest caveat existed elsewhere in the
    same prompt (`scoring._rationale`'s own wording), but never next to
    the bald value itself. Empty string when `axis` is not in
    `neutralized_axes` -- every existing prompt line for a confirmed-
    contract run (never neutralized) is therefore byte-identical to
    before this existed."""
    return (
        " (NOT COLLECTED for this source -- placeholder, not a fact)"
        if axis in neutralized_axes
        else ""
    )


def _span_gap(a_start: int, a_end: int, b_start: int, b_end: int) -> int:
    """The character distance between two match spans -- 0 if they
    overlap or touch. Comparing SPANS directly (rather than slicing text
    to a window and re-searching inside the slice) is what fixes the
    off-by-truncation bug a slice-based approach has: a slice boundary can
    bisect a value token mid-word, silently hiding a match whose START was
    well within the nominal window (hardening-pass item 3)."""
    if a_end <= b_start:
        return b_start - a_end
    if b_end <= a_start:
        return a_start - b_end
    return 0


def _contrast_marker_between(text: str, a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """True if a curated CONTRAST marker (`_CONTRAST_MARKERS`) appears
    within `_CONTRAST_MARGIN` characters of the span covering both match
    positions -- see hardening-pass item 6. Deliberately narrow: this is
    not hedge or negation detection in general, only an explicit
    comparison-to-a-different-subject marker, so a hedged-but-still-
    asserted restatement keeps firing exactly as designed."""
    lo = max(0, min(a_start, b_start) - _CONTRAST_MARGIN)
    hi = min(len(text), max(a_end, b_end) + _CONTRAST_MARGIN)
    span = text[lo:hi].lower()
    return any(marker in span for marker in _CONTRAST_MARKERS)


def _value_near_anchor(
    text: str,
    anchor_pattern: str,
    window: int,
    value_tokens: tuple[str, ...] = (),
    value_pattern: "re.Pattern[str] | None" = None,
) -> bool:
    """True if some occurrence of a value token (or, when `value_pattern`
    is given directly, some match of that pattern) appears within `window`
    characters of some occurrence of `anchor_pattern` in `text`, and no
    curated contrast marker sits between them (`_contrast_marker_between`).
    `anchor_pattern` is a REGEX fragment, not a literal string -- always
    one of this module's own fixed constants, never caller-supplied text,
    so it is used directly rather than `re.escape`'d. `value_pattern`, when
    given, must already be anchored with its own `\\b`s (or equivalent) --
    used by the criticality check to apply a decimal-number-safe pattern
    that a plain token alternation can't express."""
    if value_pattern is None:
        value_pattern = re.compile(
            r"\b(?:" + "|".join(re.escape(v) for v in value_tokens) + r")\b", re.IGNORECASE
        )
    anchor_matches = list(re.finditer(rf"\b(?:{anchor_pattern})\b", text, re.IGNORECASE))
    if not anchor_matches:
        return False
    value_matches = list(value_pattern.finditer(text))
    if not value_matches:
        return False
    for a in anchor_matches:
        for v in value_matches:
            if _span_gap(a.start(), a.end(), v.start(), v.end()) > window:
                continue
            if _contrast_marker_between(text, a.start(), a.end(), v.start(), v.end()):
                continue
            return True
    return False


def _criticality_value_pattern(value: str) -> "re.Pattern[str]":
    """A criticality value token that never matches inside a decimal
    number. Plain `\\bvalue\\b` matches "3" inside "3.5" too, because "."
    is a non-word character and `\\b` only checks the word/non-word
    boundary -- a real, reproducible false positive against CVSS-style
    decimal scores appearing near the word "criticality" in the same
    prose (hardening-pass item 6's sibling decimal-collision bug, fixed
    alongside it). Blocks a match immediately preceded by a digit or a
    "." (so "13" and the "5" in "3.5" are excluded) and immediately
    followed by "." + digit or another digit (so the "3" in "3.5" and in
    "33" are excluded) -- a bare "3" at a sentence boundary ("...is 3."
    or "...is 3,") is unaffected, since only "." DIRECTLY followed by
    another digit is treated as a decimal point."""
    escaped = re.escape(value)
    return re.compile(rf"(?<!\d)(?<!\.){escaped}(?!\.\d)(?!\d)", re.IGNORECASE)


def find_neutralized_axis_assertions(
    text: str, neutralized_axes: Iterable[str], axis_values: Mapping[str, Any]
) -> set[str]:
    """Returns the subset of `neutralized_axes` whose own placeholder
    value (`axis_values[axis]`) is stated near its own axis-name anchor
    in `text` -- see the module docstring for the full design ("why
    proximity-gated", "what this does and does not catch"). Only axes
    present in BOTH `neutralized_axes` and `axis_values` are ever checked
    -- a caller that only has some of the five need not fabricate the
    rest. `axis_values` should be the ground-truth values currently in
    effect on the asset (e.g. `agents/risk.py`'s `score_finding` tool
    result, or `enriched.asset` directly), the same values that ARE the
    placeholder whenever an axis is in `neutralized_axes`."""
    neutralized = set(neutralized_axes)
    violations: set[str] = set()

    for axis, anchor_pattern in _AXIS_ANCHOR_PATTERNS.items():
        if axis not in neutralized or axis not in axis_values:
            continue
        value = axis_values[axis]
        if value in (None, ""):
            continue
        tokens = _AXIS_VALUE_ALIASES.get(axis, {}).get(str(value), (str(value),))
        if _value_near_anchor(text, anchor_pattern, _PROXIMITY_WINDOW, value_tokens=tokens):
            violations.add(axis)

    if "criticality" in neutralized and "criticality" in axis_values:
        value = axis_values["criticality"]
        if value is not None:
            pattern = _criticality_value_pattern(str(value))
            if _value_near_anchor(
                text, r"criticalit(?:y|ies)", _CRITICALITY_WINDOW, value_pattern=pattern
            ):
                violations.add("criticality")

    if "internet_exposed" in neutralized and "internet_exposed" in axis_values:
        exposed = axis_values["internet_exposed"]
        if exposed is not None:
            # Both directions, always -- see hardening-pass item 1. Which
            # way the placeholder happens to point no longer decides which
            # phrase list is even consulted: asserting EITHER direction
            # about a value that is genuinely unknown is an equally
            # invalid claim.
            if _value_near_anchor(
                text, _SUBJECT_ANCHOR_PATTERN, _PROXIMITY_WINDOW,
                value_tokens=_ALL_EXPOSURE_CLAIM_PHRASES,
            ):
                violations.add("internet_exposed")

    return violations
